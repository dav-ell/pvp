import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:flutter/foundation.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'api.dart';
import 'group_calls.dart';
import 'media.dart';
import 'models.dart';
import 'native.dart';

class PvpController extends ChangeNotifier {
  final NativeHost host;
  final CallMedia media;
  late final GroupCalls group;
  late PvpApi api;
  Person? user, peer;
  List<Person> friends = [];
  List<Map<String, dynamic>> history = [];
  List<MediaDeviceInfo> devices = [];
  Preferences preferences = Preferences();
  String page = 'rooms',
      phase = 'idle',
      message = '',
      loginStatus = 'disabled',
      notifications = 'notRequested';
  bool meetingsAvailable = false,
      meetingModerationAvailable = false,
      openMeetingsAvailable = false;
  String? pendingMeetingLink;
  String? recentMeetingId, recentMeetingName;
  void rememberMeeting(String id, String name) {
    recentMeetingId = id;
    recentMeetingName = name;
    page = 'rooms';
    _changed();
  }

  List<Map<String, dynamic>> meetings = [];
  Future<void> refreshMeetings() async {
    if (!meetingsAvailable || user == null) return;
    final account = user!.id, service = api;
    final result = await service.request('/meetings');
    if (user?.id != account || api != service || _closing) return;
    meetings = (result as List)
        .map((m) => Map<String, dynamic>.from(m))
        .toList();
    _changed();
  }

  String? callId;
  bool loading = true,
      working = false,
      online = false,
      suspended = false,
      replaced = false,
      updatingMedia = false;
  WebSocket? _socket;
  Timer? _retry, _callTimeout;
  int _connectionGeneration = 0, _callGeneration = 0, _attempt = 0;
  Future<void> _signals = Future.value(), _cleanup = Future.value();
  bool _closing = false;
  bool _restoring = false;
  int _refreshGeneration = 0;
  Function(dynamic)? _previousDeviceChange, _deviceChange;
  bool _refreshingDevices = false, _deviceRefreshQueued = false;
  PvpController({
    NativeHost? host,
    CallMedia? media,
    GroupMedia? groupMedia,
    String? address,
  }) : host = host ?? NativeHost(),
       media = media ?? CallMedia() {
    api = PvpApi(
      address ??
          const String.fromEnvironment(
            'PVP_SERVICE',
            defaultValue: 'https://lopixel.space',
          ),
    );
    this.media.addListener(notifyListeners);
    this.media.onConnected = () {
      phase = 'connected';
      _callTimeout?.cancel();
      _changed();
    };
    this.media.onFailure = (error) => unawaited(endCall(error: error));
    this.media.sendSignal = (payload) {
      if (callId != null) {
        _send({'type': 'signal', 'call_id': callId, 'payload': payload});
      }
    };
    group = GroupCalls(
      host: this.host,
      media: groupMedia ?? GroupMedia(),
      user: () => user,
      preferences: () => preferences,
      send: (data) {
        if (!_send(data)) throw StateError('PVP is reconnecting.');
      },
      stopPreview: () => this.media.stop(),
      otherBusy: () => phase != 'idle',
    );
    group.addListener(_changed);
    _previousDeviceChange = navigator.mediaDevices.ondevicechange;
    _deviceChange = (_) => unawaited(handleDeviceChange());
    navigator.mediaDevices.ondevicechange = _deviceChange;
    this.host.onAction(_nativeAction);
  }
  bool get busy => phase != 'idle' || group.busy;
  List<Person> get accepted =>
      friends.where((p) => p.status == 'accepted').toList();
  List<Person> get requests =>
      friends.where((p) => p.status != 'accepted').toList();
  String get _preferencesKey =>
      'preferences.${api.address}.${user?.id ?? "guest"}';

  Future<void> initialize() async {
    try {
      final savedOrigin = await host.readPreferences('service');
      if (savedOrigin != null && !const bool.hasEnvironment('PVP_SERVICE')) {
        api.dispose();
        api = PvpApi(savedOrigin);
      }
      api.session = await host.readSession(api.address);
      // Camera/renderer or system-settings failures must not prevent login.
      try {
        await media.initialize();
        await refreshSystemSettings();
      } catch (e) {
        message = _error(e);
      }
      if (api.session != null) await _restore();
      pendingMeetingLink ??= await host.invoke<String>('takeMeetingLink');
    } catch (e) {
      message = _error(e);
      if (user == null) {
        _retry?.cancel();
        _retry = Timer(const Duration(seconds: 5), () {
          if (_closing || user != null || working) return;
          unawaited(api.session != null ? _recoverSession() : initialize());
        });
      }
    } finally {
      loading = false;
      _changed();
    }
  }

  Future<void> _restore() async {
    try {
      user = Person.fromJson(
        Map<String, dynamic>.from(await api.request('/me')),
      );
      preferences = Preferences.decode(
        await host.readPreferences(_preferencesKey),
      );
      await reconnect();
    } on ApiException catch (e) {
      if (e.status != 401) rethrow;
      api.session = null;
      await host.saveSession(api.address, null);
    }
  }

  Future<void> _recoverSession() async {
    if (_restoring ||
        _closing ||
        suspended ||
        api.session == null ||
        user != null) {
      return;
    }
    _restoring = true;
    _retry?.cancel();
    try {
      await _restore();
    } catch (e) {
      message = _error(e);
      _retry = Timer(
        const Duration(seconds: 10),
        () => unawaited(_recoverSession()),
      );
    } finally {
      _restoring = false;
      _changed();
    }
  }

  Future<bool> perform(Future<void> Function() action) async {
    if (working) return false;
    working = true;
    message = '';
    _changed();
    try {
      await action();
      return true;
    } catch (e) {
      message = _error(e);
      return false;
    } finally {
      working = false;
      _changed();
    }
  }

  static String _error(Object error) {
    if (error is ApiException) return error.message;
    if (error is SocketException ||
        error is TimeoutException ||
        error is HandshakeException) {
      return 'Could not reach the service. Check your connection and try again.';
    }
    final text = error.toString();
    if (text.contains('getUserMedia') || text.contains('NotAllowed')) {
      return 'Camera or microphone access failed. Check permissions in System Settings, then try again.';
    }
    return text.replaceFirst(
      RegExp(r'^(Exception|Bad state|FormatException): '),
      '',
    );
  }

  Future<bool> authenticate(
    String username,
    String password,
    String name,
    bool register,
  ) => perform(() async {
    final result = await api.request(
      register ? '/register' : '/login',
      method: 'POST',
      data: {
        'username': username.trim(),
        'password': password,
        if (register) 'display_name': name.trim(),
      },
    );
    await _enterIdentity(Map<String, dynamic>.from(result));
  });

  Future<bool> startGuest(String name) => perform(() async {
    final result = await api.request(
      '/guest/start',
      method: 'POST',
      data: {'display_name': name.trim().isEmpty ? 'Guest' : name.trim()},
    );
    await _enterIdentity(Map<String, dynamic>.from(result));
  });

  Future<void> _enterIdentity(Map<String, dynamic> result) async {
    user = Person.fromJson(result);
    try {
      await host.saveSession(api.address, api.session);
    } catch (e) {
      message = '${_error(e)} This sign-in will last until you quit.';
    }
    preferences = Preferences.decode(
      await host.readPreferences(_preferencesKey),
    );
    replaced = false;
    await reconnect();
  }

  Future<void> refresh() async {
    if (user == null) return;
    final userId = user!.id;
    final generation = ++_refreshGeneration;
    final results = await Future.wait([
      api.request('/friends'),
      api.request('/history'),
    ]);
    if (user?.id != userId || generation != _refreshGeneration) return;
    friends = (results[0] as List)
        .map((j) => Person.fromJson(Map<String, dynamic>.from(j)))
        .toList();
    history = (results[1] as List)
        .map((j) => Map<String, dynamic>.from(j))
        .toList();
    _changed();
  }

  Future<bool> addFriend(String username) => perform(() async {
    await api.request(
      '/friends/request',
      method: 'POST',
      data: {'username': username.trim()},
    );
    await refresh();
  });
  Future<void> acceptFriend(Person p) => perform(() async {
    await api.request('/friends/${p.id}/accept', method: 'POST');
    await refresh();
  });
  Future<void> removeFriend(Person p) => perform(() async {
    await api.request('/friends/${p.id}', method: 'DELETE');
    await refresh();
  });
  void navigate(String view) {
    if (page == 'settings' && view != 'settings' && !busy) {
      unawaited(stopPreview());
    }
    page = view;
    _changed();
  }

  void dismissMessage() {
    message = '';
    notifyListeners();
  }

  Future<void> reconnect() async {
    _retry?.cancel();
    if (user == null || suspended || _closing) return;
    replaced = false;
    final generation = ++_connectionGeneration;
    final old = _socket;
    _socket = null;
    online = false;
    _changed();
    await old?.close();
    try {
      final socket = await api.connect();
      if (generation != _connectionGeneration ||
          user == null ||
          _closing ||
          suspended) {
        await socket.close();
        return;
      }
      _socket = socket;
      socket.pingInterval = const Duration(seconds: 15);
      online = true;
      _attempt = 0;
      _changed();
      socket.listen(
        (event) {
          if (generation != _connectionGeneration) return;
          if (event is! String || event.length > 65536) {
            unawaited(socket.close());
            return;
          }
          try {
            final data = Map<String, dynamic>.from(jsonDecode(event));
            if (data['type'] == 'signal' || data['type'] == 'call-accepted') {
              if (++_signalMessages > 260) {
                unawaited(endCall(error: 'Too many call signals.'));
                return;
              }
              final callGeneration = _callGeneration;
              _signals = _signals
                  .then((_) async {
                    if (generation == _connectionGeneration &&
                        callGeneration == _callGeneration) {
                      await _event(data);
                    }
                  })
                  .catchError((Object e) {
                    if (callGeneration == _callGeneration) {
                      unawaited(endCall(error: _error(e)));
                    }
                  });
            } else {
              unawaited(
                _event(data).catchError((Object e) {
                  message = _error(e);
                  _changed();
                }),
              );
            }
          } catch (_) {
            message = 'The service sent an unreadable message.';
            _changed();
          }
        },
        onDone: () => _disconnected(generation),
        onError: (_) => _disconnected(generation),
        cancelOnError: true,
      );
      unawaited(
        refresh().catchError((Object e) {
          message = _error(e);
          _changed();
        }),
      );
    } catch (e) {
      if (generation == _connectionGeneration) {
        if (e is WebSocketException && e.httpStatusCode == 401) {
          await signOut(remote: false);
          message = 'Your sign-in expired. Please sign in again.';
          _changed();
          return;
        }
        message = _error(e);
        _disconnected(generation);
      }
    }
  }

  void _disconnected(int generation) {
    if (generation != _connectionGeneration) return;
    _connectionGeneration++;
    _socket = null;
    online = false;
    if (busy) unawaited(endCall(error: 'The service connection was lost.'));
    if (user != null && !suspended && !replaced && !_closing) {
      final seconds = min(30, pow(2, min(_attempt++, 5)).toInt());
      _retry?.cancel();
      _retry = Timer(
        Duration(milliseconds: seconds * 1000 + Random().nextInt(500)),
        () => unawaited(reconnect()),
      );
    }
    _changed();
  }

  int _signalMessages = 0;

  bool _send(Map<String, dynamic> payload) {
    if (!online || _socket == null) return false;
    _socket!.add(jsonEncode(payload));
    if (phase != 'idle' && payload['type'] != 'pong') {
      media.recordNetworkEvent(
        'Signaling sent: ${payload['type'] == 'signal' ? payload['payload']['type'] : payload['type']}',
      );
    }
    return true;
  }

  Future<void> _event(Map<String, dynamic> data) async {
    if (data['type'] == 'server-capabilities') {
      group.available = data['groupCalls'] == true;
      group.voiceAvailable = data['voiceRooms'] == true;
      if (group.available) group.capabilities();
      meetingsAvailable = data['permanentMeetings'] == true;
      meetingModerationAvailable = data['meetingModeration'] == true;
      openMeetingsAvailable = data['openMeetings'] == true;
      if (meetingsAvailable) await refreshMeetings();
      _changed();
      return;
    }
    if ((data['type'] as String).startsWith('room-')) {
      await group.handle(data);
      return;
    }
    if (data['type'] == 'error' && group.pending) await group.handle(data);
    if ((phase != 'idle' || data['type'] == 'incoming') &&
        data['type'] != 'ping') {
      media.recordNetworkEvent(
        'Signaling received: ${data['type'] == 'signal' ? data['payload']['type'] : data['type']}',
      );
    }
    switch (data['type']) {
      case 'ping':
        _send({'type': 'pong'});
      case 'meetings-changed':
        await refreshMeetings();
      case 'friends-changed':
        await refresh();
      case 'calling':
        if (phase != 'preparing' && phase != 'calling') {
          _send({'type': 'hangup', 'call_id': data['call_id']});
          return;
        }
        callId = data['call_id'];
        phase = 'calling';
        _changed();
      case 'incoming':
        if (busy) {
          _send({'type': 'decline', 'call_id': data['call_id']});
          return;
        }
        _callGeneration++;
        callId = data['call_id'];
        peer = Person.fromJson(Map<String, dynamic>.from(data['peer']));
        phase = 'incoming';
        _changed();
        await host.invoke('incoming', {
          'call_id': callId,
          'name': peer!.name,
          'sound': preferences.ring,
        });
      case 'call-accepted':
        if (data['call_id'] != callId) return;
        final generation = _callGeneration;
        phase = 'connecting';
        _callTimeout?.cancel();
        _callTimeout = Timer(
          const Duration(seconds: 35),
          () => unawaited(
            endCall(
              error:
                  'A direct connection could not be established. Try another network.',
            ),
          ),
        );
        await host.invoke('stopRinging');
        if (generation != _callGeneration || data['call_id'] != callId) return;
        _changed();
        await media.connect(preferences, data['initiator'] == true);
        if (generation != _callGeneration) return;
        await media.setSpeaker(preferences.speaker);
      case 'signal':
        if (data['call_id'] == callId) {
          await media.signal(
            Map<String, dynamic>.from(data['payload']),
            preferences.quality,
          );
        }
      case 'call-ended':
        if (data['call_id'] == callId) {
          final reason = data['reason'];
          await endCall(
            notifyPeer: false,
            error: reason == 'declined'
                ? '${peer?.name ?? "Your friend"} declined the call.'
                : reason == 'missed'
                ? 'No answer. Try again later.'
                : reason == 'disconnected'
                ? 'Your friend disconnected.'
                : null,
          );
        }
      case 'error':
        await endCall(
          notifyPeer: false,
          error: data['message'] ?? 'The call could not be started.',
        );
      case 'replaced':
        replaced = true;
        _retry?.cancel();
        await endCall(
          notifyPeer: false,
          error: 'PVP was opened elsewhere. Click Reconnect to use this Mac.',
        );
        online = false;
        _changed();
      case 'signed-out':
        await signOut(remote: false);
    }
  }

  Future<void> startCall(Person person) async {
    if (busy || !online || person.status != 'accepted') return;
    final generation = ++_callGeneration;
    phase = 'preparing';
    peer = person;
    message = '';
    _changed();
    await host.invoke('show');
    try {
      await _cleanup;
      if (generation != _callGeneration) return;
      await media.stop();
      if (generation != _callGeneration) return;
      media.voiceOnly = true;
      await media.acquire(preferences);
      if (generation != _callGeneration) return;
      if (!_send({'type': 'call', 'peer_id': person.id})) {
        throw const ApiException(
          0,
          'You are offline. Reconnect before calling.',
        );
      }
      phase = 'calling';
      _callTimeout = Timer(
        const Duration(seconds: 70),
        () => unawaited(endCall(error: 'No answer. Try again later.')),
      );
      _changed();
    } catch (e) {
      if (generation == _callGeneration) await endCall(error: _error(e));
    }
  }

  Future<void> answer() async {
    if (phase != 'incoming') return;
    final generation = _callGeneration;
    phase = 'preparing';
    _changed();
    await host.invoke('stopRinging');
    try {
      await _cleanup;
      if (generation != _callGeneration) return;
      await media.stop();
      if (generation != _callGeneration) return;
      media.voiceOnly = true;
      await media.acquire(preferences);
      if (generation != _callGeneration) return;
      if (!_send({'type': 'accept', 'call_id': callId})) {
        throw const ApiException(
          0,
          'You are offline. Reconnect before answering.',
        );
      }
      phase = 'connecting';
      _changed();
    } catch (e) {
      if (generation == _callGeneration) await endCall(error: _error(e));
    }
  }

  Future<void> decline() async {
    if (callId != null) _send({'type': 'decline', 'call_id': callId});
    await endCall(notifyPeer: false);
  }

  Future<void> endCall({bool notifyPeer = true, String? error}) async {
    final groupStopping = group.busy ? group.leave() : Future<void>.value();
    _callGeneration++;
    _signalMessages = 0;
    _callTimeout?.cancel();
    if (notifyPeer && callId != null) {
      _send({'type': 'hangup', 'call_id': callId});
    }
    callId = null;
    peer = null;
    phase = 'idle';
    if (error != null) message = error;
    final stopping = media.stop();
    // Platform UI/ringing is best effort. It must never gate media teardown.
    unawaited(
      host.invoke('stopRinging').then<void>((_) {}).catchError((Object _) {}),
    );
    _cleanup = Future.wait<void>([
      _cleanup,
      stopping,
      groupStopping,
    ]).then((_) {});
    _changed();
    await _cleanup;
    if (user != null && !_closing) {
      unawaited(refresh().catchError((Object _) {}));
    }
  }

  Future<bool> setQuality(Quality q) => perform(() async {
    if (updatingMedia) return;
    updatingMedia = true;
    final old = preferences.quality;
    preferences.quality = q;
    try {
      if (group.joined) {
        await group.media.applyLimits(q);
      } else if (old.height != q.height || old.fps != q.fps) {
        await media.reconfigure(preferences);
      } else {
        await media.applyLimits(q);
      }
      await host.savePreferences(_preferencesKey, preferences.encode());
    } catch (_) {
      preferences.quality = old;
      rethrow;
    } finally {
      updatingMedia = false;
    }
  });
  Future<void> loadDevices() => perform(() async {
    await media.initialize();
    await handleDeviceChange();
  });
  // Device enumeration never asks for capture. A listener remains a listener;
  // routing an already-consented input keeps every sender/track and mute flag.
  Future<void> handleDeviceChange({
    List<MediaDeviceInfo>? observedDevices,
  }) async {
    if (_closing) return;
    if (_refreshingDevices) {
      _deviceRefreshQueued = true;
      return;
    }
    _refreshingDevices = true;
    final chosen = preferences.microphone;
    try {
      final listed =
          observedDevices ?? await navigator.mediaDevices.enumerateDevices();
      if (_closing) return;
      devices = listed;
      if (chosen.isNotEmpty &&
          preferences.microphone == chosen &&
          !listed.any((d) => d.kind == 'audioinput' && d.deviceId == chosen)) {
        final active = group.joined ? group.media : media;
        final hasCapture = active.stream?.getAudioTracks().isNotEmpty == true;
        if (hasCapture) await active.setMicrophone('');
        if (_closing || preferences.microphone != chosen) return;
        preferences.microphone = '';
        active.microphoneNotice = hasCapture
            ? 'Microphone disconnected. Using System default. Your mute setting is unchanged.'
            : 'Saved microphone unavailable. System default will be used when you choose a microphone.';
        message = active.microphoneNotice;
        await host.savePreferences(_preferencesKey, preferences.encode());
      }
      _changed();
    } catch (_) {
      if (!_closing && preferences.microphone == chosen && chosen.isNotEmpty) {
        message =
            'Microphone disconnected. Choose System default or another microphone in Audio & video.';
        _changed();
      }
    } finally {
      _refreshingDevices = false;
      if (_deviceRefreshQueued && !_closing) {
        _deviceRefreshQueued = false;
        unawaited(handleDeviceChange());
      }
    }
  }

  Future<void> setDevice(String kind, String id) => perform(() async {
    final old = Preferences.decode(preferences.encode());
    if (kind == 'videoinput') {
      preferences.camera = id;
    } else if (kind == 'audioinput') {
      preferences.microphone = id;
    } else {
      preferences.speaker = id;
    }
    try {
      if (kind == 'audiooutput') {
        await (group.joined ? group.media : media).setSpeaker(id);
      } else if (kind == 'audioinput') {
        // Audio routing belongs to the native device module. Keep the current
        // sender/camera tracks so switching inputs does not interrupt the call.
        await (group.joined ? group.media : media).setMicrophone(id);
        (group.joined ? group.media : media).microphoneNotice = '';
      } else {
        if (group.joined) {
          if (!group.media.cameraOff && !group.media.screenSharing) {
            await group.media.toggleVideo(old);
            try {
              await group.media.toggleVideo(preferences);
            } catch (_) {
              await group.media.toggleVideo(old);
              group.broadcast();
              rethrow;
            }
            group.broadcast();
          }
        } else {
          await media.reconfigure(preferences);
        }
      }
      await host.savePreferences(_preferencesKey, preferences.encode());
    } catch (_) {
      preferences = old;
      rethrow;
    }
  });
  Future<void> preview() => perform(() async {
    if (!busy) {
      media.voiceOnly = false;
      await media.acquire(preferences);
    }
    devices = await navigator.mediaDevices.enumerateDevices();
  });
  Future<bool> setEchoCancellation(bool enabled) => perform(() async {
    final previous = preferences.echoCancellation;
    final activeMedia = group.joined ? group.media : media;
    try {
      await activeMedia.setEchoCancellation(enabled);
      preferences.echoCancellation = enabled;
      await host.savePreferences(_preferencesKey, preferences.encode());
    } catch (_) {
      preferences.echoCancellation = previous;
      try {
        await activeMedia.setEchoCancellation(previous);
      } catch (_) {
        // The call may have ended while the setting was being applied.
      }
      rethrow;
    }
  });

  Future<void> stopPreview() async {
    if (!busy) await media.stop();
  }

  Future<void> setControlLabels(bool value) async {
    preferences.showControlLabels = value;
    await host.savePreferences(_preferencesKey, preferences.encode());
    _changed();
  }

  Future<void> setRing(bool value) async {
    preferences.ring = value;
    await host.savePreferences(_preferencesKey, preferences.encode());
    _changed();
  }

  Future<void> refreshSystemSettings() async {
    loginStatus = await host.invoke<String>('loginStatus') ?? 'disabled';
    notifications =
        await host.invoke<String>('notifications') ?? 'notRequested';
    _changed();
  }

  Future<void> setLogin(bool value) => perform(() async {
    loginStatus = await host.invoke<String>('setLogin', value) ?? 'disabled';
  });
  Future<void> enableNotifications() => perform(() async {
    if (notifications == 'denied') {
      await host.invoke('openNotificationSettings');
      return;
    }
    await host.invoke('enableNotifications');
    await refreshSystemSettings();
  });
  Future<bool> setService(String address) => perform(() async {
    if (user != null) {
      throw const ApiException(0, 'Sign out before changing services.');
    }
    final replacement = PvpApi(address);
    await replacement.request('/me').catchError((Object e) {
      if (e is! ApiException || e.status != 401) throw e;
      return null;
    });
    api.dispose();
    api = replacement;
    await host.savePreferences('service', api.address);
    api.session = await host.readSession(api.address);
    if (api.session != null) await _restore();
  });
  Future<void> signOut({bool remote = true}) async {
    _retry?.cancel();
    _connectionGeneration++;
    await endCall();
    online = false;
    if (remote) {
      try {
        await api.request('/logout', method: 'POST');
      } catch (_) {}
    }
    await _socket?.close();
    _socket = null;
    api.session = null;
    await host.saveSession(api.address, null);
    user = null;
    meetings = [];
    meetingsAvailable = false;
    meetingModerationAvailable = false;
    openMeetingsAvailable = false;
    friends = [];
    history = [];
    preferences = Preferences();
    page = 'rooms';
    recentMeetingId = null;
    recentMeetingName = null;
    _changed();
  }

  Future<void> _nativeAction(String action, Map<String, dynamic> args) async {
    switch (action) {
      case 'meeting-link':
        pendingMeetingLink = args['url'] as String?;
        _changed();
        await host.invoke('takeMeetingLink');
      case 'call':
        final matches = accepted.where((p) => p.id == args['peer_id']);
        if (matches.isNotEmpty) await startCall(matches.first);
      case 'answer':
        if (args['call_id'] == 'room:${group.id}') {
          await group.join();
        } else if (args['call_id'] == callId) {
          await answer();
        }
      case 'decline':
        if (args['call_id'] == 'room:${group.id}') {
          await group.leave();
        } else if (args['call_id'] == callId) {
          await decline();
        }
      case 'hangup':
        await endCall();
      case 'settings':
        navigate('settings');
        await refreshSystemSettings();
      case 'hidden':
        if (!busy) await stopPreview();
      case 'sleep':
        suspended = true;
        _retry?.cancel();
        await endCall();
        ++_connectionGeneration;
        online = false;
        await _socket?.close();
        _socket = null;
        _changed();
      case 'wake':
        suspended = false;
        if (user == null) {
          await _recoverSession();
        } else {
          await reconnect();
        }
      case 'network':
        if (args['available'] == true && !online && !suspended && !replaced) {
          if (user == null) {
            await _recoverSession();
          } else {
            await reconnect();
          }
        }
      case 'quit':
        _closing = true;
        _retry?.cancel();
        await endCall();
        ++_connectionGeneration;
        await _socket?.close();
        await host.invoke('quitComplete');
    }
  }

  @override
  void dispose() {
    _closing = true;
    ++_connectionGeneration;
    ++_refreshGeneration;
    _retry?.cancel();
    _callTimeout?.cancel();
    if (identical(navigator.mediaDevices.ondevicechange, _deviceChange)) {
      navigator.mediaDevices.ondevicechange = _previousDeviceChange;
    }
    group.removeListener(_changed);
    media.removeListener(notifyListeners);
    unawaited(_socket?.close());
    api.dispose();
    super.dispose();
  }

  void _changed() {
    if (_closing) return;
    notifyListeners();
    unawaited(
      host.invoke('sync', {
        'name': user?.name,
        'online': online,
        'busy': busy,
        'incoming':
            phase == 'incoming' || (group.room != null && !group.joined),
        'friends': accepted
            .map((p) => {'id': p.id, 'name': p.name, 'online': p.online})
            .toList(),
      }),
    );
  }
}
