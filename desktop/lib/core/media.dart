import 'dart:convert';
import 'bandwidth.dart';
import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'models.dart';
import 'native.dart';
import 'security.dart';
import 'connection_evidence.dart';
import 'call_observations.dart';

class CallMedia extends ChangeNotifier {
  final local = RTCVideoRenderer(), remote = RTCVideoRenderer();
  final Future<MediaStream> Function(Map<String, dynamic>)? captureOverride;
  final Future<MediaStream> Function(Map<String, dynamic>)?
  displayCaptureOverride;
  final Future<void> Function(RTCPeerConnection)? peerCreated;
  RTCPeerConnection? connection;
  BandwidthMeter bandwidthMeter = BandwidthMeter();
  ConnectionCaps connectionCaps = ConnectionCaps();
  StreamCaps requestedCaps = StreamCaps();
  RTCDataChannel? bandwidthChannel;
  bool bandwidthSupported = false;
  Quality? _currentQuality;
  final outgoing = OutgoingMediaStats();
  final mutedSpeech = MutedSpeechObservation();
  int? appliedVideoKbps, appliedAudioKbps;
  String microphoneNotice = '';
  String get outgoingSummary => outgoing.summary(videoEnabled: !cameraOff);
  bool get mutedSpeechDetected =>
      muted &&
      stream?.getAudioTracks().isNotEmpty == true &&
      stream!.getAudioTracks().every((track) => !track.enabled) &&
      mutedSpeech.visible();
  String get limitsSummary =>
      'Video limit ${appliedVideoKbps == null ? 'unavailable' : '$appliedVideoKbps Kbps'}'
      ' · audio ${appliedAudioKbps == null ? 'unavailable' : '$appliedAudioKbps Kbps'}';
  String get bandwidth => bandwidthLabel([bandwidthMeter.rate]);

  void sendBandwidth() {
    final dc = bandwidthChannel;
    if (dc?.state == RTCDataChannelState.RTCDataChannelOpen) {
      unawaited(
        dc!.send(
          RTCDataChannelMessage(
            jsonEncode({
              'type': 'bandwidth',
              'caps': connectionCaps.receive.toJson(),
            }),
          ),
        ),
      );
    }
  }

  Future<void> updateBandwidth(Quality q) async {
    sendBandwidth();
    notifyListeners();
    await applyLimits(q);
  }

  void _attachBandwidth(RTCDataChannel dc) {
    if (dc.label != 'pvp-bandwidth' || bandwidthChannel != null) {
      unawaited(dc.close());
      return;
    }
    bandwidthChannel = dc;
    dc.onDataChannelState = (state) {
      if (state == RTCDataChannelState.RTCDataChannelOpen) sendBandwidth();
    };
    dc.onMessage = (event) {
      if (bandwidthChannel != dc ||
          event.isBinary ||
          event.text.length > 1024) {
        return;
      }
      try {
        final msg = jsonDecode(event.text);
        if (msg is! Map) return;
        if (msg['type'] == 'bandwidth') {
          final caps = StreamCaps.parse(msg['caps']);
          if (caps == null) return;
          requestedCaps = caps;
          bandwidthSupported = true;
          unawaited(
            dc.send(
              RTCDataChannelMessage(jsonEncode({'type': 'bandwidth-ack'})),
            ),
          );
          if (_currentQuality != null) {
            unawaited(
              applyLimits(_currentQuality!).catchError((Object e) {
                onFailure?.call('$e');
              }),
            );
          }
        } else if (msg['type'] == 'bandwidth-ack') {
          bandwidthSupported = true;
        }
        notifyListeners();
      } catch (_) {}
    };
  }

  MediaStream? stream;
  MediaStream? _remoteStream;
  final List<RTCIceCandidate> _pending = [];
  final List<RTCRtpSender> _senders = [];
  RTCRtpSender? _videoSender;
  bool _hasRemoteDescription = false, _initialized = false;
  int _generation = 0;
  Future<void>? _acquiring;
  bool _initiator = false;
  String securityCode = '', dtlsCipher = '', srtpCipher = '';
  String? _localSdp, _remoteSdp;
  Timer? _stats, _disconnect, _microphoneTimer;
  bool _monitoring = false;
  bool microphoneSamples = false;
  double microphoneLevel = 0;
  String microphoneName = '';
  int audioBytesSent = 0;
  DateTime? connectedAt, _lastSample;
  int _lastBytes = 0;
  double kbps = 0, rttMs = 0;
  String resolution = '', route = 'Connecting';
  bool voiceOnly = true;
  bool cameraChanging = false;
  bool muted = false, cameraOff = true;
  MediaStream? _display;
  bool screenChanging = false, _cameraBeforeSharingOff = false;
  int _shareGeneration = 0;
  Timer? _screenSourceTimer;
  String screenName = '';
  bool get screenSharing => _display != null;
  MediaStream? get outgoingVideoStream => _display ?? stream;
  ConnectionEvidence? evidence;
  final List<Map<String, String>> networkEvents = [];
  String _networkState = 'new', _iceState = 'new';
  static const stunServers = [
    'stun:stun.l.google.com:19302',
    'stun:stun1.l.google.com:19302',
  ];
  void recordNetworkEvent(
    String detail, {
    String source = 'Application event',
  }) {
    networkEvents.add({
      'at': DateTime.now().toUtc().toIso8601String(),
      'source': source,
      'detail': detail.substring(0, detail.length.clamp(0, 256)),
    });
    if (networkEvents.length > 120) networkEvents.removeAt(0);
  }

  void Function(Map<String, dynamic>)? sendSignal;
  void Function(String)? onFailure;
  void Function()? onConnected;
  CallMedia({
    this.captureOverride,
    this.displayCaptureOverride,
    this.peerCreated,
  });

  Future<List<RTCRtpSender>> videoSenders() async => _videoSender != null
      ? [_videoSender!]
      : (await connection?.getSenders() ?? <RTCRtpSender>[])
            .where((s) => s.track?.kind == 'video')
            .toList();

  Future<void> startScreenShare(
    String sourceId,
    String name,
    Preferences p, {
    SourceType sourceType = SourceType.Screen,
  }) async {
    if (connection == null || connectedAt == null || stream == null) {
      throw StateError('Connect the call before sharing your screen.');
    }
    if (screenChanging || screenSharing) return;
    final generation = _generation, token = ++_shareGeneration, pc = connection;
    screenChanging = true;
    notifyListeners();
    MediaStream? captured;
    final replaced = <(RTCRtpSender, MediaStreamTrack?)>[];
    try {
      final constraints = <String, dynamic>{
        'audio': false,
        'video': {
          'deviceId': {'exact': sourceId},
          'mandatory': {'frameRate': 15.0},
          'cursor': 'always',
        },
      };
      captured = await (displayCaptureOverride != null
          ? displayCaptureOverride!(constraints)
          : navigator.mediaDevices.getDisplayMedia(constraints));
      if (generation != _generation ||
          token != _shareGeneration ||
          connection != pc) {
        await _disposeStream(captured);
        return;
      }
      final tracks = captured.getVideoTracks();
      if (tracks.length != 1) {
        throw StateError(
          'No screen video was opened. Choose another screen or window.',
        );
      }
      // Display audio is deliberately excluded; retain the call's microphone.
      for (final audio in captured.getAudioTracks()) {
        await audio.stop();
        await captured.removeTrack(audio);
      }
      final senders = await videoSenders();
      if (senders.isEmpty) {
        throw StateError(
          'This call has no outgoing video track. Reconnect with your camera available.',
        );
      }
      tracks.single.enabled = true;
      for (final sender in senders) {
        final previous = sender.track;
        await sender.replaceTrack(tracks.single);
        replaced.add((sender, previous));
      }
      if (generation != _generation ||
          token != _shareGeneration ||
          connection != pc) {
        throw StateError('Screen sharing was canceled.');
      }
      await applyLimits(p.quality);
      if (generation != _generation ||
          token != _shareGeneration ||
          connection != pc) {
        throw StateError('Screen sharing was canceled.');
      }
      local.srcObject = captured;
      _cameraBeforeSharingOff = cameraOff;
      _display = captured;
      screenName = name;
      cameraOff = false;
      await applyLimits(p.quality);
      for (final camera in stream!.getVideoTracks()) {
        camera.enabled = false;
      }
      tracks.single.onEnded = () {
        if (_display == captured) unawaited(stopScreenShare());
      };
      recordNetworkEvent('Screen sharing started', source: 'Application event');
      if (displayCaptureOverride == null) {
        _screenSourceTimer = Timer.periodic(const Duration(seconds: 2), (
          _,
        ) async {
          if (_display != captured || generation != _generation) return;
          try {
            final sources = await desktopCapturer.getSources(
              types: [sourceType],
            );
            if (_display == captured && !sources.any((s) => s.id == sourceId)) {
              await stopScreenShare();
            }
          } catch (_) {
            if (_display == captured) await stopScreenShare();
          }
        });
      }
    } catch (_) {
      if (generation == _generation) {
        if (_display == captured && captured != null) {
          _display = null;
          screenName = '';
          cameraOff = _cameraBeforeSharingOff;
          local.srcObject = stream;
          for (final camera
              in stream?.getVideoTracks() ?? <MediaStreamTrack>[]) {
            camera.enabled = !cameraOff;
          }
        }
        for (final (sender, track) in replaced.reversed) {
          await _cleanup(() => sender.replaceTrack(track));
        }
      }
      if (captured != null && captured != _display) {
        await _disposeStream(captured);
      }
      rethrow;
    } finally {
      if (generation == _generation) {
        screenChanging = false;
        notifyListeners();
      }
    }
  }

  Future<void> stopScreenShare() async {
    _shareGeneration++;
    _screenSourceTimer?.cancel();
    final display = _display, pc = connection, generation = _generation;
    if (display == null) return;
    _display = null;
    screenName = '';
    screenChanging = true;
    cameraOff = _cameraBeforeSharingOff;
    final cameras = stream?.getVideoTracks() ?? <MediaStreamTrack>[];
    for (final camera in cameras) {
      camera.enabled = !cameraOff;
    }
    local.srcObject = stream;
    // Stop capture before waiting for the sender operation.
    for (final track in display.getTracks()) {
      track.onEnded = null;
    }
    await _disposeStream(display);
    try {
      if (connection != null && generation == _generation) {
        for (final sender in await videoSenders()) {
          await sender.replaceTrack(cameras.firstOrNull);
        }
      }
      if (generation == _generation && connection == pc) {
        recordNetworkEvent(
          'Screen sharing stopped',
          source: 'Application event',
        );
      }
    } catch (_) {
      if (generation == _generation) {
        onFailure?.call(
          'Screen sharing stopped, but the camera could not resume. Reconnect the call.',
        );
      }
    } finally {
      if (generation == _generation) {
        screenChanging = false;
        notifyListeners();
      }
    }
  }

  Future<void> initialize() async {
    if (_initialized) return;
    await local.initialize();
    await remote.initialize();
    // Native audio device enumeration is populated when the first peer is
    // created. Initialize it before listing/selecting inputs, without capture.
    final probe = await createPeerConnection({'iceServers': <dynamic>[]});
    await probe.close();
    await probe.dispose();
    _initialized = true;
  }

  Map<String, dynamic> constraints(Preferences p, {bool camera = false}) => {
    'audio': {
      if (p.microphone.isNotEmpty) 'deviceId': p.microphone,
      'echoCancellation': p.echoCancellation,
      'noiseSuppression': true,
      'autoGainControl': true,
    },
    'video': voiceOnly && !camera
        ? false
        : {
            'mandatory': {
              'minWidth': '${(p.quality.height * 16 / 9).round()}',
              'minHeight': '${p.quality.height}',
              'minFrameRate': '${p.quality.fps}',
            },
            if (p.camera.isNotEmpty) 'deviceId': p.camera,
            'optional': <dynamic>[],
          },
  };

  Future<void> listen() async {
    final generation = _generation;
    await initialize();
    if (generation != _generation) return;
    final empty = await createLocalMediaStream('pvp-listener');
    if (generation != _generation) {
      await _disposeStream(empty);
      return;
    }
    stream = empty;
    local.srcObject = empty;
    muted = true;
    cameraOff = true;
    notifyListeners();
  }

  Future<void> enableMicrophone(
    Preferences p,
    Iterable<RTCRtpSender> senders,
  ) async {
    if (_acquiring != null) {
      await _acquiring;
      return;
    }
    final pending = _enableMicrophone(p, senders);
    _acquiring = pending;
    try {
      await pending;
    } finally {
      if (_acquiring == pending) _acquiring = null;
    }
  }

  Future<void> _enableMicrophone(
    Preferences p,
    Iterable<RTCRtpSender> senders,
  ) async {
    final generation = _generation, target = stream;
    if (target == null) return;
    final captured = await _capture(p, generation);
    if (captured == null) return;
    final track = captured.getAudioTracks().firstOrNull;
    if (track == null) {
      await _disposeStream(captured);
      throw StateError('No microphone was opened. You can keep listening.');
    }
    final replaced = <RTCRtpSender>[];
    try {
      if (generation != _generation || stream != target) return;
      await _setEchoCancellation(captured, p.echoCancellation);
      for (final sender in senders) {
        await sender.replaceTrack(track);
        replaced.add(sender);
      }
      if (generation != _generation || stream != target) {
        for (final sender in replaced) {
          try {
            await sender.replaceTrack(null);
          } catch (_) {}
        }
        return;
      }
      await target.addTrack(track);
      await captured.removeTrack(track);
      if (generation != _generation || stream != target) {
        try {
          await target.removeTrack(track);
        } catch (_) {}
        await track.stop();
        return;
      }
      local.srcObject = target;
      muted = false;
      track.enabled = true;
      if (captureOverride == null) {
        _monitoring = true;
        await NativeHost().invoke('startAudioMonitor');
        if (generation == _generation) {
          _microphoneTimer = Timer.periodic(
            const Duration(milliseconds: 250),
            (_) => unawaited(_sampleMicrophone(generation)),
          );
        }
      }
      notifyListeners();
    } catch (_) {
      for (final sender in replaced) {
        try {
          await sender.replaceTrack(null);
        } catch (_) {}
      }
      if (target.getAudioTracks().contains(track)) {
        await target.removeTrack(track);
        await track.stop();
      }
      if (generation == _generation && stream == target) muted = true;
      rethrow;
    } finally {
      await _disposeStream(captured);
    }
  }

  Future<void> acquire(Preferences p) async {
    if (_acquiring != null) return _acquiring!;
    final pending = _acquire(p);
    _acquiring = pending;
    try {
      await pending;
    } finally {
      if (_acquiring == pending) _acquiring = null;
    }
  }

  Future<void> _acquire(Preferences p) async {
    final generation = _generation;
    await initialize();
    if (generation != _generation) return;
    if (stream != null) return;
    final captured = await _capture(p, generation);
    if (captured == null) return;
    if (generation != _generation) {
      await _disposeStream(captured);
      return;
    }
    stream = captured;
    local.srcObject = captured;
    muted = false;
    cameraOff = voiceOnly;
    for (final track in captured.getTracks()) {
      track.enabled = true;
    }
    if (captureOverride == null) {
      try {
        _monitoring = true;
        await NativeHost().invoke('startAudioMonitor');
        if (generation != _generation) return;
        _microphoneTimer = Timer.periodic(
          const Duration(milliseconds: 250),
          (_) => unawaited(_sampleMicrophone(generation)),
        );
      } catch (_) {
        await stop();
        rethrow;
      }
    }
    notifyListeners();
  }

  Future<void> connect(Preferences p, bool initiator) async {
    final generation = _generation;
    await acquire(p);
    if (generation != _generation || stream == null) return;
    final pc = await createPeerConnection({
      'iceServers': [
        {'urls': stunServers},
      ],
      'sdpSemantics': 'unified-plan',
      'bundlePolicy': 'max-bundle',
    });
    if (generation != _generation) {
      await pc.close();
      await pc.dispose();
      return;
    }
    connection = pc;
    recordNetworkEvent('Peer connection created; STUN configured, no TURN');
    _currentQuality = p.quality;
    pc.onDataChannel = _attachBandwidth;
    if (initiator) {
      _attachBandwidth(
        await pc.createDataChannel('pvp-bandwidth', RTCDataChannelInit()),
      );
    }
    _initiator = initiator;
    pc.onIceCandidate = (c) {
      if (generation == _generation &&
          c.candidate?.isNotEmpty == true &&
          !_relay(c.candidate!)) {
        sendSignal?.call({'type': 'candidate', 'candidate': c.toMap()});
      }
    };
    pc.onTrack = (e) {
      if (generation != _generation) return;
      if (e.streams.isNotEmpty) {
        _remoteStream = e.streams.first;
        remote.srcObject = e.streams.first;
        notifyListeners();
      }
    };
    pc.onConnectionState = (state) {
      if (generation != _generation) return;
      _networkState = state
          .toString()
          .split('.')
          .last
          .replaceFirst('RTCPeerConnectionState', '')
          .toLowerCase();
      recordNetworkEvent(
        'Peer connection: $_networkState',
        source: 'WebRTC event',
      );
      evidence = null;
      route = 'Checking media route';
      if (state == RTCPeerConnectionState.RTCPeerConnectionStateConnected) {
        _disconnect?.cancel();
        connectedAt ??= DateTime.now();
        onConnected?.call();
        notifyListeners();
      } else if (state == RTCPeerConnectionState.RTCPeerConnectionStateFailed) {
        onFailure?.call(
          'A direct connection could not be established. Try another network.',
        );
      } else if (state ==
          RTCPeerConnectionState.RTCPeerConnectionStateDisconnected) {
        _disconnect?.cancel();
        _disconnect = Timer(
          const Duration(seconds: 15),
          () => onFailure?.call('The peer connection was lost.'),
        );
      }
    };
    pc.onIceConnectionState = (state) {
      if (generation != _generation) return;
      _iceState = state
          .toString()
          .split('.')
          .last
          .replaceFirst('RTCIceConnectionState', '')
          .toLowerCase();
      recordNetworkEvent('ICE: $_iceState', source: 'WebRTC event');
    };
    for (final track in stream!.getAudioTracks()) {
      _senders.add(await pc.addTrack(track, stream!));
    }
    // Audio-only capture still receives the browser's camera. Empty injected
    // streams exercise signaling without requesting device permissions.
    if (stream!.getAudioTracks().isEmpty) {
      await pc.addTransceiver(
        kind: RTCRtpMediaType.RTCRtpMediaTypeAudio,
        init: RTCRtpTransceiverInit(direction: TransceiverDirection.RecvOnly),
      );
    }
    if (initiator) {
      final video = await pc.addTransceiver(
        kind: RTCRtpMediaType.RTCRtpMediaTypeVideo,
        init: RTCRtpTransceiverInit(
          direction: TransceiverDirection.SendRecv,
          streams: [stream!],
        ),
      );
      _videoSender = video.sender;
      _senders.add(video.sender);
      final camera = stream!.getVideoTracks().firstOrNull;
      if (camera != null) await video.sender.replaceTrack(camera);
    }
    if (peerCreated != null) await peerCreated!(pc);
    if (generation != _generation) return;
    if (initiator) {
      final offer = await pc.createOffer();
      requireEncryptedSdp(offer.sdp!);
      await pc.setLocalDescription(offer);
      await applyLimits(p.quality);
      if (generation == _generation) {
        sendSignal?.call({'type': 'offer', 'sdp': offer.sdp});
      }
    }
    _stats = Timer.periodic(
      const Duration(seconds: 1),
      (_) => unawaited(_sample(pc, generation)),
    );
  }

  Future<MediaStream?> _capture(Preferences p, int generation) async {
    final captured = await _captureStream(p, generation);
    if (captured == null) return null;
    try {
      if (generation != _generation) {
        await _disposeStream(captured);
        return null;
      }
      await _setEchoCancellation(captured, p.echoCancellation);
    } catch (_) {
      await _disposeStream(captured);
      rethrow;
    }
    return captured;
  }

  Future<MediaStream?> _captureStream(Preferences p, int generation) async {
    if (captureOverride != null) return captureOverride!(constraints(p));
    // Both permissions are granted before opening a device. Cancellation while
    // macOS is showing a permission dialog must not subsequently start capture.
    final granted = await NativeHost().invoke<bool>('capturePermissions', {
      'camera': constraints(p)['video'] != false,
    });
    if (generation != _generation) return null;
    if (granted == false) {
      final permissions = await NativeHost().invoke<Map>(
        'capturePermissionStatus',
      );
      if (permissions != null && permissions['microphone'] != 3) {
        throw StateError(
          'Microphone access is off. Enable PVP in System Settings → Privacy & Security → Microphone.',
        );
      }
      throw StateError(
        'Allow PVP camera and microphone access in System Settings, then try again.',
      );
    }
    // The pinned Darwin plugin skips audio.deviceId behind an incorrect
    // TARGET_OS_IPHONE preprocessor guard. Select explicitly, including default.
    if (p.microphone.isNotEmpty) {
      final chosen = p.microphone;
      final devices = await navigator.mediaDevices.enumerateDevices();
      if (generation != _generation) return null;
      if (p.microphone == chosen &&
          !devices.any((d) => d.kind == 'audioinput' && d.deviceId == chosen)) {
        p.microphone = '';
        microphoneNotice =
            'Saved microphone unavailable. Using System default.';
      }
    }
    await setMicrophone(p.microphone);
    if (generation != _generation) return null;
    await setSpeaker(p.speaker);
    if (generation != _generation) return null;
    final captured = await navigator.mediaDevices.getUserMedia(constraints(p));
    if (captured.getAudioTracks().isEmpty) {
      await _disposeStream(captured);
      throw StateError(
        'No microphone track was opened. Choose another microphone in Call settings.',
      );
    }
    return captured;
  }

  Future<void> _setEchoCancellation(MediaStream captured, bool enabled) async {
    // The pinned native plugin's applyConstraints only handles volume. Use the
    // SDK's local-track processing API so changes also reach active senders.
    for (final track in captured.getAudioTracks()) {
      await NativeHost().invoke('setEchoCancellation', {
        'trackId': track.id,
        'enabled': enabled,
      });
    }
  }

  Future<void> setEchoCancellation(bool enabled) async {
    // A permission prompt may still be opening this microphone. Apply the
    // latest choice after capture completes as well as to an existing stream.
    await _acquiring;
    final captured = stream;
    if (captured != null) await _setEchoCancellation(captured, enabled);
  }

  static bool _relay(String text) => isRelay(text);
  Future<void> signal(Map<String, dynamic> payload, Quality quality) async {
    final pc = connection;
    if (pc == null) return;
    final generation = _generation;
    final type = payload['type'];
    if (type == 'candidate') {
      final c = Map<String, dynamic>.from(payload['candidate']);
      requireCandidate(c);
      final candidate = RTCIceCandidate(
        c['candidate'],
        c['sdpMid'],
        c['sdpMLineIndex'],
      );
      if (_hasRemoteDescription) {
        await pc.addCandidate(candidate);
      } else {
        if (_pending.length >= 128) {
          throw StateError('Too many peer candidates.');
        }
        _pending.add(candidate);
      }
    } else if (type == 'offer' || type == 'answer') {
      final sdp = payload['sdp'] as String;
      requireEncryptedSdp(sdp);
      if (_hasRemoteDescription ||
          (type == 'offer' ? _initiator : !_initiator)) {
        throw StateError('Unexpected peer negotiation.');
      }
      await pc.setRemoteDescription(RTCSessionDescription(sdp, type));
      if (generation != _generation) return;
      _hasRemoteDescription = true;
      for (final c in _pending) {
        await pc.addCandidate(c);
      }
      _pending.clear();
      if (type == 'offer') {
        final slot = (await pc.getTransceivers())
            .where((t) => t.receiver.track?.kind == 'video')
            .firstOrNull;
        if (slot != null) {
          await slot.setDirection(TransceiverDirection.SendRecv);
          await slot.sender.setStreams([stream!]);
          _videoSender = slot.sender;
          _senders.add(slot.sender);
          final camera = stream!.getVideoTracks().firstOrNull;
          if (camera != null) await slot.sender.replaceTrack(camera);
        }
        final answer = await pc.createAnswer();
        requireEncryptedSdp(answer.sdp!);
        if (generation != _generation) return;
        await pc.setLocalDescription(answer);
        await applyLimits(quality);
        if (generation == _generation) {
          sendSignal?.call({'type': 'answer', 'sdp': answer.sdp});
        }
      }
      if (generation != _generation) return;
      final localSdp = (await pc.getLocalDescription())?.sdp;
      final remoteSdp = (await pc.getRemoteDescription())?.sdp;
      if (generation != _generation) return;
      if (localSdp != null && remoteSdp != null) {
        _localSdp = localSdp;
        _remoteSdp = remoteSdp;
        securityCode = safetyCode(localSdp, remoteSdp);
        notifyListeners();
      }
    }
  }

  Future<void> applyLimits(Quality q) async {
    _currentQuality = q;
    if (connection == null) return;
    // Fresh native parameters include the negotiated transaction/encoding IDs.
    for (final sender in await connection!.getSenders()) {
      final kind = sender.track?.kind;
      if (kind != 'video' && kind != 'audio') continue;
      final params = sender.parameters;
      if (params.encodings?.isEmpty ?? true) continue;
      for (final encoding in params.encodings!) {
        encoding.maxBitrate =
            (kind == 'video'
                ? videoCap(
                    q.videoKbps,
                    connectionCaps.send,
                    requestedCaps,
                    screenSharing,
                  )
                : q.audioKbps) *
            1000;
        if (kind == 'video') encoding.maxFramerate = q.fps;
      }
      if (!await sender.setParameters(params)) {
        throw StateError(
          'The media engine could not apply this bandwidth limit.',
        );
      }
      if (kind == 'video') {
        appliedVideoKbps = params.encodings!.first.maxBitrate == null
            ? null
            : params.encodings!.first.maxBitrate! ~/ 1000;
      } else {
        appliedAudioKbps = params.encodings!.first.maxBitrate == null
            ? null
            : params.encodings!.first.maxBitrate! ~/ 1000;
      }
    }
  }

  Future<void> reconfigure(Preferences p) async {
    if (stream == null) return;
    if (screenChanging) {
      throw StateError('Wait for the screen-sharing change to finish.');
    }
    final generation = _generation;
    final captured = await _capture(p, generation);
    if (captured == null) return;
    if (generation != _generation) {
      await _disposeStream(captured);
      return;
    }
    final old = stream;
    try {
      for (final track in captured.getTracks()) {
        track.enabled = track.kind == 'audio'
            ? !muted
            : !screenSharing && !cameraOff;
        if (screenSharing && track.kind == 'video') continue;
        for (final sender in _senders.where(
          (s) => s.track?.kind == track.kind,
        )) {
          await sender.replaceTrack(track);
        }
      }
      stream = captured;
      local.srcObject = _display ?? captured;
      await applyLimits(p.quality);
    } catch (_) {
      if (generation == _generation && old != null) {
        for (final track in old.getTracks()) {
          if (screenSharing && track.kind == 'video') continue;
          for (final sender in _senders.where(
            (s) => s.track?.kind == track.kind,
          )) {
            await sender.replaceTrack(track);
          }
        }
        stream = old;
        local.srcObject = _display ?? old;
      }
      await _disposeStream(captured);
      rethrow;
    }
    if (old != null) await _disposeStream(old);
    notifyListeners();
  }

  void toggleMic() {
    muted = !muted;
    mutedSpeech.reset();
    for (final t in stream?.getAudioTracks() ?? <MediaStreamTrack>[]) {
      t.enabled = !muted;
    }
    notifyListeners();
  }

  Future<void> toggleVideo(Preferences p) async {
    if (cameraChanging || screenChanging || stream == null) return;
    if (screenSharing) {
      toggleCamera();
      return;
    }
    final generation = _generation, original = stream!;
    bool valid() => generation == _generation && identical(original, stream);
    cameraChanging = true;
    notifyListeners();
    MediaStream? captured;
    final replaced = <(RTCRtpSender, MediaStreamTrack?)>[];
    try {
      final old = original.getVideoTracks().firstOrNull;
      if (old != null) {
        for (final sender in await videoSenders()) {
          await sender.replaceTrack(null);
          replaced.add((sender, old));
        }
        if (!valid()) return;
        await original.removeTrack(old);
        old.onEnded = null;
        await old.stop();
        voiceOnly = true;
        cameraOff = true;
      } else {
        final cameraConstraints = {
          'audio': false,
          'video': constraints(p, camera: true)['video'],
        };
        if (captureOverride != null) {
          captured = await captureOverride!(cameraConstraints);
        } else {
          final granted = await NativeHost().invoke<bool>(
            'capturePermissions',
            {'camera': true},
          );
          if (!valid()) return;
          if (granted == false) {
            throw StateError(
              'Allow camera access in System Settings → Privacy & Security → Camera.',
            );
          }
          captured = await navigator.mediaDevices.getUserMedia(
            cameraConstraints,
          );
        }
        if (!valid()) return;
        final camera = captured.getVideoTracks().firstOrNull;
        if (camera == null) {
          throw StateError(
            'No camera was opened. Choose another camera in Settings.',
          );
        }
        for (final sender in await videoSenders()) {
          final previous = sender.track;
          await sender.replaceTrack(camera);
          replaced.add((sender, previous));
        }
        if (!valid()) return;
        await original.addTrack(camera);
        camera.enabled = true;
        voiceOnly = false;
        cameraOff = false;
        camera.onEnded = () {
          if (valid()) {
            cameraOff = true;
            voiceOnly = true;
            unawaited(() async {
              await _cleanup(() => original.removeTrack(camera));
              for (final sender in await videoSenders()) {
                await _cleanup(() => sender.replaceTrack(null));
              }
              if (valid()) notifyListeners();
            }());
          }
        };
      }
      if (valid()) {
        local.srcObject = original;
        await applyLimits(p.quality);
        if (valid() && captured != null) {
          final camera = original.getVideoTracks().firstOrNull;
          if (camera != null) await captured.removeTrack(camera);
        }
      }
    } catch (_) {
      if (valid()) {
        for (final (sender, previous) in replaced) {
          try {
            await sender.replaceTrack(previous);
          } catch (_) {}
        }
        final camera = original.getVideoTracks().firstOrNull;
        if (camera != null && replaced.any((r) => r.$2 == null)) {
          await original.removeTrack(camera);
          await camera.stop();
          cameraOff = true;
          voiceOnly = true;
        }
      }
      rethrow;
    } finally {
      if (captured != null) await _disposeStream(captured);
      if (valid()) {
        cameraChanging = false;
        notifyListeners();
      }
    }
  }

  void toggleCamera() {
    cameraOff = !cameraOff;
    for (final t
        in (_display ?? stream)?.getVideoTracks() ?? <MediaStreamTrack>[]) {
      t.enabled = !cameraOff;
    }
    notifyListeners();
  }

  Future<void> setSpeaker(String id) async {
    await NativeHost().invoke('selectAudioDevice', {
      'kind': 'audiooutput',
      'id': id,
    });
  }

  Future<void> setMicrophone(String id) async {
    final name = await NativeHost().invoke<String>('selectAudioDevice', {
      'kind': 'audioinput',
      'id': id,
    });
    microphoneName = name ?? '';
    microphoneLevel = 0;
    microphoneSamples = false;
    notifyListeners();
  }

  Future<void> _sampleMicrophone(int generation) async {
    try {
      final status = await NativeHost().invoke<Map>('microphoneStatus');
      if (generation != _generation || stream == null || status == null) return;
      final rawLevel = (status['level'] as num? ?? 0).toDouble();
      microphoneLevel = muted ? 0 : rawLevel;
      microphoneSamples = status['receivingSamples'] == true;
      mutedSpeech.sample(
        muted: muted,
        hasAudioTrack:
            stream!.getAudioTracks().isNotEmpty &&
            stream!.getAudioTracks().every((track) => !track.enabled),
        receivingSamples: microphoneSamples && status['recording'] == true,
        level: rawLevel,
      );
      microphoneName = status['deviceName'] as String? ?? microphoneName;
      notifyListeners();
    } catch (_) {
      /* The host may be closing. */
    }
  }

  String get microphoneStatus => muted
      ? 'Microphone muted'
      : microphoneLevel > 0.005
      ? 'Microphone is picking up sound'
      : microphoneSamples
      ? 'No sound detected — speak or choose another microphone'
      : 'Waiting for microphone audio — check your input device';

  Future<void> _sample(RTCPeerConnection pc, int generation) async {
    try {
      final reports = await pc.getStats().timeout(const Duration(seconds: 3));
      if (generation != _generation || connection != pc) return;
      final observed = ConnectionEvidence.fromReports(
        reports
            .map(
              (r) => <String, dynamic>{
                ...r.values,
                'id': r.id,
                'type': r.type,
                'timestamp': r.timestamp,
              },
            )
            .toList(),
        connectionState: _networkState,
        iceState: _iceState,
        configuredServers: stunServers,
        localSdp: _localSdp,
        remoteSdp: _remoteSdp,
      );
      if (observed.data['selectedPairId'] != evidence?.data['selectedPairId']) {
        recordNetworkEvent(
          'Selected path: ${endpointLabel(observed.local)} ↔ ${endpointLabel(observed.remote)}',
          source: 'WebRTC statistics',
        );
      }
      bandwidthMeter.sample(
        reports
            .map(
              (r) => <String, dynamic>{...r.values, 'id': r.id, 'type': r.type},
            )
            .toList(),
      );
      evidence = observed;
      outgoing.sample(
        reports
            .map(
              (r) => <String, dynamic>{...r.values, 'id': r.id, 'type': r.type},
            )
            .toList(),
      );
      route = observed.direct
          ? 'Direct · WebRTC reported'
          : 'Media route unavailable';
      rttMs = (observed.data['rttSeconds'] as num? ?? 0) * 1000;
      if (observed.relayed) {
        onFailure?.call('Relayed media is disabled.');
        return;
      }
      if (observed.certificateMismatch || observed.transportFailed) {
        securityCode = '';
        onFailure?.call(
          observed.certificateMismatch
              ? 'The selected transport certificate does not match negotiation.'
              : 'The encrypted transport was lost.',
        );
        return;
      }
      dtlsCipher = observed.data['dtlsCipher'] as String? ?? '';
      srtpCipher = observed.data['srtpCipher'] as String? ?? '';
      int bytes = 0;
      for (final report in reports) {
        final v = report.values;
        if (report.type == 'outbound-rtp' && v['isRemote'] != true) {
          bytes += (v['bytesSent'] as num? ?? 0).toInt();
          if (v['kind'] == 'audio' || v['mediaType'] == 'audio') {
            audioBytesSent = (v['bytesSent'] as num? ?? 0).toInt();
          }
          if (v['frameHeight'] != null) {
            resolution =
                '${v['frameWidth']} × ${v['frameHeight']} · ${(v['framesPerSecond'] as num? ?? 0).round()} fps';
          }
        }
      }
      final now = DateTime.now();
      if (_lastSample != null && bytes >= _lastBytes) {
        kbps =
            (bytes - _lastBytes) *
            8 /
            now.difference(_lastSample!).inMilliseconds;
      }
      _lastBytes = bytes;
      _lastSample = now;
      notifyListeners();
    } catch (_) {
      if (generation == _generation && connection == pc) {
        evidence = null;
        route = 'Media route unavailable';
        notifyListeners();
      }
    }
  }

  Future<void> stop() async {
    _generation++;
    _shareGeneration++;
    _screenSourceTimer?.cancel();
    final display = _display;
    _display = null;
    screenChanging = false;
    screenName = '';
    _acquiring = null;
    securityCode = '';
    _localSdp = null;
    _remoteSdp = null;
    dtlsCipher = '';
    srtpCipher = '';
    _stats?.cancel();
    _disconnect?.cancel();
    _microphoneTimer?.cancel();
    final monitoring = _monitoring;
    _monitoring = false;
    final pc = connection, captured = stream, incoming = _remoteStream;
    connection = null;
    stream = null;
    _remoteStream = null;
    // Disable every sender track synchronously before any native cleanup can
    // wait. A failed/hung renderer, track stop or peer close cannot leave a
    // later track enabled while it waits its turn in the disposal sequence.
    for (final source in [captured, display]) {
      for (final track in source?.getTracks() ?? <MediaStreamTrack>[]) {
        try {
          track.enabled = false;
        } catch (_) {}
      }
    }
    if (_initialized) {
      local.srcObject = null;
      remote.srcObject = null;
    }
    _senders.clear();
    _videoSender = null;
    cameraChanging = false;
    _pending.clear();
    _hasRemoteDescription = false;
    connectedAt = null;
    _lastSample = null;
    _lastBytes = 0;
    kbps = 0;
    rttMs = 0;
    resolution = '';
    route = 'Connecting';
    evidence = null;
    bandwidthMeter = BandwidthMeter();
    connectionCaps = ConnectionCaps();
    requestedCaps = StreamCaps();
    bandwidthChannel = null;
    bandwidthSupported = false;
    _currentQuality = null;
    appliedVideoKbps = null;
    appliedAudioKbps = null;
    microphoneNotice = '';
    mutedSpeech.reset();
    outgoing.sample([]);
    networkEvents.clear();
    _networkState = 'new';
    _iceState = 'new';
    final releases = <Future<void>>[];
    if (pc != null) {
      // Start transport closure before awaiting track/renderer/native work.
      releases.add(() async {
        await _cleanup(() => pc.close());
        await _cleanup(() => pc.dispose());
      }());
    }
    if (display != null) {
      for (final track in display.getTracks()) {
        track.onEnded = null;
      }
      releases.add(_disposeStream(display));
    }
    if (captured != null) releases.add(_disposeStream(captured));
    if (incoming != null) releases.add(_cleanup(() => incoming.dispose()));
    if (monitoring) {
      releases.add(_cleanup(() => NativeHost().invoke('stopAudioMonitor')));
    }
    await Future.wait(releases);
    microphoneLevel = 0;
    microphoneSamples = false;
    audioBytesSent = 0;
    notifyListeners();
  }

  static Future<void> _disposeStream(MediaStream s) async {
    await Future.wait([
      for (final t in s.getTracks()) _cleanup(() => t.stop()),
    ]);
    await _cleanup(() => s.dispose());
  }

  static Future<void> _cleanup(Future<void> Function() release) async {
    try {
      await release();
    } catch (_) {
      debugPrint('A media cleanup operation failed.');
    }
  }
}
