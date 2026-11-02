import 'bandwidth.dart';
import 'meeting_chat.dart';
import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'package:flutter/foundation.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'models.dart';
import 'group_quality.dart';
import 'media.dart';
import 'native.dart';
import 'security.dart';
import 'connection_evidence.dart';
import 'call_observations.dart';

class GroupLink {
  final String id;
  final RTCPeerConnection pc;
  final int generation;
  final meter = BandwidthMeter();
  ConnectionCaps caps = ConnectionCaps();
  StreamCaps requested = StreamCaps();
  bool bandwidthSupported = false;
  final renderer = RTCVideoRenderer();
  MediaStream? remote;
  RTCDataChannel? control, video, chat;
  RTCRtpSender? videoSender, audioSender;
  Future<void> chain = Future.value();
  List<RTCIceCandidate> candidates = [];
  Map<String, dynamic> state = {};
  ConnectionEvidence? evidence;
  final outgoing = OutgoingMediaStats();
  String? localSdp, remoteSdp;
  int? appliedVideoKbps, appliedAudioKbps;
  String status = 'Connecting', code = '';
  bool sampling = false, ready = false, speaking = false;
  Timer? retry;
  int forwardedBytes = 0, receivedBytes = 0, sentBytes = 0;
  bool wantHigh = false, focusedScreen = false;
  DateTime? disconnectedAt;
  final openedAt = DateTime.now();
  GroupLink(this.id, this.pc, this.generation);
}

class GroupMedia extends CallMedia {
  final Map<String, GroupLink> links = {};
  DateTime? forwardedAt;
  DateTime _lastSpeech = DateTime(1970);
  GroupMedia({super.captureOverride});
  @override
  String get outgoingSummary {
    if (links.isEmpty) return 'Actual sent media unavailable';
    final values = links.values.toList();
    if (values.any((l) => !l.outgoing.fresh())) {
      return 'Actual sent media unavailable for one or more participants';
    }
    final formats = values
        .map((l) => l.outgoing.dimensions)
        .where((v) => v.isNotEmpty)
        .toSet()
        .join(' / ');
    final picture = cameraOff
        ? 'Camera off'
        : formats.isEmpty
        ? 'Sent video size unavailable'
        : 'Sent $formats';
    double? sum(bool video) {
      final rates = values
          .map((l) => video ? l.outgoing.videoKbps : l.outgoing.audioKbps)
          .toList();
      return rates.any((v) => v == null)
          ? null
          : rates.fold<double>(0, (a, b) => a + b!);
    }

    return '$picture · video ${OutgoingMediaStats.formatRate(sum(true))}'
        ' · audio ${OutgoingMediaStats.formatRate(sum(false))}'
        ' across ${values.length} peer${values.length == 1 ? '' : 's'}';
  }

  @override
  String get limitsSummary {
    String limits(bool video) {
      final values = links.values
          .map((l) => video ? l.appliedVideoKbps : l.appliedAudioKbps)
          .toList();
      if (values.isEmpty || values.any((v) => v == null)) return 'unavailable';
      final low = values.cast<int>().reduce(min),
          high = values.cast<int>().reduce(max);
      return low == high ? '$low Kbps per peer' : '$low–$high Kbps per peer';
    }

    return 'Video limit ${limits(true)} · audio ${limits(false)}';
  }

  @override
  Future<List<RTCRtpSender>> videoSenders() async =>
      links.values.map((l) => l.videoSender).whereType<RTCRtpSender>().toList();

  @override
  Future<void> applyLimits(Quality q) async {
    final count = max(1, links.length);
    final attendees = links.length + 1;
    final budget = groupVideoKbps(q, attendees);
    if (!muted && microphoneLevel > .025) _lastSpeech = DateTime.now();
    final speaking =
        !muted && DateTime.now().difference(_lastSpeech).inMilliseconds < 2000;
    for (final link in links.values.toList()) {
      for (final sender in await link.pc.getSenders()) {
        final kind = sender.track?.kind;
        if (kind != 'video' && kind != 'audio') continue;
        final p = sender.parameters;
        if (p.encodings?.isEmpty ?? true) continue;
        for (final encoding in p.encodings!) {
          encoding.maxBitrate = kind == 'video'
              ? max(
                  16000,
                  budget *
                      (forwardingEnabled(attendees) &&
                              !screenSharing &&
                              forwardedAt != null &&
                              DateTime.now()
                                      .difference(forwardedAt!)
                                      .inSeconds <
                                  2
                          ? 500
                          : 1000) ~/
                      count,
                )
              : min(q.audioKbps, 32) * 1000;
          if (kind == 'video') {
            final high = screenSharing || speaking || link.wantHigh;
            encoding.active = screenSharing || !cameraOff;
            final actualHeight = sender.track?.getSettings()['height'];
            final quality = groupCameraQuality(
              q,
              attendees,
              high,
              captureHeight: actualHeight is num && actualHeight > 0
                  ? actualHeight.toInt()
                  : null,
            );
            p.degradationPreference = screenSharing || quality.small
                ? RTCDegradationPreference.MAINTAIN_RESOLUTION
                : RTCDegradationPreference.BALANCED;
            if (!high && !quality.small) {
              encoding.maxBitrate = min(30000, encoding.maxBitrate!);
            }
            encoding.maxFramerate = screenSharing ? 15 : quality.fps;
            encoding.scaleResolutionDownBy = screenSharing ? 1 : quality.scale;
            encoding.priority = screenSharing
                ? (link.wantHigh && link.focusedScreen
                      ? RTCPriorityType.high
                      : RTCPriorityType.medium)
                : RTCPriorityType.low;
            if (screenSharing) {
              encoding.maxBitrate =
                  screenVideoKbps(
                    q,
                    link.wantHigh && link.focusedScreen,
                    links.values.any((l) => l.wantHigh && l.focusedScreen),
                    count,
                  ) *
                  1000;
            } else if (link.focusedScreen) {
              encoding.maxBitrate = min(30000, encoding.maxBitrate!);
              encoding.maxFramerate = 3;
            }
          }
        }
        if (kind == 'video') {
          for (final encoding in p.encodings!) {
            encoding.maxBitrate =
                videoCap(
                  encoding.maxBitrate! ~/ 1000,
                  link.caps.send,
                  link.requested,
                  screenSharing,
                ) *
                1000;
          }
        }
        if (!await sender.setParameters(p)) {
          throw StateError('Could not apply connection bandwidth.');
        }
        final cap = p.encodings!.first.maxBitrate;
        if (kind == 'video') {
          link.appliedVideoKbps = cap == null ? null : cap ~/ 1000;
        } else {
          link.appliedAudioKbps = cap == null ? null : cap ~/ 1000;
        }
      }
    }
  }

  @override
  Future<void> reconfigure(Preferences p) async {
    // Input/output selection uses the existing native ADM. Camera capture
    // changes require leaving this room, avoiding partial multi-sender updates.
    await applyLimits(p.quality);
  }

  @override
  Future<void> stop() async {
    final peers = links.values.toList();
    links.clear();
    for (final link in peers) {
      link.code = '';
      link.evidence = null;
      link.retry?.cancel();
      try {
        link.renderer.srcObject = null;
      } catch (_) {}
    }
    final localStopping = super.stop();
    Future<void> safely(Future<void> Function() action) async {
      try {
        await action();
      } catch (_) {}
    }

    // Every peer transport starts closing before any UI/data-channel cleanup
    // can block another peer. Local capture has already been disabled above.
    final peerStopping = [
      for (final link in peers)
        () async {
          final closing = safely(() => link.pc.close());
          final channels = [
            if (link.chat != null) safely(() => link.chat!.close()),
            if (link.control != null) safely(() => link.control!.close()),
            if (link.video != null) safely(() => link.video!.close()),
          ];
          await closing;
          await safely(() => link.pc.dispose());
          await Future.wait(channels);
          if (link.remote != null) await safely(() => link.remote!.dispose());
          await safely(() => link.renderer.dispose());
        }(),
    ];
    await Future.wait([localStopping, ...peerStopping]);
  }
}

class GroupCalls extends ChangeNotifier {
  late final MeetingChat chat;
  final NativeHost host;
  final GroupMedia media;
  final Person? Function() user;
  final Preferences Function() preferences;
  final void Function(Map<String, dynamic>) send;
  final Future<void> Function() stopPreview;
  final bool Function() otherBusy;
  Map<String, dynamic>? room;
  String message = '';
  String? focusedPeer;
  final connectionCaps = <String, ConnectionCaps>{};
  String get bandwidth => bandwidthLabel(links.values.map((l) => l.meter.rate));
  String get outgoingSummary => media.outgoingSummary;
  bool pending = false, available = false, voiceAvailable = false;
  bool personalRoom = false;
  int _token = 0;
  Timer? _stats;
  bool _stopping = false;
  Future<void>? _cleanupFuture;
  final Map<String, int> _seen = {};
  double _budgetBytes = 0;
  DateTime _budgetAt = DateTime.now();
  GroupCalls({
    required this.host,
    required this.media,
    required this.user,
    required this.preferences,
    required this.send,
    required this.stopPreview,
    required this.otherBusy,
  }) {
    chat = MeetingChat(
      self: () => user()?.id ?? '',
      name: (id) {
        if (id == user()?.id) return 'You';
        final member = members.where((m) => m['id'] == id).firstOrNull;
        return member == null
            ? 'Participant'
            : '${member['display_name']} · @${member['username']}';
      },
      error: (e) {
        message = e;
        notifyListeners();
      },
    );
    media.addListener(notifyListeners);
    media.onFailure = (error) {
      message = error;
      unawaited(leave());
    };
  }
  bool get busy => _stopping || room != null || pending;
  bool get joined =>
      members.any((m) => m['id'] == user()?.id && m['joined'] == true);
  List<Map<String, dynamic>> get members => List<Map<String, dynamic>>.from(
    (room?['members'] as List? ?? []).map((m) => Map<String, dynamic>.from(m)),
  );
  List<Map<String, dynamic>> get participants =>
      members.where((m) => m['joined'] == true).toList();
  Map<String, GroupLink> get links => media.links;
  String? get id => room?['room_id'];
  void capabilities() => send({
    'type': 'room-capabilities',
    'client': 'mac',
    'meeting_moderation': true,
    'raise_hand': true,
  });
  Map<String, dynamic>? get self =>
      members.where((m) => m['id'] == user()?.id).firstOrNull;
  bool get isAdmin => self?['is_admin'] == true;
  bool get speakingRequired => room?['raise_hand_enabled'] == true && !isAdmin;
  bool get awaitingApproval =>
      speakingRequired && self?['speaking_allowed'] != true;
  bool get moderatorMuted =>
      members.any((m) => m['id'] == user()?.id && m['moderator_muted'] == true);
  bool isModerated(String id) =>
      members.any((m) => m['id'] == id && m['moderator_muted'] == true);
  void applyModeration() {
    if (moderatorMuted) {
      media.muted = true;
      for (final track
          in media.stream?.getAudioTracks() ?? <MediaStreamTrack>[]) {
        track.enabled = false;
      }
    }
    for (final link in links.values) {
      for (final track
          in link.remote?.getAudioTracks() ?? <MediaStreamTrack>[]) {
        track.enabled = !isModerated(link.id);
      }
      if (isModerated(link.id)) {
        link.speaking = false;
      }
      unawaited(_applyReceiverModeration(link));
    }
  }

  Future<void> _applyReceiverModeration(GroupLink link) async {
    try {
      final receivers = await link.pc.getReceivers();
      if (links[link.id] != link) return;
      for (final receiver in receivers) {
        final track = receiver.track;
        if (track?.kind == 'audio') {
          track!.enabled = !isModerated(link.id);
        }
      }
    } catch (_) {
      // A peer may close while the platform receiver query is in flight.
    }
  }

  bool microphoneOpening = false, _listenIntent = false;
  bool get listening =>
      _listenIntent && (media.stream?.getAudioTracks().isEmpty ?? true);
  Future<void> enableMicrophone() async {
    if (!joined || microphoneOpening || moderatorMuted) return;
    final token = _token;
    microphoneOpening = true;
    message = 'Waiting for microphone access. You can keep listening.';
    notifyListeners();
    try {
      await media.enableMicrophone(
        preferences(),
        links.values
            .map((l) => l.audioSender)
            .whereType<RTCRtpSender>()
            .toList(),
      );
      if (token != _token || !joined) return;
      if (media.stream?.getAudioTracks().isNotEmpty == true) {
        // A participant may have arrived while permission was pending.
        for (final link in links.values.toList()) {
          try {
            await link.audioSender?.replaceTrack(
              media.stream!.getAudioTracks().first,
            );
          } catch (e) {
            failure(link, e);
          }
          if (token != _token || !joined) return;
        }
        _listenIntent = false;
        media.muted = moderatorMuted;
        for (final t in media.stream!.getAudioTracks()) {
          t.enabled = !media.muted;
        }
        message = '';
        broadcast();
      }
    } catch (e) {
      if (token == _token) {
        message =
            'Mic access unavailable. You can keep listening. ${e.toString().replaceFirst('Bad state: ', '')}';
      }
    } finally {
      if (token == _token) {
        microphoneOpening = false;
        notifyListeners();
      }
    }
  }

  void toggleMic() {
    if (moderatorMuted) return;
    media.toggleMic();
    broadcast();
  }

  Future<void> enterVoice([String? roomId]) async {
    if (!voiceAvailable) {
      throw StateError('Update the signaling service to use voice rooms.');
    }
    if (busy || otherBusy()) {
      throw StateError('Finish your current call first.');
    }
    final token = ++_token;
    pending = true;
    personalRoom = roomId == null;
    message = '';
    notifyListeners();
    try {
      await stopPreview();
      if (token != _token) return;
      media.voiceOnly = true;
      await media.acquire(preferences());
      if (token != _token) return;
      send(
        roomId == null
            ? {'type': 'voice-open'}
            : {'type': 'voice-join', 'room_id': roomId},
      );
    } catch (e) {
      if (token == _token) {
        pending = false;
        message = e.toString();
        await media.stop();
        notifyListeners();
      }
      rethrow;
    }
  }

  Future<void> start(List<String> ids) async {
    personalRoom = false;
    if (!available) {
      throw StateError(
        'Group calls require the updated PVP signaling service.',
      );
    }
    if (busy || otherBusy()) {
      throw StateError('Finish your current call first.');
    }
    final token = ++_token;
    pending = true;
    message = '';
    notifyListeners();
    try {
      await stopPreview();
      if (token != _token) return;
      media.voiceOnly = true;
      await media.acquire(preferences());
      if (token != _token) return;
      send({'type': 'room-create', 'peer_ids': ids});
    } catch (e) {
      if (token == _token) {
        pending = false;
        message = e.toString();
        await media.stop();
        notifyListeners();
      }
      rethrow;
    }
  }

  Future<void> startMeeting(String meetingId, {bool listen = false}) async {
    personalRoom = false;
    if (!available) throw StateError('Update PVP to join recurring meetings.');
    if (busy || otherBusy()) {
      throw StateError('Finish your current call first.');
    }
    final token = ++_token;
    pending = true;
    message = '';
    notifyListeners();
    try {
      await stopPreview();
      if (token != _token) return;
      media.voiceOnly = true;
      _listenIntent = listen;
      if (listen) {
        await media.listen();
      } else {
        await media.acquire(preferences());
      }
      if (token != _token) return;
      send({'type': 'meeting-enter', 'meeting_id': meetingId});
    } catch (e) {
      if (token == _token) {
        pending = false;
        message = e.toString();
        await media.stop();
        notifyListeners();
      }
      rethrow;
    }
  }

  Future<void> join() async {
    if (room == null || joined || pending) return;
    final token = _token;
    pending = true;
    message = '';
    notifyListeners();
    try {
      await host.invoke('show');
      if (token != _token) return;
      await stopPreview();
      if (token != _token) return;
      media.voiceOnly = true;
      await media.acquire(preferences());
      if (token != _token) return;
      send({'type': 'room-join', 'room_id': id});
    } catch (e) {
      if (token == _token) {
        pending = false;
        message = e.toString();
        await media.stop();
        notifyListeners();
      }
      rethrow;
    }
  }

  Future<void> _messages = Future.value();
  final Map<String, List<Map<String, dynamic>>> _earlyCandidates = {};
  Future<void> handle(Map<String, dynamic> data) {
    final token = _token;
    final next = _messages.then((_) async {
      if (token == _token) await _handle(data);
    });
    _messages = next.catchError((Object _) {});
    return next;
  }

  Future<void> _handle(Map<String, dynamic> data) async {
    if (data['type'] == 'error' && pending) {
      pending = false;
      message = data['message']?.toString() ?? 'Group call unavailable';
      if (!joined) await media.stop();
      notifyListeners();
      return;
    }
    if (data['type'] == 'room-ended') {
      if (data['room_id'] == id) await cleanup();
      return;
    }
    if (data['type'] == 'room-state') {
      final roster = (data['members'] as List)
          .map((m) => Map<String, dynamic>.from(m))
          .toList();
      final me = roster.where((m) => m['id'] == user()?.id).firstOrNull;
      if (me == null) {
        if (data['room_id'] == id) await cleanup();
        return;
      }
      if ((room != null && id != data['room_id']) || otherBusy()) {
        send({'type': 'room-leave', 'room_id': data['room_id']});
        return;
      }
      if (room != null &&
          (data['revision'] as int) <= (room!['revision'] as int)) {
        return;
      }
      if (me['joined'] == true && room == null && !pending) {
        send({'type': 'room-leave', 'room_id': data['room_id']});
        return;
      }
      if (me['joined'] != true) personalRoom = false;
      final wasJoined = joined, wasAllowed = self?['speaking_allowed'] == true;
      room = data;
      pending = false;
      if (joined) {
        applyModeration();
        if (wasJoined &&
            !wasAllowed &&
            me['speaking_allowed'] == true &&
            speakingRequired) {
          message = 'You can unmute and speak now.';
          unawaited(host.invoke('speakingAllowed'));
        } else if (awaitingApproval || !speakingRequired) {
          if (message == 'You can unmute and speak now.') message = '';
        }
        broadcast();
        _stats ??= Timer.periodic(
          const Duration(seconds: 1),
          (_) => unawaited(sample()),
        );
        await host.invoke('stopRinging');
        for (final link in links.values.toList()) {
          if (!participants.any((m) => m['id'] == link.id)) {
            await closeLink(link);
          }
        }
        for (final member in participants) {
          if (member['id'] != user()!.id &&
              !links.containsKey(member['id']) &&
              user()!.id.compareTo(member['id']) < 0) {
            await createLink(member['id'], 1, true);
          }
        }
        // Keys and routing are managed by browser publishers. Native clients
        // forward opaque packets and receive their own video via standard RTP.
        for (final link in links.values) {
          hello(link);
        }
      } else if (!wasJoined) {
        final inviter = roster
            .where((m) => m['id'] == me['invited_by'])
            .firstOrNull;
        await host.invoke('incoming', {
          'call_id': 'room:$id',
          'name': '${inviter?['display_name'] ?? 'A friend'} · Group call',
          'sound': preferences().ring,
        });
      }
      notifyListeners();
      return;
    }
    if (data['type'] == 'room-signal' && joined && data['room_id'] == id) {
      final from = data['from'] as String,
          generation = data['generation'] as int,
          payload = Map<String, dynamic>.from(data['payload']);
      if (!participants.any((m) => m['id'] == from)) return;
      var link = links[from];
      if (payload['type'] == 'offer') {
        if (link != null && generation > link.generation) {
          await closeLink(link);
          link = null;
        }
        link ??= await createLink(from, generation, false);
      }
      final key = '$from/$generation';
      if (payload['type'] == 'candidate' &&
          (link == null || link.generation < generation)) {
        requireCandidate(Map<String, dynamic>.from(payload['candidate']));
        final candidates = _earlyCandidates.putIfAbsent(key, () => []);
        if (candidates.length < 64) candidates.add(payload);
        return;
      }
      if (link == null || link.generation != generation) return;
      final candidatePeer = link;
      for (final candidate
          in _earlyCandidates.remove(key) ?? <Map<String, dynamic>>[]) {
        candidatePeer.chain = candidatePeer.chain.then(
          (_) => receive(candidatePeer, candidate),
        );
      }
      final peer = link;
      peer.chain = peer.chain.then((_) => receive(peer, payload)).catchError((
        Object e,
      ) {
        failure(peer, e);
      });
    }
  }

  Future<GroupLink> createLink(
    String peer,
    int generation,
    bool initiator,
  ) async {
    if (links.containsKey(peer)) return links[peer]!;
    final token = _token, roomId = id;
    final pc = await createPeerConnection({
      'iceServers': [
        {'urls': CallMedia.stunServers},
      ],
      'sdpSemantics': 'unified-plan',
      'bundlePolicy': 'max-bundle',
    });
    final link = GroupLink(peer, pc, generation)
      ..caps = connectionCaps.putIfAbsent(peer, () => ConnectionCaps());
    if (token != _token || id != roomId) {
      await pc.close();
      await pc.dispose();
      return link;
    }
    if (links.containsKey(peer)) {
      await pc.close();
      await pc.dispose();
      return links[peer]!;
    }
    links[peer] = link;
    media.connection ??= pc;
    bool valid() => token == _token && id == roomId && links[peer] == link;
    await link.renderer.initialize();
    final stream = media.stream;
    if (stream != null) {
      for (final track in stream.getAudioTracks()) {
        link.audioSender = await pc.addTrack(track, stream);
      }
    }
    if (stream?.getAudioTracks().isEmpty ?? true) {
      final audio = await pc.addTransceiver(
        kind: RTCRtpMediaType.RTCRtpMediaTypeAudio,
        init: RTCRtpTransceiverInit(
          direction: TransceiverDirection.SendRecv,
          streams: stream == null ? [] : [stream],
        ),
      );
      link.audioSender = audio.sender;
    }
    if (initiator) {
      final video = await pc.addTransceiver(
        kind: RTCRtpMediaType.RTCRtpMediaTypeVideo,
        init: RTCRtpTransceiverInit(
          direction: TransceiverDirection.SendRecv,
          streams: stream == null ? [] : [stream],
        ),
      );
      link.videoSender = video.sender;
      final camera = media.outgoingVideoStream?.getVideoTracks().firstOrNull;
      if (camera != null) await video.sender.replaceTrack(camera);
    }
    pc.onIceCandidate = (c) {
      if (valid() &&
          c.candidate?.isNotEmpty == true &&
          !isRelay(c.candidate!)) {
        signal(link, {'type': 'candidate', 'candidate': c.toMap()});
      }
    };
    pc.onTrack = (e) async {
      if (!valid()) return;
      if (e.streams.isNotEmpty) {
        link.remote = e.streams.first;
        applyModeration();
        link.renderer.srcObject = e.streams.first;
      } else {
        final remote =
            link.remote ?? await createLocalMediaStream('group-$peer');
        if (!valid()) return;
        link.remote = remote;
        if (!remote.getTracks().any((t) => t.id == e.track.id)) {
          await remote.addTrack(e.track);
        }
        applyModeration();
        link.renderer.srcObject = remote;
      }
      notifyListeners();
    };
    pc.onConnectionState = (state) {
      if (!valid()) return;
      link.status = state
          .toString()
          .split('.')
          .last
          .replaceFirst('RTCPeerConnectionState', '');
      if (state == RTCPeerConnectionState.RTCPeerConnectionStateConnected) {
        link.ready = true;
        link.disconnectedAt = null;
        link.retry?.cancel();
        link.retry = null;
        media.connectedAt ??= DateTime.now();
      }
      if (state == RTCPeerConnectionState.RTCPeerConnectionStateDisconnected) {
        link.disconnectedAt ??= DateTime.now();
      }
      if (state == RTCPeerConnectionState.RTCPeerConnectionStateFailed) {
        failure(link, StateError('Direct peer connection unavailable'));
      }
      notifyListeners();
    };
    pc.onDataChannel = (dc) => channel(link, dc);
    if (initiator) {
      channel(
        link,
        await pc.createDataChannel('pvp-group-chat', RTCDataChannelInit()),
      );
      channel(
        link,
        await pc.createDataChannel('pvp-group-control', RTCDataChannelInit()),
      );
      channel(
        link,
        await pc.createDataChannel(
          'pvp-group-video',
          RTCDataChannelInit()
            ..ordered = false
            ..maxRetransmits = 0,
        ),
      );
      final offer = await pc.createOffer();
      requireEncryptedSdp(offer.sdp!);
      if (!valid()) return link;
      await pc.setLocalDescription(offer);
      signal(link, {'type': 'offer', 'sdp': offer.sdp});
    }
    notifyListeners();
    return link;
  }

  void signal(GroupLink link, Map<String, dynamic> payload) {
    if (links[link.id] == link && id != null) {
      send({
        'type': 'room-signal',
        'room_id': id,
        'to': link.id,
        'generation': link.generation,
        'payload': payload,
      });
    }
  }

  Future<void> receive(GroupLink link, Map<String, dynamic> payload) async {
    if (links[link.id] != link) return;
    if (payload['type'] == 'candidate') {
      final c = Map<String, dynamic>.from(payload['candidate']);
      requireCandidate(c);
      final candidate = RTCIceCandidate(
        c['candidate'],
        c['sdpMid'],
        c['sdpMLineIndex'],
      );
      if (await link.pc.getRemoteDescription() != null) {
        await link.pc.addCandidate(candidate);
      } else {
        link.candidates.add(candidate);
      }
      return;
    }
    final sdp = payload['sdp'] as String;
    requireEncryptedSdp(sdp);
    await link.pc.setRemoteDescription(
      RTCSessionDescription(sdp, payload['type']),
    );
    for (final c in link.candidates) {
      await link.pc.addCandidate(c);
    }
    link.candidates.clear();
    if (payload['type'] == 'offer') {
      final audio = (await link.pc.getTransceivers())
          .where((t) => t.receiver.track?.kind == 'audio')
          .firstOrNull;
      if (audio != null) {
        await audio.setDirection(TransceiverDirection.SendRecv);
        link.audioSender = audio.sender;
        if (media.stream != null) {
          await audio.sender.setStreams([media.stream!]);
        }
        await audio.sender.replaceTrack(
          media.stream?.getAudioTracks().firstOrNull,
        );
      }
      final slot = (await link.pc.getTransceivers())
          .where((t) => t.receiver.track?.kind == 'video')
          .firstOrNull;
      if (slot != null) {
        await slot.setDirection(TransceiverDirection.SendRecv);
        final stream = media.stream;
        if (stream != null) await slot.sender.setStreams([stream]);
        link.videoSender = slot.sender;
        final camera = media.outgoingVideoStream?.getVideoTracks().firstOrNull;
        if (camera != null) await slot.sender.replaceTrack(camera);
      }
      final answer = await link.pc.createAnswer();
      requireEncryptedSdp(answer.sdp!);
      await link.pc.setLocalDescription(answer);
      signal(link, {'type': 'answer', 'sdp': answer.sdp});
    }
    link.localSdp = (await link.pc.getLocalDescription())!.sdp!;
    link.remoteSdp = sdp;
    link.code = safetyCode(link.localSdp!, link.remoteSdp!);
    await media.applyLimits(preferences().quality);
  }

  void channel(GroupLink link, RTCDataChannel dc) {
    if (links[link.id] != link || !joined) {
      unawaited(dc.close());
      return;
    }
    if (dc.label == 'pvp-group-chat') {
      if (link.chat != null) {
        unawaited(dc.close());
        return;
      }
      link.chat = dc;
      chat.peer(link.id, dc);
      return;
    }
    if (!['pvp-group-control', 'pvp-group-video'].contains(dc.label)) {
      unawaited(dc.close());
      return;
    }
    final control = dc.label == 'pvp-group-control';
    if (control) {
      if (link.control != null) {
        unawaited(dc.close());
        return;
      }
      link.control = dc;
    } else {
      if (link.video != null) {
        unawaited(dc.close());
        return;
      }
      link.video = dc;
    }
    dc.onDataChannelState = (state) {
      if (state == RTCDataChannelState.RTCDataChannelOpen) {
        hello(link);
        broadcast();
      }
    };
    var at = DateTime.now(), count = 0;
    dc.onMessage = (event) {
      if (links[link.id] != link) return;
      if (DateTime.now().difference(at).inMilliseconds >= 1000) {
        at = DateTime.now();
        count = 0;
      }
      if (++count > (control ? 40 : 400)) return;
      if (!control) {
        if (event.isBinary && event.binary.length <= 10000) {
          forward(link, event.binary);
        }
        return;
      }
      if (event.isBinary || event.text.length > 4096) return;
      try {
        final m = Map<String, dynamic>.from(jsonDecode(event.text));
        if (m['type'] == 'state') {
          link.state = {
            'muted': m['muted'] == true,
            'paused': m['paused'] == true,
            'sharing': m['sharing'] == true,
            'speaking': m['speaking'] == true,
            'listening': m['listening'] == true,
          };
          notifyListeners();
        } else if (m['type'] == 'bandwidth') {
          final caps = StreamCaps.parse(m['caps']);
          if (caps != null) {
            final changed =
                caps.camera != link.requested.camera ||
                caps.screen != link.requested.screen;
            link.requested = caps;
            link.bandwidthSupported = true;
            this.control(link, {'type': 'bandwidth-ack'});
            if (changed) {
              unawaited(
                media.applyLimits(preferences().quality).catchError((Object e) {
                  message = 'Could not apply requested bandwidth.';
                  notifyListeners();
                }),
              );
            }
          }
        } else if (m['type'] == 'bandwidth-ack') {
          link.bandwidthSupported = true;
        } else if (m['type'] == 'overlay-want') {
          link.wantHigh = m['high'] == true;
          link.focusedScreen = m['screen'] == true;
          unawaited(
            media.applyLimits(preferences().quality).catchError((Object e) {
              message = 'Could not apply connection bandwidth.';
              notifyListeners();
            }),
          );
        }
      } catch (_) {}
    };
  }

  void control(GroupLink link, Map<String, dynamic> m) {
    if (link.control?.state == RTCDataChannelState.RTCDataChannelOpen &&
        (link.control?.bufferedAmount ?? 0) < 32768) {
      unawaited(
        link.control!
            .send(RTCDataChannelMessage(jsonEncode(m)))
            .catchError((Object _) {}),
      );
    }
  }

  void hello(GroupLink link) => control(link, {
    'type': 'overlay-hello',
    'relay': true,
    'receive': false,
    'codec': 'vp8',
  });
  void focus(String? peer) {
    focusedPeer = peer;
    broadcast();
  }

  Future<void> updateBandwidth() async {
    broadcast();
    notifyListeners();
    await media.applyLimits(preferences().quality);
  }

  void broadcast() {
    final focusedScreen = focusedPeer == user()?.id
        ? media.screenSharing
        : focusedPeer != null && links[focusedPeer]?.state['sharing'] == true;
    for (final link in links.values) {
      control(link, {'type': 'bandwidth', 'caps': link.caps.receive.toJson()});
      control(link, {
        'type': 'overlay-want',
        'high': focusedPeer == link.id,
        'screen': focusedScreen,
      });
      control(link, {
        'type': 'state',
        'muted': media.muted,
        'listening': listening,
        'paused': media.cameraOff,
        'sharing': media.screenSharing,
        'speaking': !media.muted && media.microphoneLevel > .025,
      });
    }
  }

  List<String> tree(String source) {
    final ids = participants.map((m) => m['id'] as String).toList()..sort();
    final index = ids.indexOf(source);
    return index < 0 ? [] : [...ids.skip(index), ...ids.take(index)];
  }

  void forward(GroupLink incoming, Uint8List bytes) {
    if (!joined ||
        !forwardingEnabled(participants.length) ||
        bytes.length < 3) {
      return;
    }
    try {
      final headerLength = ByteData.sublistView(bytes).getUint16(0);
      if (headerLength > 1200 || headerLength + 2 >= bytes.length) return;
      final h = Map<String, dynamic>.from(
        jsonDecode(utf8.decode(bytes.sublist(2, 2 + headerLength))),
      );
      if (h['m'] is! String || (h['m'] as String).length > 600) return;
      final m = Map<String, dynamic>.from(jsonDecode(h['m']));
      final source = m['source'];
      if (links[source]?.state['sharing'] == true) return;
      if (m['room'] != id ||
          m['revision'] != room?['revision'] ||
          m['codec'] != 'vp8' ||
          !['key', 'delta'].contains(m['type']) ||
          m['seq'] is! int ||
          (m['seq'] as int) < 1 ||
          m['timestamp'] is! int ||
          h['part'] is! int ||
          h['total'] is! int ||
          h['len'] is! int ||
          h['total'] < 1 ||
          h['total'] > 42 ||
          h['part'] < 0 ||
          h['part'] >= h['total'] ||
          h['len'] < 17 ||
          h['len'] > 250016 ||
          h['total'] != ((h['len'] as int) + 5999) ~/ 6000 ||
          h['iv'] is! String ||
          (h['iv'] as String).length != 16 ||
          h['sig'] is! String ||
          (h['sig'] as String).length != 88) {
        return;
      }
      final path = tree(source as String),
          index = path.indexOf(user()?.id ?? '');
      if (index <= 0 || path[(index - 1) ~/ 4] != incoming.id) return;
      if (bytes.length - headerLength - 2 !=
          min(6000, (h['len'] as int) - (h['part'] as int) * 6000)) {
        return;
      }
      final packet = '$source/${m['revision']}/${m['seq']}/${h['part']}';
      if (_seen.containsKey(packet)) return;
      _seen[packet] = DateTime.now().millisecondsSinceEpoch;
      while (_seen.length > 2048) {
        _seen.remove(_seen.keys.first);
      }
      incoming.receivedBytes += bytes.length;
      if (DateTime.now().difference(_budgetAt).inMilliseconds >= 1000) {
        _budgetAt = DateTime.now();
        _budgetBytes = 0;
      }
      for (final child in path.skip(index * 4 + 1).take(4)) {
        final link = links[child], dc = link?.video;
        if (dc?.state != RTCDataChannelState.RTCDataChannelOpen ||
            (dc?.bufferedAmount ?? 0) > 65536) {
          continue;
        }
        if (_budgetBytes + bytes.length >
            groupVideoKbps(preferences().quality, participants.length) *
                1000 /
                16 *
                (media.screenSharing ||
                        links.values.any((l) => l.state['sharing'] == true)
                    ? .1
                    : 1)) {
          continue;
        }
        _budgetBytes += bytes.length;
        media.forwardedAt = DateTime.now();
        link!.forwardedBytes += bytes.length;
        link.sentBytes += bytes.length;
        unawaited(
          dc!
              .send(RTCDataChannelMessage.fromBinary(bytes))
              .catchError((Object _) {}),
        );
      }
    } catch (_) {}
  }

  Future<void> sample() async {
    if (!joined) return;
    broadcast();
    String? rejection;
    Future<void>? rejectionCleanup;
    await Future.wait(
      links.values.toList().map((link) async {
        if (link.sampling) return;
        link.sampling = true;
        try {
          if ((link.disconnectedAt != null &&
                  DateTime.now().difference(link.disconnectedAt!).inSeconds >=
                      8) ||
              (!link.ready &&
                  DateTime.now().difference(link.openedAt).inSeconds >= 15)) {
            failure(link, StateError('Peer connection timed out'));
          }
          final stats = await link.pc.getStats().timeout(
            const Duration(seconds: 3),
          );
          if (links[link.id] != link) return;
          link.meter.sample(
            stats
                .map(
                  (r) => <String, dynamic>{
                    ...r.values,
                    'id': r.id,
                    'type': r.type,
                  },
                )
                .toList(),
          );
          link.outgoing.sample(
            stats
                .map(
                  (r) => <String, dynamic>{
                    ...r.values,
                    'id': r.id,
                    'type': r.type,
                  },
                )
                .toList(),
          );
          link.evidence = ConnectionEvidence.fromReports(
            stats
                .map(
                  (r) => <String, dynamic>{
                    ...r.values,
                    'id': r.id,
                    'type': r.type,
                    'timestamp': r.timestamp,
                  },
                )
                .toList(),
            iceState:
                link.pc.iceConnectionState
                    ?.toString()
                    .split('.')
                    .last
                    .replaceFirst('RTCIceConnectionState', '')
                    .toLowerCase() ??
                'unavailable',
            connectionState: link.status.toLowerCase(),
            configuredServers: CallMedia.stunServers,
            localSdp: link.localSdp,
            remoteSdp: link.remoteSdp,
          );
          final proof = link.evidence!;
          if (proof.relayed ||
              proof.certificateMismatch ||
              proof.transportFailed) {
            link.code = '';
            if (rejection == null) {
              rejection = proof.relayed
                  ? 'Relayed media is disabled.'
                  : proof.certificateMismatch
                  ? 'The selected transport certificate does not match negotiation.'
                  : 'The encrypted transport was lost.';
              message = rejection!;
              // Begin capture/transport teardown as soon as definite failure
              // is known; another peer's pending getStats must not delay it.
              rejectionCleanup = leave();
              notifyListeners();
            }
            return;
          }
          for (final s in stats) {
            if (s.type == 'inbound-rtp' && s.values['kind'] == 'audio') {
              final level = s.values['audioLevel'];
              link.speaking =
                  link.status == 'Connected' &&
                  !isModerated(link.id) &&
                  link.state['muted'] != true &&
                  level is num &&
                  level > .025;
            }
          }
        } catch (_) {
          link.evidence = null;
          link.outgoing.sample([]);
        } finally {
          link.sampling = false;
        }
      }),
    );
    if (rejection != null) {
      await rejectionCleanup;
      message = rejection!;
      notifyListeners();
      return;
    }
    try {
      await media.applyLimits(preferences().quality);
    } catch (_) {}
    notifyListeners();
  }

  void failure(GroupLink link, Object error) {
    if (links[link.id] != link) return;
    link.status = 'Direct connection unavailable';
    link.ready = false;
    notifyListeners();
    if (user()!.id.compareTo(link.id) < 0 &&
        link.generation < 8 &&
        link.retry == null) {
      link.retry = Timer(const Duration(milliseconds: 2500), () async {
        if (!joined || links[link.id] != link) return;
        await closeLink(link);
        try {
          await createLink(link.id, link.generation + 1, true);
        } catch (_) {}
      });
    }
  }

  Future<void> closeLink(GroupLink link) async {
    chat.remove(link.id);
    if (links[link.id] == link) links.remove(link.id);
    link.retry?.cancel();
    if (media.connection == link.pc) {
      media.connection = links.values.firstOrNull?.pc;
      if (media.connection == null) media.connectedAt = null;
    }
    try {
      await link.chat?.close();
      await link.control?.close();
      await link.video?.close();
      await link.pc.close();
      await link.pc.dispose();
      link.renderer.srcObject = null;
      await link.renderer.dispose();
    } catch (_) {}
  }

  Future<void> leave() async {
    if (id != null) {
      try {
        send({'type': 'room-leave', 'room_id': id});
      } catch (_) {}
    }
    await cleanup();
  }

  Future<void> cleanup() => _cleanupFuture ??= _cleanupOnce().whenComplete(() {
    _stopping = false;
    _cleanupFuture = null;
    notifyListeners();
  });

  Future<void> _cleanupOnce() async {
    chat.clear();
    _stopping = true;
    ++_token;
    _stats?.cancel();
    _stats = null;
    pending = false;
    microphoneOpening = false;
    _listenIntent = false;
    room = null;
    personalRoom = false;
    focusedPeer = null;
    connectionCaps.clear();
    _seen.clear();
    _earlyCandidates.clear();
    final stopping = media.stop();
    unawaited(
      host.invoke('stopRinging').then<void>((_) {}).catchError((Object _) {}),
    );
    await stopping;
  }

  Map<String, dynamic> report() => {
    'schemaVersion': 2,
    'client': 'PVP macOS group call',
    'exportedAt': DateTime.now().toUtc().toIso8601String(),
    'notice':
        'WebRTC/application observations, not independent packet capture; includes peer network addresses.',
    'roomId': id,
    'revision': room?['revision'],
    'peers': links.values
        .map(
          (l) => {
            'peerId': l.id,
            'media': l.evidence?.data,
            'certificateCode': l.code,
            'forwardedBytes': l.forwardedBytes,
            'receivedBytes': l.receivedBytes,
            'sentBytes': l.sentBytes,
          },
        )
        .toList(),
  };
  @override
  void dispose() {
    _stats?.cancel();
    chat.dispose();
    media.removeListener(notifyListeners);
    unawaited(media.stop());
    super.dispose();
  }
}
