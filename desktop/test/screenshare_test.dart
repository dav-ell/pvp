import 'dart:async';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:pvp_desktop/core/media.dart';
import 'package:pvp_desktop/core/models.dart';

class Track implements MediaStreamTrack {
  @override
  final String kind;
  @override
  final String id;
  @override
  bool enabled = true;
  @override
  void Function()? onEnded;
  bool stopped = false;
  Track(this.kind, this.id);
  @override
  Future<void> stop() async {
    stopped = true;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class Stream implements MediaStream {
  @override
  final String id;
  final List<MediaStreamTrack> tracks;
  bool disposed = false;
  Stream(this.id, this.tracks);
  @override
  String get ownerTag => 'local';
  @override
  List<MediaStreamTrack> getTracks() => tracks;
  @override
  List<MediaStreamTrack> getVideoTracks() =>
      tracks.where((t) => t.kind == 'video').toList();
  @override
  List<MediaStreamTrack> getAudioTracks() =>
      tracks.where((t) => t.kind == 'audio').toList();
  @override
  Future<void> dispose() async {
    disposed = true;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class Sender implements RTCRtpSender {
  @override
  MediaStreamTrack? track;
  bool fail = false;
  Sender(this.track);
  @override
  Future<void> replaceTrack(MediaStreamTrack? next) async {
    if (fail) {
      fail = false;
      throw StateError('Disconnected');
    }
    track = next;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class Peer implements RTCPeerConnection {
  @override
  Future<void> close() async {}
  @override
  Future<void> dispose() async {}
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class Media extends CallMedia {
  final Sender sender;
  Media(this.sender, Future<MediaStream> Function(Map<String, dynamic>) capture)
    : super(displayCaptureOverride: capture);
  @override
  Future<List<RTCRtpSender>> videoSenders() async => [sender];
  @override
  Future<void> applyLimits(Quality q) async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('FlutterWebRTC.Method'),
          (call) async =>
              call.method == 'createVideoRenderer' ? {'textureId': 1} : null,
        );
  });
  test(
    'share changes only video; stop restores disabled camera and retains muted microphone',
    () async {
      final camera = Track('video', 'camera')..enabled = false;
      final mic = Track('audio', 'mic')..enabled = false;
      final display = Track('video', 'display'),
          captured = Stream('screen', [display]);
      final sender = Sender(camera),
          media = Media(Sender(camera), (_) async => captured);
      await media.local.initialize();
      media.connection = Peer();
      media.connectedAt = DateTime.now();
      media.stream = Stream('camera', [camera, mic]);
      media.cameraOff = true;
      media.muted = true;
      await media.startScreenShare('test', 'Test window', Preferences());
      expect(media.sender.track, display);
      expect(camera.enabled, false);
      expect(mic.enabled, false);
      expect(mic.stopped, false);
      await media.stopScreenShare();
      expect(media.sender.track, camera);
      expect(camera.enabled, false);
      expect(media.muted, true);
      expect(display.stopped, true);
      expect(captured.disposed, true);
      expect(media.screenSharing, false);
      expect(sender.track, camera);
      await media.stop();
    },
  );
  test('hangup during pending screen picker disposes late capture', () async {
    final pending = Completer<MediaStream>();
    final camera = Track('video', 'camera'),
        display = Track('video', 'display');
    final captured = Stream('screen', [display]),
        media = Media(Sender(camera), (_) => pending.future);
    await media.local.initialize();
    media.connection = Peer();
    media.connectedAt = DateTime.now();
    media.stream = Stream('camera', [camera]);
    final sharing = media.startScreenShare('test', 'Test', Preferences());
    await media.stop();
    pending.complete(captured);
    await sharing;
    expect(display.stopped, true);
    expect(captured.disposed, true);
    expect(media.screenSharing, false);
  });
}
