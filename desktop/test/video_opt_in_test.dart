import 'dart:async';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:pvp_desktop/core/media.dart';
import 'package:pvp_desktop/core/models.dart';
import 'screenshare_test.dart' show Track, Stream, Sender, Media, Peer;

class MutableStream extends Stream {
  MutableStream(super.id, super.tracks);
  @override
  Future<void> addTrack(
    MediaStreamTrack track, {
    bool addToNative = true,
  }) async => tracks.add(track);
  @override
  Future<void> removeTrack(
    MediaStreamTrack track, {
    bool removeFromNative = true,
  }) async => tracks.remove(track);
}

class CameraMedia extends CallMedia {
  final List<RTCRtpSender> slots;
  CameraMedia(
    this.slots,
    Future<MediaStream> Function(Map<String, dynamic>) capture,
  ) : super(captureOverride: capture);
  @override
  Future<List<RTCRtpSender>> videoSenders() async => slots;
  @override
  Future<void> applyLimits(Quality q) async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUp(
    () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('FlutterWebRTC.Method'),
          (call) async =>
              call.method == 'createVideoRenderer' ? {'textureId': 1} : null,
        ),
  );
  test(
    'default capture is microphone-only; opt-in adds video to every peer without replacing muted audio',
    () async {
      final mic = Track('audio', 'mic')..enabled = false,
          camera = Track('video', 'camera');
      final original = MutableStream('call', [mic]),
          captured = MutableStream('camera', [camera]);
      final slots = [Sender(null), Sender(null)];
      final media =
          CameraMedia(slots, (constraints) async {
              expect(constraints['audio'], false);
              expect(constraints['video'], isA<Map>());
              return captured;
            })
            ..stream = original
            ..muted = true;
      await media.local.initialize();
      expect(media.constraints(Preferences())['video'], false);
      await media.toggleVideo(Preferences());
      expect(media.stream, same(original));
      expect(original.getAudioTracks().single, same(mic));
      expect(mic.enabled, false);
      expect(mic.stopped, false);
      expect(slots.every((s) => identical(s.track, camera)), true);
      expect(camera.stopped, false);
      expect(media.cameraOff, false);
      await media.toggleVideo(Preferences());
      expect(slots.every((s) => s.track == null), true);
      expect(camera.stopped, true);
      expect(original.getVideoTracks(), isEmpty);
      expect(media.cameraOff, true);
      await media.local.initialize();
      expect(media.constraints(Preferences())['video'], false);
      await media.stop();
      media.dispose();
    },
  );
  test(
    'screen sharing from a voice call restores microphone-only media',
    () async {
      final mic = Track('audio', 'mic'), display = Track('video', 'screen');
      final sender = Sender(null),
          media = Media(
            Sender(null),
            (_) async => MutableStream('screen', [display]),
          );
      // The existing test helper exposes its single negotiated video sender.
      media.sender.track = sender.track;
      await media.local.initialize();
      media.connection = Peer();
      media.connectedAt = DateTime.now();
      media.stream = MutableStream('call', [mic]);
      await media.startScreenShare('test', 'Test screen', Preferences());
      expect(media.sender.track, same(display));
      expect(mic.stopped, false);
      await media.stopScreenShare();
      expect(media.sender.track, isNull);
      expect(media.cameraOff, true);
      expect(mic.stopped, false);
      expect(display.stopped, true);
      await media.stop();
      media.dispose();
    },
  );
  test(
    'camera failure restores all video slots and leaves the microphone running',
    () async {
      final mic = Track('audio', 'mic'), camera = Track('video', 'camera');
      final slots = [Sender(null), Sender(null)..fail = true];
      final media = CameraMedia(
        slots,
        (_) async => MutableStream('camera', [camera]),
      )..stream = MutableStream('call', [mic]);
      await expectLater(media.toggleVideo(Preferences()), throwsStateError);
      expect(slots.every((s) => s.track == null), true);
      expect(camera.stopped, true);
      expect(mic.stopped, false);
      expect(media.cameraOff, true);
      await media.stop();
      media.dispose();
    },
  );
  test(
    'hangup while camera permission is pending stops late video without attaching it',
    () async {
      final pending = Completer<MediaStream>(),
          mic = Track('audio', 'mic'),
          camera = Track('video', 'late');
      final slot = Sender(null),
          media = CameraMedia([Sender(null)], (_) => pending.future)
            ..stream = MutableStream('call', [mic]);
      media.slots[0] = slot;
      final turningOn = media.toggleVideo(Preferences());
      await media.stop();
      pending.complete(MutableStream('late', [camera]));
      await turningOn;
      expect(camera.stopped, true);
      expect(slot.track, isNull);
      expect(media.stream, isNull);
      media.dispose();
    },
  );
}
