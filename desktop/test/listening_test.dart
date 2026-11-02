import 'dart:async';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:pvp_desktop/core/media.dart';
import 'package:pvp_desktop/core/models.dart';
import 'screenshare_test.dart' show Track, Sender;
import 'video_opt_in_test.dart' show MutableStream;

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
    'listener microphone upgrade keeps the stream and binds all reserved senders',
    () async {
      final mic = Track('audio', 'mic'), slots = [Sender(null), Sender(null)];
      final captured = MutableStream('capture', [mic]),
          original = MutableStream('listener', []);
      final media = CallMedia(
        captureOverride: (constraints) async {
          expect(constraints['video'], false);
          return captured;
        },
      )..stream = original;
      await media.local.initialize();
      await media.enableMicrophone(Preferences(), slots);
      expect(media.stream, same(original));
      expect(slots.every((s) => identical(s.track, mic)), true);
      expect(original.getAudioTracks().single, same(mic));
      expect(captured.disposed, true);
      expect(mic.stopped, false);
      expect(media.muted, false);
      await media.stop();
      media.dispose();
    },
  );
  test(
    'failed listener upgrade restores every sender and leaves listening available',
    () async {
      final mic = Track('audio', 'mic'),
          slots = [Sender(null), Sender(null)..fail = true];
      final original = MutableStream('listener', []);
      final media =
          CallMedia(
              captureOverride: (_) async => MutableStream('capture', [mic]),
            )
            ..stream = original
            ..muted = true;
      await expectLater(
        media.enableMicrophone(Preferences(), slots),
        throwsStateError,
      );
      expect(slots.every((s) => s.track == null), true);
      expect(original.getAudioTracks(), isEmpty);
      expect(media.muted, true);
      expect(mic.stopped, true);
      await media.stop();
      media.dispose();
    },
  );
  test(
    'leaving during microphone permission disposes the late grant',
    () async {
      final pending = Completer<MediaStream>(),
          mic = Track('audio', 'late'),
          slot = Sender(null);
      final media = CallMedia(captureOverride: (_) => pending.future)
        ..stream = MutableStream('listener', []);
      final upgrade = media.enableMicrophone(Preferences(), [slot]);
      await media.stop();
      pending.complete(MutableStream('late', [mic]));
      await upgrade;
      expect(mic.stopped, true);
      expect(slot.track, isNull);
      expect(media.stream, isNull);
      media.dispose();
    },
  );
}
