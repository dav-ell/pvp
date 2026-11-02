import 'dart:async';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:pvp_desktop/core/controller.dart';
import 'package:pvp_desktop/core/group_calls.dart';
import 'package:pvp_desktop/core/media.dart';
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/core/native.dart';
import 'screenshare_test.dart' show Track, Stream;

class EchoMedia extends CallMedia {
  EchoMedia({super.captureOverride});
  @override
  Future<void> initialize() async {
    await local.initialize();
  }
}

class SavedHost extends NativeHost {
  String? saved;
  bool fail = false;
  @override
  Future<T?> invoke<T>(String method, [dynamic arguments]) async => null;
  @override
  Future<void> savePreferences(String key, String value) async {
    if (fail) throw StateError('Could not save settings');
    saved = value;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final calls = <Map<dynamic, dynamic>>[];
  var reject = false;
  setUp(() {
    calls.clear();
    reject = false;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(NativeHost.channel, (call) async {
          if (call.method == 'setEchoCancellation') {
            calls.add(call.arguments as Map);
            if (reject && call.arguments['enabled'] == false) {
              throw PlatformException(code: 'audio', message: 'Unavailable');
            }
          }
          return null;
        });
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('FlutterWebRTC.Method'),
          (call) async =>
              call.method == 'createVideoRenderer' ? {'textureId': 1} : null,
        );
  });

  test('new capture and recapture apply the saved echo setting', () async {
    final captured = <Stream>[];
    final media = EchoMedia(
      captureOverride: (constraints) async {
        expect(constraints['audio']['echoCancellation'], false);
        final stream = Stream('capture', [
          Track('audio', 'mic-${captured.length}'),
        ]);
        captured.add(stream);
        return stream;
      },
    );
    final preferences = Preferences(echoCancellation: false);
    expect(media.constraints(Preferences())['audio']['echoCancellation'], true);
    await media.acquire(preferences);
    expect(calls.single, {'trackId': 'mic-0', 'enabled': false});
    media.toggleMic();
    await media.reconfigure(preferences);
    expect(calls.last, {'trackId': 'mic-1', 'enabled': false});
    expect(media.muted, true);
    expect(media.stream!.getAudioTracks().single.enabled, false);
    expect(captured.first.disposed, true);
    await media.stop();
    media.dispose();
  });

  test(
    'live toggle retains muted capture and restores settings on failure',
    () async {
      final mic = Track('audio', 'mic')..enabled = false;
      final stream = Stream('active', [mic]);
      final media = EchoMedia()
        ..stream = stream
        ..muted = true;
      final host = SavedHost(),
          controller = PvpController(host: host, media: media);
      expect(await controller.setEchoCancellation(false), true);
      expect(Preferences.decode(host.saved).echoCancellation, false);
      expect(media.stream, same(stream));
      expect(mic.enabled, false);
      expect(mic.stopped, false);
      expect(await controller.setEchoCancellation(true), true);
      reject = true;
      expect(await controller.setEchoCancellation(false), false);
      expect(controller.preferences.echoCancellation, true);
      expect(calls.last['enabled'], true);
      reject = false;
      host.fail = true;
      expect(await controller.setEchoCancellation(false), false);
      expect(controller.preferences.echoCancellation, true);
      expect(calls.last['enabled'], true);
      await media.stop();
      controller.dispose();
    },
  );

  test('group calls update their shared microphone', () async {
    final mic = Track('audio', 'group-mic')..enabled = false;
    final group = GroupMedia()
      ..stream = Stream('group', [mic])
      ..muted = true;
    final controller = PvpController(host: SavedHost(), groupMedia: group);
    controller.user = const Person('me', 'me', 'Me');
    controller.group.room = {
      'room_id': 'test',
      'members': [
        {'id': 'me', 'joined': true},
      ],
    };
    expect(await controller.setEchoCancellation(false), true);
    expect(calls.single, {'trackId': 'group-mic', 'enabled': false});
    expect(mic.enabled, false);
    expect(mic.stopped, false);
    await group.stop();
    controller.group.room = null;
    controller.dispose();
  });

  test(
    'toggle waits for a pending capture and applies the latest choice',
    () async {
      final pending = Completer<MediaStream>();
      final media = EchoMedia(captureOverride: (_) => pending.future);
      final acquiring = media.acquire(Preferences());
      final changing = media.setEchoCancellation(false);
      pending.complete(Stream('late', [Track('audio', 'late-mic')]));
      await acquiring;
      await changing;
      expect(calls.map((c) => c['enabled']), [true, false]);
      await media.stop();
      media.dispose();
    },
  );
}
