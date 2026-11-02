import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/controller.dart';
import 'package:pvp_desktop/core/media.dart';
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/core/native.dart';
import 'package:pvp_desktop/core/group_calls.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'screenshare_test.dart' show Track, Stream;

class MemoryHost extends NativeHost {
  @override
  Future<void> savePreferences(String key, String value) async {}
  @override
  Future<T?> invoke<T>(String method, [dynamic arguments]) async => null;
}

class RoutingMedia extends CallMedia {
  String chosen = '';
  int captures = 0;
  bool fail = false;
  @override
  Future<void> setMicrophone(String id) async {
    if (fail) throw StateError('Device disconnected');
    chosen = id;
  }

  @override
  Future<void> reconfigure(Preferences p) async {
    captures++;
  }
}

class CameraRoutingMedia extends GroupMedia {
  final cameras = <String>[];
  @override
  Future<void> toggleVideo(Preferences p) async {
    cameras.add(p.camera);
    if (p.camera == 'unavailable') throw StateError('Camera unavailable');
    cameraOff = !cameraOff;
  }

  @override
  Future<void> stop() async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test(
    'meeting camera selection changes only an active camera and restores it on failure',
    () async {
      final media = CameraRoutingMedia()..cameraOff = false;
      final c = PvpController(host: MemoryHost(), groupMedia: media)
        ..user = const Person('self', 'self', 'Self');
      c.group.room = {
        'room_id': 'room',
        'members': [
          {'id': 'self', 'joined': true},
        ],
      };
      await c.setDevice('videoinput', 'external');
      expect(media.cameras, ['', 'external']);
      expect(media.cameraOff, false);
      await c.setDevice('videoinput', 'unavailable');
      expect(media.cameraOff, false);
      expect(c.preferences.camera, 'external');
      expect(media.cameras, [
        '',
        'external',
        'external',
        'unavailable',
        'external',
      ]);
      media.cameraOff = true;
      media.cameras.clear();
      await c.setDevice('videoinput', 'next');
      expect(media.cameras, isEmpty);
      c.group.room = null;
      c.dispose();
    },
  );
  test(
    'disconnected microphone falls back without replacing capture or unmuting',
    () async {
      final mic = Track('audio', 'consented')..enabled = false;
      final original = Stream('call', [mic]);
      final media = RoutingMedia()
        ..stream = original
        ..muted = true;
      final c = PvpController(host: MemoryHost(), media: media);
      c.preferences.microphone = 'removed';
      await c.handleDeviceChange(
        observedDevices: [
          MediaDeviceInfo(
            kind: 'audioinput',
            label: 'Built-in',
            deviceId: 'built-in',
          ),
        ],
      );
      expect(media.chosen, '');
      expect(c.preferences.microphone, '');
      expect(media.stream, same(original));
      expect(media.muted, true);
      expect(mic.enabled, false);
      expect(mic.stopped, false);
      expect(media.captures, 0);
      expect(media.microphoneNotice, contains('mute setting is unchanged'));
      media.stream = null;
      c.dispose();
    },
  );
  test(
    'listener device fallback changes future preference without routing or capture',
    () async {
      final media = RoutingMedia()..chosen = 'untouched';
      final c = PvpController(host: MemoryHost(), media: media);
      c.preferences.microphone = 'removed';
      await c.handleDeviceChange(observedDevices: []);
      expect(c.preferences.microphone, '');
      expect(media.chosen, 'untouched');
      expect(media.captures, 0);
      expect(media.microphoneNotice, contains('when you choose a microphone'));
      expect(media.stream, null);
      c.dispose();
    },
  );
  test(
    'present selected microphone remains selected and fallback failure is visible',
    () async {
      final media = RoutingMedia()..chosen = 'selected';
      final c = PvpController(host: MemoryHost(), media: media);
      c.preferences.microphone = 'selected';
      await c.handleDeviceChange(
        observedDevices: [
          MediaDeviceInfo(
            kind: 'audioinput',
            label: 'Selected',
            deviceId: 'selected',
          ),
        ],
      );
      expect(media.chosen, 'selected');
      expect(c.preferences.microphone, 'selected');
      media.stream = Stream('call', [Track('audio', 'consented')]);
      media.fail = true;
      await c.handleDeviceChange(observedDevices: []);
      expect(c.preferences.microphone, 'selected');
      expect(c.message, contains('Choose System default'));
      media.stream = null;
      c.dispose();
    },
  );
  test(
    'input routing keeps capture and mute intact; failure restores preferences',
    () async {
      final media = RoutingMedia()..muted = true;
      final c = PvpController(host: MemoryHost(), media: media);
      await c.setDevice('audioinput', 'built-in');
      expect(media.chosen, 'built-in');
      expect(media.captures, 0);
      expect(media.muted, isTrue);
      await c.setDevice('audioinput', '');
      expect(media.chosen, '');
      expect(c.preferences.microphone, '');
      media.fail = true;
      await c.setDevice('audioinput', 'disconnected');
      expect(c.preferences.microphone, '');
      expect(c.message, contains('Device disconnected'));
      c.dispose();
    },
  );
}
