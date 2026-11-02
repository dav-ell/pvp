import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/models.dart';

void main() {
  test('service addresses require TLS except for loopback development', () {
    expect(
      serviceUri('https://lopixel.space/').toString(),
      'https://lopixel.space',
    );
    expect(serviceUri('http://localhost:8787').port, 8787);
    for (final value in [
      'http://example.com',
      'https://user:secret@example.com',
      'https://example.com/path',
      'https://example.com?token=secret',
      'file:///etc/passwd',
    ]) {
      expect(() => serviceUri(value), throwsFormatException);
    }
  });
  test('saved preferences recover from corruption and bound bandwidth', () {
    expect(Preferences.decode('corrupt').quality.preset, 'balanced');
    expect(Preferences().echoCancellation, isTrue);
    expect(Preferences.decode('{}').echoCancellation, isTrue);
    expect(Preferences.decode('corrupt').echoCancellation, isTrue);
    final preferences = Preferences(
      quality: const Quality('custom', 1080, 60, 8000, 96),
      camera: 'camera',
      ring: false,
      showControlLabels: true,
      echoCancellation: false,
    );
    final roundTrip = Preferences.decode(preferences.encode());
    expect(roundTrip.quality.videoKbps, 8000);
    expect(roundTrip.camera, 'camera');
    expect(roundTrip.ring, isFalse);
    expect(roundTrip.showControlLabels, isTrue);
    expect(Preferences.decode('{}').showControlLabels, isFalse);
    expect(roundTrip.echoCancellation, isFalse);
    final bounded = Quality.fromJson({
      'height': 9000,
      'fps': -1,
      'videoKbps': 999999,
      'audioKbps': 999,
    });
    expect(bounded.height, 720);
    expect(bounded.fps, 30);
    expect(bounded.videoKbps, 8000);
    expect(bounded.audioKbps, 64);
  });
}
