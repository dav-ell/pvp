import 'package:flutter_test/flutter_test.dart';
import 'package:pvp_desktop/core/call_observations.dart';
import 'package:pvp_desktop/core/media.dart';
import 'screenshare_test.dart' show Track, Stream;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test(
    'outgoing evidence expires and resets on stream changes or counter rollback',
    () {
      final meter = OutgoingMediaStats(), at = DateTime(2026, 10, 31);
      List<Map<String, dynamic>> reports(
        int video,
        int audio, {
        String id = 'v',
      }) => [
        {
          'id': id,
          'type': 'outbound-rtp',
          'kind': 'video',
          'bytesSent': video,
          'frameWidth': 1280,
          'frameHeight': 720,
          'framesPerSecond': 29.9,
        },
        {
          'id': 'a',
          'type': 'outbound-rtp',
          'kind': 'audio',
          'bytesSent': audio,
        },
        {
          'id': 'in',
          'type': 'inbound-rtp',
          'kind': 'video',
          'bytesReceived': 9999,
          'frameWidth': 1,
          'frameHeight': 1,
          'framesPerSecond': 1,
        },
      ];
      meter.sample(reports(100, 100), now: at);
      expect(meter.videoKbps, null);
      meter.sample(
        reports(90100, 4100),
        now: at.add(const Duration(seconds: 1)),
      );
      expect(meter.videoKbps, 720);
      expect(meter.audioKbps, 32);
      expect(
        meter.summary(
          videoEnabled: true,
          now: at.add(const Duration(seconds: 1)),
        ),
        'Sent 1280 × 720 · 30 fps · video 720 Kbps · audio 32 Kbps',
      );
      expect(
        meter.summary(
          videoEnabled: false,
          now: at.add(const Duration(seconds: 1)),
        ),
        startsWith('Camera off'),
      );
      expect(
        meter.summary(
          videoEnabled: true,
          now: at.add(const Duration(seconds: 5)),
        ),
        'Actual sent media unavailable',
      );
      meter.sample(
        reports(90100, 4100, id: 'new'),
        now: at.add(const Duration(seconds: 2)),
      );
      expect(meter.videoKbps, null);
      meter.sample(
        reports(0, 0, id: 'new'),
        now: at.add(const Duration(seconds: 3)),
      );
      expect(meter.videoKbps, null);
      meter.sample([], now: at.add(const Duration(seconds: 4)));
      expect(meter.fresh(now: at.add(const Duration(seconds: 4))), false);
    },
  );
  test(
    'muted reminder requires sustained fresh input and never enables a track',
    () {
      final mic = Track('audio', 'mic')..enabled = false;
      final media = CallMedia()
        ..stream = Stream('consented', [mic])
        ..muted = true;
      final at = DateTime.now();
      void sample(
        int ms, {
        bool audio = true,
        bool fresh = true,
        bool muted = true,
        double level = .1,
      }) => media.mutedSpeech.sample(
        muted: muted,
        hasAudioTrack: audio,
        receivingSamples: fresh,
        level: level,
        now: at.add(Duration(milliseconds: ms)),
      );
      sample(0, audio: false);
      sample(1000, audio: false);
      expect(
        media.mutedSpeech.visible(now: at.add(const Duration(seconds: 1))),
        false,
      );
      sample(1200, fresh: false);
      sample(2200, fresh: false);
      expect(
        media.mutedSpeech.visible(now: at.add(const Duration(seconds: 2))),
        false,
      );
      sample(2500);
      sample(3300);
      expect(
        media.mutedSpeech.visible(
          now: at.add(const Duration(milliseconds: 3300)),
        ),
        true,
      );
      expect(mic.enabled, false);
      expect(media.muted, true);
      expect(mic.stopped, false);
      expect(
        media.mutedSpeech.visible(now: at.add(const Duration(seconds: 9))),
        false,
      );
      sample(10000);
      sample(11000);
      expect(
        media.mutedSpeech.visible(now: at.add(const Duration(seconds: 11))),
        false,
      );
      sample(24000);
      expect(
        media.mutedSpeech.visible(now: at.add(const Duration(seconds: 24))),
        true,
      );
      sample(25000, muted: false);
      expect(
        media.mutedSpeech.visible(now: at.add(const Duration(seconds: 25))),
        false,
      );
      media.stream = null;
      media.dispose();
    },
  );
}
