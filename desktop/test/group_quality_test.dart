import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:pvp_desktop/core/group_calls.dart';
import 'screenshare_test.dart' as mocks;
import 'package:pvp_desktop/core/models.dart';
import 'package:pvp_desktop/core/group_quality.dart';

class QualityTrack extends mocks.Track {
  QualityTrack(String kind) : super(kind, kind);
  @override
  Map<String, dynamic> getSettings() => {'height': 1080};
}

class QualitySender extends mocks.Sender {
  QualitySender(String kind) : super(QualityTrack(kind));
  @override
  final parameters = RTCRtpParameters(encodings: [RTCRtpEncoding()]);
  @override
  Future<bool> setParameters(RTCRtpParameters parameters) async => true;
}

class QualityPeer extends mocks.Peer {
  final camera = QualitySender('video'), audio = QualitySender('audio');
  @override
  Future<List<RTCRtpSender>> getSenders() async => [camera, audio];
}

class QualityMedia extends GroupMedia {
  bool sharing = false;
  @override
  bool get screenSharing => sharing;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test(
    'native screen sender preserves pixels, prioritizes focused viewers, and preserves audio',
    () async {
      final media = QualityMedia()..sharing = true;
      final focused = QualityPeer(), other = QualityPeer();
      media.links['focused'] = GroupLink('focused', focused, 1)
        ..wantHigh = true
        ..focusedScreen = true;
      media.links['other'] = GroupLink('other', other, 1);
      await media.applyLimits(Quality.balanced);
      expect(focused.camera.parameters.encodings!.single.maxBitrate, 6000000);
      expect(other.camera.parameters.encodings!.single.maxBitrate, 400000);
      expect(
        focused.camera.parameters.encodings!.single.scaleResolutionDownBy,
        1,
      );
      expect(
        focused.camera.parameters.degradationPreference,
        RTCDegradationPreference.MAINTAIN_RESOLUTION,
      );
      expect(
        focused.camera.parameters.encodings!.single.priority,
        RTCPriorityType.high,
      );
      expect(focused.audio.parameters.encodings!.single.maxBitrate, 32000);
      media.sharing = false;
      await media.applyLimits(Quality.balanced);
      expect(focused.camera.parameters.encodings!.single.maxBitrate, 30000);
      expect(focused.camera.parameters.encodings!.single.maxFramerate, 3);
      expect(focused.audio.parameters.encodings!.single.maxBitrate, 32000);
    },
  );
  test('forwarding threshold and screen priority match browser clients', () {
    expect(forwardingEnabled(4), false);
    expect(forwardingEnabled(5), false);
    expect(forwardingEnabled(6), true);
    expect(screenVideoKbps(Quality.balanced, true, true), 6000);
    expect(screenVideoKbps(Quality.balanced, false, true), 400);
    expect(screenVideoKbps(Quality.balanced, false, false), 2000);
    expect(
      screenVideoKbps(const Quality('custom', 480, 15, 128, 24), true, true, 4),
      32,
    );
  });
  test('quiet and speaking cameras retain 480p up to eight attendees', () {
    for (final attendees in [2, 6, 8]) {
      for (final high in [true, false]) {
        final quality = groupCameraQuality(Quality.balanced, attendees, high);
        expect(quality.scale, 1.5);
        expect(quality.fps, 24);
      }
    }
    expect(
      groupCameraQuality(Quality.balanced, 8, false, captureHeight: 480).scale,
      1,
    );
    expect(groupCameraQuality(Quality.balanced, 9, false).scale, 8);
    expect(groupCameraQuality(Quality.balanced, 9, true).scale, 2);
    expect(groupCameraQuality(Quality.balanced, 8, false).scale, 1.5);
  });
  test(
    'balanced group budget scales; explicit custom and saver limits remain',
    () {
      expect(groupVideoKbps(Quality.balanced, 8), 4200);
      expect(groupVideoKbps(Quality.balanced, 2), 1800);
      expect(groupVideoKbps(Quality.balanced, 9), 1800);
      expect(groupVideoKbps(const Quality('custom', 480, 15, 128, 24), 8), 128);
      expect(groupVideoKbps(Quality.saver, 8), 400);
      expect(groupCameraQuality(Quality.saver, 8, false).scale, 4);
      expect(groupCameraQuality(Quality.studio, 8, false).scale, 1.5);
    },
  );
}
