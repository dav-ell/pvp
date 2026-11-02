import 'dart:math';
import 'models.dart';

bool smallGroupQuality(Quality q, int attendees) =>
    attendees <= 8 && q.preset != 'saver' && q.height >= 480;

int groupVideoKbps(Quality q, int attendees) =>
    smallGroupQuality(q, attendees) &&
        q.preset == 'balanced' &&
        q.videoKbps == 1800
    ? max(q.videoKbps, 600 * max(1, attendees - 1))
    : q.videoKbps;

({double scale, int fps, bool small}) groupCameraQuality(
  Quality q,
  int attendees,
  bool high, {
  int? captureHeight,
}) {
  final small = smallGroupQuality(q, attendees);
  final sourceHeight = captureHeight ?? q.height;
  final height = small
      ? min(
          sourceHeight,
          min(q.height, q.preset == 'studio' ? 720 : 480),
        ).toDouble()
      : high
      ? sourceHeight / (attendees > 5 ? 2 : 1)
      : 90.0;
  return (
    scale: max(1.0, sourceHeight / height),
    fps: min(
      q.fps,
      small
          ? 24
          : high
          ? (attendees > 5 ? 10 : 24)
          : 3,
    ),
    small: small,
  );
}

bool forwardingEnabled(int attendees) => attendees > 5;

int screenVideoKbps(
  Quality q,
  bool focused,
  bool anyFocused, [
  int recipients = 1,
]) {
  if (q.preset == 'custom' || q.preset == 'saver') {
    return max(16, q.videoKbps ~/ max(1, recipients));
  }
  return focused ? 6000 : (anyFocused ? 400 : 2000);
}
