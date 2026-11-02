// Balanced small groups keep every participant legible, including quiet people.
export function smallGroup(p, attendees) {
  return attendees <= 8 && p.preset !== "saver" && p.resolution >= 480;
}
export function groupVideoKbps(p, attendees) {
  return smallGroup(p, attendees) && p.preset === "balanced" && p.video === 1800
    ? Math.max(p.video, 600 * Math.max(1, attendees - 1))
    : p.video;
}
export function cameraQuality(
  p,
  attendees,
  high,
  captureHeight = p.resolution,
) {
  const small = smallGroup(p, attendees);
  const height = Math.min(
    captureHeight,
    small
      ? Math.min(p.resolution, p.preset === "studio" ? 720 : 480)
      : high
        ? captureHeight / (attendees > 5 ? 2 : 1)
        : 90,
  );
  return {
    height,
    fps: Math.min(p.fps, small ? 24 : high ? (attendees > 5 ? 10 : 24) : 3),
    scale: Math.max(1, captureHeight / height),
    small,
  };
}

// Screen text needs source pixels and a larger budget than camera thumbnails.
export function screenVideoKbps(p, focused, anyFocused, recipients = 1) {
  if (p.preset === "custom" || p.preset === "saver")
    return Math.max(16, Math.floor(p.video / Math.max(1, recipients)));
  return focused ? 6000 : anyFocused ? 400 : 2000;
}
export function forwardingEnabled(attendees) {
  return attendees > 5;
}
