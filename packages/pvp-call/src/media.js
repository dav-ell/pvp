// Device access belongs to explicit application gestures, never construction.
export class MediaController {
  constructor({
    capture = (constraints) => navigator.mediaDevices.getUserMedia(constraints),
    Stream = globalThis.MediaStream,
    changed = () => {},
  } = {}) {
    this.capture = capture;
    this.stream = new Stream();
    this.changed = changed;
    this.version = 0;
    this.pending = new Map();
    this.requests = new Map();
  }
  get(kind) {
    return (
      this.stream
        .getTracks()
        .find((t) => t.kind === kind && t.readyState === "live") || null
    );
  }
  async enable(kind, constraints = true) {
    if (!["audio", "video"].includes(kind)) throw Error("Unknown media kind.");
    if (this.pending.has(kind)) return this.pending.get(kind);
    const version = this.version,
      request = (this.requests.get(kind) || 0) + 1;
    this.requests.set(kind, request);
    const task = (async () => {
      let captured;
      try {
        captured = await this.capture({
          audio: false,
          video: false,
          [kind]: constraints,
        });
      } catch (error) {
        if (version !== this.version || this.requests.get(kind) !== request)
          return null;
        throw error;
      }
      const next = captured
        .getTracks()
        .find((t) => t.kind === kind && t.readyState === "live");
      if (version !== this.version || this.requests.get(kind) !== request) {
        captured.getTracks().forEach((t) => t.stop());
        return null;
      }
      if (!next) {
        captured.getTracks().forEach((t) => t.stop());
        throw Error(
          `No ${kind === "audio" ? "microphone" : "camera"} was opened.`,
        );
      }
      const previous = this.get(kind);
      next.enabled = previous ? previous.enabled : true;
      captured
        .getTracks()
        .filter((t) => t !== next)
        .forEach((t) => t.stop());
      if (previous) {
        this.stream.removeTrack(previous);
        previous.stop();
      }
      this.stream.addTrack(next);
      next.addEventListener?.(
        "ended",
        () => {
          if (this.get(kind) !== next && next.readyState !== "ended") return;
          if (this.stream.getTracks().includes(next)) {
            this.stream.removeTrack(next);
            this.changed(this.stream);
          }
        },
        { once: true },
      );
      this.changed(this.stream);
      return next;
    })();
    this.pending.set(kind, task);
    try {
      return await task;
    } finally {
      if (this.pending.get(kind) === task) this.pending.delete(kind);
    }
  }
  mute(muted) {
    const audio = this.get("audio");
    if (audio) audio.enabled = !muted;
    this.changed(this.stream);
  }
  disable(kind) {
    this.requests.set(kind, (this.requests.get(kind) || 0) + 1);
    this.pending.delete(kind);
    for (const track of this.stream
      .getTracks()
      .filter((t) => t.kind === kind)) {
      this.stream.removeTrack(track);
      track.stop();
    }
    this.changed(this.stream);
  }
  stop() {
    this.version++;
    this.pending.clear();
    for (const track of this.stream.getTracks()) {
      this.stream.removeTrack(track);
      track.stop();
    }
    this.changed(this.stream);
  }
}
