// A negotiated camera track may exist before it has ever sent a frame. Keeping
// sound in its own audio-only element lets it start while that video waits.
export class RemotePlayback {
  constructor(video, onBlocked = () => {}) {
    this.video = video;
    this.onBlocked = onBlocked;
    this.blocked = false;
    this.closed = false;
    this.stream = new MediaStream();
    this.audio = document.createElement('audio');
    this.audio.id = video.id.replace('video', 'audio');
    this.audio.autoplay = true;
    this.audio.hidden = true;
    this.video.muted = true;
    this.video.after(this.audio);
    this.playing = () => this.setBlocked(false);
    this.audio.addEventListener('playing', this.playing);
  }
  setBlocked(blocked) {
    if (this.closed || this.blocked === blocked) return;
    this.blocked = blocked;
    this.onBlocked(blocked);
  }
  attach(remote) {
    if (this.closed) return;
    const tracks = remote.getAudioTracks().filter(track => track.readyState !== 'ended');
    for (const old of this.stream.getTracks()) if (!tracks.includes(old)) this.stream.removeTrack(old);
    for (const track of tracks) if (!this.stream.getTracks().includes(track)) this.stream.addTrack(track);
    if (this.audio.srcObject !== this.stream) this.audio.srcObject = this.stream;
    if (this.video.srcObject !== remote) this.video.srcObject = remote;
  }
  async play() {
    if (this.closed) return;
    // Video playback can remain pending until the camera is enabled. Never
    // await it before starting sound, and never play audio through both sinks.
    if (this.video.srcObject) this.video.play().catch(() => {});
    if (!this.stream.getAudioTracks().length) return;
    try {
      await this.audio.play();
      this.setBlocked(false);
    } catch (error) {
      if (error.name !== 'AbortError') this.setBlocked(true);
    }
  }
  dispose() {
    this.closed = true;
    this.audio.removeEventListener('playing', this.playing);
    this.audio.pause();
    this.audio.srcObject = null;
    this.audio.remove();
    this.video.pause();
    this.video.srcObject = null;
    for (const track of this.stream.getTracks()) this.stream.removeTrack(track);
  }
}
