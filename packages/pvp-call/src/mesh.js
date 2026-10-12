import {
  requireEncryptedSdp,
  requireCandidate,
  isRelay,
  safetyCode,
} from "./security.js";
import { inspectReport } from "./inspector.js";
import { cameraQuality, groupVideoKbps } from "./quality.js";

export const DEFAULT_ICE_SERVERS = Object.freeze([
  { urls: ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"] },
]);
export function createPeerConnection({
  iceServers = DEFAULT_ICE_SERVERS,
  Factory = globalThis.RTCPeerConnection,
} = {}) {
  // This library deliberately preserves PVP's direct-only media policy.
  if (
    !Array.isArray(iceServers) ||
    iceServers.some(
      (s) =>
        !s ||
        !(Array.isArray(s.urls) ? s.urls : [s.urls]).every(
          (u) => typeof u === "string" && /^stuns?:/.test(u),
        ),
    )
  )
    throw Error("PVP media requires STUN-only ICE servers.");
  return new Factory({ iceServers, bundlePolicy: "max-bundle" });
}
export function validateSignal(p) {
  if (
    !p ||
    !Number.isInteger(p.generation) ||
    p.generation < 1 ||
    p.generation > 10000 ||
    !/^[a-zA-Z0-9_-]{8,100}$/.test(p.fromEpoch || "") ||
    !/^[a-zA-Z0-9_-]{8,100}$/.test(p.toEpoch || "")
  )
    throw Error("Invalid call generation.");
  if (p.type === "offer" || p.type === "answer") requireEncryptedSdp(p.sdp);
  else if (p.type === "candidate") requireCandidate(p.candidate);
  else if (p.type !== "retry") throw Error("Invalid call signal.");
  return p;
}

// The application authenticates membership and transports signaling. Media goes
// straight between these peer connections; no global DOM, accounts or server.
export class PvpMesh {
  constructor({
    self,
    send,
    stream,
    onChange = () => {},
    onStream = () => {},
    onError = () => {},
    preferences,
    iceServers,
    Factory,
    Stream = globalThis.MediaStream,
  }) {
    if (!self?.id || !self.epoch || typeof send !== "function")
      throw Error("A self identity and signaling transport are required.");
    Object.assign(this, {
      self,
      send,
      stream,
      onChange,
      onStream,
      onError,
      iceServers,
      Factory,
      Stream,
    });
    this.preferences = preferences || {
      preset: "balanced",
      resolution: 480,
      fps: 24,
      video: 1800,
      audio: 48,
    };
    this.peers = new Map();
    this.links = new Map();
    this.closed = false;
  }
  setPeers(peers) {
    if (this.closed) return;
    if (
      !Array.isArray(peers) ||
      peers.length > 16 ||
      new Set(peers.map((p) => p.id)).size !== peers.length ||
      peers.some((p) => !p.id || !/^[a-zA-Z0-9_-]{8,100}$/.test(p.epoch || ""))
    )
      throw Error("Invalid call membership.");
    const next = new Map(
      peers.filter((p) => p.id !== this.self.id).map((p) => [p.id, p]),
    );
    for (const [id, link] of this.links)
      if (!next.has(id) || next.get(id).epoch !== link.peer.epoch)
        this.closeLink(id);
    this.peers = next;
    for (const peer of next.values())
      if (!this.links.has(peer.id)) {
        const link = this.createLink(peer, 1);
        if (this.self.id < peer.id)
          this.offer(link).catch((e) => this.failure(link, e));
      }
    this.notify();
  }
  valid(link) {
    return (
      !this.closed &&
      this.links.get(link.peer.id) === link &&
      this.peers.get(link.peer.id)?.epoch === link.peer.epoch
    );
  }
  notify() {
    if (!this.closed) this.onChange(this);
  }
  createLink(peer, generation) {
    const pc = createPeerConnection({
      iceServers: this.iceServers,
      Factory: this.Factory,
    });
    const link = {
      peer,
      pc,
      generation,
      remote: new this.Stream(),
      chain: Promise.resolve(),
      candidates: [],
      failures: 0,
      speaking: false,
      error: null,
    };
    this.links.set(peer.id, link);
    pc.onicecandidate = ({ candidate }) => {
      if (!this.valid(link) || !candidate || isRelay(candidate.candidate))
        return;
      try {
        const c = candidate.toJSON();
        requireCandidate(c);
        this.signal(link, { type: "candidate", candidate: c });
      } catch (e) {
        this.failure(link, e);
      }
    };
    pc.ontrack = ({ track }) => {
      if (!this.valid(link)) return;
      if (!link.remote.getTracks().includes(track)) link.remote.addTrack(track);
      this.onStream(peer.id, link.remote);
      this.notify();
    };
    pc.onconnectionstatechange = () => {
      if (!this.valid(link)) return;
      if (pc.connectionState === "connected") {
        link.error = null;
        link.failing = false;
        link.failures = 0;
        clearTimeout(link.deadline);
        clearTimeout(link.retry);
        link.retry = null;
      }
      if (pc.connectionState === "disconnected") {
        clearTimeout(link.retry);
        link.retry = setTimeout(() => {
          if (this.valid(link) && pc.connectionState === "disconnected")
            this.failure(link, Error("Peer disconnected."));
        }, 8000);
      }
      if (pc.connectionState === "failed")
        this.failure(
          link,
          Error("A direct connection could not be established."),
        );
      this.notify();
    };
    pc.ondatachannel = ({ channel }) => this.channel(link, channel);
    link.deadline = setTimeout(() => {
      if (this.valid(link) && pc.connectionState !== "connected")
        this.failure(link, Error("Direct peer connection timed out."));
    }, 20000);
    return link;
  }
  signal(link, value) {
    if (this.valid(link))
      this.send(link.peer.id, {
        ...value,
        generation: link.generation,
        fromEpoch: this.self.epoch,
        toEpoch: link.peer.epoch,
      });
  }
  async attach(link) {
    for (const tx of link.pc.getTransceivers()) {
      if (!["audio", "video"].includes(tx.receiver.track.kind)) continue;
      tx.direction = "sendrecv";
      const track =
        this.stream
          ?.getTracks()
          .find(
            (t) => t.kind === tx.receiver.track.kind && t.readyState === "live",
          ) || null;
      if (tx.sender.track !== track) await tx.sender.replaceTrack(track);
    }
  }
  async offer(link) {
    if (!this.valid(link)) return;
    for (const kind of ["audio", "video"])
      link.pc.addTransceiver(kind, {
        direction: "sendrecv",
        streams: [this.stream],
      });
    this.channel(link, link.pc.createDataChannel("pvp-presence"));
    await this.attach(link);
    const offer = await link.pc.createOffer();
    requireEncryptedSdp(offer.sdp);
    if (!this.valid(link)) return;
    await link.pc.setLocalDescription(offer);
    this.signal(link, { type: "offer", sdp: link.pc.localDescription.sdp });
  }
  receive(from, payload) {
    if (this.closed || !this.peers.has(from)) return Promise.resolve(false);
    validateSignal(payload);
    const peer = this.peers.get(from);
    if (payload.fromEpoch !== peer.epoch || payload.toEpoch !== this.self.epoch)
      return Promise.resolve(false);
    let link = this.links.get(from);
    if (payload.type === "retry") {
      if (this.self.id < from) this.retry(from, (link?.failures || 0) + 1);
      return Promise.resolve(true);
    }
    if (
      payload.type === "candidate" &&
      link &&
      payload.generation === link.generation + 1
    ) {
      link.future ||= [];
      if (link.future.length >= 64)
        throw Error("Too many early ICE candidates.");
      link.future.push(payload.candidate);
      return Promise.resolve(true);
    }
    if (
      payload.type === "offer" &&
      (!link || payload.generation > link.generation)
    ) {
      const early =
        payload.generation === link?.generation + 1 ? link.future || [] : [];
      this.closeLink(from);
      link = this.createLink(peer, payload.generation);
      link.candidates = early;
    }
    if (!link || payload.generation !== link.generation)
      return Promise.resolve(false);
    link.chain = link.chain
      .then(async () => {
        if (!this.valid(link)) return false;
        if (payload.type === "candidate") {
          if (link.pc.remoteDescription)
            await link.pc.addIceCandidate(payload.candidate);
          else {
            if (link.candidates.length >= 64)
              throw Error("Too many early ICE candidates.");
            link.candidates.push(payload.candidate);
          }
          return true;
        }
        await link.pc.setRemoteDescription({
          type: payload.type,
          sdp: payload.sdp,
        });
        for (const candidate of link.candidates.splice(0))
          await link.pc.addIceCandidate(candidate);
        await this.attach(link);
        if (payload.type === "offer") {
          const answer = await link.pc.createAnswer();
          requireEncryptedSdp(answer.sdp);
          await link.pc.setLocalDescription(answer);
          this.signal(link, {
            type: "answer",
            sdp: link.pc.localDescription.sdp,
          });
        }
        link.code = await safetyCode(
          link.pc.localDescription.sdp,
          link.pc.remoteDescription.sdp,
        );
        await this.limits(link);
        this.notify();
        return true;
      })
      .catch((e) => {
        this.failure(link, e);
        return false;
      });
    return link.chain;
  }
  channel(link, channel) {
    if (channel.label !== "pvp-presence") {
      channel.close();
      return;
    }
    link.control = channel;
    channel.onmessage = ({ data }) => {
      if (!this.valid(link) || typeof data !== "string" || data.length > 512)
        return;
      try {
        const state = JSON.parse(data);
        if (
          state.type === "presence" &&
          typeof state.speaking === "boolean" &&
          link.speaking !== state.speaking
        ) {
          link.speaking = state.speaking;
          this.notify();
        }
      } catch {}
    };
    channel.onopen = () => this.notify();
  }
  presence(speaking) {
    for (const link of this.links.values())
      if (
        link.control?.readyState === "open" &&
        link.control.bufferedAmount < 4096
      )
        link.control.send(
          JSON.stringify({ type: "presence", speaking: !!speaking }),
        );
  }
  async updateStream(stream = this.stream) {
    this.stream = stream;
    await Promise.all(
      [...this.links.values()].map(async (l) => {
        if (this.valid(l)) {
          try {
            await this.attach(l);
            await this.limits(l);
          } catch (e) {
            this.failure(l, e);
          }
        }
      }),
    );
    this.notify();
  }
  async limits(link) {
    if (!this.valid(link) || link.pc.signalingState !== "stable") return;
    const quality = cameraQuality(
      this.preferences,
      this.peers.size + 1,
      true,
      this.stream?.getVideoTracks()[0]?.getSettings().height ||
        this.preferences.resolution,
    );
    for (const sender of link.pc.getSenders()) {
      if (!sender.track) continue;
      const p = sender.getParameters();
      p.encodings ||= [{}];
      for (const e of p.encodings) {
        e.maxBitrate = Math.floor(
          1000 *
            (sender.track.kind === "audio"
              ? this.preferences.audio
              : groupVideoKbps(this.preferences, this.peers.size + 1) /
                Math.max(1, this.peers.size)),
        );
        if (sender.track.kind === "video") {
          e.maxFramerate = quality.fps;
          e.scaleResolutionDownBy = quality.scale;
        }
      }
      try {
        await sender.setParameters(p);
      } catch {
        /* Browser-specific encoder constraints are best effort. */
      }
    }
  }
  async sample() {
    for (const link of this.links.values()) {
      if (!this.valid(link)) continue;
      try {
        const reports = await link.pc.getStats();
        if (!this.valid(link)) continue;
        link.evidence = inspectReport(reports, {
          connectionState: link.pc.connectionState,
          iceState: link.pc.iceConnectionState,
        });
        if (link.evidence.relayed) {
          this.closeLink(link.peer.id);
          this.onError(Error("A media relay was rejected."));
        }
      } catch {
        /* Closing connections may reject getStats. */
      }
    }
    this.notify();
  }
  failure(link, error) {
    if (!this.valid(link) || link.failing) return;
    link.failing = true;
    link.error = error.message;
    link.speaking = false;
    clearTimeout(link.deadline);
    clearTimeout(link.retry);
    const n = (link.failures || 0) + 1;
    link.failures = n;
    if (n <= 3)
      link.retry = setTimeout(() => {
        if (this.valid(link)) this.retry(link.peer.id, n);
      }, 1200 * n);
    else this.onError(error);
    this.notify();
  }
  retry(id, failures = 0) {
    const peer = this.peers.get(id),
      old = this.links.get(id);
    if (!peer || this.closed) return;
    if (failures > 3) {
      if (old) {
        old.error = "Direct peer connection failed. Try another network.";
        this.onError(Error(old.error));
        this.notify();
      }
      return;
    }
    if (this.self.id > id) {
      if (old) {
        old.failing = false;
        this.signal(old, { type: "retry" });
      }
      return;
    }
    const generation = (old?.generation || 0) + 1;
    this.closeLink(id);
    const next = this.createLink(peer, generation);
    next.failures = failures;
    this.offer(next).catch((e) => this.failure(next, e));
    this.notify();
  }
  closeLink(id) {
    const link = this.links.get(id);
    if (!link) return;
    this.links.delete(id);
    clearTimeout(link.retry);
    clearTimeout(link.deadline);
    link.pc.ontrack = null;
    link.pc.onconnectionstatechange = null;
    link.pc.onicecandidate = null;
    link.control?.close();
    link.pc.close();
    this.onStream(id, null);
  }
  close() {
    this.closed = true;
    for (const id of [...this.links.keys()]) this.closeLink(id);
    this.peers.clear();
  }
}
