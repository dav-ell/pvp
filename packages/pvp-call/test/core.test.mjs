import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MediaController,
  CallRoom,
  createPeerConnection,
  validateSignal,
  PvpMesh,
} from "../src/index.js";
import { requireEncryptedSdp, safetyCode } from "../src/security.js";
import { cameraQuality, groupVideoKbps } from "../src/quality.js";
import { inspectReport } from "../src/inspector.js";
class Stream {
  constructor(tracks = []) {
    this.tracks = tracks;
  }
  getTracks() {
    return [...this.tracks];
  }
  getAudioTracks() {
    return this.tracks.filter((t) => t.kind === "audio");
  }
  getVideoTracks() {
    return this.tracks.filter((t) => t.kind === "video");
  }
  addTrack(t) {
    this.tracks.push(t);
  }
  removeTrack(t) {
    this.tracks = this.tracks.filter((a) => a !== t);
  }
}
const track = (kind) => ({
  kind,
  enabled: true,
  readyState: "live",
  stop() {
    this.readyState = "ended";
  },
  addEventListener() {},
});
const sdp = (n) =>
  "v=0\r\na=fingerprint:sha-256 " +
  Array(32).fill(n).join(":") +
  "\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n";
const candidate = {
  candidate: "candidate:1 1 udp 123 127.0.0.1 5000 typ host",
  sdpMid: "0",
  sdpMLineIndex: 0,
};
test("Import and construction never access devices; capture opens only the requested kind", async () => {
  const calls = [];
  const media = new MediaController({
    Stream,
    capture: async (c) => {
      calls.push(c);
      return new Stream([track(c.audio ? "audio" : "video")]);
    },
  });
  assert.equal(calls.length, 0);
  await media.enable("audio");
  assert.deepEqual(calls, [{ audio: true, video: false }]);
  assert.equal(media.get("video"), null);
  media.stop();
  assert.equal(media.get("audio"), null);
});
test("A late permission result is stopped after leave; parallel device requests are deduplicated", async () => {
  let finish,
    count = 0;
  const t = track("audio");
  const media = new MediaController({
    Stream,
    capture: () => {
      count++;
      return new Promise((r) => (finish = r));
    },
  });
  const one = media.enable("audio"),
    two = media.enable("audio");
  assert.equal(count, 1);
  media.stop();
  finish(new Stream([t]));
  assert.equal(await one, null);
  assert.equal(await two, null);
  assert.equal(t.readyState, "ended");
  assert.equal(media.stream.getTracks().length, 0);
});
test("Camera off releases capture and switching a muted microphone preserves mute", async () => {
  const tracks = [];
  const media = new MediaController({
    Stream,
    capture: async (c) => {
      const t = track(c.audio ? "audio" : "video");
      tracks.push(t);
      return new Stream([t]);
    },
  });
  await media.enable("audio");
  media.mute(true);
  await media.enable("audio", { deviceId: "new" });
  assert.equal(tracks[0].readyState, "ended");
  assert.equal(media.get("audio").enabled, false);
  const camera = await media.enable("video");
  media.disable("video");
  assert.equal(camera.readyState, "ended");
  assert.equal(media.get("video"), null);
  media.stop();
});
test("A late rejected permission prompt cannot cancel a newer device session", async () => {
  let reject;
  let n = 0;
  const media = new MediaController({
    Stream,
    capture: () =>
      ++n === 1
        ? new Promise((_, r) => (reject = r))
        : Promise.resolve(new Stream([track("audio")])),
  });
  const old = media.enable("audio");
  media.stop();
  await media.enable("audio");
  reject(new Error("Old permission denied"));
  assert.equal(await old, null);
  assert.equal(media.get("audio").readyState, "live");
  media.stop();
});
test("Media factory accepts direct STUN and rejects TURN before opening a peer connection", () => {
  class Factory {
    constructor(config) {
      this.config = config;
    }
  }
  assert.equal(
    createPeerConnection({ Factory }).config.bundlePolicy,
    "max-bundle",
  );
  assert.throws(
    () =>
      createPeerConnection({
        Factory,
        iceServers: [{ urls: "turn:relay.example" }],
      }),
    /STUN/,
  );
  assert.throws(
    () =>
      createPeerConnection({
        Factory,
        iceServers: [{ urls: ["stun:good", "turn:bad"] }],
      }),
    /STUN/,
  );
});
test("Encrypted SDP, direct candidates, call epochs and generation bounds are validated", async () => {
  requireEncryptedSdp(sdp("AA"));
  assert.equal((await safetyCode(sdp("AA"), sdp("BB"))).split(" ").length, 6);
  for (const value of [
    sdp("AA").replace("UDP/TLS/RTP/SAVPF", "RTP/AVP"),
    "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n",
    sdp("AA") + "a=crypto:1 inline:key\r\n",
  ])
    assert.throws(() => requireEncryptedSdp(value));
  const p = {
    type: "candidate",
    candidate,
    generation: 1,
    fromEpoch: "epochone1",
    toEpoch: "epochtwo2",
  };
  validateSignal(p);
  assert.throws(() =>
    validateSignal({
      ...p,
      candidate: {
        ...candidate,
        candidate: candidate.candidate.replace("typ host", "typ relay"),
      },
    }),
  );
  assert.throws(() => validateSignal({ ...p, generation: Infinity }));
  assert.throws(() => validateSignal({ ...p, toEpoch: "bad" }));
});
test("Call signaling is bound to roster identity, opt-in, recipients and fresh epochs", () => {
  const packets = [];
  const players = [
    { id: "a", name: "Alice", connected: true },
    { id: "b", name: "Bob", connected: true },
    { id: "c", name: "Offline", connected: false },
  ];
  const room = new CallRoom({
    roster: () => players,
    deliver: (id, event) => packets.push({ id, event }),
  });
  const state = (epoch) => ({
    kind: "state",
    state: { epoch, mic: true, camera: false },
  });
  assert.throws(() => room.receive("c", state("epochc333")));
  assert.throws(() => room.receive("intruder", state("epochx444")));
  room.receive("a", state("epocha111"));
  assert.throws(() =>
    room.receive("a", { kind: "signal", to: "b", signal: {} }),
  );
  room.receive("b", state("epochb222"));
  packets.length = 0;
  const signal = {
    type: "offer",
    sdp: sdp("AA"),
    generation: 1,
    fromEpoch: "epocha111",
    toEpoch: "epochb222",
  };
  room.receive("a", { kind: "signal", to: "b", from: "intruder", signal });
  assert.equal(packets[0].event.from, "a");
  assert.equal(packets[0].id, "b");
  packets.length = 0;
  room.receive("a", {
    kind: "signal",
    to: "b",
    signal: { ...signal, toEpoch: "stale333" },
  });
  assert.equal(packets.length, 0);
  room.receive("b", { kind: "leave" });
  assert.throws(() => room.receive("a", { kind: "signal", to: "b", signal }));
});
test("Room removal updates all connected participants and never exposes arbitrary packet fields", () => {
  const players = [
    { id: "a", name: "Alice", connected: true },
    { id: "b", name: "Bob", connected: true },
  ];
  const events = [];
  const room = new CallRoom({
    roster: () => players,
    deliver: (id, event) => events.push({ id, event }),
    limit: 1,
  });
  room.receive("a", {
    kind: "state",
    state: {
      epoch: "epocha111",
      mic: false,
      camera: false,
      private: "discard",
    },
  });
  assert.throws(
    () =>
      room.receive("b", {
        kind: "state",
        state: { epoch: "epochb222", mic: true, camera: false },
      }),
    /full/,
  );
  assert.equal(room.snapshot().members[0].private, undefined);
  players[0].connected = false;
  room.broadcast();
  assert.equal(room.members.size, 0);
});
test("Reported routes come from actual ICE statistics, never a guessed direct connection", () => {
  const report = inspectReport(new Map(), { connectionState: "connected" });
  assert.equal(report.direct, false);
  assert.equal(report.bytesReceived, null);
  const stats = new Map([
    [
      "t",
      {
        id: "t",
        type: "transport",
        selectedCandidatePairId: "p",
        dtlsState: "connected",
      },
    ],
    [
      "p",
      {
        id: "p",
        type: "candidate-pair",
        state: "succeeded",
        localCandidateId: "l",
        remoteCandidateId: "r",
        bytesReceived: 80,
      },
    ],
    ["l", { id: "l", type: "local-candidate", candidateType: "host" }],
    ["r", { id: "r", type: "remote-candidate", candidateType: "srflx" }],
  ]);
  assert.equal(
    inspectReport(stats, { connectionState: "connected" }).direct,
    true,
  );
});
test("Quality helpers retain small-group camera detail and cap source resolution", () => {
  const p = { preset: "balanced", resolution: 720, fps: 30, video: 1800 };
  assert.equal(cameraQuality(p, 4, false).height, 480);
  assert.equal(cameraQuality(p, 4, true, 360).height, 360);
  assert.equal(groupVideoKbps(p, 4), 1800);
});
test("A closed mesh drops incoming signaling without constructing any RTC connection", async () => {
  class Factory {
    constructor() {
      throw Error("Must not create a connection");
    }
  }
  const mesh = new PvpMesh({
    self: { id: "a", epoch: "epocha111" },
    send: () => {},
    stream: new Stream(),
    Factory,
    Stream,
  });
  mesh.close();
  assert.equal(await mesh.receive("unknown", {}), false);
  mesh.setPeers([]);
});
