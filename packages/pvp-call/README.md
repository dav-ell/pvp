# PVP Call

An Apache-2.0, framework-independent browser calling library extracted from PVP.
It has no runtime dependencies, DOM selectors, account system, signaling server,
analytics, or automatic device access. Applications supply authenticated room
membership and signaling; encrypted audio/video travels directly between peers.

This source package is not published to the npm registry. Install from a checkout
(`npm install /path/to/pvp/packages/pvp-call`) or distribute an archive made with
`npm pack` in this directory. ESM source works directly in modern bundlers.

## Application integration

```js
import { MediaController, PvpMesh } from "@dav-ell/pvp-call";

const media = new MediaController({
  changed: () => mesh?.updateStream(media.stream),
});
let mesh;

// Run only from the user's Join voice gesture. Camera remains closed.
async function joinVoice(authenticatedSelf, joinedParticipants) {
  await media.enable("audio", {
    echoCancellation: true,
    noiseSuppression: true,
    autoGainControl: true,
  });
  mesh = new PvpMesh({
    self: { id: authenticatedSelf.id, epoch: crypto.randomUUID() },
    stream: media.stream,
    send: (to, signal) => signaling.send({ to, signal }),
    onStream: (id, stream) => attachRemoteMedia(id, stream),
    onChange: () => renderParticipants(mesh.links),
    onError: (error) => showConnectionError(error.message),
  });
  // Publish self.epoch in the application's authenticated call roster first.
  publishCallState({ epoch: mesh.self.epoch, mic: true, camera: false });
  mesh.setPeers(joinedParticipants);
}

// Each participant is { id, epoch }. Identity comes from trusted signaling.
async function receiveSignal(authenticatedFrom, signal) {
  try {
    await mesh?.receive(authenticatedFrom, signal);
  } catch (error) {
    showConnectionError(error.message);
  }
}

// Optional video, from a separate explicit camera gesture.
await media.enable("video", { width: { ideal: 854 }, height: { ideal: 480 } });
publishCallState({ epoch: mesh.self.epoch, mic: true, camera: true });

media.mute(true); // Silence outgoing audio, retain the microphone.
media.disable("video"); // Stop and release the camera immediately.
publishCallState({ epoch: mesh.self.epoch, mic: false, camera: false });

mesh.close(); // Close connections, channels, and retry timers.
media.stop(); // Stop every captured device and invalidate prompts.
```

A listen-only client can create the mesh with an empty `media.stream`, without
calling `enable`. It receives audio/video and can opt into a microphone later.
Stop both the mesh and media on room changes, sign-out, page exit, and explicit
leave. Do not automatically recapture devices after a page reload.

Attach remote audio to an unmuted `<audio>` element. Keep camera previews muted
to avoid playing the same audio twice. Handle rejected `play()` promises with a
user-operated playback button. Hide remote camera elements when the trusted call
state says camera off; a stopped sender can otherwise leave a frozen last frame.

## API and responsibilities

- `MediaController`: `stream`, `get(kind)`, `enable(kind, constraints)`,
  `mute(boolean)`, `disable(kind)`, `stop()`. Pending prompts are invalidated and
  late results are stopped. Duplicate captures are coalesced. Device replacements
  preserve microphone mute state. Constructor injection supports capture tests.
- `PvpMesh`: `setPeers([{id, epoch}])`, `receive(from, signal)`,
  `updateStream(stream)`, `presence(speaking)`, `sample()`, `retry(id, 0)`, `close()`.
  `links` contains peer connections, remote streams, measured route evidence,
  pair certificate codes, and errors. Applications own rendering and playback.
- `CallRoom`: optional signaling-only helper for an authenticated application
  server or host. Supply `roster()` with authorized `{id,name,connected}` members
  and `deliver(id,event)`. Call `receive(authenticatedId, packet)`; never derive
  that first argument from the client's claimed sender. Supported packets are
  `state`, `sync`, `leave`, and `signal`. `state` contains `{epoch,mic,camera}`.
  Signals require both opted-in members and matching fresh epochs.
- `createPeerConnection`, `requireEncryptedSdp`, `requireCandidate`, and
  `safetyCode`: extracted direct-transport and certificate checks.
- `./quality` and `./inspector`: PVP's established quality helpers and measured
  WebRTC statistics, with the existing exports preserved.

The default maximum is 16 participants; configure smaller room limits as needed.
A direct mesh sends to every other participant, so small rooms are the best fit.
The existing PVP app keeps its native compatibility, signed frame forwarding,
screen sharing, meeting moderation, and chat outside this core. Those features
are not silently claimed by the reusable mesh's different signaling envelope.

## Direct connection policy

SDP must use DTLS-SRTP/SCTP and valid SHA-256 certificate fingerprints. Relay
candidates and TURN configuration are rejected. Selected ICE statistics are also
checked for relays. The app must exchange signaling over its authenticated,
secure transport and preserve trusted sender identity. A random per-join epoch
rejects stale messages after a leave/rejoin. Certificate pair codes can be shown
for users to compare through another trusted channel.

Some NAT/firewall combinations cannot establish direct connections; report that
failure instead of claiming that media is connected or silently relaying it.
The generic core does not authenticate accounts or replace your server's room
authorization. It never receives a room password or account credential.

## Tests and PVP migration

```sh
npm ci
npx playwright-core install chromium   # or set CHROME_PATH to installed Chrome
npm test
```

The standalone suite tests capture cancellation, mute/device replacement,
encrypted negotiation, direct-only ICE, membership/epoch authorization, quality,
route evidence, and real four-party audio/video in Chromium. It runs without the
PVP account server, native application, or any external signaling service.

The repository's `web/security.js`, `web/group-quality.js`, and `web/inspector.js`
remain compatibility entry points. `adapters/pvp-web.patch` wires the current
modern PVP browser client and Rust asset routes to this package. That browser
client currently exists as uncommitted application work in the working checkout;
the isolated library PR deliberately does not publish its unrelated native,
deployment, and release work. Check the patch before applying it to a matching
browser-client checkout:

```sh
git apply --check packages/pvp-call/adapters/pvp-web.patch
git apply packages/pvp-call/adapters/pvp-web.patch
```

The patch changes peer-connection construction and static module serving; it
preserves PVP's existing room protocol, forwarding, UI, and native interoperability.
Its local four-participant group integration test passes after migration.

References: [WebRTC transceivers](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/addTransceiver),
[track replacement](https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpSender/replaceTrack),
[WebRTC specification](https://www.w3.org/TR/webrtc/).
