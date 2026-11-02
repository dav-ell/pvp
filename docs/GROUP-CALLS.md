# P2P group calls

PVP 1.0.5 supports rooms of up to 16 participants across browsers and the Mac app. Select **Group call**, choose accepted friends, and start the call. Invitees see the room roster before joining or opening their camera/microphone. Participants can invite their own accepted friends, mute, pause video, share a screen, change quality, and leave independently. Invitations expire after two minutes. Removing a friend revokes their pending invitation and leaves any room that you both joined.

The Mac app receives invitations through its existing menu-bar/background connection and native notification controls. A browser must remain open and connected; browser audio/autoplay restrictions may require a click. Older dedicated apps keep their existing one-to-one protocol and do not receive group invitations. New clients only enable group calling after the server advertises support.

## Media paths

Every joined participant has a direct WebRTC connection to every other participant. Audio uses those direct encrypted RTP links. Group membership, offers, answers, and ICE candidates pass through the signaling service; media does not pass through the VM.

In rooms with more than five joined participants, a browser with VP8 WebCodecs support can encode its camera video once and distribute encrypted frames through participant data channels. Each source has a deterministic tree with at most four children per node and at most two hops for 16 members. Different sources have different trees. Intermediate participants forward the source ciphertext. The Mac app can forward those opaque packets too.

Browser receivers display verified and decrypted frames through WebCodecs. Native receivers, and browsers without the necessary encoder/decoder support, receive ordinary direct WebRTC video. **Native-origin video currently uses direct RTP to each receiver.** Thus the four-child rule applies to forwarded browser video, not to native-origin or fallback RTP. All-native rooms use the direct mesh. Mixed rooms can use both paths simultaneously.

When a browser confirms that it decoded forwarded video, the source stops that receiver's duplicate direct video. If forwarded video stops arriving, direct video resumes. Removing a participant recalculates trees and rotates browser-source media keys. Losing the signaling connection ends that client's room membership; joining again requires a new invitation. There is no media server, TURN fallback, or persistent room history.

This reduces a browser source's video encoding/upload work by distributing forwarding among participants. It does not eliminate the group's aggregate traffic, or the full mesh of audio/control connections. A participant forwards other sources as well as publishing its own. Sixteen simultaneous high-resolution videos are not a guaranteed operating mode.

## Quality and resource limits

The existing Saver, Balanced, and Studio presets provide room video payload targets of 0.4, 1.8, and 4 Mbps. They are aggregate outgoing video targets for a participant, rather than per-recipient limits. Audio has a separate per-peer target, capped at 32 kbps. Packet overhead, retransmissions, congestion control, and encoder bursts mean these are not strict interface byte ceilings.

Browser forwarding reserves part of its budget for compatibility RTP and part for encoded packets. Camera forwarding is reduced while screens are shared; screen shares themselves use direct RTP. Active speakers and pinned browser tiles request higher video quality; idle camera video uses low-frame-rate thumbnails. Native RTP similarly reduces inactive video and promotes speaking, sharing, or browser-requested video. Camera pause stops outgoing video; microphone mute preserves the captured microphone for later unmute. Speaker selection has a short hold to avoid rapid quality changes.

Encoded packets are small, unordered, and non-retransmitted. Queues, pending crypto work, assembly memory, packet rates, frame sizes, and forwarding bytes are bounded. Congestion can drop frames and trigger direct-video recovery. Trees are deterministic, not selected by measured WAN latency or forwarding capacity; redundancy and capacity-aware routing remain future improvements.

## Encryption and trust

Ordinary audio/video uses WebRTC DTLS-SRTP. Data channels use DTLS-protected SCTP. The clients reject plaintext/SDES media negotiation and relay ICE candidates. STUN assists discovery and does not carry the call media. Networks that cannot establish direct peer links can fail to connect; this implementation does not disguise server relaying as P2P.

Forwarded browser video has an additional AES-256-GCM encryption layer and an ECDSA P-256 source signature covering metadata, nonce, and ciphertext. A source distributes its key and verification public key through its own direct encrypted control connections to admitted participants. Relays cannot alter a frame into an authenticated frame from another source. Receivers validate room, roster revision, expected tree parent, bounded chunk metadata, signature, authenticated encryption, and monotonically increasing sequence numbers. Fresh keys/nonces are installed atomically on roster changes before sending resumes; old decoder/key state is discarded. Exports exclude keys, session cookies, and media content.

This is an application-specific encoded-frame protocol, not an implementation of MLS or SFrame. Pair certificate codes can be compared out of band. Account authentication, membership, and certificate negotiation still depend on the signaling service; durable identity-key pinning and protection against a malicious signaling operator are not claimed. Admitted participants can receive/record content and can disrupt forwarding. Peer addresses and traffic metadata remain visible to peers.

## Screen sharing and connection recovery

Calls of five or fewer people use direct RTP video only. Forwarding stops when a room drops back to five participants. Screen shares always use direct RTP at the capture resolution, with resolution preserved during bandwidth adaptation and a 15 fps cap. Both clients offer **Maximize** and **Restore** controls. Balanced and studio screen shares use 2 Mbps per viewer; a maximized viewer receives up to 6 Mbps while other viewers receive up to 400 Kbps. Cameras sent to a viewer focused on a screen are capped at 30 Kbps. Explicit saver/custom budgets still apply. These are encoder ceilings, not guaranteed network throughput.

Both clients serialize room negotiation and retain early ICE candidates until the matching offer/generation arrives. Failed, persistently disconnected, and stalled initial connections trigger pair recovery. Native receivers also accept audio/video tracks without an associated stream. Direct-only networking still cannot connect every cellular NAT/firewall combination; a connected participant is not evidence that every pair is reachable.

## Connection evidence

Each tile's **Connection** control displays actual selected ICE candidates, addresses/ports where the engine exposes them, DTLS/SRTP ciphers, byte counters, and the pair certificate code. The Direct label includes encoded frames delivered by their original source; Peer-forwarded video requires an intermediate participant. Browser reports identify a video's source and immediate forwarding participant separately from its direct audio link. Native reports include opaque forwarding counters. Group exports contain all peer observations with sample times. Missing or stale observations remain unverified. Browsers may hide addresses; PVP does not invent them.

These are engine/application observations, not independent packet captures or tamper-proof attestation. The generated tcpdump filter is based only on valid observed IPs/ports. External tcpdump/Wireshark can corroborate transport endpoints, while encrypted captures cannot independently identify a particular video source without application context.

## Validation and release

Automated experiments use real WebRTC connections with synthetic video/audio sources, avoiding capture of unrelated desktop content:

- A two-hop browser prototype encodes VP8, encrypts/signs it, forwards through real data channels, and verifies decoded source pixels.
- Sixteen-browser tests exercise all 240 peer-connection endpoints, incoming encrypted audio on every peer link, decoded forwarded source pixels, second-hop packets, inspector exports, deliberate ciphertext tampering/recovery, screen sharing with microphone mute preserved, key/tree changes after a forwarder leaves, and full teardown.
- Sixteen-browser compatibility tests disable WebCodecs and exercise direct audio/video, screen sharing, exports, and teardown.
- Signed Mac integration joins one native client with five browser clients, verifies five incoming encrypted media streams, and verifies browser video forwarded through the Mac app to a second-hop browser by decoded pixels.
- Existing browser, native, server, and screen-sharing checks cover the preceding one-to-one behavior. New tests cover group admission, the 16-person limit, scoped/encrypted signaling, friend-removal revocation, and cancellation before capture.

These are local interoperability tests, not a 16-device Internet benchmark. Native hardware outgoing microphone/camera/screen capture and a 16-native-device call were not exercised. Safari/Firefox and physical devices across different NATs require field validation; unsupported WebCodecs clients have a direct WebRTC fallback.

Run `npm run test:groups:16`, `PVP_GROUP_TEST_SIZE=16 PVP_GROUP_DISABLE_ALL=1 npm run test:groups`, and `npm run test:groups:native` (the native integration needs a signing identity/team). Server and Flutter test commands remain unchanged. The browser forwarding experiment is `node scripts/experiment-browser-forwarding.mjs`.

Package: [PVP-macOS-1.0.5.zip](../dist/PVP-macOS-1.0.5.zip). This is a development-signed, hardened, universal Mac package; it is not notarized. The corresponding signaling version is 0.3.4. Prior packages remain available. See [release manifest](group-calls-release.json) for checksums and the actual installed/production status. The deployment procedure backs up the database/binary and defers service replacement while signaling WebSockets are active, preserving current sessions and older dedicated apps.

Current release: [Mac 1.0.13 download](https://lopixel.space/downloads/PVP-macOS-1.0.13.zip), signaling/browser 0.3.12. See the [October 6 media-fix release record](group-video-fix-release.json) for current validation and deployment status.
