# Friends and voice rooms

The browser and Flutter clients share a dark friends-first interface: a near-black sidebar, compact searchable friend rows, online filtering and purple controls. No servers are required. Camera preview lives in browser Call settings.

**Your room** is a permanent sidebar destination, with a voice icon and “Ready when you are” status. Select it whenever you want to hang out with your microphone. Accepted friends see the room in their sidebar and can choose **Join room** without ringing or an invitation. Entering voice is explicit; ordinary online presence never activates a microphone. Camera access is not requested when entering a room. **All calls start with voice**, including direct calls, groups and recurring meetings. Choose **Turn camera on** during a call to opt into video independently of everyone else. Camera access is requested only then. Turning the camera off releases its track. Camera changes keep the microphone, mute state and peer connections intact. Screen sharing also works from a voice-only call and restores the previous camera state when stopped.

A single room lasts until its last participant leaves or disconnects. Leaving does not end the room for others. Each current participant makes the room discoverable to their accepted friends. Joining authorizes a connection to everyone currently in the room, including mutual friends you have not added yourself. The service checks friendship with at least one current participant and the sixteen-person capacity before admission. Room IDs alone do not authorize joining. Discovery returns the room ID and participant count only to accepted friends.

Solo, two-person and group states use the same existing encrypted WebRTC mesh. A video transceiver is negotiated without camera capture: the offerer creates the slot and the answerer binds the offered slot. Camera and screen tracks attach later without a new SDP exchange. Adding a participant creates the missing peer links; departing participants close only their own links. Existing microphone capture and remaining peer connections continue. Initiator ICE trickle can arrive before its offer; the service accepts bounded early candidates without resetting their budget when the offer arrives. The signaling service carries membership and SDP/ICE, not audio. Rooms are ephemeral and disappear on service restart. Existing video calls and recurring meetings retain their protocols.

The server advertises `voiceRooms: true` in its capability message. Updated clients disable joining voice against older services.

New signaling messages are `voice-open` and `voice-join` (`room_id`). Room snapshots include `voice`; accepted friend responses include nullable `voice_room` (`room_id`, `participants`). Existing clients ignore these additive fields. Voice rooms use discovery admission rather than legacy ringing invitations.

Validation:

- `cargo test --manifest-path signaling/Cargo.toml`: authorization, consent, room lifetime and existing signaling regression tests.
- `npm run test:voice`: three real browsers, microphone-only capture, friend discovery, direct peer connections, room growth and return to solo, camera denial, opt-in video, mute preservation and final track cleanup.
- `npm run test:voice:native`: compiled Flutter client with two real browser peers and native WebRTC audio reception and subsequent browser video opt-in on the same peer connections. Native capture is injected with an empty stream so this test does not access physical devices; browser audio uses generated tracks.
- Flutter analysis, unit/layout tests, browser regressions and group regressions cover the shared UI and existing calls.

Deployed on October 12, 2026: signaling/browser 0.3.13 and Mac 1.0.14+15. The public HTTPS voice-room test passed with three browser peers and opted-in video. The signed universal Mac app is published at `/downloads/PVP-macOS-1.0.14.zip` and installed locally. See `voice-release.json` for validation, artifact hashes and rollback locations. Local test screenshots are under `docs/screenshots/friends-discord-web.png` and `docs/screenshots/voice-room-web.png`.

A separate local Mac preview is packaged at `dist/PVP-voice-preview.zip`. It is locally ad-hoc signed; it is not a notarized public release. The public deployment uses the versioned signed release rather than this ad-hoc preview.

October 13 follow-up: signaling/browser 0.3.14 and Mac 1.0.15+16 present **Your room** as a standing destination with a voice icon and “Ready when you are” status. The joined personal stage keeps that name. Both versions are deployed; the Mac app is installed and published. See `your-room-release.json` for hashes, checks and rollback locations.
