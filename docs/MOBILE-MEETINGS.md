# Mobile meeting entry

The browser now gives existing `#meeting=…` links a dedicated invitation screen. Signed-in members and accountless guests use the same entry choices. Public metadata remains limited to the meeting name and access state; private rosters remain authorized.

- **Join with microphone** requests audio from the tap, alongside guest authentication. Camera access is separate and opt-in.
- **Join to listen** joins with an empty local MediaStream and a negotiated audio sender slot. It never requests microphone or camera access. **Use mic** attaches a microphone to that slot without replacing the peer connection, identity or chat.
- Capture, authentication, admission, peer connection and playback have independent states. Permission denial, missing/busy devices and unanswered prompts have persistent recovery, with listening available. A canceled or superseded capture is stopped if its permission promise resolves later.
- Phone calls use the full width, readable fields and controls, safe-area spacing, and More, People and chat sheets. Pinch zoom stays enabled. The marketing page and desktop sidebar are absent from invitation entry.
- Session storage saves only meeting intent and name. Guest credentials remain in the HttpOnly cookie. Reload restores a **Rejoin to listen** action and never silently opens a microphone. Explicit Leave clears active intent and releases capture/playback.
- A brief signaling interruption while the document remains alive reconnects the meeting using the existing tracks and mute state. Full reload and browser suspension that destroys the document require an explicit rejoin.
- A second tab can preview an invitation without replacing the first tab’s call. Joining explicitly takes ownership. The displaced tab stops its call and offers **Use this tab**; it does not reconnect in a loop.
- Remote sound plays through dedicated audio elements, independently of camera frames. A blocked autoplay attempt leaves **Tap to hear meeting** visible until playback succeeds.

Implementation: `web/meeting-join.js` owns the entry state and cancellation; `web/group-calls.js` reserves audio transceivers and handles media upgrades; `web/meeting-mobile.css` supplies invitation and mobile layouts. The server embeds the assets, so frontend changes require rebuilding the signaling binary.

## Verification

`npm test` includes browser integration, security/session/moderation checks, and the mobile suite in Chromium and Playwright WebKit. The mobile suite uses generated audio and covers 320–430px entry controls, 320/390/700px call controls, denied/missing/busy/unanswered capture, persistent errors, both listener SDP roles, mic upgrades, actual progressing playback before cameras, late permission cleanup, refresh, explicit leave, live reconnect with mute, and tab handoff. The guest suite checks encrypted audio, cameras, autoplay rejection/retry, chat and admin mute/kick. `npm run test:voice` covers voice-room regression.

`PVP_TEST_LISTENER=1 npm run test:meetings:native` tests browser listener-to-microphone upgrades against the real native WebRTC receiver with generated browser audio. Native capture is an empty fixture; this does not claim physical Mac microphone validation. Supply the available signing identity and matching team as documented in `AUDIO.md`.

The older six-participant native suite intermittently fails its requirement that every adaptive RTP camera renderer remain at 480p. Another run passed that stage, encrypted audio, bandwidth limits and bidirectional text/file transfers before a virtualized chat assertion; that assertion now scrolls to the first message. These attempted runs and the focused listener result are recorded in the release evidence. No native production code is changed by this browser release.

Physical iPhone Safari/Brave permission UI, focus zoom, keyboard, speaker routing and background suspension still require device testing. Desktop WebKit mobile emulation does not establish those results. The app remains direct P2P without TURN; restrictive networks can still prevent media connectivity.

See the [original investigation](MOBILE-MEETING-UX-AUDIT.md) and [release evidence](mobile-meetings-release.json).
