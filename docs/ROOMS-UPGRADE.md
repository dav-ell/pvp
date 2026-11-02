# PVP rooms upgrade

The browser portion of this update is deployed as signaling/web 0.3.25; see [latest release evidence](network-layout-release.json). Native changes remain source changes awaiting a new Mac package. PVP keeps its name and centers its browser and Mac experiences on a familiar room with a reusable invitation. A person can leave without ending the room for everyone else, then return using the same link. People, direct calls, settings, and existing room access controls remain available.

The visual system was revised on November 1 after review of the initial screen. It now uses shared forest/celadon tokens, Instrument Serif and Manrope, an original architectural room illustration, a horizontal navigation, and restrained room rows. See [the reference study and component decisions](DESIGN-DIRECTION.md). Conversations retain a darker, quieter call stage. The browser layout adapts to narrow screens, landscape, larger text, safe areas, and the mobile keyboard. In a two-person call, the other participant occupies the call window and your camera appears in an expandable preview; video uses containment so the whole frame remains visible. Group calls retain a flexible grid.

## Media and trust

- When an active microphone disappears, PVP attempts to recover with an available input without restarting the call, changing the camera, or unmuting the user. If recovery fails, listening continues and the user can choose another input. Joining to listen does not request a microphone.
- Quality controls show the chosen settings alongside measured outgoing video when the browser or native WebRTC implementation provides it. The local preview is not evidence of what a recipient sees. Browser group forwarding reports encoder output separately from RTP and does not claim that encoding proves delivery or playback.
- A reminder can appear when sustained sound is detected while muted. Monitoring uses an already-authorized microphone locally; it does not unmute automatically. The reminder depends on the platform supplying usable audio levels.
- Connection evidence shows the observed transport and route, and supplies a certificate comparison code when supported. People can compare the code through a separate trusted channel. An acknowledgement is local and temporary, not proof of account identity. Definite certificate mismatch, rejected relay, plaintext SRTP, or loss of the selected encrypted transport ends the affected call. Missing statistics are shown as unavailable, not treated as proof or failure. See [the security details](SECURITY.md#live-connection-proof--october-31-2026-local-source).

Media is direct between participants; restrictive networks may prevent connections because PVP has no relay fallback. In larger browser groups, a participant can forward separately signed and encrypted video. The service still sees connection and invitation metadata, and participants can see network addresses. The evidence is reported by the application and WebRTC implementation, not an independent security audit; a compromised endpoint or web origin can undermine it.

The website homepage now visualizes [anonymous, opt-in room activity](NETWORK-FRONT-PAGE.md), with an explicitly labeled example when no rooms are shared.

## Validation and follow-up

The browser suite exercises room creation, listen-only entry, rejoining while another person remains, full-window pair layouts at mobile and desktop sizes, camera framing, actual outgoing measurements, and connection evidence. It uses synthetic media in Chromium and WebKit, not physical cameras or microphones. Additional tests cover device replacement and cancellation, audio monitoring without sending muted sound, security failure cases, and larger-group encrypted video forwarding. The Flutter checks cover responsive layouts, connection evidence, and prompt media teardown. Local macOS integration exercises real WebRTC between native and browser clients and between two native clients.

Real phones and tablets, Bluetooth and USB device changes, accessibility workflows, and restrictive or changing networks still need hands-on validation. Local tests and screenshots do not establish production deployment, independent security review, or release availability.

Brand tokens are maintained in `packages/pvp-ui/brand-tokens.json`; run `npm run sync:brand` after changing them. Useful checks include `npm test`, `npm run test:rooms`, `npm run test:media-health`, `npm run test:security-proof`, and `npm run test:native`. For the six-person forwarding path, run `PVP_GROUP_TEST_SIZE=6 npm run test:groups`.
