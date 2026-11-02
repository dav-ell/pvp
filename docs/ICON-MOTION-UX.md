# PVP icon and motion release

Implemented for mobile web, desktop web and the Flutter Mac app. Web/signaling version 0.3.21; Mac 1.0.19 (20). The [approved plan](ICON-MOTION-UX-PLAN.md) and its prototype remain available as design references. Production verification and artifact hashes are recorded in [the release manifest](icon-motion-release.json).

## User-facing changes

- Calls fill the window. Back keeps the call alive and provides a Return to call strip; ongoing sharing remains explicit. Solo and two-person voice calls give avatars appropriate space. Groups keep their order, with real speaking highlights and readable names.
- A compact icon dock replaces the text toolbar. Phones expose mic, camera, More and Leave; desktop and Mac expose sharing, chat and People as well. Leave and Use mic retain captions. More offers persistent control labels, and familiar controls expose tooltips and effective toggle states.
- More, People and Audio & video provide short labeled rows. Devices, quality, echo cancellation and connection diagnostics leave the main stage. Moderation remains available in named per-person menus, with explicit removal confirmation.
- Invitations retain distinct microphone and listening choices. Listening requires no microphone permission, including in the Mac client. A pending request can be canceled or replaced by listening; late grants are disposed. Enabling a microphone uses the negotiated audio slot and preserves the call. Camera remains opt-in.
- Shorter meeting, friend and settings surfaces move explanations into disclosures. Meeting links expand on demand. Copy acknowledges clipboard completion; file consent and readable error text remain explicit.
- Chat badges count unseen incoming messages. Transfer progress and previously read messages do not create new unread counts. Both composers use attachment and send icons.
- A locally bundled Lucide family replaces mixed routine control artwork. Purple camera branding now agrees across favicon, web manifest and the Mac app icon. Native macOS menus retain system symbols.

## Implementation

`packages/pvp-ui/icons` contains 60 curated SVGs, their upstream license and pinned provenance. `scripts/sync-ui-icons.py` creates the browser sprite and Flutter asset copies offline. Flutter uses `flutter_svg` through `PvpGlyph`/`PvpIcon`; controls share `CallAction`, `CallDock`, `ContextSheet`, `SheetAction` and `SpeakingAvatar`.

Browser presentation is shared through `web/ui.js` and `web/polish.css`. Accountless admission, separate audio playback sinks, server moderation, private invitations and persistent meeting identities retain their existing boundaries. Call navigation and presentation do not replace browser video/audio elements or peer connections. Native renderers remain owned by the call controllers.

Motion follows capture promises, effective mic state, real audio activity, usable camera frames, clipboard completion and unread content. Participant entrances occur on membership changes, rather than statistics refreshes. Reduced Motion suppresses spatial effects. Hidden calls stop presentation motion while media continues. Camera opt-out immediately conceals the last frame.

## Validation

- 49 browser checks pass, including Chromium and WebKit; focused polish checks also pass after the final accessibility refinements. They exercise widths 320, 360, 390, 430, 860 and 1440, reduced motion, focus return, stored label preferences, real audio playback, camera frames, unread counts, and media identity across navigation and resizing.
- 68 Flutter checks pass, including 1/2/8/16-person layouts at 860×540 and 1440×900 with normal and 200% text. Microphone upgrade, rollback, late-grant disposal, device routing, label persistence and unread behavior have direct coverage. Static analysis is clean.
- Native/browser integration passes for listening and microphone upgrades. Browser listening checks explicitly exercise both SDP roles. A separate native-plus-five-browser run passes encrypted reception, opaque forwarding, live bandwidth controls, bidirectional text/binary/image chat, native admin appointment, moderator mute/release and removal.
- 28 Rust signaling tests pass; Clippy reports no warnings. The universal Mac archive passes strict recursive signature validation and includes arm64 and x86_64 executables.

The native six-person run decodes all five camera streams, but WebRTC adapts resolution under local load. Its hard 480p receiver assertion failed before this release; `PVP_TEST_STRICT_RESOLUTION=1` retains that separate performance check. The default interoperability run checks received frames and the actual configured quality policy has independent tests. This release does not claim a guaranteed decoded resolution.

Physical iPhone Safari/Brave, Android audio routing, VoiceOver comprehension and a first-time-user pilot remain manual review work. Desktop WebKit and generated media are useful regression checks, but do not establish those device or usability results. Production remains direct P2P without a TURN fallback.

## Screens

Screenshots show actual local calls with generated audio/video, not simulated concept state:

- [Desktop solo call](screenshots/icon-motion/solo-desktop.png)
- [Phone voice call](screenshots/icon-motion/duo-mobile.png)
- [Phone More](screenshots/icon-motion/more-mobile.png)
- [Phone Audio & video](screenshots/icon-motion/audio-mobile.png)
- [Phone invitation](screenshots/icon-motion/invitation-mobile.png)
- [Mac listening call](screenshots/icon-motion/native-listening.png)

## Release and rollback

The release process verifies every embedded asset against source, boots the candidate as the unprivileged service user against an isolated database, checks guest scope and cookie properties, and validates Caddy before promotion. Production records are compared with an online SQLite backup; a portable backup is also retained off the VM. Previous binaries, Caddy configuration and versioned Mac downloads remain available for rollback. No live database is replaced during deployment.

Public HTTPS checks passed in Chromium and WebKit, and every deployed asset plus the complete Mac download matched its release hash. The first WebKit pass timed out reloading after an explicit leave; the isolated retry passed. Temporary production test owners and meetings were removed, followed by a durable-record and database-integrity audit.
