# PVP interface polish plan

Status: implemented in web 0.3.21 and Mac 1.0.19. See [implementation and validation](ICON-MOTION-UX.md). The original interactive concept remains a simulated design reference. Scope: mobile web, desktop web and the existing Flutter Mac client. The priority is the call itself, followed by joining, navigation, meetings and settings.

Review the [interactive concept](prototypes/icon-motion-ux.html). It demonstrates visual states with simulated participants and audio activity; it never opens devices or connects to a meeting.

## Direction

Make PVP feel like a calm native calling interface: people occupy the screen, familiar symbols carry frequent actions, and motion shows what changed. Explanations appear where someone needs them. Preserve the current identity and purple accent while replacing inconsistent controls and excessive instruction text.

A useful rule: **people first, controls second, explanation on demand**. Reduce reading by removing redundant decisions and repeated information before replacing words with icons. Keep short visible labels for unfamiliar actions, permissions, errors and destructive choices. Familiar microphone/camera controls can use icons with accessible names, discoverable labels and tooltips. Apple supports icon, text or combined button presentations; Lucide itself cautions that icons do not universally replace labels. [Apple buttons](https://developer.apple.com/design/human-interface-guidelines/buttons), [Lucide accessibility](https://lucide.dev/how-to/accessibility)

## Findings from the supplied screenshots and source

| Current issue | Proposed change |
| --- | --- |
| A small self tile sits in a very large empty desktop stage. | Use an intentional solo state with a prominent avatar, one waiting status and an Invite action. Grow the people area before adding decoration. |
| Meeting title, `/16`, roster, bandwidth and connection status compete above the call. | Keep the title and one contextual status. Put a people count in the People control; put capacity in management and bandwidth in Connection details. |
| A long desktop toolbar presents every action at equal weight, including echo cancellation. | Introduce a compact call dock with familiar icons. Move devices, quality and processing options into a secondary sheet. |
| The phone More dialog is a stack of large text buttons and a technical checkbox. | Replace it with compact icon-and-label rows, grouped by purpose, in a bottom sheet with a clear close control. |
| The web uses custom SVG symbols; Mac mixes Material icons, filled buttons, a filter chip and dropdowns. | Establish one semantic Lucide icon registry and consistent control geometry across clients. Retain platform-native focus, keyboard and window behavior. |
| Existing motion mostly handles entrance, hover and navigation. | Keep its timing foundation; add event-driven state transitions for mic, camera, admission, playback and call layout. |
| Small type and reduced contrast are tempting ways to hide clutter. | Remove clutter structurally. Keep body copy readable and controls comfortably tappable. |

Relevant implementation: `web/index.html`, `web/group-calls.js`, `web/meeting-join.js`, `web/meetings.js`, `web/motion.js`, `web/motion.css`, `web/meeting-mobile.css`, `desktop/lib/ui/app.dart`, `desktop/lib/ui/group_call.dart`, `desktop/lib/ui/meetings.dart`, and `desktop/lib/ui/motion.dart`.

## Screen design

### 1. Call stage — first implementation priority

A dedicated call shell takes the full window on desktop and mobile. Account navigation recedes during a call. A Back control returns to the app with a compact ongoing-call strip; returning to the call restores the same media surfaces.

- Header: meeting name, a People icon with a count, and an invitation/share action. No duplicate roster or persistent bandwidth line.
- Solo: large avatar, “Waiting for others”, and “Invite”. No permanent `1/16` capacity warning or repeated self name in the header and tile.
- Two people: the remote person dominates; the self view is a small preview or compact identity row. Audio-only avatars get sufficient scale and space to feel intentional.
- Groups: stable participant order, balanced grid and an optional pin. Speaking highlights change emphasis without moving people around. Phone grids scroll vertically and keep the dock reachable; long names truncate visually with the full name available in People and accessibility output.
- Tile chrome: name, a small slashed mic when muted, a headphones badge when listening, and moderation state when relevant. Remove routine “Direct”, “Video paused”, role strings and Connection buttons from each tile.
- A connection problem replaces the normal status with one actionable banner. Playback blocked gets a speaker icon plus **Hear meeting**. Permission failure never becomes a cryptic icon.

**Mobile dock:** microphone, camera, More, Leave. The first three are icon controls; Leave keeps its short visible label. If listening, the microphone has a small add mark and a visible **Use mic** label until enabled. A muted microphone uses the slashed icon. These are different states: enabling capture can open a permission prompt; unmuting an existing microphone must not.

**Desktop/Mac dock:** microphone, camera, share screen, chat, People, More and Leave. Only Leave needs a permanent text label in the compact default. Hover and keyboard focus reveal concise tooltips. A user preference, **Show control labels**, provides persistent short captions on every client; it does not require changing browser or OS settings. The dock wraps or uses the mobile arrangement when space is limited.

The dock remains visible during normal calls. Avoid an auto-hiding control system in this release. Opening a sheet preserves call audio, keeps a recognizable part of the call visible where space permits, and restores focus to its invoking control.

### 2. More and secondary sheets

Replace “Meeting options” and the full-width boxed buttons with a compact sheet titled **More**. Each row contains a 22–24px icon, a short label and optional trailing state/chevron. Use separators between real groups rather than borders around every row.

- Communication: **Chat** with unread count; **People** with current count.
- Capture: **Share screen** when supported; **Flip camera** when a camera is active and switching is meaningful.
- Preferences: **Audio & video** opens devices, quality and echo cancellation; **Connection** opens diagnostics.
- Close: a familiar X in a 44px+ button, with accessible name “Back to call”; Escape and an explicit close both work. A drag handle is a visual affordance, not the only way out.

Desktop uses an anchored popover or side panel; phones use a bottom sheet. Detents and dragging are optional enhancements after reliable click/keyboard behavior. Chat and People keep short text labels because their content is meant to be scanned.

Hide unsupported screen sharing rather than repeatedly presenting a dead action. Do not show Flip camera before a camera is active. Keep active sharing conspicuous with a persistent sharing treatment and **Stop sharing**, including a minimized call. Host moderation lives in the People list’s per-person menu with named, contextual confirmations for removal.

**Audio & video** contains a labeled echo-cancellation switch, default on, with optional one-line help. Do not substitute an unexplained waveform glyph for this technical setting. Device names and quality choices remain written. Move Mbps and packet details into Connection; keep them available for troubleshooting.

### 3. Invitation and permission recovery

Preserve the new dedicated meeting journey and its proven listening path. Simplify the presentation to the meeting name, name field, a camera-off symbol, and two explicit choices: **Join** with a microphone icon, and **Listen** with headphones. If comprehension testing confuses these labels, retain **Join with mic** and **Join to listen**; a few extra words are preferable to accidental capture.

Keep “No account needed” once for guests. Consolidate privacy and help disclosures, but retain a concise direct-IP disclosure before joining. The host and public presence are shown only where existing authorized metadata permits them. A visual preview never invents an anonymous roster.

Permission pending: microphone glyph, bounded activity indicator, “Allow microphone access”, Listen and Cancel. After a prolonged wait, use “Still waiting for access”. Denied/unavailable: concise title, **Listen**, **Try mic**, and contextual Help. Keep OS/browser instructions inside Help and persistent until resolved. Display “Mic access unavailable” when the browser cannot establish the exact denial reason.

Rejoin: “Welcome back”, saved identity, **Rejoin** with headphones and an explicit microphone alternative. Full reload still defaults to listening. No animation or visual simplification silently changes permission intent.

### 4. Meetings, friends, chat and settings

- Meeting library: name is primary; link/lock icon shows access with a short label available. Current presence is secondary; persistent membership count and capacity belong in details. Copy turns briefly into a check only after the clipboard action succeeds. Add/Create remains a labeled primary action.
- Meeting details: replace duplicate link paragraphs and a giant read-only URL field with Share/Copy actions and an expandable link. Keep access controls written and explicit.
- Friends: avatar, name and meaningful presence; a single call button. Remove permanent helper paragraphs, promotional footers and redundant status labels. Keep text labels in unfamiliar navigation destinations rather than replacing the whole app with an unlabeled icon rail.
- Chat: standard composer icons for attachment and send; readable messages and visible transfer state. Unread counts track unseen messages, not all historical messages. New messages do not move call controls or interrupt the stage.
- Settings: icon-led grouped rows with a label and current value. Explanations appear after opening a setting or using help. Technical controls remain understandable through short text, not symbolic guesses.
- Empty states: one illustration or relevant symbol, one sentence, one action. No decorative slogan alongside several paragraphs explaining the same action.
- Notifications: local acknowledgement stays near its control. Persistent problems stay in context. Avoid transient toasts as the only evidence of a failed operation.

## Icon system

Adopt **Lucide** as the shared interface family. Use selected, locally bundled vector assets pinned to a release; no runtime CDN and no wholesale icon library in the browser. The prototype uses a recorded Lucide release and retains its license. For Flutter, render the same curated SVG subset through one icon adapter, selecting a maintained rendering dependency during implementation; do not mix in a second icon family for routine controls. Native system menus/window controls retain their platform treatment. [Lucide vanilla integration](https://lucide.dev/guide/lucide), [license](https://lucide.dev/license)

| Meaning | Lucide glyphs | State treatment |
| --- | --- | --- |
| Microphone | `mic`, `mic-off` | Slash and background distinguish muted state; label/action and pressed state remain explicit. |
| Enable capture while listening | `mic` with a small add badge | Visible “Use mic”; independent of ordinary mute. |
| Camera | `video`, `video-off` | Empty/off silhouette and active surface; camera stays off until consent. |
| Screen sharing | `screen-share`, `screen-share-off` | Persistent active badge; explicit Stop sharing action. |
| Chat | `message-circle` | Unread dot/count only when messages are unseen. |
| People | `users-round` | Count of people present; no routine `/16` in the dock. |
| More / close | `ellipsis`, `x` | Stable location; focus returns on close. |
| Listen / playback | `headphones`, `volume-2`, `volume-x` | Listening mode differs from blocked output. |
| Invitation / copied | `link`, `copy`, `check` | Success check is temporary; errors keep a retry. |
| Devices / settings | `settings-2`, `switch-camera` | Labeled rows inside settings and More. |
| Recovery / leave | `wifi-off`, `phone-off` | Recovery has text; Leave is red plus glyph and label. |

Start at a 24-unit grid and Lucide’s standard 2px stroke. Use 20px in dense rows, 24px in call controls, and optically balanced 28px glyphs in 52–56px phone buttons. Avoid arbitrary mixtures of thin, filled and emoji icons. Small badges need their own size and contrast tokens. Icon meaning must remain stable across the web and Mac clients. [Lucide stroke width](https://lucide.dev/guide/lucide/basics/stroke-width)

For the app logo, preserve the recognizable purple/camera identity in this pass, refine optical alignment and small-size silhouettes, and align the favicon, web manifest, download branding, Mac dock and menu-bar template assets. The existing green favicon and purple UI mark are inconsistent. App-brand artwork is a separate vector asset, not a generic Lucide icon with a gradient applied. Review it at 16, 32, 64, 128 and 1024px before packaging.

## Motion that carries information

Extend the existing PVP Signal foundation: response 110ms, travel 180ms, settle 280ms. Motion begins with the state change and never delays an action, media cleanup or accessibility update. Duration values are design targets to tune on devices, not simulated progress guarantees.

| Event | Motion and persistent result | Authoritative trigger |
| --- | --- | --- |
| Mute/unmute | Short press response; mic/slash transition and surface change. | Effective track enable state, respecting admin mute. |
| Microphone request | Small bounded activity indicator in the mic control, then success or a recovery card. | Capture promise, attempt token and track state. Never imply a browser prompt was displayed. |
| Speaking | Small level bars or restrained avatar ring respond to audio; decay smoothly to stillness. | Smoothed real audio activity. No random pulses in the app. |
| Joining | One compact connection transition; settle into the participant stage. | Admission and peer state. Never display a fake percent counter. |
| Camera on/off | Placeholder gives way to the first usable frame; off returns immediately to avatar. | Actual capture/remote frames. A returning animation must not retain a stopped camera image. |
| Participant arrives/leaves | New avatar appears once; remaining tiles move to their new positions once. | Membership change. Do not animate stats refreshes or reorder on every speaker change. |
| Sheet opens | Surface rises from the dock on phone or expands from its anchor on desktop. | User action; contents and controls work immediately. |
| Copy succeeds | Copy icon becomes a check, then returns after a brief acknowledgement. | Clipboard completion, with text fallback on failure. |
| Chat arrives | A dot/count appears at Chat/More. | New unread content; clear on viewing. No endless bouncing badge. |
| Network drops | Speaking motion settles; a reconnect symbol and concise action appear. | Lost signaling/peer state. Do not pulse a healthy-looking avatar while reconnecting. |
| Playback blocked | Speaker action gets an initial emphasis and then remains still and visible. | Playback rejection; hide only after playback succeeds. |
| Leave | Stop media immediately; present the left/rejoin state with a short transition. | Explicit leave. No exit animation may postpone stopping audio/video. |

Do not use continuous decorative shimmer, pulsing idle screens, ambient particles, exaggerated bounce or universal icon morphs. A well-chosen crossfade/short translation is often clearer than bending one unrelated symbol into another.

Reduce Motion replaces spatial travel, scale and waves with immediate state changes or a brief opacity transition. Status, focus and readable errors remain. Pause or stop animation in hidden documents and offscreen tiles; use transform/opacity where suitable and reuse existing audio sampling rather than starting a second high-frequency loop. [Apple motion](https://developer.apple.com/design/human-interface-guidelines/motion), [Apple Reduced Motion](https://developer.apple.com/help/app-store-connect/manage-app-accessibility/reduced-motion-evaluation-criteria)

## Text and accessibility rules

A normal connected call shows the meeting title, participant names and at most one short contextual status. Aim to remove at least half the non-name explanatory copy currently visible on the default call surfaces; measure at comparable viewport and state. This is a design target, not a claim of measured usability improvement.

Examples: “Meeting members” → “People”; “Turn camera on” → a video-off control with accessible action “Turn camera on”; “Your bandwidth · measuring…” → Connection detail; “You joined · Waiting for others” → “Waiting for others”; “Ready for a hello” → omit from a healthy call; “Allow microphone access in your browser to join a call” → “Mic access unavailable” plus Listen / Try mic / Help.

Every icon button has an accessible name on the button and a stable semantic state. For toggles, use a stable label plus `aria-pressed` or equivalent Flutter semantics, and expose the effective state. Momentary actions such as Use mic do not pretend to be toggles. Decorative SVGs are hidden from assistive technology. Tooltips are available by keyboard focus and mouse hover, and do not act as the only touch instruction. The Show control labels preference is available with a written label in More.

Keep critical text when hiding it could change someone’s decision: capture intent, playback activation, destructive removal, link deletion and private/open access. Use color plus shape/state, not color alone. Target at least 44×44px controls and 52–56px phone dock buttons, 16px+ form inputs, 4.5:1 normal text contrast and 3:1 essential non-text controls. Preserve browser zoom, larger text, keyboard navigation, VoiceOver names and focus restoration. The WCAG animation-from-interaction criterion is AAA; these motion choices are product requirements independent of that conformance level. [WCAG non-text contrast](https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html), [WCAG animation](https://www.w3.org/WAI/WCAG22/Understanding/animation-from-interactions.html)

## Implementation sequence and review gates

1. **Audit and freeze the vocabulary.** Inventory visible strings, icons and control states across direct calls, meetings, voice rooms, app navigation and Mac. Agree the icon map, label rules and core tokens. Record existing screenshots and call/media identity checks. Deliver the shared control-state spec before styling individual screens.
2. **Ship the call surface coherently.** Build the icon component, compact dock, intentional solo/two-person/group stage, More/People/chat sheets and contextual status in web and Mac. Preserve current IDs or migrate tests to semantic roles/labels. Include the short-copy pass; replacing icons alone will leave the hierarchy problem intact.
3. **Connect informative motion.** Bind mic, speaking, camera, participant, playback and reconnect transitions to existing state. Extend `motion.js`/`motion.css` and `PvpMotion`; centralize reduced-motion and interruption behavior. Keep media elements, tracks and peer connections stable through style changes.
4. **Apply the same language to the rest of the app.** Simplify invitation/recovery, meetings, friends, chat and settings; normalize branding assets. Keep accountless entry, privacy disclosure, private invitations and admin controls intact.
5. **Validate and release.** Review on physical iPhone Safari/Brave, Android Chrome, desktop browsers and the Mac app, including keyboard, screen reader, large text, reduced motion and slow/error states. Package browser and Mac changes with versioned assets and rollback backups after the approved design is implemented.

Suggested implementation units: shared `CallAction`, `StatusBadge`, `CallDock`, `ParticipantTile`, `ContextSheet` and `InlineRecovery` components; one semantic icon registry; a short-copy catalog; and a compact status model that consumes the existing join/media state. Keep presentation changes out of signaling and authentication unless a demonstrated missing state requires a narrow addition.

## Acceptance and usability checks

- Compare the current screenshots with the new call and More surfaces at equal scale. The person and main action should read first. Routine calls have no settings checkbox, Mbps line, promotional copy or duplicated roster.
- First-time participants can identify mic state, enable their camera deliberately, open chat and leave without a verbal walkthrough. Test both icon-only and Show control labels presentations. Ask users to describe what they think will happen before acting; time-to-first-action alone does not establish comprehension.
- Pilot with 5–8 people unfamiliar with PVP, including at least two people using the label preference or accessibility settings. Treat this as formative feedback, not statistical proof. Target at least 90% unassisted completion across the tested tasks and zero accidental microphone activation caused by ambiguous icons. Revise labels where comprehension is weak.
- No motion indicates speaking when no real audio activity exists, implies successful admission before it occurs, or claims microphone access based on a click alone.
- Reduced Motion preserves every state and action. Tests cover rapid toggles, live preference changes, interrupted transitions, focus restoration, 200% text, 320px widths, landscape, safe areas and keyboard interaction.
- Existing media assertions continue to pass: listening without capture, both SDP roles, listener→mic without reconnecting, camera-off audio playback, autoplay retry, permission failure and late-grant disposal, refresh/rejoin, live reconnect, tab ownership, moderation and access control.
- Changes to icon, tooltip, sheet, badge or animation do not reconstruct a video element, restart capture, replace a peer connection, reset chat, or replay entrances on ordinary stats updates.
- Real-device review covers touch discoverability, actual prompt behavior, speaker/headphone routes and sustained-call performance. Test ongoing sharing and errors as carefully as the polished default state.

## Concept boundaries

The accompanying concept makes the hierarchy, icons, dock, sheet, label preference and motion states reviewable. It uses explicitly simulated audio/activity and permission outcomes. It is not a media implementation or a tested drop-in replacement. Browser layout and interaction checks establish the concept’s behavior only; they do not establish native accessibility or real call correctness.

## Planning artifacts checked

The standalone concept was exercised in Chromium and Playwright WebKit at 320, 360, 390 and 430 CSS-pixel widths. Checked: microphone/camera control state, simulated listening upgrades, More → Audio navigation, switch state, close/Escape and focus return, visible-label preference, permission/playback/reconnect scenarios, leave/rejoin, clipboard acknowledgement, and reduced motion. No script errors or document overflow were observed in those runs. These checks cover the simulated concept only.

- [Screen overview](prototypes/icon-motion-ux.png)
- [Phone More sheet](prototypes/icon-motion-options.png)
- [Recorded concept checks](prototypes/icon-motion-ux-evidence.json)
- [Pinned Lucide source](prototypes/polish-assets/SOURCE.json) and [license](prototypes/polish-assets/LICENSE)
