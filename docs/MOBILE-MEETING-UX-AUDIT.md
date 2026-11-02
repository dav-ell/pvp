# Mobile meeting UX investigation and redesign proposal

Date: October 17, 2026. Original scope: investigation and proposal. The approved implementation is documented in [MOBILE-MEETINGS.md](MOBILE-MEETINGS.md); deployment status and verification are recorded in [mobile-meetings-release.json](mobile-meetings-release.json). The measurements below describe the previous production experience.

## Recommendation

Give meeting links a dedicated join and call experience that uses the full phone screen. Make microphone access an optional capability, with **Join with microphone** and **Join to listen** available from the beginning. Keep permission recovery and rejoining inside that experience.

The present flow puts a visitor through the marketing page, guest authentication, an account-style meeting management screen and microphone capture before admitting them. These stages expose internal application structure and several failure states to someone whose only goal is to join a conversation.

Review the [interactive concept](/Users/davell/Documents/github/pvp/docs/prototypes/mobile-meeting-ux.html), its [screen overview](/Users/davell/Documents/github/pvp/docs/prototypes/mobile-meeting-ux.png), and the [recorded audit evidence](/Users/davell/Documents/github/pvp/docs/prototypes/mobile-meeting-ux-evidence.json). The concept simulates product states; it does not connect to meetings, open a microphone, or reproduce an operating-system permission dialog.

## Evidence and limits

I examined all three supplied screenshots and traced the frontend and meeting signaling code. I fetched production HTML, CSS and meeting code read-only. Production health reports 0.3.19. Its HTML, CSS and `meetings.js` match this workspace; `app.js` and `group-calls.js` have additional local changes, including the earlier audio-playback correction.

For the audit I replayed the production client files against an isolated local service. I used Chromium and Playwright WebKit with an iPhone-sized touch viewport, injected denied, unanswered, missing, busy and successful microphone outcomes, checked refresh behavior, and introduced a 6.1-second guest-admission delay. No production accounts, calls or database writes were created.

These browser runs establish layout geometry and application behavior. Desktop WebKit with mobile emulation is not a physical iPhone. Native focus zoom, the software keyboard, Safari/Brave permission menus, browser pull-to-refresh, phone audio routing and background suspension still need physical-device checks. The exact reason a particular phone did not show a permission dialog cannot be recovered from these screenshots.

## What is failing

| Finding | Evidence and confidence | Consequence |
| --- | --- | --- |
| A desktop navigation column remains on phones | Confirmed in both engines: 160px sidebar on a 390px viewport, leaving 230px for the entire meeting. At 320px it consumes half the screen. | The useful interface is squeezed into a narrow column even at normal zoom. |
| Some controls are clipped without document overflow | At 320px, Join extends from x=257 to x=364, outside the viewport, while document width still reports 320px. At 360px it extends 4px beyond the viewport. | Tests that only assert `scrollWidth <= innerWidth` falsely report a healthy mobile layout. |
| The first action starts below the fold | On a 390×700 content viewport, the initial guest Join button starts at y=736 in Chromium and y=731 in WebKit. The marketing story is still above it. | An invitation initially presents promotion and explanatory text before the action the visitor needs. |
| Entry controls are small | Both engines compute 13px input text; the name field is about 38px high and Join about 36px high. | Poor legibility and touch comfort. The small input text is a strong focus-zoom suspect on the supplied iPhone screenshots. |
| Microphone capture gates admission | Injected denial, missing hardware and busy-device errors all prevent a `meeting-enter` message. No listen action exists. | Someone unable or unwilling to grant microphone access cannot even enter to listen. |
| Errors disappear while the problem persists | The microphone error toast is gone after 6.5 seconds. The page still says “Ready for a hello.” | The visitor loses both the explanation and any indication that joining failed. |
| Pending permission is treated as an existing call | After eight seconds with an unanswered capture promise, there is no visible permission-wait state. In WebKit, a second Join click reports “Finish your current call first.” | The interface presents a false conflict instead of helping the user answer, cancel, or listen. |
| Refresh restores identity but loses the meeting journey | Refresh makes zero capture requests and opens the full meeting detail page, with the same sidebar and another Join button. | A browser refresh turns a simple invitation into an unfamiliar management screen. |
| Capture is requested after asynchronous admission work | With the injected delay, the microphone call occurs about 6.1 seconds after the original tap; transient user activation is false in both engines. | This is a browser-policy risk, especially for permission retries. It is not proof that the delay caused the reported missing prompt. |
| Signaling readiness is presented as overall readiness | “Ready for a hello” appears after the WebSocket opens, including when permission fails or remains unanswered. | Server connectivity is confused with entering a meeting and hearing it. |
| Audio playback has a separate known defect | The earlier reproduction received audio while the mixed audio/video element waited for its first camera frame. The separate audio sink fix is local. | A successful join still does not prove sound is playing. This must be included in the first reliability release. |

The relevant layout rules are in [styles.css](/Users/davell/Documents/github/pvp/web/styles.css:246). The microphone gate is in [prepareMedia](/Users/davell/Documents/github/pvp/web/app.js:290) and [startMeeting](/Users/davell/Documents/github/pvp/web/group-calls.js:82). The full management view is built by [MeetingLinks.detail](/Users/davell/Documents/github/pvp/web/meetings.js:58). Refresh handling is in [boot](/Users/davell/Documents/github/pvp/web/app.js:813).

### Interpreting the screenshots

Image 1 shows the guest form embedded beneath the marketing story. Images 2 and 3 show the restored guest identity inside the desktop application shell. Image 3 appears consistent with the measured normal 160px sidebar. Image 2 is visibly magnified and cropped further to the right. Small-field focus zoom is a plausible contributor; manual page zoom and device text settings can also affect the result.

The viewport declaration already includes `width=device-width, initial-scale=1`. Adding that declaration again will not solve this. The design should use readable controls and a layout that tolerates zoom. Disabling pinch zoom or forcing the page back to scale 1 would interfere with accessibility and would not fix the narrow meeting column.

### Why a microphone prompt may not appear

“No prompt” is not a single error condition. Previously granted access may need no new prompt; denied or restricted access may reject immediately. The request may also remain unanswered. `getUserMedia()` can fail for permission, context, device and policy reasons, and its promise may remain pending indefinitely. The app currently collapses these cases into a few temporary messages. [Media capture documentation](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

Safari has also implemented user-gesture checks for capture after a previous denial. Moving capture through several network operations is therefore a risk to investigate, not an established explanation for every iPhone failure. Request the microphone directly from an explicit microphone action, with feature-detected permission information as an aid rather than a dependency. [WebKit permission retry change](https://bugs.webkit.org/show_bug.cgi?id=203362), [current capture implementation](https://github.com/WebKit/WebKit/blob/main/Source/WebCore/Modules/mediastream/MediaDevices.cpp)

## Proposed experience

### 1. One invitation screen

Opening an existing meeting link, whether signed in or anonymous, should immediately select a meeting-specific screen. Show a compact loading version of that screen while fetching metadata; do not first paint the marketing hero or dashboard.

The screen contains:

- Meeting title and an optional host/presence summary where authorized metadata permits it.
- One name field, prefilled from the current session when available.
- **Join with microphone** as the speaking action.
- **Join to listen**, clearly visible beside that choice in the reading order.
- A short “Camera off; turn it on later” explanation.
- A concise disclosure that direct-call participants can see the visitor’s network address, with additional privacy and moderation details in an expandable section.
- Sign-in as a secondary option, preserving the original meeting destination.

Remove the fixed sidebar, account navigation, link-copy input, permanent membership roster, “All meetings” action, admin explanations and promotional hero from this route. Hosts can open meeting management through an explicit action; management remains a separate screen.

Preserve existing `#meeting=…` links. A new URL format is optional, not a prerequisite. Public previews must not start exposing a full account or member roster just to support the design. The prototype’s host and presence text is illustrative; show it only when available through an appropriate authorized response, and otherwise omit it without blocking entry.

### 2. Listening does not require microphone permission

**Join to listen** creates or restores the scoped guest identity, joins the meeting and negotiates incoming audio without calling `getUserMedia()`. The camera remains off. Once connected, show **Joined · Listening**, and make **Use mic** available in the call.

**Use mic** requests only microphone access from that tap. Success attaches the microphone to the existing call, preserving the peer connections, participant identity and chat. Failure keeps the person listening and explains how to recover. Admin mute and removal rules continue to apply.

Listening still requires a supported browser, an available meeting place and a working direct peer connection. It does not bypass private admission, a removed guest session or the 16-member limit. A restrictive network can still prevent this direct-only app from connecting.

This needs media-engine work, not just a new button: [createLink](/Users/davell/Documents/github/pvp/web/group-calls.js:147) currently derives audio negotiation from captured microphone tracks, and reconciliation requires a local stream. Reserve an audio transceiver even when there is no microphone track. An initially negotiated send/receive audio slot with no sender track can support receiving first and adding a permitted microphone later. Validate both offerer directions and browser/native combinations before relying on that approach.

### 3. An explicit microphone and connection state machine

Use a small controller for join intent, authentication, capture, room admission, connection and playback. These are separate facts. A pending capture request must not count as an existing call conflict.

| Situation | Persistent app message | Available actions |
| --- | --- | --- |
| Asking for the microphone | “Waiting for microphone access. Check your browser’s prompt.” | Join to listen; cancel this attempt. |
| Known permission block | “Your microphone is blocked. You can still join to listen.” | Join to listen; microphone help; retry after changing access. |
| Access refused, exact reason unknown | “We couldn’t access your microphone.” | Join to listen; check access; retry. |
| No microphone found | “No microphone is available on this device.” | Join to listen; choose another input where supported. |
| Input cannot be opened | “The microphone is unavailable right now.” | Join to listen; retry; relevant device help. |
| Permission request unanswered | “Still waiting for microphone access.” | Join to listen; cancel. Keep these available without waiting for a rejection. |
| Connecting to peers | “Connecting to the meeting…” | Cancel; connection help after a bounded wait. |
| Admitted but playback is blocked | “You joined. Tap to hear the meeting.” | A prominent **Tap to hear meeting** action. |
| Joined alone | “You joined. Waiting for others.” | Normal call controls. |
| Session removed or link revoked | Explain that access is unavailable. | Contact host or return; do not present a microphone retry. |
| Meeting full | “This meeting is full.” | Retry availability; contact host. No promise that listening bypasses capacity. |

Permission and recovery information belongs next to the action and stays until resolved. Use toasts for minor confirmations. Avoid mentioning a camera when a microphone-only request fails. Avoid directing a phone guest to a tiny settings icon on another screen.

A website cannot reset a browser or OS denial. Help should account for site-level access, browser-level iPhone permission and restricted embedded browser contexts. Offer the original link for opening in a full browser when necessary. Do not promise a universal “Open in Safari” command or invent a browser-settings deep link; the available action varies by browser.

Do not require the Permissions API. Query it only when supported, catch unsupported microphone permission names, and treat unknown as unknown. Browser UI remains the authority.

### 4. Make microphone intent immediate and cancellation safe

The initial microphone action should start the capture request within its tap handler. Guest credential creation can proceed in parallel; send room admission only when authentication and the chosen media mode are ready. The capture controller must therefore be independent of the current account object, with an attempt token that survives the anonymous-to-guest transition safely.

If admission fails, the visitor switches to listening, or the attempt is canceled, stop any acquired tracks. `getUserMedia()` has no universally usable prompt-cancel operation: if a canceled request resolves later, stop its tracks immediately and never attach them. Keep one capture attempt active instead of issuing repeated overlapping prompts. After roughly eight seconds without a decision, show the waiting/help state rather than treating it as a failed call or silently issuing another request.

The same controller should distinguish slow guest authentication, a failed signaling connection, meeting admission rejection, failed direct ICE connectivity and blocked playback. “Join” must not repeatedly restart the entire sequence when only one capability is missing.

### 5. A phone-sized call screen

Use the full width for the call. Show the meeting name, people present and real call status. Keep microphone, camera, More and Leave controls reachable with safe-area spacing. Use labels such as **Use mic**, **Mute**, **Camera on** and **Leave**; an unexplained red/green icon is insufficient.

People, chat, sharing, device options and host controls open as full-width sheets or dedicated secondary screens. Preserve the call while those views are open and provide an obvious return action. The ordinary guest does not need the friends sidebar. Keep admin tools visible only to authorized roles.

Treat speaker playback and microphone capture separately. The existing [audio-only playback correction](/Users/davell/Documents/github/pvp/web/playback.js:1) is a prerequisite: camera-off calls must play sound without waiting for a video frame. Starting playback can itself need a user action, particularly for a listener who is not capturing audio. Show a clear sound action when needed instead of assuming a successful join guarantees autoplay. [WebKit media autoplay policy](https://webkit.org/blog/7763/a-closer-look-into-webrtc/)

### 6. Layout, zoom and scrolling

- Use a single content column on narrow screens. The call route should have no permanently reserved sidebar width.
- Start text inputs at 16px or larger, with readable body text and scalable sizing. Verify iPhone focus zoom rather than masking it by disabling zoom.
- Target 48–52px primary buttons and at least 44px practical touch areas for call controls. These are product comfort targets; WCAG’s AA target-size criterion has different minimums and exceptions.
- Allow long names and meeting titles to wrap without pushing controls off screen. Keep secondary paragraphs concise and move optional detail into disclosures.
- Account for safe areas, expanding browser chrome, landscape orientation and the keyboard. Prefer one intentional scroll surface per screen. Use dynamic viewport units carefully; verify sticky actions do not cover focused fields or the last content row.
- Keep pinch zoom and text enlargement available. Check reflow at 320 CSS pixels and text enlargement to 200%, including focus and error states. [W3C Reflow guidance](https://www.w3.org/WAI/WCAG21/Understanding/reflow), [W3C Resize Text guidance](https://www.w3.org/WAI/WCAG21/Understanding/resize-text)

`overscroll-behavior` can help contain scroll chaining on supporting browsers, but it is not a reliable global solution for iPhone pull-to-refresh. WebKit has an open report specifically about that limitation. Do not globally cancel touch events, disable zoom or trap scrolling. The design must also recover from refresh. [WebKit pull-to-refresh report](https://bugs.webkit.org/show_bug.cgi?id=275947)

### 7. Refresh and reconnect are designed states

Persist non-secret meeting intent and the chosen display name in origin-scoped session storage as the user progresses. Recovery refers to the same browser context; changing browser or entering private mode can create a separate cookie/storage context. Preserve the meeting destination on handoff without promising to transfer a guest credential. Keep the real guest token in its existing HttpOnly cookie. Do not put a credential or full bearer link into an analytics event.

After a full reload, show **Welcome back → Rejoin to listen**, with the saved name and destination already present. Provide **Join with microphone** as an explicit alternative. Do not replay the marketing page, require the name again or silently reopen a microphone. A browser may need a new tap to begin sound, so “instant audible rejoin after any reload” is not a promise the UI can make.

An interrupted connection while the document and capture remain alive can reconnect under the existing join intent, preserving microphone mute state. If the phone suspends or ends capture, show an appropriate resume action. Explicitly leaving clears active join intent and disposes sound/capture; returning later must not automatically rejoin.

Handle expired guest sessions, deleted links, kicks, full meetings and duplicate tabs as distinct outcomes. An expired session can get a new normal guest entry when access permits it; a known kicked session must not turn “refresh” into a silent block bypass. Duplicate tabs should explain which tab owns the call and offer an explicit takeover, preventing reconnect loops between tabs.

## Implementation structure

| Component | Responsibility |
| --- | --- |
| Meeting route / join view | Resolve the link immediately, load a compact preview, collect display name and media intent, render persistent recovery. |
| Join controller | Track attempt, guest/account identity, admission, cancellation, reconnect and restore intent. Expose state instead of relying on button-local flags. |
| Capture controller | Request the chosen device from an explicit action, classify failure, retain one attempt, stop late results, and upgrade a listener without replacing the call. |
| Media engine | Negotiate receive audio without capture; keep sender slots and mute/moderation state coherent; use independent audio playback. |
| Mobile call view | Full-width participants, clear call/sound/capture status, accessible controls and secondary sheets. |
| Existing management view | Create permanent links, manage membership and roles, and copy/share links deliberately. |

Keep the current scoped guest authentication, private-meeting rules and server authorization. No weakening of origin checks or expansion of anonymous roster access is needed. Add protocol fields only where cross-client state or media upgrades require them; listener intent is not an admin role. Test compatibility instead of assuming the current Mac client handles every new negotiation case.

## Delivery order

1. **Restore basic reliability.** Include the existing camera-off playback fix; implement capture-independent listening and persistent permission recovery; replace misleading readiness/conflict states. Fix small inputs, clipped Join controls and the phone sidebar at the same time.
2. **Ship the dedicated meeting journey.** Add the compact invitation screen, explicit join controller, full-width call controls and safe rejoin screen. Preserve existing links and signed-in user behavior.
3. **Harden phone lifecycle and accessibility.** Add real-device permission/retry/background tests, keyboard and zoom checks, duplicate-tab handling and privacy-conscious diagnostics. Improve the broader friends/library mobile layout separately; guests should not have to navigate it to join.

A native phone app or installation requirement is unnecessary for the first overhaul. The browser journey should work for a one-time visitor opening a link from a message. Optional installation can be evaluated later for frequent use.

## Release acceptance checks

### Device and layout coverage

Test physical iPhone Safari and Brave, plus opening the same link from Messages and another embedded browser where available. Record actual OS/browser versions. Add Android Chrome and a desktop-to-phone call. Use 320, 360, 390 and 430 CSS-pixel widths, landscape, browser bars expanded/collapsed, keyboard shown/hidden, increased text and VoiceOver.

At standard 390×700 content size, show the name and both joining choices without requiring the promotional scroll. At all supported widths, every primary control must be inside the visible interaction area or reachable by a straightforward vertical scroll. Assert control bounding boxes against their actual clipping ancestors, not just the document’s `scrollWidth`.

### Permissions and media

- Fresh prompt: allow, deny, leave unanswered, and grant after the app has switched to listening.
- Access already granted, previously denied at the site, and disabled at the OS/browser level.
- No microphone, input busy, device change and unsupported permission-query APIs.
- Listener joining first and second, including both SDP offerer orders and browser/Mac pairs.
- Listener can hear, then enable a microphone without losing the call or chat. Denied upgrade leaves listening intact.
- Both cameras stay off while actual remote playback advances with a known test tone. Validate sound on real phone speakers/headphones with the other person; packet counters alone do not establish audible output.
- Autoplay rejection keeps a usable sound action visible until playback starts. Mic permission help and sound activation must not be confused.
- Admin mute, unmute permission, kick, full meeting, private link and revoked link retain their existing protections.

### Recovery and lifecycle

- Refresh before entry, during permission, during signaling, while listening and while speaking.
- Back/forward cache, short app switch, screen lock, incoming phone call, network loss/recovery and a slow connection.
- Explicit Leave never restores capture or sound through a late promise or reconnect.
- Refreshed guests keep their meeting/name and get the safe rejoin screen. Expired/removed sessions receive the correct explanation.
- A second tab cannot silently steal the call repeatedly or generate a reconnect fight.

### Feedback and observability

Show immediate action feedback, a useful persistent state while waiting, and specific recovery after failure. In controlled healthy-network tests, record time from tap to room admission and first remote playback; separate time spent waiting on the user’s permission choice. Do not count an empty room as a media failure.

If diagnostics are added, record a per-attempt random identifier, chosen mode, phase durations, coarse capability support and error category. JavaScript can record that capture was requested; it cannot reliably record that the OS actually displayed a prompt. Do not log audio, names, tokens, raw meeting URLs, SDP or peer addresses into general analytics. A user-requested local diagnostic report can expose additional redacted detail deliberately.

## Artifacts and verification performed

- Production-versus-workspace file comparison and measured browser states are retained in [evidence JSON](/Users/davell/Documents/github/pvp/docs/prototypes/mobile-meeting-ux-evidence.json).
- The [interactive concept](/Users/davell/Documents/github/pvp/docs/prototypes/mobile-meeting-ux.html) covers invitation, denied/unanswered/unavailable microphone, listener/speaker mode, playback activation, refresh/rejoin, interruption, full/private/unavailable meeting and explicit leave.
- Its simulated flows and scenario menus were exercised in Chromium and WebKit at 320–430px widths with no JavaScript errors or document overflow. Form input text is 16px. These are prototype checks, not an implementation of listen-only calling or permission recovery.
- Physical iPhone gesture, focus-zoom, permission-dialog and audio-route verification remains part of implementation acceptance. No production changes were made for this proposal.
