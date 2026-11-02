# Brand and product consolidation proposal

October 30, 2026 · Original strategy, updated October 31 after implementation

The PVP name is retained. The implemented room-first browser/Mac experience and feedback fixes are documented in [the upgrade record](ROOMS-UPGRADE.md). The investigation and research below describe the reasoning; timelines and research criteria remain planning guidance, not completed user studies.

**Recommendation: make this a familiar room for a small group that meets again.** Use **small-group calling** as the plain category and **A room for your people.** as the working brand promise. The confirmed primary audience is small recurring groups. That choice should govern the home screen, naming, invitation, call experience, native app, and future feature decisions.

The unit of the product becomes a durable room. A conversation happens inside it; a link brings people back. Voice, optional video, chat, sharing, ringing and moderation support that one job.

## What the investigation established

Reviewed the web entry, navigation and calling source; current Flutter UI source; recovery app; shared calling library; design and release records; and official competitor sources. Built the current signaling service and opened it in Chromium against a disposable local database. Confirmed guest-first entry and the account flow that returns to Friends, with three creation actions: Create meeting link, Group call, Add a friend. Observed no browser JavaScript errors during that walkthrough. Created no production accounts or meetings and requested no physical media access.

Local evidence is in `.build/brand-audit/`: entry and account-home screenshots, recovery landing screenshot and `observations.json`. Some older screenshots under `docs/screenshots/` depict earlier designs; they are not evidence of the current interface. Native findings below come from source and existing validation records, not a newly launched Mac build. This investigation did not independently verify production deployment or call quality across external networks.

The accompanying standalone concept was checked in Chromium for keyboard tab navigation, name entry, simulated joining/controls and leave/return. Its three views fit widths 320, 390, 768 and 1440 without horizontal page overflow; no JavaScript errors or external HTTP requests were observed. This checks the proposal artifact, not production media behavior or full accessibility compliance.

| Finding | Evidence in this checkout | Consequence |
| --- | --- | --- |
| The product changes its primary task after sign-in. | `web/index.html:133–145` leads with reusable links; `web/app.js:759` selects meetings for guests and people for accounts. | An account should add convenience to the same product, rather than redirect people into a social network. |
| Several ways of connecting compete at once. | `web/index.html:169–184`: Meeting links, Zoom conversion, Friends, Recent calls, voice rooms, group-call creation. | Choose one primary destination and one creation action. |
| “Your room” and a recurring meeting have different lifetimes. | `docs/VOICE-ROOMS.md:5–9`: standing sidebar destination, ephemeral live room; `docs/RECURRING-MEETINGS.md`: durable meeting identity. | A shared label requires explicit lifecycle and admission design. A cosmetic rename will not unify these models. |
| A competitor occupies permanent navigation. | `web/index.html:141,172`; `docs/GUEST-LINKS-ZOOM.md`. | “Open more private Zoom” makes the product sound like an alternative mode of Zoom. The feature creates a separate call and transfers no host or passcode controls. |
| Three visual generations survive in the CSS. | `web/styles.css:1,126`, `web/polish.css:2`: paper/forest, dark/Discord blue, then dark/violet. | A new identity needs consolidated tokens and components, not another override stylesheet. |
| The camera mark suggests video first. | `web/icon.svg`; `desktop/lib/ui/app.dart:261–289`. Voice and listen-only entry already exist. | Develop a mark about a place or gathering that still works with every camera off. |
| There is also an intentionally separate recovery product. | `recovery/README.md:3–24`; `recovery/index.html:25–29,65–79`. | Fellowship has a different audience, consent model and identity boundary. Keep that boundary explicit. |

## Brand foundation

**Audience:** people who already have a small group and want to meet regularly: a weekly check-in, a book circle, a study group or a recurring catch-up. The first validation cohort should be existing groups of roughly 3–8 people. That is a proposed research focus, not a change to the implemented 16-person ceiling or proof of the best commercial audience.

**Job:** “Give our group one familiar place to come back to, without asking everyone to set up another account.”

**Positioning:** For small groups that meet again, this is a familiar calling room with one reusable invitation. People can arrive to listen, speak when ready and turn on their camera if they choose.

**Promise:** A room for your people.

**Personality:** welcoming, calm, capable, candid. Express warmth through names, generous space and considerate defaults. Use short, literal language around actions and failures.

**Reasons to believe:** durable invitations; accountless guest entry; listening without camera or microphone permission; optional cameras; encrypted peer connections; a restrained room interface. These are a useful combination around a specific job. They are not individually unique market claims.

**Product filter:** a new feature should help someone create a room, invite their group, join successfully, participate comfortably or return next time. Features outside that chain need a stronger case before entering the primary interface.

## One product model

| Concept | Meaning | Product treatment |
| --- | --- | --- |
| Room | A durable named place with a stable invitation, owner/admin roles and an explicit access policy. | Primary object on the home screen. |
| Conversation | A live gathering in that room. It ends when people leave; the room remains. | One active stage that adapts to listening, voice, camera and sharing. |
| Invitation | A way into a particular room, governed by its admission rules. | Preview → name → listen/microphone choice → room. |
| People | Optional saved contacts and friend relationships. | A secondary invitation/calling convenience. |
| Account | A way to retain access and manage supported features across sessions. | Optional for joining; signing in keeps Rooms as home. Do not imply unimplemented room ownership recovery. |

Proposed main navigation: **Rooms**, then **People**; **Settings/Help** in a utility position. The primary action is **Create room**. Each room offers **Join room** and **Copy link**. Recent activity can appear within a room or secondary history; it does not need equal standing with Rooms.

New visitors see a concise explanation, Create room, and a way to open an invitation. Returning visitors see their available rooms. Signing in adds supported account features without changing that hierarchy. Guests must be told what is retained on the current browser/device; cross-device room sync or host recovery must not be implied until implemented.

An invitation always lands on that room's preview, even when the person is signed in. Show the room title and admission policy, a name field, **Join to listen** and **Join with microphone**. Camera remains off. Listening requests no device access; the microphone choice must match actual capture and mute behavior. Access and host/admin controls remain written and explicit.

The room keeps the group name, participants, a stable compact control dock and a clear Leave action. Chat and screen sharing support the conversation. They do not create separate product identities. Expose voice-only layouts as complete experiences rather than empty video grids. After leaving, provide a clear route back to the same room.

Define what persists: the room identity, invitation, access policy and supported membership/roles. Existing call chat clears on leaving (`docs/MEETING-CHAT.md`); the redesign must state that behavior and avoid implying persistent messages, files or a group inbox. Any persistent conversation history is a separate product and storage decision.

## Feature consolidation

| Existing surface | Proposed destination | Handling |
| --- | --- | --- |
| Recurring meeting links | Rooms | Foundation of the new product. Preserve IDs, URLs, membership, roles and access policy. |
| “Your room” and live voice-room discovery | Rooms presentation, with existing behavior retained during migration | A standing personal room requires durable identity and deliberate admission design. Do not silently convert friends-of-participants admission into link access. |
| Standalone “Group call” creation | Room creation/invitation actions | Consolidate the visible flow first. Preserve active calls and protocols while adapters converge. |
| Direct friend calling | People → Call, or an invitation action | Preserve ringing and incoming-call handling; use the shared room-stage components. Keep temporary direct calls distinct from durable rooms until their identity/lifecycle is designed. |
| Friends, requests, presence | People | Useful optional capability; remove the friend-acquisition requirement from the core loop. |
| “Open more private Zoom” | Secondary Help/migration tool, if retained | Remove comparative branding from primary navigation. Explain that it creates a separate room. Preserve old deterministic links and their access rules. |
| Meeting admins and speaking turns | Room controls, with roles and policy visible | Advanced group options; do not assume all recurring groups want chair-guided sharing. |
| Bandwidth controls and connection inspector | Audio/video settings and troubleshooting | Preserve capability, keep technical details out of the healthy default room. Recent call polish already does some of this; retain it. |
| Fellowship recovery app | Separate product experience on the shared engine | Keep chosen names, isolated sessions, chair flows and privacy-specific copy separate. Do not cross-list recovery rooms or import social profile names. |
| Original UDP app and call library | Technical documentation | Retain implementation/project naming without making every internal module part of the consumer brand. |

## PVP identity

**Keep the PVP name.** The approved direction uses the existing name with one descriptor, Small-group calling, and one promise, A room for your people. The original camera mark is replaced by a doorway/place symbol, with matching browser, app, and menu-bar assets. Internal app identifiers and existing invitation formats remain compatible.

The production-source visual identity uses one shared semantic token source in `packages/pvp-ui/brand-tokens.json`, generated into browser CSS and Flutter constants with `scripts/sync-brand-tokens.mjs`. The earlier concept remains a design reference; it is separate from the implemented application.

Recommended visual territory: **a warm, contemporary room**. The accompanying [interactive direction](prototypes/brand-direction.html) uses the PVP working label and provisional artwork. It is a local UI simulation, not a production UI or a finished logo system.

| Element | Direction | Purpose |
| --- | --- | --- |
| Marketing/home base | Warm paper `#F7F4EE`, warm ink `#24272B` | A calm, readable sense of place. |
| Signature accent | Restrained amber `#F3BE7C` with dark text | Invitation and warmth; status colors remain separate. |
| Active conversation | Deep ink surfaces, the same accent and typography | Continuity with home while giving people and shared content priority. |
| Supporting colors | Muted clay and quiet neutrals | Limited variation for room identities and avatars. |
| Typography | Readable humanist/system sans; deliberate size hierarchy | Consistency in browser, mobile and native contexts. A custom family is a later self-hosted licensing/performance decision. |
| Mark | Original place/gathering/threshold exploration | Recognizable at favicon/menu-bar sizes and with cameras off. No generic video icon as the brand mark. |
| Iconography | Preserve the curated local Lucide family | Existing cross-platform investment is useful. |
| Motion | Preserve 110/180/280 ms foundation and reduced-motion support | Show actual state changes and speaking activity; avoid decorative idle pulses. |

Amber is an exploration, not the brand strategy itself. Assess it beside the existing violet identity using the same screens and user tasks. Final colors must pass contrast checks for every control/state. The final identity deliverables include a wordmark, original symbol, app icon, monochrome/menu-bar variants, typography scale, color roles, component states, motion rules and a short usage guide.

## Voice and claims

One clear action per control. Warmth belongs mainly in the landing page and empty states; device access, admission and recovery need literal copy.

| Current wording | Proposed wording |
| --- | --- |
| P2P HANGOUTS | Small-group calling |
| Your people. One link. Meet here anytime. | A room for your people. |
| Create meeting link / Create permanent link | Create room |
| Meeting links | Rooms |
| Get P2P meeting | Create room from invitation, inside a clearly described migration tool |
| Open more private Zoom | Move your group here, as optional migration/help copy |
| No friends yet / Add a friend | Your first room starts here / Create room, on the primary home |
| Join with mic | Join with microphone |
| Network details and quality readings on healthy calls | Connection and audio/video detail, on request |

Supporting copy: **Create a room, share the link, and come back together. Join to listen or use your microphone. Your camera is your choice.**

Keep claims specific: “No account needed to join,” “Camera off when you arrive,” “Listen without microphone access,” and “Encrypted peer connections.” Pair direct-call privacy explanations with the actual boundary: participants can learn each other's IP address; the service sees setup metadata; some networks cannot connect directly. Describe recording policy precisely rather than promising that nobody can record. A non-expiring invitation does not by itself guarantee permanent hosting or recover host control.

Remove blanket “more private than Zoom” positioning. Zoom supports optional E2EE, while Discord now applies E2EE by default to voice/video outside Stage channels. [Zoom encryption documentation](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0075502), [Discord encryption announcement](https://discord.com/blog/every-voice-and-video-call-on-discord-is-now-end-to-end-encrypted).

## Competitive frame

These are strategic interpretations of current official materials, checked October 30, 2026; they are not a full market study.

| Reference | Expectation to account for | Implication |
| --- | --- | --- |
| [Discord](https://discord.com/) | Gaming, expressive groups, persistent communities and drop-in voice. | Its sidebar and vocabulary suggest a much broader community product. |
| [FaceTime](https://support.apple.com/en-us/109364) | Immediate personal calling; Android/Windows guests can already join browser links. | Browser guest access alone is insufficient differentiation. |
| [Skype](https://support.microsoft.com/en-us/skype/skype-is-retiring-in-may-2025-what-you-need-to-know) | Contacts and direct calling as a remembered model. Consumer Skype retired in May 2025. | Treat it as a historical mental model. |
| [Zoom Meetings](https://www.zoom.com/en/products/virtual-meetings/) | Work meetings, collaboration and AI productivity. [Guest entry](https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0059553) can already work without an account, subject to host settings. | Differentiate through audience and the complete recurring-group experience. |
| [Whereby Meetings](https://whereby.com/information/meetings) | Browser rooms and guest entry with no download/login; [room links stay the same](https://support.whereby.com/en/articles/4369602). | Reusable rooms are a coherent product model, not unoccupied market territory. |

The hypothesis to validate is **continuity for a small recurring group, with comfortable listening and optional video**. Do not launch with a claim that reusable links, encryption or accountless joining are unique.

## Sequence and reviewable deliverables

Estimates below are planning ranges for focused work, not a delivery commitment. Implementation effort depends on room-lifecycle decisions, host identity and how much existing protocol behavior is retained.

| Phase | Concrete work | Exit condition |
| --- | --- | --- |
| 1. Brand/product brief, roughly 2–3 focused days | Finalize audience, positioning, vocabulary, room lifecycle/admission mapping and claims inventory. Interview 4–6 recurring groups about their current invitation and return workflow. | One agreed product model; a shortlist of actual group needs and migration constraints. |
| 2. Identity and connected prototype, roughly 4–7 days | Identity applications using the retained PVP name; landing, Rooms, invitation, active room, leave/return; mobile and Mac variants; permission/reconnect states. | A consistent identity and a prototype newcomers can understand and use. |
| 3. Consolidation, roughly 1–2 weeks after scope is set | One Rooms home for guests/accounts; unified visible creation flow; shared tokens emitted to CSS/Dart; consolidate CSS layers; apply copy and brand assets. Preserve existing call/media ownership. | Core create → share → join → leave → return works across web and Mac without regressions. |
| 4. Pilot and rollout, roughly one recurring-group cycle or more | Pilot existing groups across their real networks and a second gathering; complete branding surfaces, migration checks and release evidence. | Returning groups can reuse their invitation; old links and roles work; connection failures are understood and resolved or transparently scoped. |

The first implementation slice should cover **Rooms home → create → copy invitation → guest preview → listen/microphone choice → room → leave and return**, while keeping the current name. This tests the consolidation before committing every surface to a new identity. The PVP name is retained throughout.

## Technical and migration boundaries

- Build the durable room experience on recurring meeting identity. Initially use adapters/presentation changes for ephemeral voice rooms and direct calls. Do not rewrite the whole transport to begin the rebrand.
- Preserve meeting IDs, existing URL/hash formats, `pvp:` deep links, database records, membership, moderation, access rules and guest-host sessions. A rename must not turn a private meeting into a public room or grant a Zoom-derived room an invented host.
- Keep Fellowship cookies, chosen names and room lists isolated. Sharing a media library does not require sharing identity or navigation.
- Guest host controls currently depend on a retained session; losing it loses management rights. Design durable host recovery or a clear supported ownership-transfer path before claiming reliable group administration across devices. Invitation possession alone must never confer host powers.
- Retain Keychain/session storage namespaces, bundle identifiers and old deep-link handlers unless there is a deliberate migration. Changing the display name does not require changing every internal identifier. If the domain changes, retain the old origin/links and design session/ownership continuity rather than assuming redirects move cookies.
- Preserve capture consent, listen-only admission, late-permission cancellation, camera teardown, real speaking state, moderation enforcement and native renderer ownership. The shared call stage is a presentation goal, not permission to merge security states.
- The implementation still rejects TURN/relay candidates. Test real household, mobile and restrictive networks before making reliability promises. Keep the current direct policy explicit; any relay fallback requires a separate technical/product decision and updated claims.
- Retain the useful Lucide assets, call dock/context sheets, keyboard support and reduced-motion behavior. Generate semantic color/type/spacing/status/motion tokens into CSS and Dart rather than manually maintaining parallel palettes.

## How to judge success

Proposed acceptance criteria, not measured results:

- At least 4 of 5 unfamiliar participants explain the product as a reusable place for a small group after a short introduction and find the create/join action without help.
- Guests can open an existing invitation and enter to listen without an account or a device prompt. A denied microphone permission does not block listening.
- Signing in preserves Rooms as the home and opening an invitation preserves the intended room.
- Existing groups use the same invitation for a second gathering. Track successful return by group, not just the number of links created.
- Report time from opening an invitation to receiving the first real remote audio, join failures and reconnect outcomes on the actual browser/network matrix. Establish a baseline before setting a performance target.
- Room access, host/admin roles and recovery behavior survive the intended restart/session scenarios. Existing open/private/Zoom-derived invitations retain their documented policies.
- Web and Mac share the same nouns, brand assets, control meanings and call states. Verify keyboard, screen-reader, reduced-motion and large-text behavior; final colors meet contrast requirements.

Use consented research sessions and aggregated results that avoid participant names or attendance logs. The initial research question is whether this room-first model makes the product understandable and worth returning to; brand comprehension alone does not establish retention or product-market fit.

## Complete brand surface inventory

The identity rollout covers: landing and metadata; room/invitation/share copy; prejoin and leave screens; notifications and permission explanations; favicon/manifest; app/Dock/menu-bar icons; native app display name and menus; downloads/archives and launcher discovery; settings and Help; privacy/claims copy; screenshots and README; domain/redirect planning. Preserve old compatible identifiers and assets wherever existing installations or links require them.

The result should be a product someone can describe in one sentence and recognize at every step: **a room for their people, ready for the next time they meet.**
