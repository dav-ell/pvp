# PVP design direction · November 1, 2026

The website front page has since moved to the [peer-network direction](NETWORK-FRONT-PAGE.md): a centered invitation with anonymous room clusters. The architectural illustration remains in the native Rooms welcome. The study below records the preceding visual-system work.

The earlier Rooms screen repeated large outlined containers, competing headings, and instructions that should have been evident from the interface. This revision gives the room itself a visual identity and brings the core actions into a compact, consistent system. PVP is still for small recurring groups with a reusable room link.

## Reference study

These are design observations from the live sites, not claims of endorsement or affiliation. Reference screenshots were inspected locally; no reference artwork, proprietary fonts, logos, or copy is included in PVP.

| Reference | What the study informed |
| --- | --- |
| [Dropbox Brand](https://brand.dropbox.com/), the [CSS Design Awards 2025 Website of the Year](https://www.cssdesignawards.com/blog/2025-website-of-the-year-winners/430/) | Build one system across type, color, image and interaction. Its [typography](https://brand.dropbox.com/typography) and [color](https://brand.dropbox.com/color) guidance informed the decision to assign explicit roles to display type, functional labels and accents. |
| [Teenage Engineering](https://teenage.engineering/products) | Give the object room to carry the composition. For PVP, an original architectural room replaces generic avatars and placeholder cards. Navigation and supporting copy get less visual weight. |
| [Family](https://family.co/) | Make illustration feel native to the product, and keep controls legible beneath the personality. PVP uses its own simple room illustration rather than borrowing Family's mascots. |
| [Cosmos](https://www.cosmos.so/) | Study the relationship between large typography, negative space and a clear action. PVP keeps the room library focused on entering or sharing a room. |

## Visual decisions

- **A room as the signature.** The shared SVG depicts an open door, a small table, and three chairs. It is original vector artwork, used in the web welcome and native Rooms view. Existing rooms use restrained numbered rows, names and actual presence rather than decorative cards or invented activity.
- **Type with distinct jobs.** Instrument Serif carries the invitation and room names. Manrope handles forms, navigation, status and controls. Both font files are bundled locally with their SIL Open Font Licenses; loading does not call a font service.
- **Forest, celadon, paper and terracotta.** Forest is the primary action and text color. Celadon sits behind the room and informs the selected state; terracotta belongs to the table illustration. Color no longer competes with a live video feed.
- **One quiet navigation.** Rooms, People and Settings sit in a horizontal header. The native compact header offers the same destinations in a menu. Website account actions remain available from Settings on a phone.
- **Fewer competing surfaces.** The empty library is one composition. Saved rooms form a list with an enter action and a copy control. The invitation input is a row, not another feature card. Room settings use spacing and rules to establish hierarchy.

## Component details

Primary buttons have an 8 px radius, a 44 px minimum web target and explicit hover, pressed, focus and disabled states. Utility buttons retain accessible names when their visible text is reduced to an icon. Inputs use a 7 px radius and a minimum 46 px height. The spacing rhythm uses 4, 8, 12, 16, 24, 32, 48 and 64 px steps, with optical adjustments around the artwork and display type.

The phone layout puts artwork in the document flow so it cannot obscure copy. Room headers and actions wrap on narrow screens. Native layouts also switch composition for large text. The call stage retains its full-window video, contained framing and stable media nodes; shared type and accent changes carry through its controls. Motion respects reduced-motion preferences.

## Review record

Local browser screenshots cover the [landing page](screenshots/site-welcome.png), [empty Rooms](screenshots/site-rooms-empty.png), [populated Rooms](screenshots/site-rooms.png), [mobile landing](screenshots/site-welcome-mobile.png), [mobile rooms](screenshots/site-rooms-mobile.png), and [invitation entry](screenshots/site-invitation-mobile.png). The native integration refreshes the actual Rooms screenshot. Existing browser regressions check the responsive room flow, keyboard and focus handling, camera framing, persistent media nodes, encrypted calls and leave/rejoin. Flutter checks include narrow layouts and double text size. Production release status is unchanged by this design revision.

Validation for this revision: the 73-test browser suite passed, followed by the six Chromium/WebKit mobile, call and room tests after the final component adjustments. Five motion tests passed with an added horizontal marker check. Flutter analysis and all 126 tests passed, including explicit target-size checks and double text size. Native/browser and native/native encrypted-call integration passed. Screenshot review checked widths 320, 390, 768 and 1440 in both browser engines, including mobile sign-out and absence of page errors.
