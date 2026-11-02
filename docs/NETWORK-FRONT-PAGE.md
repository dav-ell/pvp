# Network front page

The website now uses a centered invitation surrounded by peer clusters. The composition takes inspiration from the open central space of [Cosmos](https://www.cosmos.so/) and the activity-driven front page of [GitHub](https://github.com/). PVP's graphs, typography, palette and interactions are its own.

[Desktop preview](screenshots/network-home.png) · [700 px preview](screenshots/network-home-700.png) · [Phone preview](screenshots/network-home-mobile.png) · [Explanation](screenshots/network-explained.png)

## What a visitor sees

Each cluster represents a room size. Each dot represents one peer in that size, and the lines illustrate peer-to-peer connections. Hovering, focusing, or tapping a cluster explains the pattern. The graph supports keyboard activation, pausing motion, and the system's reduced-motion preference. Core entry actions lead directly to the existing create-room or invitation fields.

A peer is not identified by an IP. Network address translation can put multiple devices behind one public address; see [RFC 4787, section 3](https://www.rfc-editor.org/rfc/rfc4787.html#section-3). PVP keeps them separate as peers and publishes no addresses.

## Live activity and privacy

Room activity is off by default. A host of a room accessible by link can open **Room settings → Public room map → Share anonymous room activity** in the browser. The current native source includes the same control; the published Mac 1.0.20 archive predates this interface. Private rooms cannot opt in. Other participants can see the sharing notice in the room preview/settings.

The public `/api/network` endpoint contains only a histogram of live, joined peer counts for opted-in, unrevoked rooms. For example, `{ "peers": 3, "count": 2 }` means two shared room shapes with three peers each. It exposes no room names, invitation links, room/account/session identifiers, network candidates, IP addresses, locations, audio/video state or certificate data. Pending invitees and offline peers are excluded. The read is bounded by active rooms rather than all saved rooms.

The page samples up to eight clusters on desktop and six on phones, spreading the sample across available sizes. The layout can show fewer when space is tight. Positions and dots are anonymous representations of those counts. A node does not persistently track a person, and a cluster is not a link into a room. Showing a room's anonymous size does not make it publicly joinable without its invitation.

Live counts come from room membership, not measured transport telemetry. Lines are explicitly labeled illustrations and do not claim that every connection is established, that a packet was received, or that encryption was independently verified. Call-specific connection evidence remains available inside the call.

The page refreshes at 15-second intervals while visible, stops polling when hidden or signed in, and uses bounded requests without account cookies. With no opted-in activity or an unavailable service, it shows an explicitly labeled P2P example. It does not invent live rooms or live traffic. Disabling sharing removes that room from subsequent snapshots; an open page can retain its preceding snapshot until its next refresh.

## Checks

The browser suite passes 79 tests. After the final resize transition fix, all 15 focused network, polish, motion and room-experience tests pass again. Dedicated Chromium and WebKit tests cover the empty/example state, actual live room membership, owner-only opt-in through the interface, two peers sharing the local IP remaining separate dots, payload privacy, disabling sharing, service failure, reduced motion, keyboard interaction, entry actions and narrow viewports. Layout checks cover 320–1440 px, the reported 700 px width, enlarged headings, CSS zoom, full drift phases and resizing with motion enabled. All 36 signaling tests and strict Clippy pass. The preceding source upgrade also passed Flutter analysis and 126 tests; native code was not changed for this layout patch.

The screenshots show the example state from the public deployment. Browser/signaling **0.3.25 is live at [lopixel.space](https://lopixel.space)** as of November 1, 2026. See [the latest release evidence](network-layout-release.json) and [the initial homepage release](network-release.json).

## Layout around the invitation

The SVG uses the hero's actual pixel dimensions. Placement measures the rendered text line boxes, both buttons, the reserved graph explanation and the footer. A packing pass prefers positions around the invitation, then shrinks or omits clusters when those positions are crowded. Each reserved footprint includes captions, halos, rotation and the entire drift envelope, with additional space around copy and other clusters. A mask provides a second boundary around the copy.

Viewport changes, font loading and content resizing recalculate placement. The hero can grow with enlarged text. Responsive moves take effect immediately, and remove any retiring shape immediately, so an old larger graph cannot briefly overlap text at its new position. Existing cluster elements and their independent drift phases survive ordinary count updates. Hover and keyboard explanations occupy reserved space below the invitation instead of floating across other graphs.

## Motion and forwarding

Every cluster drifts in two directions on its own 13–21 second cycle, peer halos breathe on staggered cycles, and small illustrated signals travel along the links. While labeled examples are visible, one example gains or loses a peer approximately every seven seconds, with a short crossfade. Live shapes change only when shared membership counts change. Larger examples use the browser implementation's four-child tree for one video source: first-hop peers receive it, then forwarding peers pass it onward. Filled dots mark sources; double rings mark forwarders. Fainter complete links retain the distinction that audio remains directly connected. Six or more participants indicate eligibility; codec support, data limits and actual client state can require direct-video fallback. The public histogram does not observe whether forwarding is active.

Pause stops CSS and path animations together. Motion also stops for reduced-motion preferences, hidden pages, signed-in views and when the graph scrolls offscreen. Replaced diagrams cancel their old animations. Public postdeployment checks verified all 38 asset hashes, animated rendering, mobile WebKit, permission-free listening, generated audio/video, observed encrypted direct transport, live opt-in sizes and leave/rejoin. Temporary verification records were removed, existing durable records match the backup, and database integrity and foreign keys pass. Only signaling restarted, with zero established signaling connections. Binary/database rollback and a protected off-VM backup are retained.
