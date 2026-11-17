# Connection inspector

During a direct call, open **More → Connection**. In a group call, use a participant's connection details. The inspector reports ICE candidate types, tested-pair states, media counters, and DTLS/SRTP details from the active call. It also shows bandwidth use and lets you set separate limits for sending and receiving camera and screen video.

The selected ICE pair describes the active media path. The browser marks old samples as stale. Compare the certificate verification code with your peer over a separate trusted channel to check the current connection's certificates.

**Save report** creates a local JSON snapshot. Connection details and reports omit network addresses, ports, and packet-capture commands. The timeline includes application and WebRTC state changes. Call teardown clears media observations. Direct WebRTC peers exchange network addresses to establish the connection.

## Release and validation — October 4, 2026

Flutter 1.0.3+4 and signaling/browser 0.3.2 use the existing authenticated calling protocol and database schema. Existing native clients continue to use it. The isolated patched Flutter SDK is used without changing other Flutter apps or the global SDK.

Local validation passes 17 browser/security scenarios, 10 Flutter unit/widget checks, Flutter analysis, five Rust signaling tests, strict signaling clippy and the Rust launcher check. Browser integration compares displayed and exported endpoints and counters to actual engine reports, including legitimate ICE path changes; it exercises mobile layout and teardown. Native integration checks selected endpoints against live stats, confirms the actual signaling socket port, opens the inspector, and verifies browser/native calls in both directions plus native–native DTLS.

Fixtures using documentation-only address ranges are confined to model tests. Product observations and integration screenshots come from real engine/socket data. Native compatibility tests inject empty local capture streams and receive generated browser media; they do not prove physical microphone transmission. That separate hardware test remains blocked by denied macOS microphone permission from the audio release.

The Mac release is universal, development-signed, sandboxed and hardened; it is not notarized. See [the release manifest](inspector-release.json) for hashes, installation backup and deployment validation.

All five production browser scenarios and the native production integration suite passed against `https://lopixel.space`, including the inspector's live endpoints, both browser/native call directions and native–native DTLS. The deployed server is 0.3.2. Eight exact verification accounts were removed afterward and SQLite integrity is `ok`. Existing game and relay services remain active. The installed Mac app is 1.0.3; the previous 1.0.2 app is backed up at `.build/PVP-before-inspector-1.0.2-1791135636.app`. Protected server binary/database rollback is `/var/backups/pvp/inspector-2026-10-04-1791135590`; the upgrade was gated on no active signaling WebSockets.
