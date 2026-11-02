# Connection inspector

During a call, click **Connection inspector** in the Mac app's top bar or the browser's call controls. The inspector uses observations from that call; it contains no illustrative IPs or generated packet rows.

## What the display establishes

The diagram displays the selected ICE candidate pair's reported local and remote addresses, ports and protocol. The inspector follows `transport.selectedCandidatePairId`; when that field is unavailable it accepts only one succeeded nominated/selected pair. Multiple possible paths, missing candidates or unavailable statistics do not produce a direct-path claim. State changes and failed samples clear that claim, and the browser explicitly marks old samples as stale.

The detailed view includes actual candidate endpoints, tested-pair states and STUN request/response counters where exposed, incoming/outgoing RTP counters, selected-pair byte counters, DTLS state/ciphers and SRTP cipher. Every observation has its source and sample time. The event timeline contains application signaling events and WebRTC state changes, not individual packets.

The Mac client obtains signaling IPs and ports from the live `dart:io` socket after the authenticated, non-redirecting WebSocket handshake. It does not resolve a hostname and pretend the result is the active socket. The browser shows its actual WebSocket URL and state and explicitly marks its socket tuple as unavailable. Its API does not expose that tuple.

Configured STUN URLs are labeled as configuration. A STUN URL reported with a discovered candidate is labeled as a reported server. Neither is represented as an observed packet destination IP. TURN remains disabled and relayed candidates remain rejected. The display does not silently introduce a relay fallback.

## Independent verification

The inspector builds copyable `tcpdump` commands from validated literal IPs, numeric ports and the reported protocol. Run them in Terminal during the call. Mac commands use `pktap,all`, which includes loopback and tunnel interfaces; browser users can choose Linux's `any` interface. PVP does not execute a privileged capture command, ask for an administrator password, or capture unrelated machine traffic.

The media filter matches both directions at the reported peer endpoint. If its address is hidden, a literal local **host** candidate can supply a local-socket filter. A public STUN/NAT mapping is never substituted as a local binding. If neither tuple is usable, the filter is unavailable. Native signaling has a separate filter for its actual service socket. Stop capture with Control-C. For a capture to inspect in Wireshark, append `-w PVP-call.pcap` to the command before the quoted filter; the capture file contains the matching encrypted network traffic.

The selected candidates describe ICE endpoints. A public NAT-mapped local endpoint can differ from the IP/port captured on the Mac before router translation. Browser privacy can hide addresses, including peer-reflexive candidates; these remain unavailable rather than being guessed from another candidate or from DNS. VPN encapsulation changes what is visible on physical interfaces. RTP/WebRTC counters and packet captures count different layers, so totals need not be equal.

The app's display and JSON export are app-reported evidence. An altered app could fabricate them. Users checking with their own `tcpdump` or Wireshark obtain independent observations of the traffic. Endpoint observations establish the network path; peer identity still depends on authenticated signaling and independent comparison of the existing certificate verification code.

References: [WebRTC statistics](https://www.w3.org/TR/webrtc-stats/), [ICE connectivity checks](https://www.rfc-editor.org/rfc/rfc8445.html), and [`dart:io` socket endpoints](https://api.dart.dev/dart-io/Socket/remotePort.html). On this Mac, `man tcpdump` documents `pktap,all` including loopback and tunnels.

## Data handling

Observations and a bounded 120-event timeline stay in memory. Call teardown clears media endpoints and events. **Save report** creates an allowlisted JSON snapshot locally, only when requested. Native export uses a user-selected file with a save panel; the browser downloads a JSON file. Reports include IP addresses and timestamps but exclude credentials, cookies, SDP and media payloads. Export is diagnostic evidence, not cryptographically signed proof.

Inspector screenshots made during integration tests contain real observed endpoints and are kept under ignored `.build/inspector/screenshots/`, outside the documentation screenshots intended for publication.

## Release and validation — October 4, 2026

Flutter 1.0.3+4 and signaling/browser 0.3.2 use the existing authenticated calling protocol and database schema. Existing native clients continue to use it. The isolated patched Flutter SDK is used without changing other Flutter apps or the global SDK.

Local validation passes 17 browser/security scenarios, 10 Flutter unit/widget checks, Flutter analysis, five Rust signaling tests, strict signaling clippy and the Rust launcher check. Browser integration compares displayed and exported endpoints and counters to actual engine reports, including legitimate ICE path changes; it exercises mobile layout and teardown. Native integration checks selected endpoints against live stats, confirms the actual signaling socket port, opens the inspector, and verifies browser/native calls in both directions plus native–native DTLS.

Fixtures using documentation-only address ranges are confined to model tests. Product observations and integration screenshots come from real engine/socket data. Native compatibility tests inject empty local capture streams and receive generated browser media; they do not prove physical microphone transmission. That separate hardware test remains blocked by denied macOS microphone permission from the audio release.

The Mac release is universal, development-signed, sandboxed and hardened; it is not notarized. See [the release manifest](inspector-release.json) for hashes, installation backup and deployment validation.

All five production browser scenarios and the native production integration suite passed against `https://lopixel.space`, including the inspector's live endpoints, both browser/native call directions and native–native DTLS. The deployed server is 0.3.2. Eight exact verification accounts were removed afterward and SQLite integrity is `ok`. Existing game and relay services remain active. The installed Mac app is 1.0.3; the previous 1.0.2 app is backed up at `.build/PVP-before-inspector-1.0.2-1791135636.app`. Protected server binary/database rollback is `/var/backups/pvp/inspector-2026-10-04-1791135590`; the upgrade was gated on no active signaling WebSockets.
