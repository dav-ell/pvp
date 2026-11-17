# Production security remediation — November 17, 2026

Signaling 0.3.29 and the hardened UDP relay are deployed to the existing Lopixel
VM. The relay now has 11 descriptors, down from 3,328 immediately before this
rollout. Its source caps simultaneous backend socket/readers at 256 and expires
idle readers. It runs as dedicated `pvp-relay` with no added privileges, no core
dumps and a 1,024-descriptor hard limit. See the deploy drop-in. Caddy, frps,
SSH, Tailscale, firewall rules and game backend routing were preserved.

Signaling remains the `pvp` identity. Session creation times survive renewals;
all sessions now have a 90-day absolute ceiling in addition to 30 idle days.
Older sessions receive a conservative estimated creation time from their stored
expiry. SQLite/rusqlite and Tokio are updated and tied to the new binary hashes.

A consistent private SQLite backup and both old binaries/units were retained
under `/var/backups/pvp/security-20261117T194229Z`. All 13 existing table counts
match before and after migration (users 9, sessions 4, friends 6, history 23,
meetings 7, meeting_members 12, meeting_controls 1, meeting_access 7,
meeting_blocks 0, discovery_preferences 1, meeting_visits 0, meeting_network 0,
meeting_speaking 0). Public HTTPS health reports 0.3.29.

Deployed SHA256:

- signaling: `64218fb2a7d252db0c4db06bf1b0aedfa199f813b4bd98967432f3c3f3373d96`
- relay: `79c282327319a4d0604c005eb2bc7ce63a9971c91699e00d749789ffee27bc22`

The existing supported signed universal Mac release remains 1.0.20+21, SHA256
`6804124166a158e2203f1bef877e0360efd240795526b1ef52e6a49bfa5d92ad`.
All older downloadable archives were moved into a root-only private backup;
old URLs return 404 and the supported URL returns 200. Existing installations
are not remotely upgraded. Users should use the supported download. No Windows,
Linux or Android native build is supported by this release policy.

Dart's eMudhra advisory explicitly excludes macOS/iOS/Web because those platforms
use Apple/browser certificate verification. Android/Windows and unpatched Linux
builds would require Dart >=3.13.7 / Flutter >=3.47.8; do not publish those builds
using the older local Mac build SDK. [Dart maintainer advisory](https://github.com/dart-lang/sdk/security/advisories/GHSA-frr6-h895-5pxp).

Validation: 37 signaling tests, four relay tests, 81 browser tests and 129 Flutter
unit tests pass. Browser tests use real loopback signaling and synthetic media.
Default macOS runs now select muted headless Chromium. WebKit is explicit opt-in
because synthetic tones can reach physical speakers. Physical capture/native
live-call integration and a new Mac binary release were not performed.
Pre-existing native/UI changes were preserved, tested and committed.

OSV scanned 420 locked Rust/Dart versions. Only optional legacy-client maintenance
notices for `audiopus_sys` and `paste` remain; neither is a new High/Critical
application vulnerability. The supported Flutter app does not use that legacy
Rust media path. Blocking scheduled CI audits retain those notices explicitly.
Keep weekly scans and track new SQLite/Tokio/Flutter/WebRTC and OS security fixes.
