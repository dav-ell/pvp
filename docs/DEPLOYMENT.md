# PVP signaling deployment

## Existing host

- Droplet: `mc-relay`, DigitalOcean ID `584889790`, New York 3, 512 MB.
- Host: `143.198.19.179`; public app: `https://lopixel.space`.
- Service: `pvp-signaling.service`, user `pvp`, loopback `127.0.0.1:8787`.
- Binary: `/usr/local/bin/pvp-signaling`; origin: `/etc/pvp/signaling.env`.
- Database: `/var/lib/pvp/pvp.sqlite`; retain it when upgrading.
- Caddy: `/etc/caddy/Caddyfile`, HTTPS with automatic certificate renewal.
- Existing `pvp-relay.service`, `frps.service`, UDP 19132, TCP 7000 and TCP 25565 are separate.

No API token or private SSH key belongs in this repository. The app server does not need a DigitalOcean credential.

## Build Linux from macOS

Build compiler output on a Linux volume to avoid macOS filesystem emulation issues:

```sh
docker run --rm --platform linux/amd64 \
  -v "$PWD:/src:ro" -v pvp-cargo:/usr/local/cargo -v pvp-build:/build \
  -w /src -e CARGO_TARGET_DIR=/build rust:1-bookworm \
  cargo build --locked --release --manifest-path signaling/Cargo.toml
mkdir -p .build
docker run --rm -v pvp-build:/build:ro -v "$PWD/.build:/out" \
  debian:bookworm-slim cp /build/release/pvp-signaling /out/pvp-signaling
```

The binary embeds the frontend. Rebuild after HTML/CSS/JavaScript changes. Run the test suite before deployment.

## Ubuntu installation

Copy the binary and the files from `deploy/` with your SSH/scp tooling. Run on the VM:

```sh
apt-get update
apt-get install -y caddy
useradd --system --home-dir /var/lib/pvp --shell /usr/sbin/nologin pvp
install -d -o pvp -g pvp -m 0700 /var/lib/pvp
install -d -m 0755 /etc/pvp
printf '%s\n' 'PVP_ORIGIN=https://lopixel.space' > /etc/pvp/signaling.env
chmod 0600 /etc/pvp/signaling.env
install -m 0755 pvp-signaling /usr/local/bin/pvp-signaling
install -m 0644 pvp-signaling.service /etc/systemd/system/pvp-signaling.service
install -m 0644 Caddyfile /etc/caddy/Caddyfile
ufw allow 80/tcp
ufw allow 443/tcp
systemctl daemon-reload
systemctl enable --now pvp-signaling
caddy validate --config /etc/caddy/Caddyfile
systemctl restart caddy
```

Allow TCP 80 and 443 in the attached DigitalOcean cloud firewall too, retaining existing rules. DNS must resolve to the droplet before Caddy can issue a certificate. Change both `PVP_ORIGIN` and the Caddy site address for another domain.

## Verify, upgrade, back up

```sh
curl --fail https://lopixel.space/health
systemctl status pvp-signaling caddy
journalctl -u pvp-signaling -u caddy --since '10 minutes ago'
```

Health identifies `direct-p2p` media. Local test accounts are not copied to production. Registration is open; calling requires an accepted friendship.

For upgrades, stage a new binary, retain the old one for rollback, atomically rename the new binary into place, and restart `pvp-signaling`. Do not overwrite an executing file or remove `/var/lib/pvp`. Restarting interrupts active ringing/calls because signaling stays in memory.

For a consistent backup, install `sqlite3` and run as root:

```sh
sqlite3 /var/lib/pvp/pvp.sqlite '.backup /root/pvp-backup.sqlite'
chmod 0600 /root/pvp-backup.sqlite
```

Protect backups as account data. Restore while the service is stopped, ensure ownership `pvp:pvp`, and restart.

## Verification on October 3, 2026

The deployed HTTPS service passed all four browser integration scenarios, including a real WebRTC audio/video connection with generated tracks, direct ICE candidates, live bitrate caps, accepted-friend calling, delayed recipient arrival, decline, and hangup. Three Rust authorization/history tests also passed. The new server used about 21 MB of memory after startup and had no service restarts during verification. Both existing game/relay services remained active. Temporary production verification accounts were removed afterward.

Physical camera/microphone capture and calls between separate external networks still require manual verification. Strict P2P has no TURN fallback. Credentials used for infrastructure setup were not copied into the app, repository, or deployed service.

The Flutter macOS client also passed native/browser WebRTC integration against this live service, including incoming calls with the native window hidden, both call directions, native video rendering, direct candidate checks, and Keychain persistence. Its temporary verification accounts were removed and SQLite integrity checked. Native clients use the existing authenticated API and WebSocket; no additional server ports or credentials are required.

The 0.3.0 security update passed five production browser scenarios and original 1.0.0 plus hardened 1.0.1 native/browser interoperability checks, including native–native DTLS. No signaling clients were connected during upgrade. Rollback artifacts are `/var/backups/pvp/security-2026-10-03`; see [the full review](SECURITY.md).

## Docker-independent Linux build

The final 0.3.0 binary is statically linked for `x86_64-unknown-linux-musl`. It was built with Rust 1.95.0, cargo-zigbuild 0.23.4 and Zig 0.13.0 after the local Docker daemon stopped responding. Other Docker processes were not restarted. The candidate passed an unprivileged health preflight on port 8788 before replacing production signaling.

```sh
python3 -m venv .build/cross-tools
.build/cross-tools/bin/python -m pip install cargo-zigbuild==0.23.4 ziglang==0.13.0
rustup target add x86_64-unknown-linux-musl
# Ensure cargo and rustc are from the same rustup toolchain, including its target.
PATH="$HOME/.cargo/bin:$PWD/.build/cross-tools/bin:$PATH" \
  CARGO_ZIGBUILD_PYTHON_PATH="$PWD/.build/cross-tools/bin/python" \
  .build/cross-tools/bin/cargo-zigbuild zigbuild --locked --release \
  --manifest-path signaling/Cargo.toml --target x86_64-unknown-linux-musl
# Output: signaling/target/x86_64-unknown-linux-musl/release/pvp-signaling
```

See [cargo-zigbuild's official instructions](https://github.com/rust-cross/cargo-zigbuild) for other platforms/toolchains.

## Audio update on October 4, 2026

Signaling 0.3.1 embeds the audio and startup fixes described in [the audio release record](AUDIO.md). The API, call protocol and database schema are unchanged. A staged static Linux binary passed an unprivileged health, asset and registration preflight. Production replacement was gated on no active signaling WebSockets; only `pvp-signaling` was restarted.

All five production browser scenarios passed, including two-way inbound audio energy, mute/unmute, microphone switching, partial track-replacement rollback and playback recovery. Four exact verification accounts were removed afterward. SQLite integrity is `ok`, deployed health is 0.3.1, the deployed binary matches [the release hash](audio-release.json), and `pvp-signaling`, Caddy, `pvp-relay` and `frps` are active.

Protected binary/database backups are `/var/backups/pvp/audio-2026-10-04-1791119548` for original 0.3.0 and `/var/backups/pvp/audio-final-2026-10-04-1791120484` before the final browser startup fix. Flutter 1.0.2 is installed with a local backup of the previous app. Physical Mac microphone transmission remains blocked in testing by denied macOS microphone permission.

## Connection inspector update on October 4, 2026

Signaling/browser 0.3.2 adds the embedded `/inspector.js` module and live inspector UI without changing the authenticated protocol or database schema. Flutter 1.0.3 is installed with a backup of 1.0.2. An unprivileged candidate preflight checked health, new assets and registration. The final binary was swapped only after confirming no active signaling WebSockets, and only `pvp-signaling` restarted.

All five production browser scenarios and native production integration passed, including displayed/exported selected endpoints, native signaling socket ports, both browser/native call directions and native–native DTLS. Eight exact temporary verification accounts were removed; SQLite integrity is `ok`. Health is 0.3.2 and all four existing services are active. Protected rollback is `/var/backups/pvp/inspector-2026-10-04-1791135590`. See [the inspector release](CONNECTION-INSPECTOR.md) and [hashes](inspector-release.json).

## Permanent recurring meetings release

This release deployed signaling/browser 0.3.6 and Mac app 1.0.7+8; the admin release below supersedes it. The additive `meetings` and `meeting_members` tables preserve stable URLs independently of live calls. Existing accounts, friendships, sessions and call protocols are retained. See [recurring meeting usage and migration](RECURRING-MEETINGS.md) and the [release manifest](recurring-meetings-release.json).

The candidate passed an isolated unprivileged health/assets, persistent-cookie and recurring-meeting API preflight. Production embedded assets match repository hashes; the installed signed app was reopened and its TLS connection to the existing VM verified. Only signaling was restarted. Binary/database rollback is `/var/backups/pvp/meetings-2026-10-04-1791167565`; the old native app was retained. A consistent integrity-checked database backup was also saved off the VM on the Mac. Use `scripts/backup-meetings.sh` to take another snapshot before moving the instance; backups are not scheduled automatically.

## Meeting admin release on October 5, 2026

Production signaling/browser is 0.3.7 and the installed Mac app is 1.0.8+9. Owners appoint admins; admins mute, allow unmute and kick members. Roles and enforced mutes persist in the additive `meeting_controls` table. Existing users, friendships and meeting rosters match the predeployment snapshot. See [admin behavior and compatibility](MEETING-ADMINS.md) and [validation, hashes and backup paths](meeting-admins-release.json).

The unprivileged candidate passed its API/assets/session preflight. Only signaling restarted. The universal signed Mac app reopened and established its TLS connection to the existing VM. Public assets match tested sources. Server binary/database rollback is `/var/backups/pvp/moderation-2026-10-05-1791202552`; the previous Mac app and an integrity-checked off-VM SQLite snapshot are retained. Native/browser admin and ordinary group integrations passed, including fresh native audio receiver state and kick capture teardown.

## Mac app download

Mac browsers show **Download for Mac** on the sign-in screen and in the authenticated sidebar. Caddy serves the current universal signed app at `/downloads/PVP-macOS-1.0.8.zip` from `/var/www/pvp/downloads`, with an attachment filename and `nosniff`. Only the exact published archive route is exposed; other requests continue to signaling. The package requires macOS 13+, supports Apple silicon and Intel, and is development-signed but not notarized. When publishing a new app, upload and hash-check its archive, then update both browser links and the exact Caddy route. See [release details](mac-download-release.json).

## Open meeting links release

Production signaling/browser 0.3.8 and Mac 1.0.9+10 add an opt-in **Anyone with the link** creation option. Existing links remain private. New access-policy and account-block tables are additive; existing accounts, friends, meeting rosters and roles were verified against the rollback snapshot. Browser, server, Flutter and signed native/browser integration checks passed. Only signaling restarted; Caddy reloaded to publish the new signed archive while retaining the old download URL. The Mac app was reopened; the installer leaves existing Keychain credentials and preferences untouched. See [usage](OPEN-MEETINGS.md) and [validation, hashes and rollback/portable backup paths](open-meetings-release.json).

## Meeting chat release

Production signaling/browser 0.3.9 and Mac 1.0.10+11 add **Chat** during group calls and recurring meetings. Text and accepted image/binary attachments travel directly over reliable DTLS peer data channels. Payloads and live history are not stored on the server. Files are consent-based and bounded to 100 MiB; receivers verify SHA-256 before saving. Only signaling restarted; Caddy reloaded to publish the signed universal archive while retaining earlier downloads. The installed app reopened, and its executable hash matches the packaged release. Existing database rows and integrity were verified, with a fresh portable snapshot retained. See [usage and protocol](MEETING-CHAT.md) and [validation, hashes and backup paths](meeting-chat-release.json).

## Meeting UX release on October 5, 2026

Mac 1.0.11+12 is installed and reopened; signaling/browser 0.3.10 is live. The meeting stage, toolbar, chat composer and connection details were updated, and the website links to the new signed universal download. See [the release record](meeting-ux-release.json) for validation, hashes and rollback locations. The production upgrade preserved the database and previous app; only signaling restarted and Caddy reloaded.

## Meetings library UX release on October 5, 2026

Mac 1.0.12+13 is installed and reopened; signaling/browser 0.3.11 is live. The meetings library, creation form, details and membership views use separate screens with persistent primary actions. The signed universal app is published through the new versioned download. All 38 Flutter tests and 26 browser tests passed. See [release validation, hashes and rollback paths](meetings-ux-release.json). The database and prior app are retained in rollback backups.

## Group video and screen-share fixes on October 6, 2026

Signaling/browser 0.3.12 is live, and Mac 1.0.13+14 is installed and published. Camera forwarding starts at six joined participants and stops at five. Encoded frames sent by the original source are labeled Direct; only delivery through another participant is labeled Peer-forwarded video. The release also includes the pending connection recovery and maximized screen-share quality changes. See [validation, hashes and rollback locations](group-video-fix-release.json).

The full browser, Flutter and server suites passed, as did five/six-person browser regressions and native/browser encrypted media, chat/file and second-hop forwarding integration. Candidate preflight passed before the signaling restart. Production assets and the full HTTPS archive match the tested artifacts. Database integrity and account, friend, meeting roster, moderation, access-policy and block rows were preserved. Binary/database, Caddy and installed-app rollback backups and an off-VM database snapshot are retained.

## Friends and voice-first calls release on October 12, 2026

Signaling/browser 0.3.13 is live. Mac 1.0.14+15 is signed, published and installed. The dark friends-first UI adds discoverable P2P rooms. Direct calls, groups, rooms and meetings begin with microphone-only capture; camera and screen tracks attach through an already negotiated video slot. Camera changes retain microphone and mute state.

The staged service passed unprivileged startup, secure session/meeting checks and twenty exact asset hashes. Only signaling restarted; Caddy reloaded the new versioned download route while retaining earlier archives. Accounts, friendships, meeting membership, moderation and access policies match the consistent rollback backup. Public HTTPS tests passed room discovery, three peers, denied camera access, video opt-in, mute preservation and return to solo. The three exact verification accounts were removed and database integrity/foreign keys checked. The full HTTPS Mac archive matches the signed build; the installed app connects to the existing host. See [validation, hashes and rollback locations](voice-release.json).

## Your room presentation on October 13, 2026

Signaling/browser 0.3.14 and signed Mac 1.0.15+16 are deployed and the Mac app is installed. The personal room is a standing **Your room** navigation row with a voice icon and “Ready when you are” status. Voice entry remains explicit; active personal room headings retain the name. Layout and voice-call regressions, unprivileged candidate preflight, source/HTTPS asset and archive hashes, and public three-browser voice/video checks passed. Exactly three temporary accounts were removed; database integrity and foreign keys are verified. Existing archives, service/database rollback, the previous installed app and a fresh off-VM database backup are retained. See [release details](your-room-release.json).

## PVP Signal motion release on October 14, 2026

Signaling/browser 0.3.15 is live. The signed universal Mac 1.0.16+17 archive is published, and the installed Mac app was updated and reopened. Both clients now use PVP Signal motion: quick screen and dialog arrivals, tactile controls, caller waves, and reduced-motion support. Browser navigation and new friend/chat rows animate while ordinary presence and delivery updates stay still.

The 25 server tests, 41 web tests and 51 native unit/widget tests passed. An unprivileged candidate preflight verified startup, all 22 embedded asset hashes, persistent secure sessions and the meeting API. Public HTTPS checks verified the complete signed archive and all assets. Three browsers completed voice-room discovery, microphone-only entry, camera denial, video opt-in, mute preservation, return to solo and teardown. Public motion checks verified rapid navigation, dialog focus and live reduced-motion changes.

Only signaling restarted; Caddy reloaded the new versioned download route while preserving earlier downloads. Durable database records match the rollback snapshot at deployment; exactly three temporary verification accounts were removed afterward, with integrity and foreign keys verified. The prior binary, database, Caddy configuration and installed app are retained. See [release validation, hashes and rollback paths](motion-release.json).

## Browser camera switching release on October 14, 2026

Signaling/browser 0.3.16 adds **Switch camera** in preview, individual calls and group calls. Camera cycling preserves microphone tracks and mute state, releases video capture before opening the next device, and attempts to restore the previous camera if capture fails. Front/back facing-mode fallback supports phones whose camera lists are incomplete.

All 42 web tests, 25 server tests and two additional three-browser checks passed. The unprivileged server preflight verified all 22 embedded assets and session/meeting behavior. The production upgrade occurred with no active signaling connections; only signaling restarted. The prior binary and consistent database backup are retained, and durable database records match that snapshot. Public HTTPS checks matched all assets and verified front/back camera switching with three connected browsers at an iPhone-sized viewport. Exactly three temporary verification accounts were removed, with database integrity and foreign keys verified. Physical iPhone Safari testing remains unverified. See [release validation and rollback](camera-switch-release.json).

## Friend autocomplete release on October 15, 2026

Signaling/browser 0.3.18 is live, and signed universal Mac 1.0.17+18 is published. Add-friend username suggestions begin at two characters. The account-level **Show me in friend autocomplete** preference defaults to enabled and is enforced by the service. Opted-out users remain reachable by exact username. Existing friends, pending requests and the searching user are excluded from suggestions.

All 26 service tests, 43 browser tests and 51 native tests passed. The focused discovery test passed locally and on public HTTPS, including opt-out persistence after reload and an exact-username request. All 22 public assets and the full signed Mac archive match their tested hashes. The additive discovery preferences table retains existing accounts, friendships and meetings; durable records match the consistent rollback snapshot. Two exact temporary verification accounts were removed and database integrity/foreign keys checked.

Only signaling restarted (one established transport connection at deployment); Caddy reloaded the new download route. Previous binary, database and Caddy configuration are retained at the rollback path in [the release record](friend-discovery-release.json). The new Mac app is published for download; the locally installed app was not replaced.

## Accountless guest release on October 17, 2026

Signaling/browser 0.3.19 is live, and the signed universal Mac 1.0.18+19 archive is published. Open meeting links accept a display name and explicit browser join without an account. Temporary guest identities are scoped to one meeting, expire after eight hours, and never create database accounts or saved memberships. The Mac app labels guests and retains host mute/kick controls. Private links still require account invitations.

The current server/web sources and Mac interface changes are included in these builds. Before deployment, 44 browser/JavaScript tests, 28 Rust tests and 51 Flutter tests passed, along with Clippy and Flutter analysis. The final versioned guest test passed locally and over public HTTPS with real encrypted audio/chat, mobile entry, moderation and revoked/private-link denial. All 22 public assets and the complete 32.7 MB Mac archive match their release hashes.

The production-host candidate passed unprivileged startup, assets, account/guest cookie checks and scoped admission before replacement. Only signaling restarted, with no established connections at that point; Caddy reloaded the new download route while retaining earlier downloads. Durable database records match the consistent rollback snapshot. Binary/database and Caddy rollback backups, plus an integrity-checked off-server database backup, are retained. The exact temporary public verification account and its meetings were removed afterward. See [release validation, hashes and backup paths](guest-meetings-release.json). The locally installed Mac app was not replaced.

## Mobile meeting browser release · October 17, 2026

Production is **0.3.20**. Meeting links now open a dedicated invitation with microphone and listen-only choices. Phone calls fill the viewport, errors remain visible, reload offers a safe rejoin, and the camera-off audio playback correction is included. All 26 public assets match the release manifest.

The candidate passed isolated preflight as the service user before an atomic binary replacement. There were zero established app-service TCP connections at restart. The previous binary and consistent database backup are in `/var/backups/pvp/mobile-meetings-2026-10-18-1792290356`; an additional portable database backup is stored off the VM. Existing durable records compare exactly after removing the three temporary public verification owners. Caddy and the Mac download are unchanged; all four existing services are active.

Validation includes 47 browser regressions, current mobile flows in Chromium/WebKit, three public HTTPS integration suites, 28 Rust tests, strict Clippy, voice rooms, and focused browser-listener/native-audio interoperability. The older six-participant native suite has an unresolved adaptive-resolution assertion variance; physical iPhone permission, keyboard and audio-route checks remain outstanding. See [implementation and limits](MOBILE-MEETINGS.md) and [release evidence](mobile-meetings-release.json).

## Icon and motion polish — web 0.3.21 / Mac 1.0.19

This release applies the [approved interface overhaul](ICON-MOTION-UX.md) across browser and Mac. The signed universal Mac archive is served at `/downloads/PVP-macOS-1.0.19.zip`; previous versioned archives remain available. [The release record](icon-motion-release.json) contains artifact hashes and validation results.

Production promotion passed unprivileged candidate startup, guest-cookie/scope checks, all 29 embedded asset hashes, and Caddy validation. Online SQLite, binary and Caddy rollback artifacts are at `/var/backups/pvp/icon-motion-2026-10-17-1792293566`. A portable database backup was copied off the VM before promotion. Durable records matched the backup after restart, and the signaling, Caddy, game relay and frps services remained active. There were no established signaling connections at restart.

## Guest links and more private Zoom release on October 23, 2026

Signaling/browser 0.3.22 is live, and signed universal Mac 1.0.20+21 is published at `/downloads/PVP-macOS-1.0.20.zip`. Guests can create, share, reuse, and host links without registration. **Open more private Zoom** maps numbered Zoom invitation variants to a stable PVP room, provides a permanent link and sharing message, and makes entry and capture explicit. Zoom passcodes and host roles do not transfer; these rooms have no automatic admin.

The candidate passed isolated unprivileged API and asset checks. The production restart occurred with zero signaling connections. Only signaling restarted; Caddy reloaded the new download route and retains previous archives. All 29 HTTPS assets and the full signed download match the release hashes. Public browser verification passed guest creation, clipboard sharing, preserved host access after reload, Zoom normalization, mobile guest admission and two-way encrypted WebRTC audio. Existing durable records match the rollback snapshot after removal of the exact verification records; database integrity and foreign keys are verified. A protected server rollback and off-VM portable database backup are retained. Local Mac installation was not changed. See [the release manifest](guest-links-zoom-release.json).

## Room brand and animated network homepage · November 1, 2026

Signaling/browser **0.3.23** is deployed at [lopixel.space](https://lopixel.space). It includes the room-first brand and media improvements, live connection evidence, and the [anonymous network homepage](NETWORK-FRONT-PAGE.md). Room clusters drift and pulse; larger examples illustrate participant video forwarding while retaining direct audio links. The new additive `meeting_network` setting is off by default and owner-controlled for link-accessible rooms.

The static Linux candidate passed an isolated unprivileged API preflight and all 38 embedded asset hashes. All 77 browser regressions, 36 Rust tests and strict Clippy passed. Promotion occurred with zero established signaling connections. Only `pvp-signaling` restarted; Caddy and the existing Mac download remain in place. Binary and consistent database rollback are `/var/backups/pvp/network-2026-11-01-1793573534`; a protected portable copy was saved off the VM before promotion.

Public HTTPS checks verified all asset hashes, animation, mobile WebKit, guest entry without capture, generated audio/video, observed encrypted direct transport, opt-in anonymous activity and leave/rejoin. One exact verification account and its room were removed. Existing durable records match the backup, SQLite integrity and foreign keys pass, and all four services are active. See [hashes and validation evidence](network-release.json). Native source changes have not been packaged into a new Mac release in this deployment.

## Responsive network layout and evolving examples · November 1, 2026

Signaling/browser **0.3.25** is deployed at [lopixel.space](https://lopixel.space). Graphs measure the rendered invitation and buttons, reserve their full drift envelope, and shrink or disappear when space is crowded. Every visible graph drifts independently. Labeled examples gently gain and lose peers; live diagrams follow real shared membership counts. Font changes and viewport resizing recompute placement without leaving an old larger shape behind during a transition.

All 79 browser regressions passed, followed by 15 focused checks after the final resize transition correction. The 36 Rust tests, strict Clippy and static Linux build passed. The candidate passed isolated unprivileged startup, room/privacy admission checks and all 38 asset hashes. Only signaling restarted, with zero established signaling connections. Caddy and the existing Mac download are unchanged. The previous binary and consistent database snapshot are retained at `/var/backups/pvp/network-layout-2026-11-01-1793592810`; a protected portable database backup was saved off the VM before promotion.

Public HTTPS checks verified all assets, the reported 700 px layout, enlarged text, example peer changes, mobile WebKit, permission-free listening, generated audio/video, observed encrypted direct transport, anonymous room sizes and leave/rejoin. The first call verification timed out during teardown; the final check explicitly waits for the host to become solo and for rejoined video. Both exact temporary accounts and rooms were removed. Existing durable records match the backup, SQLite integrity and foreign keys pass, and all four services are active. See [hashes and release evidence](network-layout-release.json) and [layout details](NETWORK-FRONT-PAGE.md).
