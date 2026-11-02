> Preserved runbook for the original UDP client. Run it with `cargo run --features legacy --bin pvp-legacy`; the default binary now opens the WebRTC app. Configuration, protocol, and media routing below apply only to legacy mode.

# pvp — Peer Video Player

**pvp** is a peer-to-peer video and audio call tool written in Rust. Two peers share the same AES-256 encryption key, discover public UDP addresses via STUN, **prefer a direct hole-punched path**, and fall back to a **TURN-like UDP relay** on the public DigitalOcean host when direct connectivity fails. Media is camera video (H.264) and microphone audio (Opus), end-to-end encrypted with AES-256-CBC.

There is **no** multi-subcommand CLI: you run the binary, optionally share your public address for direct P2P, or press Enter to meet on the relay, then press **ESC** in the video window to quit.

## How a call works

1. Load `config.json` (`encryption_key` + optional `relay`).
2. Bind a UDP socket on **`0.0.0.0:5000`**.
3. Query Google STUN (`stun.l.google.com:19302`) for your public IP:port and print it.
4. Prompt for peer `IP:port` **or** Enter / `relay` to use the TURN relay only.
5. **Prefer P2P:** UDP hole punch (`PUNCH` / `PUNCH_ACK`, ~10s). On failure (or if you chose relay), **JOIN** the configured relay room.
6. Open camera index **0**, encode H.264 + mono Opus @ 48 kHz, encrypt fragments, send to peer **or** relay.
7. Receive, decrypt, reassemble, decode, display, play audio.
8. Press **ESC** (key code 27) to exit.

Both peers need the **same** `encryption_key`. For relay mode they also need the same `relay.token` and `relay.room`.

## Prerequisites

| Dependency | Role |
|------------|------|
| Rust toolchain (edition 2021) | Build client |
| OpenCV 4 (with highgui, videoio) | Camera + display window |
| pkg-config | OpenCV discovery at build time |
| A camera and mic | Runtime media |

### macOS (Homebrew)

```bash
brew install opencv pkg-config
```

### Linux

Install OpenCV 4 development packages that provide `pkg-config opencv4`, plus GUI/camera backends as needed.

## Build and run (client)

From the repo root (where `config.json` lives):

```bash
cargo build --release
cargo run --release
```

The client loads **`config.json` from the current working directory**.

## Configuration

See `config.example.json`. Required and optional fields:

```json
{
  "encryption_key": "<64 hex chars → 32-byte AES key>",
  "relay": {
    "server": "143.198.19.179:19132",
    "token": "<shared secret matching the relay service>",
    "room": "default",
    "prefer_p2p": true
  }
}
```

| Field | Meaning |
|-------|---------|
| `encryption_key` | End-to-end AES-256 key (media is never decrypted on the relay) |
| `relay.server` | Public UDP endpoint of `pvp-relay` |
| `relay.token` | Relay JOIN auth (must match server `PVP_RELAY_TOKEN`) |
| `relay.room` | Room id both peers join (max 64 ASCII bytes) |
| `relay.prefer_p2p` | Documented intent; UI still offers direct address first when true |

Generate keys:

```bash
openssl rand -hex 32   # encryption_key
openssl rand -hex 24   # relay token
```

## Two-peer setup

### Direct P2P (preferred)

1. Same `encryption_key` on both machines.
2. Start `pvp` on each; note STUN public addresses.
3. Enter the **other** peer’s `IP:port` at the prompt (both sides).
4. Hole punch within ~10s → media goes peer-to-peer.

### Relay fallback (TURN-like)

1. Same `encryption_key`, `relay.token`, and `relay.room`.
2. Start `pvp` on both.
3. Press **Enter** (or type `relay`) at the peer prompt — or enter a direct address and let hole punch fail to auto-fallback.
4. Both JOIN the relay room; media is forwarded (still E2E encrypted).

**Firewall (clients):** UDP **5000** for direct P2P. Relay only needs outbound UDP to the relay host.

## Public relay (DigitalOcean `mc-relay`)

| Item | Value |
|------|--------|
| Host | `143.198.19.179` / `lopixel.space` |
| Public UDP (clients) | **`19132`** (shared with Bedrock via demux; cloud FW only allows this UDP port) |
| Core bind | `127.0.0.1:3478` (loopback, not public) |
| Bedrock frps | `127.0.0.1:19133` (frpc `remotePort = 19133`) |
| Unit | `pvp-relay.service` |
| Env | `/etc/pvp-relay/env` |
| Binary | `/usr/local/bin/pvp-relay` |

Why 19132: DigitalOcean firewall `mc-relay-fw` currently allows only **UDP 19132** (plus SSH/frp/MC Java TCP). Arbitrary ports like 3478 never reach the droplet from the internet. The relay therefore demuxes on **19132**:

- Packets starting with `PVPR` (or already classified pvp flows) → pvp core
- Everything else → Minecraft Bedrock (frps)

### Deploy / rebuild relay (from this Mac, Docker required for `cross`)

```bash
cd relay
cross build --release --target x86_64-unknown-linux-musl
ssh -i ~/.ssh/id_ed25519 root@143.198.19.179 'systemctl stop pvp-relay'
scp -i ~/.ssh/id_ed25519 target/x86_64-unknown-linux-musl/release/pvp-relay \
  root@143.198.19.179:/usr/local/bin/pvp-relay
ssh -i ~/.ssh/id_ed25519 root@143.198.19.179 'systemctl start pvp-relay && systemctl status pvp-relay'
```

Ideal long-term: add **UDP 3478** to DO cloud firewall `mc-relay-fw` and bind the public front there so Bedrock keeps sole use of 19132.

## Relay crate (`relay/`)

Lightweight binary (Tokio only — no OpenCV). Protocol:

- Control: magic `PVPR` + type + body (`JOIN` / `KEEPALIVE` with room+token)
- Media: authenticated PVP2 packets (version + 25-byte header + AES ciphertext + 32-byte MAC) forwarded unchanged between the two peers in a room

```bash
cd relay && cargo test && cargo build --release
```

## Media and protocol (summary)

| Item | Value in source |
|------|-----------------|
| Local client bind | `0.0.0.0:5000` |
| STUN server | `stun.l.google.com:19302` |
| Video | Camera index 0, request 640×480 @ 30 fps, H.264, window `"Video Stream"` |
| Audio | Mono, 48 kHz, 20 ms Opus frames (960 samples) |
| Crypto | AES-256-CBC + PKCS7, random IV; version/header/ciphertext authenticated with HMAC-SHA-256 |
| Packet header | 25 bytes: type(1)+seq(4)+frag_idx(2)+total_frags(2)+iv(16); `0`=video, `1`=audio |
| Max plaintext chunk | 1300 bytes |
| Exit | ESC = `wait_key` code 27 |

## Known limitations

- **Mono audio only**; output sample-rate resampling not implemented.
- **Input chunking simplified**; partial cpal frames may drop.
- **Relay is not IETF TURN** — custom room JOIN + UDP forward.
- **Public relay shares UDP 19132** with Bedrock demux until DO cloud FW allows a dedicated port.
- **No CLI flags**; config file + interactive prompt.
- **Single camera** (index 0).

## Project layout

```
src/
  main.rs                 # STUN, P2P / relay connect, camera/audio loop
  cli.rs                  # Peer address or "relay" prompt
  config.rs               # encryption_key + relay settings
  network/
    mod.rs                # Packet header, constants
    stun.rs / hole_punch.rs
    relay.rs              # Client JOIN + keepalive
    sender.rs / receiver.rs
relay/                    # pvp-relay server (deploy to DO)
config.example.json
```

Agent notes: [`.grok/skills/pvp-architecture/`](.grok/skills/pvp-architecture/).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Authenticated UDP update — October 11, 2026

Rebuild both peers together. The PVP2 envelope authenticates packets before header parsing, reassembly or decryption; old unauthenticated packets are rejected. The relay can forward the new envelope without decoding it. Partial-frame limits and a completed-frame replay window bound receiving state. Rotate the shared media key between calls; replay state is per receiver lifetime. Existing release archives contain the earlier protocol. See [the red-team review](RED-TEAM-2026-10-11.md) for validation and limits.
