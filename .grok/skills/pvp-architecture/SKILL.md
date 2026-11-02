---
name: pvp-architecture
description: >
  Architecture and edit/debug guidance for the pvp peer video/audio UDP tool.
  Use when working on pvp, peer video player, STUN/hole punch, AES media packets,
  OpenH264/Opus send/receive paths, config.json encryption_key, or when the user
  runs /pvp-architecture or asks how pvp networking, encoding, or modules work.
---

# pvp architecture (agent guide)

**User runbook** is the repo root `README.md`. This skill is for navigating and changing code safely. Prefer facts from source over README if they ever diverge.

## Runtime sequence (authoritative)

`src/main.rs` order of operations:

1. `config::load_config("config.json")` → AES key + optional `RelayConfig`
2. `UdpSocket::bind("0.0.0.0:5000")`
3. `network::stun::perform_stun_query` → print public addr (non-fatal on failure)
4. `cli::read_peer_connect_choice(relay_available)` → Direct(addr) or RelayOnly
5. **Prefer P2P:** `hole_punch` to peer; on failure (if relay configured) → `network::relay::join_relay`
6. **Or** RelayOnly → `join_relay` immediately
7. OpenCV camera index `0`, highgui window `"Video Stream"`
8. cpal + bridges; spawn `sender_task` (dest = peer **or** relay addr) + `receiver_task` + optional relay keepalive
9. Main loop; **ESC = 27** exits

Media destination for sender is either the hole-punched peer or the relay `SocketAddr`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/main.rs` | Orchestration, OpenCV capture/display, cpal setup, audio bridges, main FPS loop |
| `src/cli.rs` | Peer `IP:port` prompt; prefers IPv4 from `to_socket_addrs` |
| `src/config.rs` | JSON `encryption_key` hex → 32 bytes |
| `src/network/mod.rs` | `PacketType`, `PacketHeader`, audio constants, `MatAsYuv`, `MAX_PAYLOAD_SIZE` |
| `src/network/stun.rs` | STUN BINDING to `stun.l.google.com:19302`, XOR-MAPPED-ADDRESS, 3s recv timeout |
| `src/network/hole_punch.rs` | Send `PUNCH`, accept `PUNCH`/`PUNCH_ACK`/other from peer, 10s overall timeout |
| `src/network/sender.rs` | H.264 + Opus encode, AES-256-CBC encrypt, fragment, UDP send |
| `src/network/receiver.rs` | UDP recv (skips `PVPR` control), decrypt, reassemble, decode |
| `src/network/relay.rs` | Client JOIN/KEEPALIVE to pvp-relay (`PVPR` magic) |
| `relay/` crate | Server: room JOIN + media forward; optional public demux |
| `build.rs` | OpenCV pkg-config / link paths; macOS Homebrew dynamic link |

### Public relay (DO mc-relay)

| Item | Value |
|------|--------|
| Droplet | `143.198.19.179` (`lopixel.space`) |
| Client-facing UDP | **`:19132`** (DO cloud FW `mc-relay-fw` only allows this UDP today) |
| Core | `127.0.0.1:3478` |
| Bedrock frps | `127.0.0.1:19133` (frpc `remotePort=19133` on ons) |
| Unit / env | `pvp-relay.service` · `/etc/pvp-relay/env` |

Demux: `PVPR` / known pvp flows → core; else → Bedrock. Prefer adding **UDP 3478** to DO FW long-term.

Deep packet and constant tables: `references/protocol-and-modules.md`.

## Task / channel graph

```
cpal input callback ──mpsc──► audio_bridge ──SendData::Audio──┐
OpenCV main loop ──try_send──SendData::Video─────────────────┼──► sender_task ──UDP──► peer
                                                              │
peer ──UDP──► receiver_task ──(seq, Mat)──► main imshow       │
                  └──── Vec<f32> ──► playback_bridge ──ring──► cpal output
```

- Combined send channel: `mpsc::channel::<SendData>(100)`
- Video to main: capacity 10
- Audio to playback: capacity 100
- Socket + key shared via `Arc` / `Copy` into sender and receiver tasks

## When editing

### Safe touch points

- **Constants** in `network/mod.rs` (`AUDIO_*`, `MAX_PAYLOAD_SIZE`, `PACKET_HEADER_SIZE`) — changing them breaks interoperability with peers on old builds; update both ends and any docs.
- **`fragment_and_send` / reassembly** — header layout must stay wire-compatible (`serialize`/`deserialize` in `mod.rs`).
- **Crypto** — AES-256-CBC + PKCS7, IV in header (16 bytes). Wrong key → padding errors on decrypt (logged, fragment dropped).
- **Hole punch messages** are plaintext `PUNCH` / `PUNCH_ACK` bytes, not encrypted media packets.

### Common pitfalls

1. **`config.json` path is relative to CWD**, not the binary path (`main` hardcodes `"config.json"`).
2. **Port is fixed** at 5000 bind; STUN may map a different *public* port — peers must exchange the STUN-printed address, not always `:5000` on the public IP.
3. **Video seq from main is ignored** in `sender_task`; sender maintains its own `video_seq_num` / `audio_seq_num`.
4. **Mono only** — `AUDIO_CHANNELS = 1`; input resampler errors if channels ≠ 1.
5. **Output resampling TODO** in `setup_audio_output` — do not document as working.
6. **OpenCV + OpenH264** native deps: build failures are often env (`pkg-config opencv4`, Homebrew paths), not Rust logic. See `build.rs`.
7. **Dropping frames**: full send channel drops video via `try_send`; do not switch to blocking send on the main loop without rethinking FPS/`wait_key`.
8. **Reassembly buffers** expire incomplete frames after 2s; fragment index/total must be consistent per seq.

### Tests

Unit tests live next to pure logic:

- `config::tests` — hex key load / length validation
- `network::tests` — `PacketHeader` round-trip, `PacketType`, header size constant

Run: `cargo test` (may still need OpenCV linked for the crate; tests themselves avoid camera/UDP).

### Do not invent

- No CLI flags, config fields beyond `encryption_key`, TURN, multi-party, or stereo wire format unless implementing them.
- Prefer documenting limitations over “fixing” incomplete resampling in docs alone.

## Debug checklist

| Symptom | Likely area |
|---------|-------------|
| Key load error | `config.json` missing/wrong hex length |
| Bind fail | Port 5000 in use |
| STUN timeout | UDP blocked outbound/inbound to STUN; still may work on LAN with private IP |
| Hole punch timeout | Peers not simultaneous; wrong public port; symmetric NAT |
| Decrypt padding errors | Mismatched keys |
| Black/no window | Camera open failed (fatal) or no decoded frames yet |
| Wrong audio pitch | Output device ≠ 48 kHz (resampling unimplemented) |
| Build OpenCV errors | `build.rs` / pkg-config / Homebrew |

## Related paths

- User docs: `/Users/davell/Documents/github/pvp/README.md` (or repo-relative `README.md`)
- Protocol detail: `references/protocol-and-modules.md` (this skill directory)
