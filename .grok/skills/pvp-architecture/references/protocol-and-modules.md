# pvp protocol and module reference

Source of truth: `src/network/*`, `src/config.rs`, `src/main.rs`. Update this file when wire format or constants change.

## Constants (`src/network/mod.rs`)

| Name | Value | Notes |
|------|-------|-------|
| `AUDIO_SAMPLE_RATE` | `48000` | Opus + cpal target |
| `AUDIO_CHANNELS` | `1` | Mono |
| `AUDIO_FRAME_SIZE` | `960` | 20 ms @ 48 kHz |
| `MAX_PAYLOAD_SIZE` | `1300` | Plaintext chunk before encrypt |
| `PACKET_HEADER_SIZE` | `25` | 1+4+2+2+16 |

## Packet header wire layout (big-endian fields)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | `packet_type` (`0` Video, `1` Audio) |
| 1 | 4 | `seq_num` u32 BE |
| 5 | 2 | `frag_idx` u16 BE |
| 7 | 2 | `total_frags` u16 BE |
| 9 | 16 | `iv` AES-CBC IV |

Full UDP packet: `[header 25 bytes][AES-256-CBC ciphertext PKCS7]`.

Encryption: one random IV per fragment; key is shared 32-byte AES-256 key from `config.json`.

Fragmentation: encoded bitstream/chunk split with `chunks(MAX_PAYLOAD_SIZE)`; receiver maps by `seq_num` + `frag_idx` until all fragments present, then concat → decode.

## PacketType

```text
Video = 0
Audio = 1
```

Invalid type bytes fail header deserialize.

## STUN (`stun.rs`)

- Server string: `stun.l.google.com:19302`
- Method: BINDING request / success with XOR-MAPPED-ADDRESS
- Recv timeout: 3 seconds
- Prefer IPv4 resolution of STUN host

## Hole punch (`hole_punch.rs`)

- Outbound: raw bytes `PUNCH`
- Success on peer `PUNCH`, `PUNCH_ACK`, or other data from expected `peer_addr`
- Reply `PUNCH_ACK` on receiving `PUNCH` (or opportunistic on other data)
- Punch interval 100 ms; overall timeout 10 s; short recv poll 50 ms

## Sender path (`sender.rs`)

1. `SendData::Video(ignored_seq, Mat)` or `SendData::Audio(Vec<f32>)`
2. Video: BGR → YUV I420 → OpenH264 encode → fragment_and_send
3. Audio: require `len == AUDIO_FRAME_SIZE * AUDIO_CHANNELS`; Opus VOIP 32 kbps encode → fragment_and_send
4. Per fragment: random IV, PKCS7 pad, AES-256-CBC encrypt, prepend header, `send_to(peer)`

## Receiver path (`receiver.rs`)

1. `recv_from` into 2048-byte buffer
2. Deserialize header; decrypt with key + header.iv
3. Insert into video or audio reassembly `HashMap<u32, (Vec<Option<Vec<u8>>>, Instant)>`
4. On complete: video → H.264 decode → pack I420 → `COLOR_YUV2BGR_I420` → send `(seq, Mat)`; audio → Opus `decode_float` → send `Vec<f32>`
5. Incomplete buffers older than 2 s discarded

## Config (`config.rs`)

- File: path argument (main uses `"config.json"`)
- JSON field: `encryption_key` string — decode hex; require exactly 32 bytes
- Optional `relay` object: `server`, `token`, `room`, `prefer_p2p` / `enabled`

## Relay control (`network/relay.rs` + `relay/` crate)

- Magic `PVPR` (4 bytes); not used by media PacketType (0/1)
- JOIN/KEEPALIVE body: `room_len u8 | room | token_len u8 | token`
- JOIN_OK status: 0 = waiting, 1 = peer present
- Media after JOIN: unmodified pvp UDP datagrams (header+ciphertext)
- Public DO endpoint today: `143.198.19.179:19132` (demux with Bedrock)

## Main media defaults (`main.rs`)

| Setting | Value |
|---------|-------|
| Bind | `0.0.0.0:5000` |
| Camera | index `0`, CAP_ANY |
| Requested size/FPS | 640×480 @ 30 |
| Window | `"Video Stream"`, WINDOW_AUTOSIZE |
| Exit key | `wait_key` code `27` (ESC) |
| Audio buffer | `AUDIO_FRAME_SIZE * 100` samples in ringbuf |
