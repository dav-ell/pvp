// File: /Users/davell/Documents/github/pvp/src/network/relay.rs
//! Client-side join/keepalive for the pvp-relay (TURN-like) service.
//!
//! Control frames use magic `PVPR`. After JOIN, media is sent as ordinary
//! authenticated PVP2 envelopes to the relay address; the relay
//! forwards them unchanged to the other peer in the room.

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time;

/// Shared with `relay/src/main.rs`.
pub const MAGIC: &[u8; 4] = b"PVPR";
pub const MSG_JOIN: u8 = 1;
pub const MSG_JOIN_OK: u8 = 2;
pub const MSG_KEEPALIVE: u8 = 3;
pub const MSG_ERROR: u8 = 4;
#[allow(dead_code)]
pub const MSG_PEER_READY: u8 = 5;
#[allow(dead_code)]
pub const MSG_PEER_GONE: u8 = 6;

#[allow(dead_code)]
pub const STATUS_WAITING: u8 = 0;
pub const STATUS_PEER_PRESENT: u8 = 1;

const JOIN_TIMEOUT: Duration = Duration::from_secs(5);
const JOIN_RETRY: Duration = Duration::from_millis(400);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Build a JOIN or KEEPALIVE control packet (same body layout).
pub fn build_join_packet(room: &str, token: &str, msg_type: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    if room.is_empty() || room.len() > 64 {
        return Err("room id must be 1..=64 bytes".into());
    }
    if token.is_empty() || token.len() > 128 {
        return Err("relay token must be 1..=128 bytes".into());
    }
    if !room.is_ascii() {
        return Err("room id must be ASCII".into());
    }
    let mut pkt = Vec::with_capacity(5 + 1 + room.len() + 1 + token.len());
    pkt.extend_from_slice(MAGIC);
    pkt.push(msg_type);
    pkt.push(room.len() as u8);
    pkt.extend_from_slice(room.as_bytes());
    pkt.push(token.len() as u8);
    pkt.extend_from_slice(token.as_bytes());
    Ok(pkt)
}

/// True if this datagram is a pvp-relay control frame (not media).
pub fn is_control_packet(data: &[u8]) -> bool {
    data.len() >= 5 && &data[0..4] == MAGIC
}

/// Join a relay room. Retries until JOIN_OK or timeout.
///
/// Returns the relay `SocketAddr` to use as the media destination (same as
/// `relay_addr` after resolution). Does not require the peer to be present yet.
pub async fn join_relay(
    socket: &UdpSocket,
    relay_addr: SocketAddr,
    room: &str,
    token: &str,
) -> Result<SocketAddr, Box<dyn Error>> {
    let join_pkt = build_join_packet(room, token, MSG_JOIN)?;
    println!(
        "Joining relay {} room=\"{}\" ...",
        relay_addr, room
    );

    let deadline = tokio::time::Instant::now() + JOIN_TIMEOUT;
    let mut buf = [0u8; 512];

    loop {
        socket.send_to(&join_pkt, relay_addr).await?;

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("relay JOIN timed out (no JOIN_OK)".into());
        }
        let wait = remaining.min(JOIN_RETRY);

        match time::timeout(wait, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                if src != relay_addr {
                    // Ignore unrelated packets during join (e.g. late hole-punch).
                    continue;
                }
                let pkt = &buf[..n];
                if !is_control_packet(pkt) {
                    continue;
                }
                match pkt[4] {
                    MSG_JOIN_OK => {
                        let status = if n >= 6 { pkt[5] } else { STATUS_WAITING };
                        if status == STATUS_PEER_PRESENT {
                            println!("Relay JOIN_OK: peer already present in room.");
                        } else {
                            println!("Relay JOIN_OK: waiting for peer in room \"{}\".", room);
                        }
                        return Ok(relay_addr);
                    }
                    MSG_ERROR => {
                        let msg = parse_error_message(pkt);
                        return Err(format!("relay rejected JOIN: {}", msg).into());
                    }
                    _ => continue,
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                // timeout on this attempt; retry until deadline
            }
        }
    }
}

fn parse_error_message(pkt: &[u8]) -> String {
    // PVPR | ERROR | code | len | msg
    if pkt.len() < 7 {
        return "unknown error".to_string();
    }
    let code = pkt[5];
    let len = pkt[6] as usize;
    let msg = if pkt.len() >= 7 + len {
        String::from_utf8_lossy(&pkt[7..7 + len]).into_owned()
    } else {
        "truncated".to_string()
    };
    format!("code={} {}", code, msg)
}

/// Background task: re-send JOIN periodically so the relay does not expire us.
pub async fn relay_keepalive_task(
    socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    room: String,
    token: String,
) {
    let pkt = match build_join_packet(&room, &token, MSG_KEEPALIVE) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("relay keepalive: bad packet: {}", e);
            return;
        }
    };
    let mut interval = time::interval(KEEPALIVE_INTERVAL);
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        if let Err(e) = socket.send_to(&pkt, relay_addr).await {
            eprintln!("relay keepalive send failed: {}", e);
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_join_has_magic_and_type() {
        let p = build_join_packet("room1", "tok", MSG_JOIN).unwrap();
        assert_eq!(&p[0..4], b"PVPR");
        assert_eq!(p[4], MSG_JOIN);
        assert_eq!(p[5], 5); // room len
        assert_eq!(&p[6..11], b"room1");
    }

    #[test]
    fn is_control_detects_magic() {
        assert!(is_control_packet(b"PVPR\x01xxxx"));
        assert!(!is_control_packet(&[0u8; 25])); // video-like
        assert!(!is_control_packet(b"PUNC"));
    }
}
