// File: /Users/davell/Documents/github/pvp/src/network/hole_punch.rs
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time;
use std::error::Error;

/// Attempts UDP hole punching with the specified peer.
///
/// Sends "PUNCH" messages periodically to the `peer_addr` and listens for
/// incoming "PUNCH" or "PUNCH_ACK" messages from that same address.
///
/// # Arguments
///
/// * `socket` - An asynchronous `UdpSocket` bound locally.
/// * `peer_addr` - The public `SocketAddr` of the peer (obtained via signaling/STUN).
///
/// # Returns
///
/// A `Result` containing the confirmed `SocketAddr` of the peer upon successful
/// punching, or a `Box<dyn Error>` if it times out.
pub async fn perform_hole_punch(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
) -> Result<SocketAddr, Box<dyn Error>> {
    println!("Initiating UDP hole punching to peer {}...", peer_addr);

    let punch_message = b"PUNCH";
    let ack_message = b"PUNCH_ACK";
    let timeout_duration = Duration::from_secs(10);
    let punch_interval = Duration::from_millis(100);
    let recv_timeout = Duration::from_millis(50); // Short timeout for checking receives
    let start_time = Instant::now();

    let mut recv_buf = [0u8; 1024]; // Buffer for punch/ack messages

    loop {
        // Send punch packet
        if let Err(e) = socket.send_to(punch_message, peer_addr).await {
             eprintln!("Warning: Failed to send punch packet: {}", e);
             // Don't immediately fail, maybe transient network issue
        }

        // Check for incoming packets with a short timeout
        match time::timeout(recv_timeout, socket.recv_from(&mut recv_buf)).await {
            Ok(Ok((num_bytes, src_addr))) => {
                // Check if it's the peer we expect
                if src_addr == peer_addr {
                    let received_data = &recv_buf[..num_bytes];
                    // Check if it's a PUNCH message from the peer
                    if num_bytes >= punch_message.len() && received_data == punch_message {
                        println!("Hole punching successful! Received PUNCH from peer {}", src_addr);
                        // Send confirmation ACK back
                        if let Err(e) = socket.send_to(ack_message, src_addr).await {
                            eprintln!("Warning: Failed to send PUNCH_ACK: {}", e);
                        }
                        return Ok(src_addr);
                    }
                    // Check if it's an ACK message from the peer (meaning they received our PUNCH first)
                    else if num_bytes >= ack_message.len() && received_data == ack_message {
                         println!("Hole punching successful! Received PUNCH_ACK from peer {}", src_addr);
                         return Ok(src_addr);
                    }
                    // Received something else from the peer, assume punch worked anyway
                    else {
                        println!("Hole punching likely successful! Received other data ({} bytes) from peer {}", num_bytes, src_addr);
                         // Optionally send an ACK just in case
                         if let Err(e) = socket.send_to(ack_message, src_addr).await {
                             eprintln!("Warning: Failed to send final PUNCH_ACK: {}", e);
                         }
                        return Ok(src_addr);
                    }
                } else {
                    // Ignore packets from other sources during punching
                    // println!("Ignoring packet from unexpected source: {}", src_addr);
                }
            }
            Ok(Err(e)) => {
                // Don't necessarily error out on recv error, could be transient
                eprintln!("Warning: Error receiving packet during hole punch: {}", e);
            }
            Err(_) => {
                // Timeout on recv, normal behavior, continue sending punches
            }
        }

        // Check for overall timeout
        if start_time.elapsed() >= timeout_duration {
            return Err("Hole punching timed out after 10 seconds. Ensure the peer is running and trying to punch simultaneously.".into());
        }

        // Wait before sending the next punch
        time::sleep(punch_interval).await;
    }
}