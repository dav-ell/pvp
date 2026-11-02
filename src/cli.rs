// File: /Users/davell/Documents/github/pvp/src/cli.rs
use std::io::{self, Write};
use std::net::{SocketAddr, ToSocketAddrs};

/// Result of the peer-address prompt.
#[derive(Debug, Clone)]
pub enum PeerConnectChoice {
    /// Try direct UDP hole punch to this address.
    Direct(SocketAddr),
    /// Skip direct P2P; use the configured relay only.
    RelayOnly,
}

/// Prompts for the peer's public IP:port, or `relay` / empty to use TURN relay.
///
/// When `relay_available` is false, empty/`relay` is rejected and only a
/// socket address is accepted (legacy behavior).
pub fn read_peer_connect_choice(relay_available: bool) -> PeerConnectChoice {
    loop {
        if relay_available {
            print!(
                "Enter peer's public IP:port for direct P2P\n\
                 (or press Enter / type 'relay' to use the TURN relay only): "
            );
        } else {
            print!("Enter peer's public IP and port (e.g., 192.168.1.1:5000 or [::1]:5000): ");
        }
        io::stdout().flush().expect("Failed to flush stdout");

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read input");
        let input = input.trim();

        if relay_available && (input.is_empty() || input.eq_ignore_ascii_case("relay")) {
            println!("Using TURN relay path (no direct hole punch).");
            return PeerConnectChoice::RelayOnly;
        }

        if input.is_empty() {
            println!("Address required when no relay is configured. Try again.");
            continue;
        }

        match input.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.find(|addr| addr.is_ipv4()) {
                    println!("Using peer address: {}", addr);
                    return PeerConnectChoice::Direct(addr);
                }
                match input.parse::<SocketAddr>() {
                    Ok(addr) => {
                        println!("Using peer address: {}", addr);
                        return PeerConnectChoice::Direct(addr);
                    }
                    Err(_) => {
                        println!(
                            "Could not parse '{}' as a valid IPv4 or IPv6 socket address. Please try again.",
                            input
                        );
                    }
                }
            }
            Err(e) => {
                println!(
                    "Invalid address format or DNS lookup failed: {}. Please enter IP:PORT directly and try again.",
                    e
                );
            }
        }
    }
}
