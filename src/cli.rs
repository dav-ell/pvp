// File: /Users/davell/Documents/github/pvp/src/cli.rs
use std::net::{SocketAddr, ToSocketAddrs};
use std::io::{self, Write};

/// Prompts the user to enter the peer's public IP address and port,
/// validates the input, and returns the parsed `SocketAddr`.
///
/// This function will loop until a valid IPv4 or IPv6 address is entered.
/// It prioritizes IPv4 if the input resolves to multiple addresses.
///
/// # Returns
///
/// The validated `SocketAddr` of the peer.
pub fn read_peer_address() -> SocketAddr {
    loop {
        print!("Enter peer's public IP and port (e.g., 192.168.1.1:5000 or [::1]:5000): ");
        io::stdout().flush().expect("Failed to flush stdout");

        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read input");
        let input = input.trim();

        // Try resolving as potentially a hostname or IP literal
        match input.to_socket_addrs() {
            Ok(mut addrs) => {
                // Prioritize finding an IPv4 address if available
                if let Some(addr) = addrs.find(|addr| addr.is_ipv4()) {
                    println!("Using peer address: {}", addr);
                    return addr;
                } else {
                     // If no IPv4, try parsing directly as SocketAddr (handles IPv6 literals better)
                     match input.parse::<SocketAddr>() {
                        Ok(addr) => {
                            println!("Using peer address: {}", addr);
                            return addr;
                        }
                        Err(_) => {
                             println!("Could not parse '{}' as a valid IPv4 or IPv6 socket address. Please try again.", input);
                        }
                    }
                }
            }
            Err(e) => {
                println!("Invalid address format or DNS lookup failed: {}. Please enter IP:PORT directly and try again.", e);
            }
        }
    }
}