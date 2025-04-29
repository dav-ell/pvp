// File: /Users/davell/Documents/github/pvp/src/network/stun.rs
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time;
use std::error::Error;

// STUN related imports
use stun_rs::{
    MessageEncoderBuilder, MessageDecoderBuilder, StunMessageBuilder,
    MessageClass, TransactionId,
};
use stun_rs::methods::BINDING;
use stun_rs::attributes::stun::{XorMappedAddress, ErrorCode as StunErrorCode}; // Alias StunErrorCode

// Google's public STUN server address
const STUN_SERVER: &str = "stun.l.google.com:19302";

/// Performs a STUN query to discover the public IP address and port.
///
/// Uses the provided `UdpSocket` to send a BINDING request to the STUN server
/// and parses the response to extract the `XOR-MAPPED-ADDRESS`.
///
/// # Arguments
///
/// * `socket` - An asynchronous `UdpSocket` bound to a local address.
/// * `stun_server_addr_str` - The address string of the STUN server (e.g., "stun.l.google.com:19302").
///
/// # Returns
///
/// A `Result` containing the discovered public `SocketAddr` or a `Box<dyn Error>` on failure.
pub async fn perform_stun_query(socket: &UdpSocket, stun_server_addr_str: &str) -> Result<SocketAddr, Box<dyn Error>> {
    println!("Performing STUN query to {}...", stun_server_addr_str);

    // Resolve STUN server address, preferring IPv4
    let mut resolved_addrs = stun_server_addr_str.to_socket_addrs()?;
    let stun_socket_addr = resolved_addrs
        .find(|addr| addr.is_ipv4())
        .ok_or_else(|| format!("Could not resolve {} to an IPv4 address", stun_server_addr_str))?;
    println!("Resolved STUN server address to: {}", stun_socket_addr);

    // 1. Create Binding Request
    let message = StunMessageBuilder::new(BINDING, MessageClass::Request)
        .with_transaction_id(TransactionId::default())
        .build();

    // 2. Encode Request
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = vec![0u8; 1500]; // Standard MTU size buffer
    let size = encoder.encode(&mut buffer, &message)?;
    let encoded_request = &buffer[..size];

    // 3. Send Request using Tokio socket and resolved SocketAddr
    socket.send_to(encoded_request, stun_socket_addr).await?;
    println!("STUN request sent.");

    // 4. Receive Response using Tokio socket
    let mut recv_buf = [0u8; 1500];
    let (num_bytes, src_addr) = match time::timeout(Duration::from_secs(3), socket.recv_from(&mut recv_buf)).await {
        Ok(Ok(data)) => data,
        Ok(Err(e)) => return Err(Box::new(e)), // IO error on recv_from
        Err(_) => return Err("STUN query timed out after 3 seconds".into()), // Timeout error
    };
    println!("Received {} bytes from STUN server {}", num_bytes, src_addr);
    let response_data = &recv_buf[..num_bytes];

    // 5. Decode Response
    let decoder = MessageDecoderBuilder::default().build();
    let (response_msg, _) = decoder.decode(response_data).map_err(|e| e.to_string())?;

    // 6. Extract XOR-MAPPED-ADDRESS
    if response_msg.class() == MessageClass::SuccessResponse {
        if let Some(attr) = response_msg.get::<XorMappedAddress>() {
            let xor_addr = attr.as_xor_mapped_address()?;
            let public_addr = xor_addr.socket_address();
            Ok(*public_addr)
        } else {
            Err("XOR-MAPPED-ADDRESS attribute not found in STUN success response".into())
        }
    } else if response_msg.class() == MessageClass::ErrorResponse {
        let error_details = match response_msg.get::<StunErrorCode>() { // Use aliased StunErrorCode
            Some(err_attr_enum) => {
                match err_attr_enum.as_error_code() {
                    Ok(err_attr) => format!("Error Code: {}, Reason: {}", err_attr.error_code().error_code(), err_attr.error_code().reason()),
                    Err(_) => "Could not parse ErrorCode attribute".to_string(),
                }
            },
            None => "No ErrorCode attribute found".to_string(),
        };
        Err(format!("STUN query failed with ErrorResponse: {}", error_details).into())
    } else {
        Err(format!("Received unexpected STUN message class: {:?}", response_msg.class()).into())
    }
}


/// Returns the STUN server address constant.
pub fn get_stun_server_address() -> &'static str {
    STUN_SERVER
}