use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::io::{self, Write};

use aes::Aes256;
use aes::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};
use aes::cipher::block_padding::{Pkcs7, UnpadError};
use cbc::{Encryptor as CbcEncryptorGeneric, Decryptor as CbcDecryptorGeneric};
use opencv::{
    core::{Mat, CV_8UC1}, // Removed Mat_AUTO_STEP
    highgui,
    imgproc,
    prelude::*,
    videoio,
};
use openh264::{decoder::Decoder, encoder::Encoder};
use openh264::formats::YUVSource;
use rand::Rng;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use tokio::net::UdpSocket; // Use Tokio's UdpSocket
use tokio::sync::mpsc; // Use Tokio's MPSC channels

// STUN related imports
use stun_rs::{
    MessageEncoderBuilder, MessageDecoderBuilder, StunMessageBuilder,
    MessageClass, TransactionId,
};
use stun_rs::methods::BINDING;
use stun_rs::attributes::stun::XorMappedAddress;

// Define specific encryptor/decryptor types
type Aes256CbcEncryptor = CbcEncryptorGeneric<Aes256>;
type Aes256CbcDecryptor = CbcDecryptorGeneric<Aes256>;

// Packet header for UDP transmission
struct PacketHeader {
    seq_num: u32,
    frag_idx: u16,
    total_frags: u16,
    iv: [u8; 16],
}

// Helper struct to implement the Yuv trait for OpenCV Mat data
struct MatAsYuv<'a> {
    width: usize,
    height: usize,
    y: &'a [u8],
    u: &'a [u8],
    v: &'a [u8],
}

// Implement YUVSource trait with the correct methods
impl<'a> YUVSource for MatAsYuv<'a> {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }
    fn strides(&self) -> (usize, usize, usize) {
        (self.width, self.width / 2, self.width / 2)
    }
    fn y(&self) -> &[u8] { self.y }
    fn u(&self) -> &[u8] { self.u }
    fn v(&self) -> &[u8] { self.v }
}

// Read AES-256 key from JSON file
fn read_key_from_json(file_path: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let json_str = std::fs::read_to_string(file_path)?;
    let json: Value = serde_json::from_str(&json_str)?;
    let key_hex = json["encryption_key"]
        .as_str()
        .ok_or("encryption_key field not found or not a string in config.json")?;
    let key_bytes = hex::decode(key_hex)?;
    if key_bytes.len() != 32 {
        return Err(format!("Key must be 32 bytes (64 hex chars), but got {} bytes", key_bytes.len()).into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

// --- STUN Query Function ---
const STUN_SERVER: &str = "stun.l.google.com:19302"; // Google's public STUN server

// Make the function async and use Tokio's UdpSocket
async fn perform_stun_query(socket: &UdpSocket, stun_server_addr_str: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
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
    let mut buffer = vec![0u8; 1500];
    let size = encoder.encode(&mut buffer, &message)?;
    let encoded_request = &buffer[..size];

    // 3. Send Request using Tokio socket and resolved SocketAddr
    socket.send_to(encoded_request, stun_socket_addr).await?;
    println!("STUN request sent.");

    // 4. Receive Response using Tokio socket
    let mut recv_buf = [0u8; 1500];
    let (num_bytes, src_addr) = match tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut recv_buf)).await {
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
        let error_details = match response_msg.get::<stun_rs::attributes::stun::ErrorCode>() {
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

// --- Read Peer Address from User (Remains synchronous) ---
fn read_peer_address() -> SocketAddr {
    loop {
        print!("Enter peer's public IP and port (e.g., 192.168.1.1:5000): ");
        io::stdout().flush().expect("Failed to flush stdout");

        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read input");
        let input = input.trim();

        match input.to_socket_addrs() {
            Ok(mut addrs) => {
                // Prioritize finding an IPv4 address
                if let Some(addr) = addrs.find(|addr| addr.is_ipv4()) {
                    println!("Using peer address: {}", addr);
                    return addr;
                } else {
                     // If no IPv4, try again with the input as maybe it was valid IPv6
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


// --- Perform UDP Hole Punching (Remains async) ---
async fn perform_hole_punch(
    socket: &UdpSocket, // Use Tokio's UdpSocket
    peer_addr: SocketAddr,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    println!("Initiating UDP hole punching to peer {}...", peer_addr);

    let punch_message = b"PUNCH";
    let timeout = Duration::from_secs(10);
    let punch_interval = Duration::from_millis(100);
    let start_time = Instant::now();

    let mut recv_buf = [0u8; 1024];

    loop {
        // Send punch packet
        socket.send_to(punch_message, peer_addr).await?;

        // Check for incoming packets with a short timeout
        match tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut recv_buf)).await {
            Ok(Ok((num_bytes, src_addr))) => {
                // Check if the packet is from the peer and is a punch message
                if src_addr == peer_addr && num_bytes >= punch_message.len() && &recv_buf[..punch_message.len()] == punch_message {
                    println!("Hole punching successful! Received response from peer {}", src_addr);
                    // Send one last confirmation punch back
                    socket.send_to(b"PUNCH_ACK", src_addr).await?;
                    return Ok(src_addr);
                } else if src_addr == peer_addr {
                    // Received something else from the peer, assume punch worked
                    println!("Hole punching successful! Received other data from peer {}", src_addr);
                     // Send one last confirmation punch back
                     socket.send_to(b"PUNCH_ACK", src_addr).await?;
                    return Ok(src_addr);
                } else if num_bytes >= punch_message.len() && &recv_buf[..punch_message.len()] == b"PUNCH_ACK" && src_addr == peer_addr {
                     println!("Hole punching successful! Received PUNCH_ACK from peer {}", src_addr);
                     return Ok(src_addr);
                }
                // Ignore packets from other sources or unexpected content during punching
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
        if start_time.elapsed() >= timeout {
            return Err("Hole punching timed out after 10 seconds. Ensure the peer is running and trying to punch simultaneously.".into());
        }

        // Wait before sending the next punch
        tokio::time::sleep(punch_interval).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Socket Setup using Tokio UdpSocket
    let local_addr = "0.0.0.0:5000";
    let socket = UdpSocket::bind(local_addr).await?;
    println!("Socket bound to {}", socket.local_addr()?);

    // Perform STUN query (await the async function)
    // Prefix with _ to silence unused variable warning
    let _public_socket_addr = match perform_stun_query(&socket, STUN_SERVER).await {
        Ok(public_addr) => {
            println!("*** Your public address is likely: {} ***", public_addr);
            println!("*** Share this address with your peer. ***");
            Some(public_addr)
        }
        Err(e) => {
            eprintln!("!!! STUN query failed: {} !!!", e);
            eprintln!("!!! Proceeding without public address information. NAT traversal might fail if not symmetric. !!!");
            None
        }
    };

    // Prompt user for peer's address (synchronous call within async main)
    let peer_addr = read_peer_address();

    // Perform UDP hole punching (await the async function)
    let connected_peer_addr = perform_hole_punch(&socket, peer_addr).await?;
    println!("Successfully established potential connection path to peer {}", connected_peer_addr);

    // Note: No explicit socket.connect() needed for Tokio UDP send_to/recv_from

    // Read encryption key
    let key = read_key_from_json("config.json")?;

    // Initialize OpenCV (remains synchronous)
    highgui::named_window("Video", highgui::WINDOW_AUTOSIZE)?;
    let mut cap = videoio::VideoCapture::new(0, videoio::CAP_ANY)?;
    if !cap.is_opened()? {
        eprintln!("Failed to open camera");
        std::process::exit(1); // Or return Err(...)
    }
    cap.set(videoio::CAP_PROP_FRAME_WIDTH, 640.0)?;
    cap.set(videoio::CAP_PROP_FRAME_HEIGHT, 480.0)?;
    cap.set(videoio::CAP_PROP_FPS, 30.0)?;

    // Set up Tokio MPSC channels for communication
    let (tx_send, rx_send) = mpsc::channel::<(u32, Mat)>(10); // Bounded channel
    let (tx_recv, mut rx_recv) = mpsc::channel::<(u32, Mat)>(10); // Receiver needs to be mutable

    // Wrap socket in Arc for sharing between tasks
    let socket = Arc::new(socket);
    let socket_sender = Arc::clone(&socket);
    let socket_receiver = Arc::clone(&socket);
    let key_clone = key;

    // Spawn networking tasks directly onto the Tokio runtime
    let sender_handle = tokio::spawn(sender_task(socket_sender, connected_peer_addr, key_clone, rx_send));
    let receiver_handle = tokio::spawn(receiver_task(socket_receiver, key, tx_recv));

    // Main video loop (handling UI and camera capture)
    let mut seq_num = 0;
    let target_frame_duration = Duration::from_secs_f64(1.0 / 30.0);

    loop {
        let frame_start = Instant::now();

        // Capture frame
        let mut frame = Mat::default();
        if cap.read(&mut frame)? && !frame.empty() {
            // Use try_send for non-blocking send from the main loop
            match tx_send.try_send((seq_num, frame)) {
                 Ok(_) => seq_num = seq_num.wrapping_add(1),
                 Err(mpsc::error::TrySendError::Full(_)) => {
                     // eprintln!("Sender channel full, dropping frame {}", seq_num);
                     // Drop the frame implicitly by doing nothing
                 },
                 Err(mpsc::error::TrySendError::Closed(_)) => {
                     eprintln!("Networking task (sender) closed the channel.");
                     break;
                 }
            }
        } else {
            // No frame read, maybe sleep briefly
            tokio::time::sleep(Duration::from_millis(5)).await; // Use Tokio sleep
        }

        // Display received frame (use try_recv for non-blocking check)
        match rx_recv.try_recv() {
            Ok((_rec_seq_num, decoded_frame)) => {
                if !decoded_frame.empty() {
                    highgui::imshow("Video", &decoded_frame)?;
                }
            },
            Err(mpsc::error::TryRecvError::Empty) => {
                // No frame received yet, continue loop
            },
            Err(mpsc::error::TryRecvError::Disconnected) => {
                eprintln!("Networking task (receiver) closed the channel.");
                break;
            }
        }

        // Exit on ESC key (ASCII 27) - OpenCV GUI runs synchronously
        if highgui::wait_key(1)? == 27 {
            break;
        }

        // Maintain target FPS using Tokio sleep
        let elapsed = frame_start.elapsed();
        if elapsed < target_frame_duration {
            tokio::time::sleep(target_frame_duration - elapsed).await;
        }
    }

    println!("Exiting main loop...");
    // Optionally, you could signal the tasks to shut down gracefully here
    // For now, wait for them to complete (they should exit when channels close)
    println!("Waiting for network tasks...");
    let _ = tokio::try_join!(sender_handle, receiver_handle)?; // Wait for tasks, propagate panics

    println!("Network tasks finished. Application finished.");
    highgui::destroy_all_windows()?;
    Ok(()) // Return Ok(()) from main
}


// --- Sender Task (Handles encoding, encrypting, sending) ---
async fn sender_task(
    socket: Arc<UdpSocket>,        // Use Tokio's UdpSocket
    peer_addr: SocketAddr,        // Pass the confirmed peer address
    key: [u8; 32],
    mut rx_send: mpsc::Receiver<(u32, Mat)>, // Use Tokio's MPSC Receiver
) {
    let mut encoder = match Encoder::new() {
        Ok(enc) => enc,
        Err(e) => {
            eprintln!("Failed to initialize H.264 encoder: {:?}", e);
            return;
        }
    };

    // Receive frames from the main loop via the channel
    while let Some((seq_num, frame)) = rx_send.recv().await {
        let mut yuv_mat = Mat::default();
        if imgproc::cvt_color_def(
            &frame,
            &mut yuv_mat,
            imgproc::COLOR_BGR2YUV_I420
        ).is_err() {
            eprintln!("Failed to convert frame {} to YUV", seq_num);
            continue;
        }

        let width = yuv_mat.cols() as usize;
        let height = (yuv_mat.rows() * 2 / 3) as usize; // I420 height is 1.5x BGR height
        let yuv_data = match yuv_mat.data_bytes() {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Failed to get YUV data bytes for frame {}: {:?}", seq_num, e);
                continue;
            }
        };

        let y_size = width * height;
        let uv_width = width / 2;
        let uv_height = height / 2;
        let uv_size = uv_width * uv_height;
        let expected_total_size = y_size + 2 * uv_size;

        if yuv_data.len() < expected_total_size {
             eprintln!("YUV data size mismatch for frame {}. Expected at least {}, got {}. Skipping.", seq_num, expected_total_size, yuv_data.len());
             continue;
        }

        // Extract planes carefully based on I420 format (Y, then U, then V)
        let y_plane = &yuv_data[..y_size];
        let u_plane = &yuv_data[y_size..y_size + uv_size];
        let v_plane = &yuv_data[y_size + uv_size .. expected_total_size]; // Use expected_total_size

        let yuv_view = MatAsYuv {
            width,
            height,
            y: y_plane,
            u: u_plane,
            v: v_plane,
        };

        let fragments: Vec<Vec<u8>> = {
            let bitstream_result = encoder.encode(&yuv_view);
            let bitstream = match bitstream_result {
                Ok(bs) => bs.to_vec(),
                Err(e) => {
                    eprintln!("Failed to encode frame {}: {:?}", seq_num, e);
                    continue; // Skip this frame
                }
            };

            if bitstream.is_empty() {
                 // eprintln!("Warning: Encoder produced empty bitstream for frame {}", seq_num);
                continue; // Skip if encoding yields nothing
            }

            // Fragment the encoded bitstream
            const MAX_PAYLOAD_SIZE: usize = 1300; // Leave space for header + IV + potential padding
            bitstream.chunks(MAX_PAYLOAD_SIZE)
                     .map(|chunk| chunk.to_vec())
                     .collect()
        };

        let total_frags = fragments.len() as u16;

        if total_frags == 0 {
             eprintln!("Warning: No fragments generated after encoding frame {}", seq_num);
            continue;
        }

        for (frag_idx, frag_data) in fragments.iter().enumerate() {
            if frag_data.is_empty() {
                eprintln!("Warning: Empty fragment {}/{} for frame {}", frag_idx, total_frags, seq_num);
                continue;
            }

            let iv = rand::thread_rng().gen::<[u8; 16]>();
            let mut buf = frag_data.to_vec(); // Clone fragment data for encryption buffer
            let original_len = buf.len();

            // PKCS7 padding requires buffer to be large enough for at least one padding byte
            // Resize buffer to next block size multiple for encryption_padded_mut
            let block_size = 16; // AES block size
            let padded_len = (original_len / block_size + 1) * block_size;
            buf.resize(padded_len, 0); // Resize with zeros, padding will overwrite


            let encryptor = Aes256CbcEncryptor::new(&key.into(), &iv.into());

            let ciphertext_slice = match encryptor.encrypt_padded_mut::<Pkcs7>(&mut buf, original_len) {
                 Ok(ct) => ct,
                 Err(_) => {
                     eprintln!("Encryption padding failed for seq {}, frag {}", seq_num, frag_idx);
                     continue; // Skip this fragment
                 }
            };

            let header = PacketHeader {
                seq_num,
                frag_idx: frag_idx as u16,
                total_frags,
                iv,
            };

            // Construct the final packet: Header | IV | Ciphertext
            let mut packet = Vec::with_capacity(8 + 16 + ciphertext_slice.len()); // Header=8, IV=16
            packet.write_u32::<BigEndian>(header.seq_num).unwrap();
            packet.write_u16::<BigEndian>(header.frag_idx).unwrap();
            packet.write_u16::<BigEndian>(header.total_frags).unwrap();
            packet.extend_from_slice(&header.iv);
            packet.extend_from_slice(ciphertext_slice);

            // Send using Tokio socket's send_to
            if let Err(e) = socket.send_to(&packet, peer_addr).await {
                eprintln!("Failed to send UDP packet for frame {}, frag {}: {}", seq_num, frag_idx, e);
                // If send fails, the receiver might miss fragments.
                // Consider breaking or implementing retry/error handling logic.
            }
        }
    }
    println!("Sender task finished (channel closed).");
}


// --- Receiver Task (Handles receiving, decrypting, decoding) ---
async fn receiver_task(
    socket: Arc<UdpSocket>,       // Use Tokio's UdpSocket
    key: [u8; 32],
    tx_recv: mpsc::Sender<(u32, Mat)>, // Use Tokio's MPSC Sender
) {
    let mut decoder = match Decoder::new() {
        Ok(dec) => dec,
        Err(e) => {
            eprintln!("Failed to initialize H.264 decoder: {:?}", e);
            return;
        }
    };
    // Buffer to reassemble frames from fragments
    let mut frame_reassembly_buffer: HashMap<u32, Vec<Option<Vec<u8>>>> = HashMap::new();
    // Keep track of the last received index for each frame to potentially discard old frames
    let mut frame_last_seen: HashMap<u32, Instant> = HashMap::new();
    let max_buffer_age = Duration::from_secs(2); // Discard incomplete frames older than this

    let mut recv_buf = vec![0u8; 2048]; // Buffer for incoming UDP packets

    loop {
        // Clean up old, incomplete frames periodically
        let now = Instant::now();
        frame_reassembly_buffer.retain(|seq_num, _| {
            if let Some(last_seen) = frame_last_seen.get(seq_num) {
                if now.duration_since(*last_seen) > max_buffer_age {
                    // eprintln!("Discarding stale frame buffer for seq {}", seq_num);
                    frame_last_seen.remove(seq_num);
                    return false; // Remove the entry
                }
            } else {
                 // If somehow it's not in frame_last_seen, keep it for now but log warning
                 // eprintln!("Warning: Frame {} in reassembly buffer but not in last_seen map.", seq_num);
                 frame_last_seen.insert(*seq_num, now); // Add it now
            }
            true // Keep the entry
        });


        // Receive packet using Tokio socket's recv_from
        let (num_bytes, src_addr) = match socket.recv_from(&mut recv_buf).await {
            Ok(result) => result,
            Err(e) => {
                 if tx_recv.is_closed() {
                      println!("Receiver task exiting: channel closed.");
                      break; // Exit if the main thread channel is closed
                 }
                eprintln!("Failed to receive UDP packet: {}", e);
                // Add a small delay to prevent tight loop on persistent errors
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue; // Try receiving again
            }
        };

        let packet_data = &recv_buf[..num_bytes];

        // --- Packet Parsing and Decryption ---
        const HEADER_SIZE: usize = 8; // seq(4) + frag_idx(2) + total_frags(2)
        const IV_SIZE: usize = 16;
        const MIN_PACKET_SIZE: usize = HEADER_SIZE + IV_SIZE + 1; // Must have at least 1 byte of ciphertext

        if packet_data.len() < MIN_PACKET_SIZE {
            eprintln!("Received packet too small: {} bytes (from {})", packet_data.len(), src_addr);
            continue;
        }

        // Parse header
        let mut cursor = Cursor::new(&packet_data[..HEADER_SIZE]);
        let seq_num = match cursor.read_u32::<BigEndian>() { Ok(v) => v, Err(_) => { eprintln!("Failed to read seq_num from {}", src_addr); continue; }};
        let frag_idx = match cursor.read_u16::<BigEndian>() { Ok(v) => v, Err(_) => { eprintln!("Failed to read frag_idx for seq {} from {}", seq_num, src_addr); continue; }};
        let total_frags = match cursor.read_u16::<BigEndian>() { Ok(v) => v, Err(_) => { eprintln!("Failed to read total_frags for seq {} from {}", seq_num, src_addr); continue; }};

        // Extract IV
        let iv_start = HEADER_SIZE;
        let iv_end = iv_start + IV_SIZE;
        let iv: [u8; 16] = match packet_data[iv_start..iv_end].try_into() {
             Ok(arr) => arr,
             Err(_) => { eprintln!("Failed to extract IV slice for seq {} from {}", seq_num, src_addr); continue; }
        };

        // Extract ciphertext
        let ciphertext_slice = &packet_data[iv_end..];

        // Basic validation of fragment info
         if total_frags == 0 || frag_idx >= total_frags {
             eprintln!("Invalid fragment indices received from {}: seq {}, idx {}, total {}", src_addr, seq_num, frag_idx, total_frags);
             continue;
         }

        // Decrypt
        let mut decrypt_buf = ciphertext_slice.to_vec(); // Clone ciphertext for in-place decryption
        let decryptor = Aes256CbcDecryptor::new(&key.into(), &iv.into());

        let plaintext_slice = match decryptor.decrypt_padded_mut::<Pkcs7>(&mut decrypt_buf) {
            Ok(pt) => pt,
            Err(UnpadError) => {
                eprintln!("Decryption failed (padding error) for seq {}, frag {} from {}", seq_num, frag_idx, src_addr);
                continue; // Skip this fragment
            }
            // Other potential errors if decrypt_padded_mut changes signature
        };
        let plaintext = plaintext_slice.to_vec(); // Clone the decrypted data


        // --- Frame Reassembly ---
        frame_last_seen.insert(seq_num, Instant::now()); // Update last seen time

        let entry = frame_reassembly_buffer
            .entry(seq_num)
            .or_insert_with(|| vec![None; total_frags as usize]);

        // Check consistency: If total_frags changed for an existing entry, reset it.
        if entry.len() != total_frags as usize {
             eprintln!("Inconsistent total_frags for seq {}. Previous {}, new {}. Discarding old parts.", seq_num, entry.len(), total_frags);
             *entry = vec![None; total_frags as usize]; // Reset with correct size
        }

        // Store the fragment if the slot is empty and index is valid
        if (frag_idx as usize) < entry.len() {
             if entry[frag_idx as usize].is_none() {
                 entry[frag_idx as usize] = Some(plaintext);
             } else {
                 // Duplicate fragment received, ignore it
                 // eprintln!("Duplicate fragment {}/{} for seq {}", frag_idx, total_frags, seq_num);
             }
        } else {
             // This case should be caught by the earlier check `frag_idx >= total_frags`
             eprintln!("Fragment index {} out of bounds for buffer size {} (seq {})", frag_idx, entry.len(), seq_num);
             continue;
        }

        // Check if frame is complete
        if entry.iter().all(Option::is_some) {
            let mut complete_frame_data = Vec::new();
            // Drain the entry to get owned fragments and assemble the frame
            for fragment_option in entry.drain(..) { // Use drain which consumes the Vec<Option<...>>
                complete_frame_data.extend_from_slice(&fragment_option.unwrap()); // We know it's Some
            }

            // Remove the entry from the main buffer and the timestamp map now that it's processed
             frame_reassembly_buffer.remove(&seq_num);
             frame_last_seen.remove(&seq_num);


            // --- H.264 Decoding ---
            match decoder.decode(&complete_frame_data) {
                Ok(Some(decoded_yuv)) => {
                    // Successfully decoded a frame
                    let (width, height) = decoded_yuv.dimensions();
                    let (y_stride, u_stride, v_stride) = decoded_yuv.strides();

                    let y_plane = decoded_yuv.y();
                    let u_plane = decoded_yuv.u();
                    let v_plane = decoded_yuv.v();

                    // --- YUV (I420) to BGR Conversion ---
                    // Create a packed YUV representation suitable for OpenCV's cvtColor
                    // I420 format: Y plane first, then U plane, then V plane.
                    // OpenCV expects a single Mat with height = actual_height * 3 / 2

                    let uv_width = width / 2;
                    let uv_height = height / 2;
                    let expected_y_size = width * height; // Expected size without padding
                    let expected_u_size = uv_width * uv_height;
                    let expected_v_size = expected_u_size;
                    let total_packed_size = expected_y_size + expected_u_size + expected_v_size;

                    let mut packed_yuv_data = Vec::with_capacity(total_packed_size);
                    let mut copy_error = false;

                    // Copy Y plane, handling potential stride differences
                    if y_stride == width { // Fast path: no padding
                        if y_plane.len() >= expected_y_size {
                            packed_yuv_data.extend_from_slice(&y_plane[..expected_y_size]);
                        } else {
                            eprintln!("Error: Y plane too small ({} < {}) for seq {}. Skipping.", y_plane.len(), expected_y_size, seq_num);
                            copy_error = true;
                        }
                    } else { // Slow path: copy row by row
                        for r in 0..height {
                            let start = r * y_stride;
                            let end = start + width;
                            if end <= y_plane.len() {
                                packed_yuv_data.extend_from_slice(&y_plane[start..end]);
                            } else {
                                eprintln!("Error: Y plane row {} out of bounds (end={} > len={}) for seq {}. Skipping.", r, end, y_plane.len(), seq_num);
                                copy_error = true;
                                break;
                            }
                        }
                    }

                    // Copy U plane if no error yet
                    if !copy_error {
                        if u_stride == uv_width { // Fast path
                            if u_plane.len() >= expected_u_size {
                                packed_yuv_data.extend_from_slice(&u_plane[..expected_u_size]);
                            } else {
                                eprintln!("Error: U plane too small ({} < {}) for seq {}. Skipping.", u_plane.len(), expected_u_size, seq_num);
                                copy_error = true;
                            }
                        } else { // Slow path
                            for r in 0..uv_height {
                                let start = r * u_stride;
                                let end = start + uv_width;
                                if end <= u_plane.len() {
                                    packed_yuv_data.extend_from_slice(&u_plane[start..end]);
                                } else {
                                    eprintln!("Error: U plane row {} out of bounds (end={} > len={}) for seq {}. Skipping.", r, end, u_plane.len(), seq_num);
                                    copy_error = true;
                                    break;
                                }
                            }
                        }
                    }

                    // Copy V plane if no error yet
                    if !copy_error {
                         if v_stride == uv_width { // Fast path
                             if v_plane.len() >= expected_v_size {
                                 packed_yuv_data.extend_from_slice(&v_plane[..expected_v_size]);
                             } else {
                                 eprintln!("Error: V plane too small ({} < {}) for seq {}. Skipping.", v_plane.len(), expected_v_size, seq_num);
                                 copy_error = true;
                             }
                         } else { // Slow path
                            for r in 0..uv_height {
                                let start = r * v_stride;
                                let end = start + uv_width;
                                if end <= v_plane.len() {
                                    packed_yuv_data.extend_from_slice(&v_plane[start..end]);
                                } else {
                                    eprintln!("Error: V plane row {} out of bounds (end={} > len={}) for seq {}. Skipping.", r, end, v_plane.len(), seq_num);
                                    copy_error = true;
                                    break;
                                }
                            }
                        }
                    }


                    // Final check on data integrity before creating Mat
                    if copy_error || packed_yuv_data.len() != total_packed_size {
                        if !copy_error { // Only print size mismatch if copy didn't already fail
                            eprintln!("Error: Final packed YUV data size mismatch. Expected {}, got {}. Skipping frame {}.",
                                      total_packed_size, packed_yuv_data.len(), seq_num);
                        }
                        continue; // Skip this frame
                    }

                    // Create OpenCV Mat header for the packed YUV data (I420 format)
                    // The Mat height needs to be actual_height * 3 / 2 for I420
                    let yuv_mat_height = height as i32 * 3 / 2;
                    // --- Fix Starts Here: Added unsafe block ---
                    // Create the Mat first
                    // Safety: Creating a Mat with dimensions derived from a successfully decoded frame
                    // and a standard type (CV_8UC1) is generally safe, assuming sufficient memory.
                    let yuv_mat_result = match unsafe { Mat::new_rows_cols(yuv_mat_height, width as i32, CV_8UC1) } {
                        Ok(mut mat) => {
                             // Get mutable bytes, handling the Result explicitly
                            match mat.data_bytes_mut() {
                                Ok(mat_data_slice) => {
                                    // Check size before copying
                                    if mat_data_slice.len() == packed_yuv_data.len() {
                                        mat_data_slice.copy_from_slice(&packed_yuv_data);
                                        Ok(mat) // Return the owned, populated Mat
                                    } else {
                                        Err(opencv::Error::new(opencv::core::StsUnmatchedSizes,
                                            format!("Mat data size {} != packed data size {}", mat_data_slice.len(), packed_yuv_data.len())
                                        ))
                                    }
                                }
                                Err(e) => {
                                    // Error getting mutable slice from Mat
                                    eprintln!("Failed to get mutable Mat data for seq {}: {:?}", seq_num, e);
                                    Err(e) // Propagate OpenCV error
                                }
                            }
                        },
                        Err(e) => Err(e) // Propagate Mat creation error
                    };
                    // --- Fix Ends Here ---


                    // Now handle the result of creating and populating the yuv_mat
                    match yuv_mat_result {
                        Ok(yuv_mat_owned) => {
                             let mut bgr_frame = Mat::default();
                             if imgproc::cvt_color_def(
                                 &yuv_mat_owned, // Use the owned Mat
                                 &mut bgr_frame,
                                 imgproc::COLOR_YUV2BGR_I420, // Conversion code for packed I420
                             ).is_ok() {
                                 // Send the decoded BGR frame to the main loop
                                 if tx_recv.send((seq_num, bgr_frame)).await.is_err() {
                                     eprintln!("Receiver channel disconnected. Exiting receiver task.");
                                     break; // Stop the loop if the channel is closed
                                 }
                             } else {
                                 eprintln!("Failed to convert packed YUV to BGR for seq {}", seq_num);
                                 // Continue to next packet even if conversion fails
                             }
                        }
                        Err(e) => {
                             eprintln!("Failed to create or populate YUV Mat for seq {}: {:?}", seq_num, e);
                             // Continue to next packet
                        }
                    }
                },
                Ok(None) => { /* Decoder needs more data or produced no output, normal */ },
                Err(e) => {
                    eprintln!("H.264 decoding error for seq {}: {:?}", seq_num, e);
                    // Decoding errors might happen with corrupted data, continue processing
                }
            }
        }
    }
    println!("Receiver task finished.");
}