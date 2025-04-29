// File: /Users/davell/Documents/github/pvp/src/network/sender.rs
use crate::network::{PacketHeader, MatAsYuv}; // Import from parent network module
use std::sync::Arc;
use std::net::SocketAddr;

use aes::Aes256;
use aes::cipher::{BlockEncryptMut, KeyIvInit};
use aes::cipher::block_padding::Pkcs7;
use cbc::Encryptor as CbcEncryptorGeneric;
use opencv::{
    core::{Mat, AlgorithmHint},
    imgproc,
    prelude::*,
};
use openh264::{
    encoder::{Encoder, EncoderConfig},
    OpenH264API,
};
use rand::Rng;
use byteorder::{BigEndian, WriteBytesExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

// Define specific encryptor type using the generic CBC implementation
type Aes256CbcEncryptor = CbcEncryptorGeneric<Aes256>;

/// Asynchronous task responsible for sending video data to the peer.
///
/// Receives raw `Mat` frames from the main thread via an MPSC channel,
/// converts them to YUV, encodes them using H.264, encrypts the encoded data,
/// fragments it into packets with headers, and sends them over UDP.
///
/// # Arguments
///
/// * `socket` - An `Arc`-wrapped asynchronous `UdpSocket` for sending packets.
/// * `peer_addr` - The confirmed `SocketAddr` of the peer to send data to.
/// * `key` - The 32-byte AES-256 encryption key.
/// * `rx_send` - An MPSC `Receiver` to get `(u32, Mat)` frames from the main thread.
pub async fn sender_task(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    key: [u8; 32],
    mut rx_send: mpsc::Receiver<(u32, Mat)>, // Takes ownership
) {
    // Initialize H.264 encoder
    let config = EncoderConfig::new(); // Use default config for simplicity
    let api = OpenH264API::from_source();
    let mut encoder = match Encoder::with_api_config(api, config) {
        Ok(enc) => enc,
        Err(e) => {
            eprintln!("Failed to initialize H.264 encoder: {:?}", e);
            return;
        }
    };

    println!("Sender task started, waiting for frames...");

    // Receive frames from the main loop via the channel
    while let Some((seq_num, frame)) = rx_send.recv().await {
        let mut yuv_mat = Mat::default();
        if imgproc::cvt_color(
            &frame,
            &mut yuv_mat,
            imgproc::COLOR_BGR2YUV_I420, // Assuming input from OpenCV capture is BGR
            0,
            AlgorithmHint::ALGO_HINT_DEFAULT, // <<< Corrected enum variant
        ).is_err() {
            eprintln!("Failed to convert frame {} to YUV_I420", seq_num);
            continue;
        }

        let width = yuv_mat.cols() as usize;
        // For I420, the Mat height is 1.5 times the actual frame height.
        let height = (yuv_mat.rows() * 2 / 3) as usize;
        let yuv_data = match yuv_mat.data_bytes() {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Failed to get YUV data bytes for frame {}: {:?}", seq_num, e);
                continue;
            }
        };

        // Calculate expected plane sizes for I420 format
        let y_size = width * height;
        let uv_width = width / 2;
        let uv_height = height / 2;
        let uv_size = uv_width * uv_height;
        let expected_total_size = y_size + 2 * uv_size;

        if yuv_data.len() < expected_total_size {
            eprintln!(
                "YUV data size mismatch for frame {}. Expected at least {}, got {}. Skipping.",
                seq_num, expected_total_size, yuv_data.len()
            );
            continue;
        }

        // Extract planes based on I420 layout (Y, then U, then V)
        let y_plane = &yuv_data[..y_size];
        let u_plane = &yuv_data[y_size..y_size + uv_size];
        let v_plane = &yuv_data[y_size + uv_size..expected_total_size];

        let yuv_view = MatAsYuv {
            width,
            height,
            y: y_plane,
            u: u_plane,
            v: v_plane,
        };

        // Encode the YUV frame
        let fragments: Vec<Vec<u8>> = {
            let bitstream = match encoder.encode(&yuv_view) {
                Ok(bs) => bs.to_vec(), // Convert encoded bitstream to owned Vec<u8>
                Err(e) => {
                    eprintln!("Failed to encode frame {}: {:?}", seq_num, e);
                    continue; // Skip this frame
                }
            };

            if bitstream.is_empty() {
                // Encoder might not produce output for every frame (e.g., B-frames disabled)
                // eprintln!("Warning: Encoder produced empty bitstream for frame {}", seq_num);
                continue; // Skip if encoding yields nothing for this frame
            }

            // Fragment the encoded bitstream into manageable chunks for UDP
            // Leave space for header (8), IV (16), and potential encryption padding
            const MAX_PAYLOAD_SIZE: usize = 1300;
            bitstream
                .chunks(MAX_PAYLOAD_SIZE)
                .map(|chunk| chunk.to_vec()) // Convert slices to owned Vec<u8>
                .collect()
        };

        let total_frags = fragments.len() as u16;

        if total_frags == 0 {
            // This shouldn't happen if bitstream wasn't empty, but check anyway
            eprintln!(
                "Warning: No fragments generated after encoding frame {} (bitstream size: {})",
                seq_num, 0
            ); // bitstream moved
            continue;
        }

        // Process and send each fragment
        for (frag_idx, frag_data) in fragments.into_iter().enumerate() {
            // Use into_iter to consume
            if frag_data.is_empty() {
                eprintln!(
                    "Warning: Empty fragment {}/{} for frame {}. Skipping.",
                    frag_idx, total_frags, seq_num
                );
                continue;
            }

            // Generate a unique IV for each fragment
            let iv = rand::thread_rng().gen::<[u8; 16]>();

            // Prepare buffer for encryption (needs mutable copy)
            let mut buf = frag_data; // Take ownership of the fragment data
            let original_len = buf.len();

            // PKCS7 padding requires the buffer to be large enough for at least one padding byte.
            // Resize buffer to the next multiple of the block size (16 for AES).
            let block_size = 16;
            let padded_len = (original_len / block_size + 1) * block_size;
            buf.resize(padded_len, 0); // Resize, padding will overwrite zeros

            // Create encryptor instance
            let encryptor = Aes256CbcEncryptor::new(&key.into(), &iv.into());

            // Encrypt the data in-place with PKCS7 padding
            let ciphertext_slice = match encryptor.encrypt_padded_mut::<Pkcs7>(&mut buf, original_len)
            {
                Ok(ct) => ct, // Returns slice of the padded ciphertext within buf
                Err(_) => {
                    // Error is Infallible theoretically, but handle defensively
                    eprintln!(
                        "Encryption padding failed unexpectedly for seq {}, frag {}",
                        seq_num, frag_idx
                    );
                    continue; // Skip this fragment
                }
            };

            // Create the packet header
            let header = PacketHeader {
                seq_num,
                frag_idx: frag_idx as u16,
                total_frags,
                iv,
            };

            // Construct the final packet: Header | IV | Ciphertext
            // Pre-allocate vector capacity for efficiency
            let mut packet = Vec::with_capacity(8 + 16 + ciphertext_slice.len());
            packet.write_u32::<BigEndian>(header.seq_num).unwrap(); // Use BigEndian for network order
            packet.write_u16::<BigEndian>(header.frag_idx).unwrap();
            packet.write_u16::<BigEndian>(header.total_frags).unwrap();
            packet.extend_from_slice(&header.iv); // Append IV
            packet.extend_from_slice(ciphertext_slice); // Append encrypted data

            // Send the packet using Tokio's async send_to
            if let Err(e) = socket.send_to(&packet, peer_addr).await {
                eprintln!(
                    "Failed to send UDP packet for frame {}, frag {}: {}",
                    seq_num, frag_idx, e
                );
                // Consider adding logic here: if sending fails, maybe break the inner loop
                // for this frame, as the receiver likely won't be able to reassemble it.
            }
        }
    }
    println!("Sender task finished (channel closed).");
}