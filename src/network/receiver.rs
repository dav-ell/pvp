// File: /Users/davell/Documents/github/pvp/src/network/receiver.rs
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::io::Cursor;

use aes::Aes256;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use aes::cipher::block_padding::{Pkcs7, UnpadError};
use cbc::Decryptor as CbcDecryptorGeneric;
use opencv::{
    core::{Mat, CV_8UC1, AlgorithmHint},
    imgproc,
    prelude::{MatTraitManual},
};
use openh264::decoder::Decoder;
use openh264::formats::YUVSource;
use byteorder::{BigEndian, ReadBytesExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time;

// Define specific decryptor type using the generic CBC implementation
type Aes256CbcDecryptor = CbcDecryptorGeneric<Aes256>;

/// Asynchronous task responsible for receiving video data from the peer.
///
/// Listens for incoming UDP packets, parses the header, decrypts the payload,
/// reassembles fragments into complete encoded frames, decodes the H.264 frames
/// into YUV, converts them to BGR `Mat` objects, and sends them to the main
/// thread via an MPSC channel for display.
///
/// # Arguments
///
/// * `socket` - An `Arc`-wrapped asynchronous `UdpSocket` for receiving packets.
/// * `key` - The 32-byte AES-256 decryption key.
/// * `tx_recv` - An MPSC `Sender` to send decoded `(u32, Mat)` frames to the main thread.
pub async fn receiver_task(
    socket: Arc<UdpSocket>,
    key: [u8; 32],
    tx_recv: mpsc::Sender<(u32, Mat)>, // Takes ownership
) {
    // Initialize H.264 decoder
    let mut decoder = match Decoder::new() {
        Ok(dec) => dec,
        Err(e) => {
            eprintln!("Failed to initialize H.264 decoder: {:?}", e);
            return;
        }
    };

    // Buffer to reassemble frames from fragments. Maps seq_num to a vector of optional fragments.
    let mut frame_reassembly_buffer: HashMap<u32, Vec<Option<Vec<u8>>>> = HashMap::new();
    // Keep track of the last time a fragment was seen for each frame to discard old/stale buffers.
    let mut frame_last_seen: HashMap<u32, Instant> = HashMap::new();
    let max_buffer_age = Duration::from_secs(2); // Discard incomplete frames older than this

    let mut recv_buf = vec![0u8; 2048]; // Reusable buffer for incoming UDP packets

    println!("Receiver task started, listening for packets...");

    loop {
        // --- Periodically clean up stale frame reassembly buffers ---
        let now = Instant::now();
        // Use retain for efficient in-place filtering
        frame_reassembly_buffer.retain(|seq_num, _| {
            if let Some(last_seen) = frame_last_seen.get(seq_num) {
                if now.duration_since(*last_seen) > max_buffer_age {
                    // eprintln!("Discarding stale frame buffer for seq {}", seq_num);
                    frame_last_seen.remove(seq_num); // Remove timestamp too
                    false // Remove the entry from frame_reassembly_buffer
                } else {
                    true // Keep the entry
                }
            } else {
                // This case implies the frame was somehow removed from last_seen but not the buffer.
                // Log a warning and remove it from the buffer for consistency.
                eprintln!(
                    "Warning: Frame {} in reassembly buffer but not in last_seen map. Discarding.",
                    seq_num
                );
                false // Remove the entry
            }
        });

        // --- Receive Packet ---
        // Use select! if you need to handle channel closure signal simultaneously
        let (num_bytes, src_addr) = match socket.recv_from(&mut recv_buf).await {
            Ok(result) => result,
            Err(e) => {
                // Check if the sender channel (main thread) is closed. If so, exit gracefully.
                if tx_recv.is_closed() {
                    println!("Receiver task exiting: Main thread channel closed.");
                    break;
                }
                eprintln!("Failed to receive UDP packet: {}. Retrying...", e);
                // Add a small delay to prevent spamming errors in a tight loop on persistent issues
                time::sleep(Duration::from_millis(10)).await;
                continue; // Try receiving again
            }
        };

        let packet_data = &recv_buf[..num_bytes];

        // --- Packet Parsing and Validation ---
        const HEADER_SIZE: usize = 8; // seq(4) + frag_idx(2) + total_frags(2)
        const IV_SIZE: usize = 16;
        const MIN_PACKET_SIZE: usize = HEADER_SIZE + IV_SIZE + 1; // Header + IV + at least 1 byte of ciphertext

        if packet_data.len() < MIN_PACKET_SIZE {
            eprintln!(
                "Received packet too small: {} bytes (from {})",
                packet_data.len(),
                src_addr
            );
            continue;
        }

        // Parse header using Cursor for safe reading
        let mut cursor = Cursor::new(&packet_data[..HEADER_SIZE]);
        let seq_num = match cursor.read_u32::<BigEndian>() {
            Ok(v) => v,
            Err(_) => {
                eprintln!("Failed to read seq_num from {}", src_addr);
                continue;
            }
        };
        let frag_idx = match cursor.read_u16::<BigEndian>() {
            Ok(v) => v,
            Err(_) => {
                eprintln!("Failed to read frag_idx for seq {} from {}", seq_num, src_addr);
                continue;
            }
        };
        let total_frags = match cursor.read_u16::<BigEndian>() {
            Ok(v) => v,
            Err(_) => {
                eprintln!("Failed to read total_frags for seq {} from {}", seq_num, src_addr);
                continue;
            }
        };

        // Extract IV
        let iv_start = HEADER_SIZE;
        let iv_end = iv_start + IV_SIZE;
        let iv: [u8; 16] = match packet_data[iv_start..iv_end].try_into() {
            Ok(arr) => arr,
            Err(_) => {
                eprintln!(
                    "Failed to extract IV slice (size {}) for seq {} from {}",
                    packet_data.len(),
                    seq_num,
                    src_addr
                );
                continue;
            } // Should be impossible if MIN_PACKET_SIZE check passed
        };

        // Extract ciphertext slice (the rest of the packet)
        let ciphertext_slice = &packet_data[iv_end..];

        // Basic validation of fragment info
        if total_frags == 0 || frag_idx >= total_frags {
            eprintln!(
                "Invalid fragment indices received from {}: seq {}, idx {}, total {}",
                src_addr, seq_num, frag_idx, total_frags
            );
            continue;
        }

        // --- Decryption ---
        let mut decrypt_buf = ciphertext_slice.to_vec(); // Clone ciphertext for in-place decryption
        let decryptor = Aes256CbcDecryptor::new(&key.into(), &iv.into());

        let plaintext_slice = match decryptor.decrypt_padded_mut::<Pkcs7>(&mut decrypt_buf) {
            Ok(pt) => pt, // Returns slice of the original plaintext within decrypt_buf
            Err(UnpadError) => {
                eprintln!(
                    "Decryption failed (padding error) for seq {}, frag {} from {}. Might be wrong key or corrupted data.",
                    seq_num, frag_idx, src_addr
                );
                continue; // Skip this fragment
            }
            // Other errors are unlikely with current `cbc`/`aes` versions but handle defensively if needed
        };
        // Clone the decrypted plaintext slice for storage
        let plaintext = plaintext_slice.to_vec();

        // --- Frame Reassembly ---
        frame_last_seen.insert(seq_num, Instant::now()); // Update last seen time

        let total_frags_usize = total_frags as usize;
        let frag_idx_usize = frag_idx as usize;

        // Get or insert the buffer for this sequence number
        let frame_buffer = frame_reassembly_buffer
            .entry(seq_num)
            .or_insert_with(|| vec![None; total_frags_usize]);

        // Consistency check: If total_frags changed mid-frame, discard old parts.
        if frame_buffer.len() != total_frags_usize {
            eprintln!(
                "Inconsistent total_frags for seq {}. Previous {}, new {}. Discarding old parts.",
                seq_num,
                frame_buffer.len(),
                total_frags
            );
            *frame_buffer = vec![None; total_frags_usize]; // Reset with correct size
            if frag_idx_usize < total_frags_usize {
                // Bounds check again
                frame_buffer[frag_idx_usize] = Some(plaintext);
            } else {
                eprintln!(
                    "Fragment index {} still out of bounds after reset for seq {}",
                    frag_idx_usize, seq_num
                );
                continue; // Skip this invalid fragment index even after reset
            }
        } else {
            // Store the fragment if the slot is empty and index is valid
            if frag_idx_usize < frame_buffer.len() {
                // Check index is within current bounds
                if frame_buffer[frag_idx_usize].is_none() {
                    frame_buffer[frag_idx_usize] = Some(plaintext);
                } else {
                    // Duplicate fragment received, ignore it silently
                    // eprintln!("Duplicate fragment {}/{} for seq {}", frag_idx, total_frags, seq_num);
                }
            } else {
                // This should theoretically be caught by the initial frag_idx >= total_frags check
                eprintln!(
                    "Fragment index {} out of bounds for buffer size {} (seq {})",
                    frag_idx_usize,
                    frame_buffer.len(),
                    seq_num
                );
                continue;
            }
        }

        // Check if frame is complete (all slots in the vector are Some)
        if frame_buffer.iter().all(Option::is_some) {
            // Frame is complete, remove it from the buffer to process
            let completed_fragments = frame_reassembly_buffer.remove(&seq_num).unwrap(); // Should exist
            frame_last_seen.remove(&seq_num); // Remove timestamp too

            // Assemble the complete frame data by concatenating fragments
            let mut complete_frame_data = Vec::new();
            // Use drain to take ownership and avoid clones
            for fragment_option in completed_fragments.into_iter() {
                complete_frame_data.extend_from_slice(&fragment_option.unwrap()); // We know it's Some
            }

            // --- H.264 Decoding ---
            println!(
                "Reassembled frame for seq {}: size = {} bytes.",
                seq_num,
                complete_frame_data.len()
            );
            // Log first few bytes for debugging H.264 issues if needed
            // let bytes_to_log = std::cmp::min(16, complete_frame_data.len());
            // if bytes_to_log > 0 { println!("First {} bytes (hex): {}", bytes_to_log, hex::encode(&complete_frame_data[..bytes_to_log])); }

            match decoder.decode(&complete_frame_data) {
                Ok(Some(decoded_yuv)) => {
                    // Successfully decoded a frame into YUV planes
                    let (width, height) = decoded_yuv.dimensions();
                    let (y_stride, u_stride, v_stride) = decoded_yuv.strides();

                    let y_plane = decoded_yuv.y();
                    let u_plane = decoded_yuv.u();
                    let v_plane = decoded_yuv.v();

                    // --- YUV (I420) to BGR Conversion for OpenCV Display ---
                    // We need to reconstruct a packed YUV Mat (height = 1.5 * actual height)
                    // that OpenCV's cvtColor with COLOR_YUV2BGR_I420 can understand.

                    let uv_width = width / 2;
                    let uv_height = height / 2;
                    // Calculate expected sizes *without* padding/stride issues
                    let expected_y_size = width * height;
                    let expected_u_size = uv_width * uv_height;
                    let expected_v_size = expected_u_size;
                    let total_packed_size = expected_y_size + expected_u_size + expected_v_size;

                    let mut packed_yuv_data = Vec::with_capacity(total_packed_size);
                    let mut copy_error = false;

                    // Copy Y plane, handling potential stride differences
                    if y_stride == width {
                        // Fast path: no padding in Y plane
                        if y_plane.len() >= expected_y_size {
                            packed_yuv_data.extend_from_slice(&y_plane[..expected_y_size]);
                        } else {
                            eprintln!(
                                "Error: Decoded Y plane too small ({} < {}) for seq {}. Skipping.",
                                y_plane.len(),
                                expected_y_size,
                                seq_num
                            );
                            copy_error = true;
                        }
                    } else {
                        // Slow path: copy row by row to remove stride padding
                        for r in 0..height {
                            let start = r * y_stride;
                            let end = start + width;
                            if end <= y_plane.len() {
                                packed_yuv_data.extend_from_slice(&y_plane[start..end]);
                            } else {
                                eprintln!(
                                    "Error: Decoded Y plane row {} out of bounds (end={} > len={}) for seq {}. Skipping.",
                                    r, end, y_plane.len(), seq_num
                                );
                                copy_error = true;
                                break;
                            }
                        }
                    }

                    // Copy U plane if no error yet
                    if !copy_error {
                        if u_stride == uv_width {
                            // Fast path
                            if u_plane.len() >= expected_u_size {
                                packed_yuv_data.extend_from_slice(&u_plane[..expected_u_size]);
                            } else {
                                eprintln!(
                                    "Error: Decoded U plane too small ({} < {}) for seq {}. Skipping.",
                                    u_plane.len(),
                                    expected_u_size,
                                    seq_num
                                );
                                copy_error = true;
                            }
                        } else {
                            // Slow path
                            for r in 0..uv_height {
                                let start = r * u_stride;
                                let end = start + uv_width;
                                if end <= u_plane.len() {
                                    packed_yuv_data.extend_from_slice(&u_plane[start..end]);
                                } else {
                                    eprintln!(
                                        "Error: Decoded U plane row {} out of bounds (end={} > len={}) for seq {}. Skipping.",
                                        r, end, u_plane.len(), seq_num
                                    );
                                    copy_error = true;
                                    break;
                                }
                            }
                        }
                    }

                    // Copy V plane if no error yet
                    if !copy_error {
                        if v_stride == uv_width {
                            // Fast path
                            if v_plane.len() >= expected_v_size {
                                packed_yuv_data.extend_from_slice(&v_plane[..expected_v_size]);
                            } else {
                                eprintln!(
                                    "Error: Decoded V plane too small ({} < {}) for seq {}. Skipping.",
                                    v_plane.len(),
                                    expected_v_size,
                                    seq_num
                                );
                                copy_error = true;
                            }
                        } else {
                            // Slow path
                            for r in 0..uv_height {
                                let start = r * v_stride;
                                let end = start + uv_width;
                                if end <= v_plane.len() {
                                    packed_yuv_data.extend_from_slice(&v_plane[start..end]);
                                } else {
                                    eprintln!(
                                        "Error: Decoded V plane row {} out of bounds (end={} > len={}) for seq {}. Skipping.",
                                        r, end, v_plane.len(), seq_num
                                    );
                                    copy_error = true;
                                    break;
                                }
                            }
                        }
                    }

                    // Final check before creating Mat and converting
                    if copy_error || packed_yuv_data.len() != total_packed_size {
                        if !copy_error {
                            // Only print size mismatch if copy didn't already fail
                            eprintln!(
                                "Error: Final packed YUV data size mismatch after handling strides. Expected {}, got {}. Skipping frame {}.",
                                total_packed_size, packed_yuv_data.len(), seq_num
                            );
                        }
                        continue; // Skip this frame
                    }

                    // Create OpenCV Mat for the packed YUV data (I420 format)
                    // The Mat height needs to be actual_height * 3 / 2 for COLOR_YUV2BGR_I420
                    let yuv_mat_height = height as i32 * 3 / 2;
                    let yuv_mat_result = unsafe {
                        // Safety: Creating a Mat with dimensions derived from a successfully decoded frame
                        // and a standard type (CV_8UC1) is safe, assuming sufficient memory is available.
                        // The dimensions are validated to match the packed YUV data size.
                        Mat::new_rows_cols(yuv_mat_height, width as i32, CV_8UC1)
                    };
                    let mut yuv_mat = match yuv_mat_result {
                        Ok(mat) => mat,
                        Err(e) => {
                            eprintln!("Failed to create YUV Mat for seq {}: {:?}", seq_num, e);
                            continue;
                        }
                    };

                    // Copy the packed YUV data into the Mat
                    match yuv_mat.data_bytes_mut() {
                        Ok(mat_data) => {
                            if mat_data.len() >= packed_yuv_data.len() {
                                mat_data[..packed_yuv_data.len()].copy_from_slice(&packed_yuv_data);
                            } else {
                                eprintln!(
                                    "Error: Mat buffer too small ({} < {}) for seq {}. Skipping.",
                                    mat_data.len(),
                                    packed_yuv_data.len(),
                                    seq_num
                                );
                                continue;
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to access Mat data for seq {}: {:?}", seq_num, e);
                            continue;
                        }
                    }

                    let mut bgr_frame = Mat::default(); // Destination for BGR data
                    if imgproc::cvt_color(
                        &yuv_mat,
                        &mut bgr_frame,
                        imgproc::COLOR_YUV2BGR_I420, // Conversion code for packed I420
                        0,
                        AlgorithmHint::ALGO_HINT_DEFAULT, // <<< Corrected enum variant
                    )
                    .is_ok()
                    {
                        // Send the successfully converted BGR frame to the main loop
                        if tx_recv.send((seq_num, bgr_frame)).await.is_err() {
                            eprintln!("Receiver channel disconnected. Exiting receiver task.");
                            break; // Stop the loop if the channel is closed
                        }
                    } else {
                        eprintln!("Failed to convert packed YUV to BGR for seq {}", seq_num);
                        // Continue to next packet even if conversion fails
                    }
                }
                Ok(None) => {
                    /* Decoder needs more data or produced no output this time, normal */
                }
                Err(e) => {
                    eprintln!(
                        "H.264 decoding error for seq {}: {:?}. Input data might be corrupt.",
                        seq_num, e
                    );
                    // Decoding errors might happen, continue processing subsequent packets
                }
            }
        } // End if frame_buffer.iter().all(Option::is_some)
    } // End loop
    println!("Receiver task finished.");
}