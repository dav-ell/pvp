use crate::network::{
    PacketHeader, PacketType, AUDIO_SAMPLE_RATE, AUDIO_CHANNELS, AUDIO_FRAME_SIZE,
    PACKET_HEADER_SIZE,
};
use crate::network::relay;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;

use aes::Aes256;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use aes::cipher::block_padding::{Pkcs7, UnpadError};
use cbc::Decryptor as CbcDecryptorGeneric;
use opencv::{
    core::{Mat, CV_8UC1},
    imgproc,
    prelude::{MatTrait, MatTraitConst}, // Added for data_mut, total, elem_size methods
};
use crate::network::cvt_color;
use openh264::decoder::Decoder as H264Decoder; // Alias to avoid name clash
use openh264::formats::YUVSource;
use opus::{Decoder as OpusDecoder, Channels as OpusChannels}; // Alias to avoid name clash
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time;

// Define specific decryptor type using the generic CBC implementation
type Aes256CbcDecryptor = CbcDecryptorGeneric<Aes256>;


/// Asynchronous task responsible for receiving video and audio data from the peer.
///
/// Listens for incoming UDP packets, parses the header, identifies packet type,
/// decrypts the payload, reassembles fragments into complete encoded frames/audio chunks,
/// decodes (H.264 video, Opus audio), and sends the results to the appropriate
/// downstream tasks (main thread for video, audio playback task for audio) via MPSC channels.
///
/// # Arguments
///
/// * `socket` - An `Arc`-wrapped asynchronous `UdpSocket` for receiving packets.
/// * `key` - The 32-byte AES-256 decryption key.
/// * `tx_video_recv` - An MPSC `Sender` to send decoded video `(u32, Mat)` frames to the main thread.
/// * `tx_audio_recv` - An MPSC `Sender` to send decoded audio `Vec<f32>` samples to the audio playback task.
pub async fn receiver_task(
    socket: Arc<UdpSocket>,
    key: [u8; 32],
    tx_video_recv: mpsc::Sender<(u32, Mat)>, // Video frames to main thread
    tx_audio_recv: mpsc::Sender<Vec<f32>>, // Audio samples to playback task
) {
    // --- H.264 Decoder Setup ---
    let mut h264_decoder = match H264Decoder::new() {
        Ok(dec) => dec,
        Err(e) => {
            eprintln!("FATAL: Failed to initialize H.264 decoder: {:?}", e);
            return;
        }
    };

    // --- Opus Decoder Setup ---
    let mut opus_decoder = match OpusDecoder::new(
        AUDIO_SAMPLE_RATE,
        if AUDIO_CHANNELS == 1 { OpusChannels::Mono } else { OpusChannels::Stereo },
    ) {
        Ok(dec) => dec,
        Err(e) => {
            eprintln!("FATAL: Failed to initialize Opus decoder: {:?}", e);
            return;
        }
    };
    // Pre-allocate buffer for decoded Opus audio. Max 120ms frame = 5760 samples.
    let mut opus_decode_buffer_f32 = vec![0f32; AUDIO_FRAME_SIZE * 6 * AUDIO_CHANNELS as usize];


    // Buffers for reassembling fragments
    type ReassemblyBuffer = HashMap<u32, (Vec<Option<Vec<u8>>>, Instant)>; // (fragments, last_seen)
    let mut video_reassembly_buffer: ReassemblyBuffer = HashMap::new();
    let mut audio_reassembly_buffer: ReassemblyBuffer = HashMap::new();
    let mut video_replay = pvp::packet_security::ReplayWindow::default();
    let mut audio_replay = pvp::packet_security::ReplayWindow::default();
    let max_buffer_age = Duration::from_secs(2); // Discard incomplete frames/chunks older than this

    let mut recv_buf = vec![0u8; 2048]; // Reusable buffer for incoming UDP packets

    println!("Receiver task started, listening for packets...");

    loop {
        // --- Periodically clean up stale reassembly buffers ---
        let now = Instant::now();
        video_reassembly_buffer.retain(|_, (_, last_seen)| now.duration_since(*last_seen) <= max_buffer_age);
        audio_reassembly_buffer.retain(|_, (_, last_seen)| now.duration_since(*last_seen) <= max_buffer_age);


        // --- Check if downstream channels are closed ---
        if tx_video_recv.is_closed() || tx_audio_recv.is_closed() {
             println!("Receiver task exiting: Downstream channel closed.");
             break;
        }

        // --- Receive Packet ---
        let (num_bytes, src_addr) = match socket.recv_from(&mut recv_buf).await {
            Ok(result) => result,
            Err(e) => {
                // Check again if channels closed during the await
                if tx_video_recv.is_closed() || tx_audio_recv.is_closed() {
                     println!("Receiver task exiting: Downstream channel closed after recv error.");
                     break;
                }
                eprintln!("Receiver: Failed to receive UDP packet: {}. Retrying...", e);
                time::sleep(Duration::from_millis(10)).await; // Prevent error spam
                continue;
            }
        };

        let packet_data = &recv_buf[..num_bytes];

        // Ignore pvp-relay control frames (JOIN_OK, PEER_READY, PEER_GONE, etc.)
        if relay::is_control_packet(packet_data) {
            continue;
        }

        // Authenticate the entire header, IV and ciphertext before parsing,
        // allocating reassembly state, decrypting, or invoking native codecs.
        let Some(packet_data) = pvp::packet_security::open(packet_data, &key) else {
            continue;
        };
        // --- Packet Header Parsing and Validation ---
        if packet_data.len() < PACKET_HEADER_SIZE {
            eprintln!("Receiver: Received packet too small: {} bytes (from {})", packet_data.len(), src_addr);
            continue;
        }

        let header = match PacketHeader::deserialize(packet_data) {
             Ok(h) => h,
             Err(e) => {
                 eprintln!("Receiver: Failed to deserialize packet header from {}: {}", src_addr, e);
                 continue;
             }
        };

        // Extract ciphertext slice (the rest of the packet after the header)
        let ciphertext_slice = &packet_data[PACKET_HEADER_SIZE..];


        // Basic validation of fragment info
        let maximum = match header.packet_type {
            PacketType::Video => 1024,
            PacketType::Audio => 16,
        };
        let replay = match header.packet_type {
            PacketType::Video => &mut video_replay,
            PacketType::Audio => &mut audio_replay,
        };
        if !replay.accepts(header.seq_num) {
            continue;
        }
        if header.total_frags == 0
            || header.total_frags > maximum
            || header.frag_idx >= header.total_frags
        {
            eprintln!(
                "Receiver ({:?}): Invalid fragment indices received from {}: seq {}, idx {}, total {}",
                header.packet_type, src_addr, header.seq_num, header.frag_idx, header.total_frags
            );
            continue;
        }

        // --- Decryption ---
        let mut decrypt_buf = ciphertext_slice.to_vec(); // Clone ciphertext for in-place decryption
        let decryptor = Aes256CbcDecryptor::new(&key.into(), &header.iv.into());

        let plaintext_slice = match decryptor.decrypt_padded_mut::<Pkcs7>(&mut decrypt_buf) {
            Ok(pt) => pt, // Returns slice of the original plaintext within decrypt_buf
            Err(UnpadError) => {
                eprintln!(
                    "Receiver ({:?}): Decryption failed (padding error) for seq {}, frag {} from {}. Might be wrong key or corrupted data.",
                    header.packet_type, header.seq_num, header.frag_idx, src_addr
                );
                continue; // Skip this fragment
            }
        };
        // Clone the decrypted plaintext slice for storage
        let plaintext = plaintext_slice.to_vec();

        // --- Reassembly by Type ---
        let reassembly_buffer = match header.packet_type {
            PacketType::Video => &mut video_reassembly_buffer,
            PacketType::Audio => &mut audio_reassembly_buffer,
        };

        if reassembly_buffer.len() >= 32 && !reassembly_buffer.contains_key(&header.seq_num) {
            continue;
        }
        // --- Fragment Insertion ---
        let total_frags_usize = header.total_frags as usize;
        let frag_idx_usize = header.frag_idx as usize;

        // Get or insert the buffer entry for this sequence number
        let (frame_buffer, last_seen) = reassembly_buffer
            .entry(header.seq_num)
            .or_insert_with(|| (vec![None; total_frags_usize], Instant::now()));

        // Update last seen time immediately after insertion
        *last_seen = Instant::now();


        // Consistency check: If total_frags changed mid-frame, discard old parts.
        if frame_buffer.len() != total_frags_usize {
            eprintln!(
                "Receiver ({:?}): Inconsistent total_frags for seq {}. Previous {}, new {}. Discarding old parts.",
                header.packet_type, header.seq_num, frame_buffer.len(), header.total_frags
            );
            *frame_buffer = vec![None; total_frags_usize]; // Reset with correct size
            // Attempt to insert the current fragment after reset (bounds check again)
             if frag_idx_usize < total_frags_usize && frame_buffer[frag_idx_usize].is_none() {
                 frame_buffer[frag_idx_usize] = Some(plaintext);
             } else if frag_idx_usize >= total_frags_usize {
                  eprintln!(
                    "Receiver ({:?}): Fragment index {} still out of bounds after reset for seq {}",
                    header.packet_type, frag_idx_usize, header.seq_num
                );
                 continue; // Skip invalid index
             } // else: duplicate fragment after reset, ignore silently
        } else {
            // Store the fragment if the slot is empty and index is valid
            if frag_idx_usize < frame_buffer.len() { // Check index is within current bounds
                if frame_buffer[frag_idx_usize].is_none() {
                    frame_buffer[frag_idx_usize] = Some(plaintext);
                } // else: Duplicate fragment received, ignore it silently
            } else {
                 eprintln!(
                    "Receiver ({:?}): Fragment index {} out of bounds for buffer size {} (seq {})",
                    header.packet_type, frag_idx_usize, frame_buffer.len(), header.seq_num
                );
                continue;
            }
        }


        // --- Check for Completion ---
        // Check if frame/chunk is complete (all slots in the vector are Some)
        // Must re-borrow frame_buffer immutably here for the check
        let is_complete = {
            let (frame_buffer_check, _) = reassembly_buffer.get(&header.seq_num).unwrap(); // Should exist
             frame_buffer_check.iter().all(Option::is_some)
        };

        if is_complete {
            replay.complete(header.seq_num);
            // Frame/chunk is complete, remove it from the buffer to process
             // Use remove() which returns the value
            if let Some((completed_fragments_opts, _)) = reassembly_buffer.remove(&header.seq_num) {

                // Assemble the complete data by concatenating fragments
                let mut complete_data = Vec::new();
                for fragment_option in completed_fragments_opts.into_iter() {
                    // We know it's Some because is_complete was true
                    complete_data.extend_from_slice(&fragment_option.unwrap());
                }

                // Process the completed data based on packet type
                let process_result = match header.packet_type {
                    PacketType::Video => {
                        process_video_frame(&complete_data, header.seq_num, &mut h264_decoder, &tx_video_recv).await
                    }
                    PacketType::Audio => {
                        process_audio_chunk(&complete_data, header.seq_num, &mut opus_decoder, &mut opus_decode_buffer_f32, &tx_audio_recv).await
                    }
                };

                if let Err(e) = process_result {
                     eprintln!(
                         "Receiver ({:?}): Error processing seq {}: {}",
                         header.packet_type, header.seq_num, e
                     );
                }

            } // else: Log error? Should not happen if is_complete was true.

        } // End if is_complete

    } // End loop

    println!("Receiver task finished.");
}


/// Processes a complete, reassembled, decrypted video frame.
async fn process_video_frame(
    data: &[u8],
    seq_num: u32,
    decoder: &mut H264Decoder,
    tx_video_recv: &mpsc::Sender<(u32, Mat)>,
) -> Result<(), String> {
    // println!("VID Receiver: Processing frame seq {}", seq_num); // Debug
    match decoder.decode(data) {
        Ok(Some(decoded_yuv)) => {
            let (width, height) = decoded_yuv.dimensions();
            let (y_stride, u_stride, v_stride) = decoded_yuv.strides();
            let y_plane = decoded_yuv.y();
            let u_plane = decoded_yuv.u();
            let v_plane = decoded_yuv.v();

            // --- YUV (I420) to BGR Conversion ---
            let uv_width = width / 2;
            let uv_height = height / 2;
            let expected_y_size = width * height;
            let expected_u_size = uv_width * uv_height;
            let expected_v_size = expected_u_size;
            let total_packed_size = expected_y_size + expected_u_size + expected_v_size;

            // Validate plane lengths (accounting for strides/padding)
            if y_plane.len() < (y_stride * height) as usize ||
               u_plane.len() < (u_stride * uv_height) as usize ||
               v_plane.len() < (v_stride * uv_height) as usize {
                return Err(format!("Decoded YUV plane size mismatch for seq {}", seq_num));
            }

            let mut packed_yuv_data = Vec::with_capacity(total_packed_size);

            // Pack Y plane row-by-row (handles strides/padding)
            for row in 0..height {
                let y_start = (row * y_stride) as usize;
                let y_end = y_start + width;
                if y_end > y_plane.len() {
                    return Err(format!("Y plane row {} out of bounds for seq {}", row, seq_num));
                }
                packed_yuv_data.extend_from_slice(&y_plane[y_start..y_end]);
            }

            // Pack U plane row-by-row
            for row in 0..uv_height {
                let u_start = (row * u_stride) as usize;
                let u_end = u_start + uv_width;
                if u_end > u_plane.len() {
                    return Err(format!("U plane row {} out of bounds for seq {}", row, seq_num));
                }
                packed_yuv_data.extend_from_slice(&u_plane[u_start..u_end]);
            }

            // Pack V plane row-by-row
            for row in 0..uv_height {
                let v_start = (row * v_stride) as usize;
                let v_end = v_start + uv_width;
                if v_end > v_plane.len() {
                    return Err(format!("V plane row {} out of bounds for seq {}", row, seq_num));
                }
                packed_yuv_data.extend_from_slice(&v_plane[v_start..v_end]);
            }

            if packed_yuv_data.len() != total_packed_size {
                return Err(format!("Final packed YUV size mismatch for seq {} (expected {}, got {})", seq_num, total_packed_size, packed_yuv_data.len()));
            }

            // Create OpenCV Mat for packed YUV data (contiguous I420)
            let yuv_mat_height = height as i32 * 3 / 2;
            let mut yuv_mat = match unsafe { Mat::new_rows_cols(yuv_mat_height, width as i32, CV_8UC1) } { // Wrapped in unsafe block
                Ok(mat) => mat,
                Err(e) => return Err(format!("Failed to create YUV Mat for seq {}: {:?}", seq_num, e)),
            };

            // Copy packed data into the Mat (unsafe but safe for contiguous single-channel Mat)
            let ptr = yuv_mat.data_mut(); // Removed ? as it returns *mut u8 directly
            let elem_size = yuv_mat.elem_size().map_err(|e| e.to_string())? as usize; // Map error to String for compatibility
            let len = yuv_mat.total() as usize * elem_size;
            if packed_yuv_data.len() == len {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        packed_yuv_data.as_ptr(),
                        ptr as *mut u8,
                        len,
                    );
                }
            } else {
                return Err(format!("Packed YUV data size mismatch for Mat copy in seq {}", seq_num));
            }

            let mut bgr_frame = Mat::default(); // Destination for BGR data
            if cvt_color(
                &yuv_mat,
                &mut bgr_frame,
                imgproc::COLOR_YUV2BGR_I420,
            )
            .is_ok()
            {
                // Send the BGR frame to the main loop
                if tx_video_recv.send((seq_num, bgr_frame)).await.is_err() {
                    // Don't return Err, just signal that the channel is closed upstream
                    println!("VID Receiver: Video channel disconnected while sending frame {}.", seq_num);
                    // Task will exit soon anyway due to channel checks in main loop
                }
            } else {
                return Err(format!("Failed to convert packed YUV to BGR for seq {}", seq_num));
            }
             // yuv_mat and packed_yuv_data go out of scope here - safe since cvt_color copied to bgr_frame.
        }
        Ok(None) => { /* Decoder needs more data or produced no output, normal */ }
        Err(e) => {
            return Err(format!("H.264 decoding error for seq {}: {:?}. Data might be corrupt.", seq_num, e));
        }
    }
    Ok(())
}


/// Processes a complete, reassembled, decrypted audio chunk.
async fn process_audio_chunk(
    data: &[u8],
    seq_num: u32,
    decoder: &mut OpusDecoder,
    decode_buffer: &mut [f32], // Reusable buffer for output samples
    tx_audio_recv: &mpsc::Sender<Vec<f32>>,
) -> Result<(), String> {
    // println!("AUD Receiver: Processing chunk seq {}", seq_num); // Debug
    match decoder.decode_float(data, decode_buffer, false) { // false = no FEC
        Ok(decoded_samples_count) => {
            if decoded_samples_count > 0 {
                // Create a new Vec with exactly the decoded samples
                let decoded_samples = decode_buffer[..decoded_samples_count * AUDIO_CHANNELS as usize].to_vec();

                // Send the decoded audio samples to the playback task
                 if tx_audio_recv.send(decoded_samples).await.is_err() {
                      println!("AUD Receiver: Audio channel disconnected while sending chunk {}.", seq_num);
                     // Task will exit soon anyway
                 }

            } else {
                 // This can happen if the packet contains only padding or is invalid
                 // eprintln!("AUD Receiver: Opus decoder returned 0 samples for seq {}", seq_num);
            }
        }
        Err(e) => {
            // Log decoding errors but don't necessarily stop the whole receiver
            return Err(format!("Opus decoding error for seq {}: {:?}. Data might be corrupt.", seq_num, e));
        }
    }
     Ok(())
}