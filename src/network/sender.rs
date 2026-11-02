use crate::network::{
    PacketHeader, MatAsYuv, PacketType, AUDIO_SAMPLE_RATE, AUDIO_CHANNELS,
    AUDIO_FRAME_SIZE, MAX_PAYLOAD_SIZE,
};
use std::sync::Arc;
use std::net::SocketAddr;

use aes::Aes256;
use aes::cipher::{BlockEncryptMut, KeyIvInit};
use aes::cipher::block_padding::Pkcs7;
use cbc::Encryptor as CbcEncryptorGeneric;
use opencv::{
    core::Mat,
    imgproc,
    prelude::*,
};
use crate::network::cvt_color;
use openh264::{
    encoder::{Encoder as H264Encoder, EncoderConfig as H264EncoderConfig}, // Alias to avoid name clash
    OpenH264API,
};
use opus::{Encoder as OpusEncoder, Application as OpusApplication, Channels as OpusChannels}; // Alias to avoid name clash
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::select; // Import select! macro

// Define specific encryptor type using the generic CBC implementation
type Aes256CbcEncryptor = CbcEncryptorGeneric<Aes256>;

// Enum to represent data received by the sender task
#[derive(Debug)]
pub enum SendData {
    Video(u32, Mat),
    Audio(Vec<f32>), // Raw f32 audio samples
}

/// Asynchronous task responsible for sending video and audio data to the peer.
///
/// Receives raw video `Mat` frames and raw audio `f32` samples via MPSC channels,
/// encodes them (H.264 for video, Opus for audio), encrypts the encoded data,
/// fragments it into packets with headers, and sends them over UDP.
///
/// # Arguments
///
/// * `socket` - An `Arc`-wrapped asynchronous `UdpSocket` for sending packets.
/// * `peer_addr` - The confirmed `SocketAddr` of the peer to send data to.
/// * `key` - The 32-byte AES-256 encryption key.
/// * `rx_send` - An MPSC `Receiver` to get `SendData` (video or audio) from other tasks.
pub async fn sender_task(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    key: [u8; 32],
    mut rx_send: mpsc::Receiver<SendData>, // Combined channel for video/audio
) {
    // --- H.264 Encoder Setup ---
    let h264_config = H264EncoderConfig::new(); // Use default config for simplicity
    let h264_api = OpenH264API::from_source();
    let mut h264_encoder = match H264Encoder::with_api_config(h264_api, h264_config) {
        Ok(enc) => enc,
        Err(e) => {
            eprintln!("FATAL: Failed to initialize H.264 encoder: {:?}", e);
            return;
        }
    };

    // --- Opus Encoder Setup ---
    let mut opus_encoder = match OpusEncoder::new(
        AUDIO_SAMPLE_RATE,
        if AUDIO_CHANNELS == 1 { OpusChannels::Mono } else { OpusChannels::Stereo },
        OpusApplication::Voip, // Optimize for voice/low latency
    ) {
        Ok(enc) => enc,
        Err(e) => {
            eprintln!("FATAL: Failed to initialize Opus encoder: {:?}", e);
            return;
        }
    };
    // Recommended Opus bitrate for VOIP mono @ 48kHz: 20-40 kbps. Let's use 32kbps.
    if let Err(e) = opus_encoder.set_bitrate(opus::Bitrate::Bits(32000)) {
         eprintln!("Warning: Failed to set Opus bitrate: {:?}", e);
    }


    println!("Sender task started, waiting for video/audio data...");

    let mut video_seq_num: u32 = 0;
    let mut audio_seq_num: u32 = 0;

    // Buffer for encoded audio output from Opus
    // Max Opus packet size for 60ms stereo 48kHz is ~1276 bytes. Add some buffer.
    let mut opus_out_buffer = vec![0u8; 2048];


    // Receive frames/audio from the main loop/audio capture via the channel
    loop {
        select! {
            // Biased select ensures we check for channel closure first
            biased;

            // Receive data (could be video or audio)
            maybe_data = rx_send.recv() => {
                match maybe_data {
                    Some(SendData::Video(_frame_seq_num_ignored, frame)) => {
                        // --- Video Processing ---
                        // Use internal sequence number for video packets
                        let current_video_seq = video_seq_num;
                        video_seq_num = video_seq_num.wrapping_add(1);

                        let mut yuv_mat = Mat::default();
                        if cvt_color(
                            &frame,
                            &mut yuv_mat,
                            imgproc::COLOR_BGR2YUV_I420, // Assuming input from OpenCV capture is BGR
                        )
                        .is_err()
                        {
                            eprintln!("VID Sender: Failed to convert frame {} to YUV_I420", current_video_seq);
                            continue;
                        }

                        let width = yuv_mat.cols() as usize;
                        // For I420, the Mat height is 1.5 times the actual frame height.
                        let height = (yuv_mat.rows() * 2 / 3) as usize;
                        let yuv_data = match yuv_mat.data_bytes() {
                            Ok(data) => data,
                            Err(e) => {
                                eprintln!("VID Sender: Failed to get YUV data bytes for frame {}: {:?}", current_video_seq, e);
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
                                "VID Sender: YUV data size mismatch for frame {}. Expected at least {}, got {}. Skipping.",
                                current_video_seq, expected_total_size, yuv_data.len()
                            );
                            continue;
                        }

                        // Extract planes based on I420 layout (Y, then U, then V)
                        let y_plane = &yuv_data[..y_size];
                        let u_plane = &yuv_data[y_size..y_size + uv_size];
                        let v_plane = &yuv_data[y_size + uv_size..expected_total_size];

                        let yuv_view = MatAsYuv {
                            width, height, y: y_plane, u: u_plane, v: v_plane,
                        };

                        // Encode the YUV frame
                        let encoded_video_data = match h264_encoder.encode(&yuv_view) {
                            Ok(bs) => bs.to_vec(), // Convert encoded bitstream to owned Vec<u8>
                            Err(e) => {
                                eprintln!("VID Sender: Failed to encode frame {}: {:?}", current_video_seq, e);
                                continue; // Skip this frame
                            }
                        };

                        if encoded_video_data.is_empty() {
                            // Encoder might not produce output for every frame (e.g., B-frames disabled)
                            // eprintln!("Warning: H264 Encoder produced empty bitstream for frame {}", current_video_seq);
                            continue; // Skip if encoding yields nothing for this frame
                        }

                        // Fragment and send the encoded video data
                        fragment_and_send(
                            PacketType::Video,
                            current_video_seq,
                            &encoded_video_data,
                            &key,
                            &socket,
                            peer_addr,
                        ).await;

                    }, // End Video Processing
                    Some(SendData::Audio(audio_samples)) => {
                        // --- Audio Processing ---
                         // Use internal sequence number for audio packets
                        let current_audio_seq = audio_seq_num;
                        audio_seq_num = audio_seq_num.wrapping_add(1);

                        // Ensure the input slice length matches the Opus frame size
                        if audio_samples.len() != AUDIO_FRAME_SIZE * AUDIO_CHANNELS as usize {
                            eprintln!(
                                "AUD Sender: Received audio data size {} does not match Opus frame size {}. Skipping.",
                                audio_samples.len(),
                                AUDIO_FRAME_SIZE * AUDIO_CHANNELS as usize
                            );
                            continue;
                        }

                        // Encode audio using Opus
                        match opus_encoder.encode_float(&audio_samples, &mut opus_out_buffer) {
                            Ok(encoded_len) => {
                                if encoded_len > 0 {
                                    let encoded_audio_data = &opus_out_buffer[..encoded_len];
                                    // Fragment and send the encoded audio data
                                    fragment_and_send(
                                        PacketType::Audio,
                                        current_audio_seq,
                                        encoded_audio_data,
                                        &key,
                                        &socket,
                                        peer_addr,
                                    ).await;
                                } else {
                                     eprintln!("AUD Sender: Opus encoder produced 0 bytes for seq {}.", current_audio_seq);
                                }
                            }
                            Err(e) => {
                                eprintln!("AUD Sender: Failed to encode audio frame {}: {:?}", current_audio_seq, e);
                                // Consider if we should reset the encoder here?
                                // For now, just log and continue.
                            }
                        }
                    }, // End Audio Processing
                    None => {
                        println!("Sender task stopping: Channel closed (received None).");
                        break; // Exit loop if channel is closed
                    }
                } // end match maybe_data
            } // end recv operation
        } // end select!
    } // end loop

    println!("Sender task finished.");
}


/// Helper function to encrypt, fragment, and send data (video or audio).
async fn fragment_and_send(
    packet_type: PacketType,
    seq_num: u32,
    encoded_data: &[u8],
    key: &[u8; 32],
    socket: &Arc<UdpSocket>,
    peer_addr: SocketAddr,
) {
    // Fragment the encoded data into manageable chunks for UDP
    let fragments: Vec<&[u8]> = encoded_data
        .chunks(MAX_PAYLOAD_SIZE)
        .collect();

    let maximum = match packet_type {
        PacketType::Video => 1024,
        PacketType::Audio => 16,
    };
    if fragments.len() > maximum {
        return;
    }
    let total_frags = fragments.len() as u16;

    if total_frags == 0 {
        eprintln!(
            "Sender ({:?}): Warning: No fragments generated for seq {} (encoded size: {}). Skipping.",
            packet_type, seq_num, encoded_data.len()
        );
        return;
    }

    // Process and send each fragment
    for (frag_idx, frag_data) in fragments.into_iter().enumerate() {
        if frag_data.is_empty() {
            eprintln!(
                "Sender ({:?}): Warning: Empty fragment {}/{} for seq {}. Skipping.",
                packet_type, frag_idx, total_frags, seq_num
            );
            continue;
        }

        // Generate a unique IV for each fragment
        let iv: [u8; 16] = rand::thread_rng().gen();

        // --- Encryption ---
        // Prepare buffer for encryption (needs mutable copy)
        let mut buf = frag_data.to_vec(); // Clone fragment data
        let original_len = buf.len();

        // PKCS7 padding requires the buffer to be large enough for at least one padding byte.
        // Resize buffer to the next multiple of the block size (16 for AES).
        let block_size = 16;
        let padded_len = (original_len / block_size + 1) * block_size;
        buf.resize(padded_len, 0); // Resize, padding will overwrite zeros

        // Create encryptor instance
        let encryptor = Aes256CbcEncryptor::new(key.into(), &iv.into());

        // Encrypt the data in-place with PKCS7 padding
        let ciphertext_slice = match encryptor.encrypt_padded_mut::<Pkcs7>(&mut buf, original_len)
        {
            Ok(ct) => ct, // Returns slice of the padded ciphertext within buf
            Err(_) => {
                // Error is Infallible theoretically, but handle defensively
                eprintln!(
                    "Sender ({:?}): Encryption padding failed unexpectedly for seq {}, frag {}",
                    packet_type, seq_num, frag_idx
                );
                continue; // Skip this fragment
            }
        };

        // --- Packet Construction ---
        // Create the packet header
        let header = PacketHeader {
            packet_type,
            seq_num,
            frag_idx: frag_idx as u16,
            total_frags,
            iv,
        };

        // Construct the final packet: Header | Ciphertext
        // Header serialization already includes IV
        let header_bytes = header.serialize();
        let mut packet = Vec::with_capacity(header_bytes.len() + ciphertext_slice.len());
        packet.extend_from_slice(&header_bytes);
        packet.extend_from_slice(ciphertext_slice); // Append encrypted data
        let packet = pvp::packet_security::seal(&packet, key);


        // Check total packet size against common MTU limits (optional but good practice)
        if packet.len() > 1472 { // (1500 MTU - 20 IP header - 8 UDP header)
             eprintln!(
                 "Sender ({:?}): Warning: Packet size {} for seq {}, frag {} exceeds 1472 bytes. Fragmentation might occur.",
                 packet_type, packet.len(), seq_num, frag_idx
             );
        }


        // --- Send Packet ---
        // Send the packet using Tokio's async send_to
        if let Err(e) = socket.send_to(&packet, peer_addr).await {
            eprintln!(
                "Sender ({:?}): Failed to send UDP packet for seq {}, frag {}: {}",
                packet_type, seq_num, frag_idx, e
            );
            // If one fragment fails, subsequent fragments for this frame/audio chunk
            // are useless. Consider breaking the inner loop here.
            break;
        }
        // Add a small delay between sending fragments to avoid overwhelming the receiver buffer?
        // tokio::time::sleep(Duration::from_micros(50)).await; // Optional short delay
    }
}