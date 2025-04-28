// File: /Users/davell/Documents/github/pvp/src/main.rs
// Change: Modified receiver_task to handle YUV stride differences.

use std::net::UdpSocket;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use aes::Aes256;
use aes::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};
use aes::cipher::block_padding::{Pkcs7, UnpadError};
use cbc::{Encryptor as CbcEncryptorGeneric, Decryptor as CbcDecryptorGeneric}; // Use generic names
use opencv::{
    core::{Mat, Mat_AUTO_STEP, CV_8UC1}, // Removed self, ToInputArray, ToOutputArray
    highgui,
    imgproc,
    prelude::*,
    videoio,
};
use openh264::{decoder::Decoder, encoder::Encoder}; // Removed DecodedYUV import
use openh264::formats::YUVSource;
use rand::Rng;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crossbeam::channel; // Specify channel for clarity

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
    // Returns (width, height)
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }
    // Returns (stride_y, stride_u, stride_v) in bytes
    fn strides(&self) -> (usize, usize, usize) {
        // Assuming standard I420 strides
        (self.width, self.width / 2, self.width / 2)
    }
    fn y(&self) -> &[u8] { self.y }
    fn u(&self) -> &[u8] { self.u }
    fn v(&self) -> &[u8] { self.v }
}

// Read AES-256 key from JSON file
fn read_key_from_json(file_path: &str) -> [u8; 32] {
    let json_str = std::fs::read_to_string(file_path).expect("Failed to read config.json");
    let json: Value = serde_json::from_str(&json_str).expect("Failed to parse JSON");
    let key_hex = json["encryption_key"]
        .as_str()
        .expect("encryption_key must be a string");
    let key_bytes = hex::decode(key_hex).expect("Failed to decode hex key");
    assert_eq!(key_bytes.len(), 32, "Key must be 32 bytes (64 hex chars)");
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    key
}

fn main() {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <destination_ip>", args[0]);
        std::process::exit(1);
    }
    let dest_ip = &args[1];
    let dest_addr = format!("{}:5000", dest_ip);
    let local_addr = "0.0.0.0:5000";

    // Read encryption key
    let key = read_key_from_json("config.json");

    // Set up UDP socket
    let socket = UdpSocket::bind(local_addr).expect("Failed to bind UDP socket");
    socket
        .connect(&dest_addr)
        .expect("Failed to connect to destination");

    // Initialize OpenCV
    highgui::named_window("Video", highgui::WINDOW_AUTOSIZE).expect("Failed to create window");
    let mut cap = videoio::VideoCapture::new(0, videoio::CAP_ANY).expect("Failed to init camera");
    if !cap.is_opened().unwrap() {
        eprintln!("Failed to open camera");
        std::process::exit(1);
    }
    cap.set(videoio::CAP_PROP_FRAME_WIDTH, 640.0)
        .expect("Failed to set width");
    cap.set(videoio::CAP_PROP_FRAME_HEIGHT, 480.0)
        .expect("Failed to set height");
    cap.set(videoio::CAP_PROP_FPS, 30.0).expect("Failed to set FPS");

    // Set up channels for communication between threads
    let (tx_send, rx_send) = channel::bounded::<(u32, Mat)>(10);
    let (tx_recv, rx_recv) = channel::bounded::<(u32, Mat)>(10);

    // Wrap socket in Arc for sharing between tasks
    let socket = Arc::new(socket);
    let socket_sender = Arc::clone(&socket);
    let socket_receiver = Arc::clone(&socket);
    let key_clone = key; // Clone key for sender task

    // Spawn networking thread with Tokio runtime
    let network_thread = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        rt.block_on(async {
            // Spawn sender and receiver tasks
            let sender_handle = tokio::spawn(sender_task(socket_sender, key_clone, rx_send));
            // Pass the original key (or another clone) to receiver_task
            let receiver_handle = tokio::spawn(receiver_task(socket_receiver, key, tx_recv));
            // Wait for both tasks to complete (or error)
            tokio::try_join!(sender_handle, receiver_handle).expect("Network tasks failed");
        });
    });

    // Main video loop (UI thread)
    let mut seq_num = 0;
    loop {
        let start = Instant::now();

        // Capture frame
        let mut frame = Mat::default();
        if cap.read(&mut frame).unwrap_or(false) && !frame.empty() {
             match tx_send.try_send((seq_num, frame)) { // Use try_send to avoid blocking UI
                 Ok(_) => seq_num = seq_num.wrapping_add(1), // Increment only if sent
                 Err(channel::TrySendError::Full(_)) => {
                     // eprintln!("Sender channel full, dropping frame {}", seq_num);
                     // Optional: Drop frame or handle differently
                 },
                 Err(channel::TrySendError::Disconnected(_)) => {
                     eprintln!("Networking thread disconnected (sender)");
                     break; // Exit loop if channel is broken
                 }
             }
        } else {
             eprintln!("Failed to capture frame or frame empty");
             // Optional: add a small delay if camera read fails consistently
             thread::sleep(Duration::from_millis(10));
        }

        // Display received frame
        match rx_recv.try_recv() { // Use try_recv to avoid blocking UI
            Ok((_rec_seq_num, decoded_frame)) => {
                if !decoded_frame.empty() {
                    highgui::imshow("Video", &decoded_frame).expect("Failed to display frame");
                } else {
                    eprintln!("Received empty frame from network task.");
                }
            },
            Err(channel::TryRecvError::Empty) => {
                // No frame received yet, continue loop
            },
            Err(channel::TryRecvError::Disconnected) => {
                eprintln!("Networking thread disconnected (receiver)");
                break; // Exit loop if channel is broken
            }
        }

        // Exit on ESC key (ASCII 27)
        // wait_key returns -1 if no key is pressed within the timeout
        if highgui::wait_key(1).unwrap_or(-1) == 27 {
            break;
        }

        // Maintain target FPS (adjust sleep duration)
        let elapsed = start.elapsed();
        let frame_duration = Duration::from_secs_f64(1.0 / 30.0); // Target ~30 FPS
        if elapsed < frame_duration {
            thread::sleep(frame_duration - elapsed);
        }
    }

    // Optional: Signal the network thread to shut down gracefully if needed
    // (e.g., close channels, set atomic flag)

    println!("Exiting main loop, waiting for network thread...");
    network_thread.join().expect("Network thread panicked");
    println!("Network thread joined. Application finished.");
    highgui::destroy_all_windows().expect("Failed to destroy OpenCV windows");
}

// --- Sender Task (Handles encoding, encrypting, sending) ---
async fn sender_task(
    socket: Arc<UdpSocket>,
    key: [u8; 32],
    rx_send: channel::Receiver<(u32, Mat)>,
) {
    let mut encoder = match Encoder::new() {
        Ok(enc) => enc,
        Err(e) => {
            eprintln!("Failed to initialize H.264 encoder: {:?}", e);
            return; // Exit task if encoder fails
        }
    };

    // Convert std::net::UdpSocket to tokio::net::UdpSocket *once* outside the loop
    let std_socket_clone = match socket.as_ref().try_clone() {
         Ok(s) => s,
         Err(e) => {
              eprintln!("Failed to clone std socket for Tokio conversion: {}", e);
              return;
         }
        };
    let tokio_socket = match tokio::net::UdpSocket::from_std(std_socket_clone) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to convert std socket to Tokio socket: {}", e);
            return;
        }
    };

    while let Ok((seq_num, frame)) = rx_send.recv() { // Blocks until a frame is received
        // Convert BGR to YUV420P
        let mut yuv_mat = Mat::default();
        if imgproc::cvt_color_def(
            &frame,
            &mut yuv_mat,
            imgproc::COLOR_BGR2YUV_I420
        ).is_err() {
            eprintln!("Failed to convert frame {} to YUV", seq_num);
            continue; // Skip this frame
        }

        // Prepare YUV data slices for the encoder
        let width = yuv_mat.cols() as usize;
        // OpenCV's I420 Mat height includes U and V planes (height * 3 / 2)
        // We need the original frame height for the Yuv trait implementation
        let height = (yuv_mat.rows() * 2 / 3) as usize;
        let yuv_data = match yuv_mat.data_bytes() {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Failed to get YUV data bytes for frame {}: {:?}", seq_num, e);
                continue;
            }
        };

        // Calculate plane sizes
        let y_size = width * height;
        let uv_width = width / 2;
        let uv_height = height / 2;
        let uv_size = uv_width * uv_height;
        let expected_total_size = y_size + 2 * uv_size;

        if yuv_data.len() < expected_total_size {
             eprintln!("YUV data size mismatch for frame {}. Expected {}, got {}. Skipping.", seq_num, expected_total_size, yuv_data.len());
             continue;
        }

        let y_plane = &yuv_data[..y_size];
        let u_plane = &yuv_data[y_size..y_size + uv_size];
        // Ensure V plane slice doesn't go out of bounds
        let v_plane = &yuv_data[y_size + uv_size .. expected_total_size];

        // Create our Yuv trait implementor
        let yuv_view = MatAsYuv {
            width,
            height,
            y: y_plane,
            u: u_plane,
            v: v_plane,
        };

        // Encode frame and process bitstream in a separate block
        // Collect owned fragments (Vec<Vec<u8>>) to fix lifetime issue
        let fragments: Vec<Vec<u8>> = { // Explicit type annotation for clarity
            let bitstream_result = encoder.encode(&yuv_view);
            let bitstream = match bitstream_result {
                Ok(bs) => bs.to_vec(), // Convert encoded bitstream (NAL units) to Vec<u8>
                Err(e) => {
                    eprintln!("Failed to encode frame {}: {:?}", seq_num, e);
                    continue;
                }
            };

            if bitstream.is_empty() {
                // Encoder might return empty if it needs more frames or GOP structure etc.
                // This might not be an error, just continue.
                // eprintln!("Encoder returned empty bitstream for frame {}", seq_num);
                continue;
            }

            // Fragment if necessary
            const MAX_FRAG_SIZE: usize = 1360; // Slightly less than common MTU (1500) minus headers
            // Map chunks to owned Vec<u8> and collect
            bitstream.chunks(MAX_FRAG_SIZE)
                     .map(|chunk| chunk.to_vec()) // Create owned Vec<u8> from slice
                     .collect() // Collects into Vec<Vec<u8>>
        }; // bitstream goes out of scope here, but fragments now owns the data

        let total_frags = fragments.len() as u16;

        if total_frags == 0 { // Should not happen if bitstream wasn't empty, but check
            eprintln!("Warning: Empty fragments generated for frame {}", seq_num);
            continue;
        }

        // Iterate over owned fragments (&Vec<u8>)
        for (frag_idx, frag_data) in fragments.iter().enumerate() {
            // Generate random IV per fragment
            let iv = rand::thread_rng().gen::<[u8; 16]>();

            // --- Encrypt fragment using encrypt_padded_mut ---
            // Clone fragment data into a buffer that might grow due to padding
            // frag_data is &Vec<u8>, to_vec() clones it
            let mut buf = frag_data.to_vec();
            let original_len = buf.len(); // Needed for encrypt_padded_mut
            // Reserve enough space for potential padding (up to one block)
            buf.resize(original_len + 16, 0); // Pad with zeros, PKCS7 will overwrite

            // Create encryptor instance
            let encryptor = Aes256CbcEncryptor::new(&key.into(), &iv.into());

            // Encrypt in place using encrypt_padded_mut
            let ciphertext_slice = match encryptor.encrypt_padded_mut::<Pkcs7>(&mut buf, original_len) {
                 Ok(ct) => ct,
                 Err(_) => { // PadError doesn't carry much info
                     eprintln!("Encryption padding failed for seq {}, frag {}", seq_num, frag_idx);
                     continue; // Skip this fragment
                 }
            };
            // --- End Encryption ---

            // Create packet header
            let header = PacketHeader {
                seq_num,
                frag_idx: frag_idx as u16,
                total_frags,
                iv,
            };

            // Assemble packet: Header | IV | Ciphertext
            // Pre-allocate buffer: 4 (seq) + 2 (idx) + 2 (total) + 16 (IV) + ciphertext len
            let mut packet = Vec::with_capacity(8 + 16 + ciphertext_slice.len());
            packet.write_u32::<BigEndian>(header.seq_num).unwrap(); // Assume Vec write doesn't fail
            packet.write_u16::<BigEndian>(header.frag_idx).unwrap();
            packet.write_u16::<BigEndian>(header.total_frags).unwrap();
            packet.extend_from_slice(&header.iv);
            packet.extend_from_slice(ciphertext_slice); // Use the slice from encrypt_padded_mut

            // Send packet using the Tokio socket created outside the loop
            if let Err(e) = tokio_socket.send(&packet).await {
                eprintln!("Failed to send UDP packet for frame {}, frag {}: {}", seq_num, frag_idx, e);
                // Consider if we should break or continue on send error
            }
        }
    }
    println!("Sender task finished.");
}

// --- Receiver Task (Handles receiving, decrypting, decoding) ---
async fn receiver_task(
    socket: Arc<UdpSocket>,
    key: [u8; 32],
    tx_recv: channel::Sender<(u32, Mat)>,
) {
    let mut decoder = match Decoder::new() {
        Ok(dec) => dec,
        Err(e) => {
            eprintln!("Failed to initialize H.264 decoder: {:?}", e);
            return; // Exit task if decoder fails
        }
    };
    // Buffer to reassemble frames: SeqNum -> Vec<Option<FragmentData>>
    let mut frame_reassembly_buffer: HashMap<u32, Vec<Option<Vec<u8>>>> = HashMap::new();

    // Convert std::net::UdpSocket to tokio::net::UdpSocket *once*
      let std_socket_clone = match socket.as_ref().try_clone() {
          Ok(s) => s,
          Err(e) => {
               eprintln!("(Receiver) Failed to clone std socket for Tokio conversion: {}", e);
               return;
          }
         };
    let tokio_socket = match tokio::net::UdpSocket::from_std(std_socket_clone) {
        Ok(s) => s,
        Err(e) => {
             eprintln!("(Receiver) Failed to convert std socket to Tokio socket: {}", e);
             return;
        }
    };

    let mut recv_buf = vec![0u8; 2048]; // Reusable buffer for receiving UDP packets

    loop {
        // Receive packet
        let (num_bytes, _src_addr) = match tokio_socket.recv_from(&mut recv_buf).await {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Failed to receive UDP packet: {}", e);
                // Consider breaking loop on certain errors
                continue;
            }
        };

        let packet_data = &recv_buf[..num_bytes];

        // --- Parse Header ---
        // Ensure packet is large enough for header + IV
        const HEADER_SIZE: usize = 8; // seq(4) + idx(2) + total(2)
        const IV_SIZE: usize = 16;
        if packet_data.len() < HEADER_SIZE + IV_SIZE {
            eprintln!("Received packet too small: {} bytes", packet_data.len());
            continue;
        }

        // Use cursor to read header fields safely
        let mut cursor = Cursor::new(&packet_data[..HEADER_SIZE]);
        let seq_num = match cursor.read_u32::<BigEndian>() { Ok(v) => v, Err(_) => { eprintln!("Failed to read seq_num"); continue; }};
        let frag_idx = match cursor.read_u16::<BigEndian>() { Ok(v) => v, Err(_) => { eprintln!("Failed to read frag_idx"); continue; }};
        let total_frags = match cursor.read_u16::<BigEndian>() { Ok(v) => v, Err(_) => { eprintln!("Failed to read total_frags"); continue; }};

        // Extract IV and Ciphertext
        let iv_start = HEADER_SIZE;
        let iv_end = iv_start + IV_SIZE;
        let iv: [u8; 16] = match packet_data[iv_start..iv_end].try_into() {
             Ok(arr) => arr,
             Err(_) => { eprintln!("Failed to extract IV slice"); continue; } // Should not happen if size check passed
        };
        let ciphertext_slice = &packet_data[iv_end..]; // This is a slice for now

         if total_frags == 0 || (frag_idx >= total_frags) {
             eprintln!("Invalid fragment indices received: idx {}, total {}", frag_idx, total_frags);
             continue;
        }

        // --- Decrypt fragment using decrypt_padded_mut ---
        // Clone ciphertext slice into a mutable buffer for in-place decryption
        let mut decrypt_buf = ciphertext_slice.to_vec();

        // Create decryptor instance
        let decryptor = Aes256CbcDecryptor::new(&key.into(), &iv.into());

        // Decrypt in place using decrypt_padded_mut
        let plaintext_slice = match decryptor.decrypt_padded_mut::<Pkcs7>(&mut decrypt_buf) {
            Ok(pt) => pt,
            Err(UnpadError) => { // Decryption error is UnpadError
                eprintln!("Decryption failed (padding error) for seq {}, frag {}", seq_num, frag_idx);
                // Potentially remove entry from buffer if decryption fails consistently?
                // frame_reassembly_buffer.remove(&seq_num);
                continue; // Skip this fragment
            }
        };
        // Convert the resulting plaintext slice back to owned Vec<u8> for storage
        let plaintext = plaintext_slice.to_vec();
        // --- End Decryption ---

        // Store fragment in reassembly buffer
        let entry = frame_reassembly_buffer
            .entry(seq_num)
            .or_insert_with(|| vec![None; total_frags as usize]);

        // Check if buffer size matches total_frags (it might change if first packet had wrong total)
        if entry.len() != total_frags as usize {
             eprintln!("Inconsistent total_frags for seq {}. Previous {}, new {}. Discarding old.", seq_num, entry.len(), total_frags);
             // Discard old fragments and start fresh with the new total_frags size
             *entry = vec![None; total_frags as usize];
        }

        // Place fragment if slot is empty and index is valid
        if (frag_idx as usize) < entry.len() {
             if entry[frag_idx as usize].is_none() {
                 entry[frag_idx as usize] = Some(plaintext);
             } else {
                 eprintln!("Duplicate fragment received for seq {}, frag {}", seq_num, frag_idx);
             }
        } else {
             // This case should be caught by the earlier frag_idx check, but belt-and-suspenders
             eprintln!("Fragment index {} out of bounds for buffer size {}", frag_idx, entry.len());
             continue;
        }

        // Check if frame is complete (all slots in Vec are Some)
        if entry.iter().all(Option::is_some) {
            let mut complete_frame_data = Vec::new();
            // Drain the entry to get ownership and assemble the frame
            for fragment_option in entry.drain(..) {
                complete_frame_data.extend_from_slice(&fragment_option.unwrap()); // We know it's Some
            }

            // Remove the entry for this sequence number now that we've drained it
             frame_reassembly_buffer.remove(&seq_num);

            // Decode H.264 bitstream to YUV frame(s)
            match decoder.decode(&complete_frame_data) {
                Ok(Some(decoded_yuv)) => {
                    // Convert YUV frame to BGR Mat for display
                    // Use dimensions() and strides() which return usize
                    let (width, height) = decoded_yuv.dimensions();
                    let (y_stride, u_stride, v_stride) = decoded_yuv.strides(); // Returns (usize, usize, usize)

                    // Get Y, U, V plane data
                    let y_plane = decoded_yuv.y();
                    let u_plane = decoded_yuv.u();
                    let v_plane = decoded_yuv.v();

                    // Calculate expected unpadded sizes and create a tightly packed buffer
                    let uv_width = width / 2;
                    let uv_height = height / 2;
                    let unpadded_y_size = width * height;
                    let unpadded_u_size = uv_width * uv_height;
                    let unpadded_v_size = unpadded_u_size;
                    let total_unpadded_size = unpadded_y_size + unpadded_u_size + unpadded_v_size;

                    let mut packed_yuv_data = Vec::with_capacity(total_unpadded_size);
                    let mut copy_error = false;

                    // Copy Y plane, row by row, skipping padding
                    for r in 0..height {
                        let start = r * y_stride;
                        let end = start + width; // Copy only 'width' bytes
                        if end <= y_plane.len() { // Bounds check
                            packed_yuv_data.extend_from_slice(&y_plane[start..end]);
                        } else {
                            eprintln!("Error: Y plane row {} out of bounds during copy (start={}, end={}, len={}). Skipping frame {}.", r, start, end, y_plane.len(), seq_num);
                            copy_error = true;
                            break;
                        }
                    }

                    // Copy U plane, row by row, skipping padding
                    if !copy_error {
                        for r in 0..uv_height {
                            let start = r * u_stride;
                            let end = start + uv_width; // Copy only 'uv_width' bytes
                            if end <= u_plane.len() { // Bounds check
                                packed_yuv_data.extend_from_slice(&u_plane[start..end]);
                            } else {
                                eprintln!("Error: U plane row {} out of bounds during copy (start={}, end={}, len={}). Skipping frame {}.", r, start, end, u_plane.len(), seq_num);
                                copy_error = true;
                                break;
                            }
                        }
                    }

                    // Copy V plane, row by row, skipping padding
                     if !copy_error {
                        for r in 0..uv_height {
                            let start = r * v_stride;
                            let end = start + uv_width; // Copy only 'uv_width' bytes
                             if end <= v_plane.len() { // Bounds check
                                packed_yuv_data.extend_from_slice(&v_plane[start..end]);
                            } else {
                                 eprintln!("Error: V plane row {} out of bounds during copy (start={}, end={}, len={}). Skipping frame {}.", r, start, end, v_plane.len(), seq_num);
                                copy_error = true;
                                break;
                            }
                        }
                    }

                    // If any copy failed or size mismatch, skip this frame
                    if copy_error || packed_yuv_data.len() != total_unpadded_size {
                        if !copy_error { // Only print size mismatch if copy didn't already fail
                             eprintln!("Error: Packed YUV data size mismatch. Expected {}, got {}. Skipping frame {}.",
                                      total_unpadded_size, packed_yuv_data.len(), seq_num);
                        }
                        continue;
                    }

                    // Create OpenCV Mat header pointing to the *packed* YUV data
                    // This requires unsafe block because Mat doesn't take ownership.
                    // We MUST ensure packed_yuv_data outlives yuv_mat if yuv_mat is used later.
                    // Here, we convert immediately, so it's okay.
                    let yuv_mat = unsafe {
                        match Mat::new_rows_cols_with_data_unsafe(
                            height as i32 * 3 / 2, // Total height for I420 format in OpenCV Mat (needs i32)
                            width as i32,          // Width (needs i32)
                            CV_8UC1,               // Type: 8-bit unsigned, 1 channel (planar)
                            packed_yuv_data.as_mut_ptr() as *mut std::ffi::c_void, // Data pointer to packed data
                            Mat_AUTO_STEP // Auto step calculation should work now
                            // Alternatively, could specify step explicitly: width as usize
                        ) {
                            Ok(mat) => mat,
                            Err(e) => {
                                eprintln!("Failed to create YUV Mat header from packed data for seq {}: {:?}", seq_num, e);
                                continue; // Skip processing this frame
                            }
                        }
                    };

                    // Convert the (now correctly formatted) YUV Mat to BGR Mat
                    let mut bgr_frame = Mat::default();
                    if imgproc::cvt_color_def(
                        &yuv_mat, // Use the Mat created from packed data
                        &mut bgr_frame,
                        imgproc::COLOR_YUV2BGR_I420, // Conversion code
                    ).is_err() {
                        eprintln!("Failed to convert packed YUV to BGR for seq {}", seq_num);
                        continue; // Skip sending this frame
                    }

                    // Send the decoded BGR frame to the main thread for display
                    if tx_recv.send((seq_num, bgr_frame)).is_err() {
                        eprintln!("Receiver channel disconnected. Exiting receiver task.");
                        break; // Exit loop if main thread is gone
                    }

                },
                Ok(None) => {
                    // Decoding was successful, but produced no displayable frame. This is normal.
                    // e.g., received SPS/PPS NAL units, or decoder needs more data.
                },
                Err(e) => {
                    eprintln!("H.264 decoding error for seq {}: {:?}", seq_num, e);
                    // Frame data might be corrupted. Discard.
                }
            } // End match decoder.decode
        } // End if frame complete

         // Optional: Add buffer cleanup logic here
         // e.g., remove frames older than N seconds or M sequence numbers behind current
         // frame_reassembly_buffer.retain(|&s, _| seq_num.wrapping_sub(s) < 100); // Keep last ~100 frames

    } // End loop

    println!("Receiver task finished.");
}