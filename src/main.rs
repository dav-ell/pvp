use std::net::{SocketAddr, UdpSocket, ToSocketAddrs}; // Added SocketAddr and ToSocketAddrs
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use aes::Aes256;
use aes::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};
use aes::cipher::block_padding::{Pkcs7, UnpadError};
use cbc::{Encryptor as CbcEncryptorGeneric, Decryptor as CbcDecryptorGeneric}; // Use generic names
use opencv::{
    core::{Mat, Mat_AUTO_STEP, CV_8UC1},
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
use crossbeam::channel;

// STUN related imports
use stun_rs::{
    MessageEncoderBuilder, MessageDecoderBuilder, StunMessageBuilder,
    MessageClass, TransactionId, // Removed unused StunAttribute
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

// --- STUN Query Function ---
const STUN_SERVER: &str = "stun.l.google.com:19302"; // Google's public STUN server

fn perform_stun_query(socket: &UdpSocket, stun_server_addr_str: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    println!("Performing STUN query to {}...", stun_server_addr_str);

    // Resolve STUN server address, preferring IPv4
    let mut resolved_addrs = stun_server_addr_str.to_socket_addrs()?;
    let stun_socket_addr = resolved_addrs
        .find(|addr| addr.is_ipv4()) // Prefer IPv4 since we bound to 0.0.0.0
        .ok_or_else(|| format!("Could not resolve {} to an IPv4 address", stun_server_addr_str))?;
    println!("Resolved STUN server address to: {}", stun_socket_addr);

    // 1. Create Binding Request
    let message = StunMessageBuilder::new(BINDING, MessageClass::Request)
                    .with_transaction_id(TransactionId::default()) // Use a random transaction ID
                    .build();

    // 2. Encode Request
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = vec![0u8; 1500]; // Standard MTU size buffer
    let size = encoder.encode(&mut buffer, &message)?;
    let encoded_request = &buffer[..size];

    // 3. Send Request using resolved SocketAddr
    socket.send_to(encoded_request, stun_socket_addr)?; // Pass resolved SocketAddr directly
    println!("STUN request sent.");

    // 4. Receive Response
    let mut recv_buf = [0u8; 1500];
    // Set a reasonable read timeout
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    let (num_bytes, src_addr) = match socket.recv_from(&mut recv_buf) {
        Ok(data) => data,
        Err(e) => {
            // Reset timeout before returning the error
            socket.set_read_timeout(None)?;
            return Err(Box::new(e)); // Wrap the IO error
        }
    };
    // Reset timeout after receiving or if an error occurred previously
    socket.set_read_timeout(None)?;
    println!("Received {} bytes from STUN server {}", num_bytes, src_addr);
    let response_data = &recv_buf[..num_bytes];


    // 5. Decode Response
    let decoder = MessageDecoderBuilder::default().build(); // No special context needed for basic response
    // Handle potential decode errors
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
        // Handle STUN error response
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
    }
     else {
        Err(format!("Received unexpected STUN message class: {:?}", response_msg.class()).into())
    }
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

    // --- Socket Setup and STUN Query ---
    let socket = UdpSocket::bind(local_addr).expect("Failed to bind UDP socket");
    println!("Socket bound to {}", local_addr);

    // Perform STUN query
    let _public_socket_addr: Option<SocketAddr> = match perform_stun_query(&socket, STUN_SERVER) { // Prefix with underscore
        Ok(public_addr) => {
            println!("*** Discovered public address via STUN: {} ***", public_addr);
            Some(public_addr)
        }
        Err(e) => {
            eprintln!("!!! STUN query failed: {} !!!", e);
            eprintln!("!!! Proceeding without public address information. NAT traversal might fail. !!!");
            None
        }
    };
     // --- End Socket Setup and STUN Query ---

    // Read encryption key
    let key = read_key_from_json("config.json");

    // *Now* connect the socket for peer communication
    socket
        .connect(&dest_addr)
        .expect("Failed to connect to destination");
    println!("Socket connected to {}", dest_addr);


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
                 },
                 Err(channel::TrySendError::Disconnected(_)) => {
                     eprintln!("Networking thread disconnected (sender)");
                     break; // Exit loop if channel is broken
                 }
             }
        } else {
             // eprintln!("Failed to capture frame or frame empty"); // Reduce verbosity
             thread::sleep(Duration::from_millis(10));
        }

        // Display received frame
        match rx_recv.try_recv() { // Use try_recv to avoid blocking UI
            Ok((_rec_seq_num, decoded_frame)) => {
                if !decoded_frame.empty() {
                    highgui::imshow("Video", &decoded_frame).expect("Failed to display frame");
                } else {
                    // eprintln!("Received empty frame from network task."); // Reduce verbosity
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
            return;
        }
    };

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

    while let Ok((seq_num, frame)) = rx_send.recv() {
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
        let height = (yuv_mat.rows() * 2 / 3) as usize;
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
             eprintln!("YUV data size mismatch for frame {}. Expected {}, got {}. Skipping.", seq_num, expected_total_size, yuv_data.len());
             continue;
        }

        let y_plane = &yuv_data[..y_size];
        let u_plane = &yuv_data[y_size..y_size + uv_size];
        let v_plane = &yuv_data[y_size + uv_size .. expected_total_size];

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
                    continue;
                }
            };

            if bitstream.is_empty() {
                continue;
            }

            const MAX_FRAG_SIZE: usize = 1360;
            bitstream.chunks(MAX_FRAG_SIZE)
                     .map(|chunk| chunk.to_vec())
                     .collect()
        };

        let total_frags = fragments.len() as u16;

        if total_frags == 0 {
            eprintln!("Warning: Empty fragments generated for frame {}", seq_num);
            continue;
        }

        for (frag_idx, frag_data) in fragments.iter().enumerate() {
            let iv = rand::thread_rng().gen::<[u8; 16]>();

            let mut buf = frag_data.to_vec();
            let original_len = buf.len();
            buf.resize(original_len + 16, 0);

            let encryptor = Aes256CbcEncryptor::new(&key.into(), &iv.into());

            let ciphertext_slice = match encryptor.encrypt_padded_mut::<Pkcs7>(&mut buf, original_len) {
                 Ok(ct) => ct,
                 Err(_) => {
                      eprintln!("Encryption padding failed for seq {}, frag {}", seq_num, frag_idx);
                      continue;
                 }
            };

            let header = PacketHeader {
                seq_num,
                frag_idx: frag_idx as u16,
                total_frags,
                iv,
            };

            let mut packet = Vec::with_capacity(8 + 16 + ciphertext_slice.len());
            packet.write_u32::<BigEndian>(header.seq_num).unwrap();
            packet.write_u16::<BigEndian>(header.frag_idx).unwrap();
            packet.write_u16::<BigEndian>(header.total_frags).unwrap();
            packet.extend_from_slice(&header.iv);
            packet.extend_from_slice(ciphertext_slice);

            if let Err(e) = tokio_socket.send(&packet).await {
                eprintln!("Failed to send UDP packet for frame {}, frag {}: {}", seq_num, frag_idx, e);
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
            return;
        }
    };
    let mut frame_reassembly_buffer: HashMap<u32, Vec<Option<Vec<u8>>>> = HashMap::new();

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

    let mut recv_buf = vec![0u8; 2048];

    loop {
        let (num_bytes, _src_addr) = match tokio_socket.recv_from(&mut recv_buf).await {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Failed to receive UDP packet: {}", e);
                continue;
            }
        };

        let packet_data = &recv_buf[..num_bytes];

        const HEADER_SIZE: usize = 8;
        const IV_SIZE: usize = 16;
        if packet_data.len() < HEADER_SIZE + IV_SIZE {
            eprintln!("Received packet too small: {} bytes", packet_data.len());
            continue;
        }

        let mut cursor = Cursor::new(&packet_data[..HEADER_SIZE]);
        let seq_num = match cursor.read_u32::<BigEndian>() { Ok(v) => v, Err(_) => { eprintln!("Failed to read seq_num"); continue; }};
        let frag_idx = match cursor.read_u16::<BigEndian>() { Ok(v) => v, Err(_) => { eprintln!("Failed to read frag_idx"); continue; }};
        let total_frags = match cursor.read_u16::<BigEndian>() { Ok(v) => v, Err(_) => { eprintln!("Failed to read total_frags"); continue; }};

        let iv_start = HEADER_SIZE;
        let iv_end = iv_start + IV_SIZE;
        let iv: [u8; 16] = match packet_data[iv_start..iv_end].try_into() {
             Ok(arr) => arr,
             Err(_) => { eprintln!("Failed to extract IV slice"); continue; }
        };
        let ciphertext_slice = &packet_data[iv_end..];

         if total_frags == 0 || (frag_idx >= total_frags) {
              eprintln!("Invalid fragment indices received: idx {}, total {}", frag_idx, total_frags);
              continue;
         }

        let mut decrypt_buf = ciphertext_slice.to_vec();
        let decryptor = Aes256CbcDecryptor::new(&key.into(), &iv.into());

        let plaintext_slice = match decryptor.decrypt_padded_mut::<Pkcs7>(&mut decrypt_buf) {
            Ok(pt) => pt,
            Err(UnpadError) => {
                eprintln!("Decryption failed (padding error) for seq {}, frag {}", seq_num, frag_idx);
                continue;
            }
        };
        let plaintext = plaintext_slice.to_vec();

        let entry = frame_reassembly_buffer
            .entry(seq_num)
            .or_insert_with(|| vec![None; total_frags as usize]);

        if entry.len() != total_frags as usize {
             eprintln!("Inconsistent total_frags for seq {}. Previous {}, new {}. Discarding old.", seq_num, entry.len(), total_frags);
             *entry = vec![None; total_frags as usize];
        }

        if (frag_idx as usize) < entry.len() {
             if entry[frag_idx as usize].is_none() {
                 entry[frag_idx as usize] = Some(plaintext);
             } else {
                 // eprintln!("Duplicate fragment received for seq {}, frag {}", seq_num, frag_idx); // Reduce verbosity
             }
        } else {
             eprintln!("Fragment index {} out of bounds for buffer size {}", frag_idx, entry.len());
             continue;
        }

        if entry.iter().all(Option::is_some) {
            let mut complete_frame_data = Vec::new();
            for fragment_option in entry.drain(..) {
                complete_frame_data.extend_from_slice(&fragment_option.unwrap());
            }

             frame_reassembly_buffer.remove(&seq_num);

            match decoder.decode(&complete_frame_data) {
                Ok(Some(decoded_yuv)) => {
                    let (width, height) = decoded_yuv.dimensions();
                    let (y_stride, u_stride, v_stride) = decoded_yuv.strides();

                    let y_plane = decoded_yuv.y();
                    let u_plane = decoded_yuv.u();
                    let v_plane = decoded_yuv.v();

                    let uv_width = width / 2;
                    let uv_height = height / 2;
                    let unpadded_y_size = width * height;
                    let unpadded_u_size = uv_width * uv_height;
                    let unpadded_v_size = unpadded_u_size;
                    let total_unpadded_size = unpadded_y_size + unpadded_u_size + unpadded_v_size;

                    let mut packed_yuv_data = Vec::with_capacity(total_unpadded_size);
                    let mut copy_error = false;

                    for r in 0..height {
                        let start = r * y_stride;
                        let end = start + width;
                        if end <= y_plane.len() {
                            packed_yuv_data.extend_from_slice(&y_plane[start..end]);
                        } else {
                            eprintln!("Error: Y plane row {} out of bounds during copy (start={}, end={}, len={}). Skipping frame {}.", r, start, end, y_plane.len(), seq_num);
                            copy_error = true;
                            break;
                        }
                    }

                    if !copy_error {
                        for r in 0..uv_height {
                            let start = r * u_stride;
                            let end = start + uv_width;
                            if end <= u_plane.len() {
                                packed_yuv_data.extend_from_slice(&u_plane[start..end]);
                            } else {
                                eprintln!("Error: U plane row {} out of bounds during copy (start={}, end={}, len={}). Skipping frame {}.", r, start, end, u_plane.len(), seq_num);
                                copy_error = true;
                                break;
                            }
                        }
                    }

                     if !copy_error {
                        for r in 0..uv_height {
                            let start = r * v_stride;
                            let end = start + uv_width;
                             if end <= v_plane.len() {
                                packed_yuv_data.extend_from_slice(&v_plane[start..end]);
                            } else {
                                 eprintln!("Error: V plane row {} out of bounds during copy (start={}, end={}, len={}). Skipping frame {}.", r, start, end, v_plane.len(), seq_num);
                                copy_error = true;
                                break;
                            }
                        }
                    }

                    if copy_error || packed_yuv_data.len() != total_unpadded_size {
                        if !copy_error {
                             eprintln!("Error: Packed YUV data size mismatch. Expected {}, got {}. Skipping frame {}.",
                                       total_unpadded_size, packed_yuv_data.len(), seq_num);
                        }
                        continue;
                    }

                    let yuv_mat = unsafe {
                        match Mat::new_rows_cols_with_data_unsafe(
                            height as i32 * 3 / 2,
                            width as i32,
                            CV_8UC1,
                            packed_yuv_data.as_mut_ptr() as *mut std::ffi::c_void,
                            Mat_AUTO_STEP
                        ) {
                            Ok(mat) => mat,
                            Err(e) => {
                                eprintln!("Failed to create YUV Mat header from packed data for seq {}: {:?}", seq_num, e);
                                continue;
                            }
                        }
                    };

                    let mut bgr_frame = Mat::default();
                    if imgproc::cvt_color_def(
                        &yuv_mat,
                        &mut bgr_frame,
                        imgproc::COLOR_YUV2BGR_I420,
                    ).is_err() {
                        eprintln!("Failed to convert packed YUV to BGR for seq {}", seq_num);
                        continue;
                    }

                    if tx_recv.send((seq_num, bgr_frame)).is_err() {
                        eprintln!("Receiver channel disconnected. Exiting receiver task.");
                        break;
                    }

                },
                Ok(None) => { /* Normal case, no frame decoded */ },
                Err(e) => {
                    eprintln!("H.264 decoding error for seq {}: {:?}", seq_num, e);
                }
            }
        }

    }

    println!("Receiver task finished.");
}