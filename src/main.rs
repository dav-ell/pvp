// File: /Users/davell/Documents/github/pvp/src/main.rs

// Declare modules
mod config;
mod cli;
mod network; // This refers to the network/mod.rs file and its submodules

// Crate imports
use std::sync::Arc;
use std::time::{Duration, Instant};
use opencv::{
    core::Mat,
    highgui,
    prelude::*,
    videoio,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time; // Import Tokio's time

// Main function using Tokio runtime
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Peer Video Player (PVP)...");

    // --- Configuration ---
    let key = config::read_key_from_json("config.json")?;
    println!("Encryption key loaded successfully.");

    // --- Network Setup ---
    let local_addr = "0.0.0.0:5000"; // Listen on all interfaces, port 5000
    let socket = UdpSocket::bind(local_addr).await?;
    println!("Socket bound to {}", socket.local_addr()?);

    // --- STUN Query ---
    // Use the function from the stun submodule
    let stun_server = network::stun::get_stun_server_address();
    let public_socket_addr = match network::stun::perform_stun_query(&socket, stun_server).await {
        Ok(public_addr) => {
            println!("\n*******************************************************");
            println!("*** Your public address is likely: {} ***", public_addr);
            println!("*** Share this address with your peer.               ***");
            println!("********************************************************\n");
            Some(public_addr)
        }
        Err(e) => {
            eprintln!("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            eprintln!("!!! STUN query failed: {} !!!", e);
            eprintln!("!!! Could not determine public IP address.          !!!");
            eprintln!("!!! NAT traversal might fail if direct connection   !!!");
            eprintln!("!!! requires it (e.g., symmetric NATs).             !!!");
            eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            eprintln!("Proceeding, but connection may fail.\n");
            None
        }
    };
    // Keep public_socket_addr in scope if needed later, otherwise allow underscore prefix
    let _ = public_socket_addr;

    // --- Peer Connection ---
    // Prompt user for peer's address (synchronous call okay here during setup)
    let peer_addr = cli::read_peer_address();

    // Perform UDP hole punching using the function from the hole_punch submodule
    let connected_peer_addr = network::hole_punch::perform_hole_punch(&socket, peer_addr).await?;
    println!("Successfully established potential connection path to peer {}", connected_peer_addr);
    // Note: `connected_peer_addr` might be the same as `peer_addr`, but confirms reachability.

    // --- Video Setup ---
    let window_name = "Video Stream";
    highgui::named_window(window_name, highgui::WINDOW_AUTOSIZE)?;

    println!("Opening camera...");
    let mut cap = videoio::VideoCapture::new(0, videoio::CAP_ANY)?; // Use camera index 0
    let opened = videoio::VideoCapture::is_opened(&cap)?;
    if !opened {
        eprintln!("FATAL: Failed to open default camera (index 0).");
        eprintln!("Ensure a camera is connected and drivers are installed.");
        // Consider checking permissions if on Linux/macOS
        return Err("Failed to open camera".into());
    }

    // Set desired camera properties (best effort)
    let frame_width = 640.0;
    let frame_height = 480.0;
    let fps = 30.0;
    cap.set(videoio::CAP_PROP_FRAME_WIDTH, frame_width)?;
    cap.set(videoio::CAP_PROP_FRAME_HEIGHT, frame_height)?;
    cap.set(videoio::CAP_PROP_FPS, fps)?;

    println!("Camera opened successfully ({}x{} @ {}fps requested).", frame_width, frame_height, fps);

    // --- Asynchronous Task Setup ---
    // Create MPSC channels for communication between main loop and network tasks
    // Bounded channels prevent unbounded memory growth if one task is much faster.
    let (tx_send, rx_send) = mpsc::channel::<(u32, Mat)>(10); // Main -> Sender
    let (tx_recv, mut rx_recv) = mpsc::channel::<(u32, Mat)>(10); // Receiver -> Main

    // Wrap socket in Arc for safe sharing between async tasks
    let socket = Arc::new(socket);
    let socket_sender = Arc::clone(&socket);
    let socket_receiver = Arc::clone(&socket);
    let key_clone_send = key; // Clone key for sender task
    let key_clone_recv = key; // Clone key for receiver task

    // Spawn network tasks onto the Tokio runtime using functions from submodules
    println!("Spawning network tasks...");
    let sender_handle = tokio::spawn(async move {
        network::sender::sender_task(socket_sender, connected_peer_addr, key_clone_send, rx_send).await
    });
    let receiver_handle = tokio::spawn(async move {
        network::receiver::receiver_task(socket_receiver, key_clone_recv, tx_recv).await
    });
    println!("Network tasks spawned.");

    // --- Main Event Loop ---
    let mut seq_num: u32 = 0; // Use u32 for sequence numbers
    let target_frame_duration = Duration::from_secs_f64(1.0 / fps); // Target duration between frames

    println!("Starting main video loop... Press ESC in the window to exit.");
    loop {
        let frame_start = Instant::now();

        // --- Capture Frame ---
        let mut frame = Mat::default();
        if cap.read(&mut frame)? { // Read frame from camera
            if !frame.empty() {
                // Send the captured frame (and sequence number) to the sender task
                // Use try_send for non-blocking behavior from the main loop.
                // If the channel is full, we drop the frame to avoid blocking the capture loop.
                match tx_send.try_send((seq_num, frame)) {
                    Ok(_) => {
                        seq_num = seq_num.wrapping_add(1); // Increment sequence number
                    },
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // eprintln!("Sender channel full, dropping frame {}", seq_num);
                        // Frame is implicitly dropped here
                    },
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        eprintln!("Networking task (sender) closed the channel unexpectedly. Exiting.");
                        break; // Exit main loop if sender task died
                    }
                }
            } else {
                 eprintln!("Warning: Captured empty frame from camera.");
                 // Optionally sleep briefly if empty frames are frequent
                 time::sleep(Duration::from_millis(10)).await;
            }
        } else {
            eprintln!("Warning: Failed to read frame from camera.");
            // Consider breaking or attempting to reopen camera if this persists
            time::sleep(Duration::from_millis(100)).await; // Sleep longer if read fails
        }

        // --- Display Received Frame ---
        // Check for frames received from the receiver task (non-blocking)
        match rx_recv.try_recv() {
            Ok((rec_seq_num, decoded_frame)) => {
                if !decoded_frame.empty() {
                    // println!("Displaying frame {}", rec_seq_num); // Debug log
                    highgui::imshow(window_name, &decoded_frame)?;
                } else {
                     eprintln!("Warning: Received empty decoded frame {} from receiver task.", rec_seq_num);
                }
            },
            Err(mpsc::error::TryRecvError::Empty) => {
                // No frame received yet, continue loop (normal)
            },
            Err(mpsc::error::TryRecvError::Disconnected) => {
                eprintln!("Networking task (receiver) closed the channel unexpectedly. Exiting.");
                break; // Exit main loop if receiver task died
            }
        }

        // --- Handle User Input (Exit Key) ---
        // Check for ESC key press (ASCII 27) in the OpenCV window.
        // wait_key(1) is crucial for OpenCV window event processing.
        let key_code = highgui::wait_key(1)?; // Wait 1ms for a key press
        if key_code == 27 {
            println!("ESC key pressed, exiting...");
            break; // Exit main loop
        }

        // --- Maintain Target FPS ---
        let elapsed = frame_start.elapsed();
        if elapsed < target_frame_duration {
            // Use Tokio's sleep for async-friendly waiting
            time::sleep(target_frame_duration - elapsed).await;
        } else {
            // Optional: Log if falling behind FPS target
            // eprintln!("Warning: Frame loop took longer than target: {:?}", elapsed);
        }
    }

    // --- Cleanup ---
    println!("Exiting main loop...");
    // Dropping tx_send and closing rx_recv implicitly signals tasks to shut down
    // (sender will finish when tx_send drops, receiver when rx_recv drops or tx_recv.is_closed())

    // Wait for network tasks to finish cleanly.
    println!("Waiting for network tasks to complete...");
    // Use tokio::try_join! to wait for both handles and propagate any panics.
    if let Err(e) = tokio::try_join!(sender_handle, receiver_handle) {
        eprintln!("Error joining network tasks: {}", e);
    }

    println!("Closing OpenCV window...");
    highgui::destroy_window(window_name)?; // Explicitly destroy the window

    println!("Application finished cleanly.");
    Ok(()) // Return Ok from main
}