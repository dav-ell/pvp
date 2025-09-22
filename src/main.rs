// Declare modules
mod config;
mod cli;
mod network; // This refers to the network/mod.rs file and its submodules

// Crate imports
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::error::Error;

use opencv::{
    core::Mat,
    highgui,
    prelude::*,
    videoio,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time;
use ringbuf::{HeapRb, HeapProd, HeapCons};
use ringbuf::traits::{Consumer, Producer, Split};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, SampleRate, StreamConfig};
use rubato::{Resampler, SincFixedIn, SincFixedOut, SincInterpolationType, SincInterpolationParameters, WindowFunction};

// Local imports
use network::{AUDIO_SAMPLE_RATE, AUDIO_CHANNELS, AUDIO_FRAME_SIZE};
use network::sender::SendData;

// Constants for audio buffering
const AUDIO_BUFFER_SIZE: usize = AUDIO_FRAME_SIZE * 100;


// Main function using Tokio runtime
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Starting Peer Video Player (PVP) with Audio...");

    // --- Configuration ---
    let key = config::read_key_from_json("config.json")?;
    println!("Encryption key loaded successfully.");

    // --- Network Setup ---
    let local_addr = "0.0.0.0:5000"; // Listen on all interfaces, port 5000
    let socket = UdpSocket::bind(local_addr).await?;
    println!("Socket bound to {}", socket.local_addr()?);

    // --- STUN Query ---
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
    let _ = public_socket_addr; // Keep potentially needed later

    // --- Peer Connection ---
    let peer_addr = cli::read_peer_address();
    let connected_peer_addr = network::hole_punch::perform_hole_punch(&socket, peer_addr).await?;
    println!("Successfully established potential connection path to peer {}", connected_peer_addr);

    // --- Video Setup ---
    let window_name = "Video Stream";
    highgui::named_window(window_name, highgui::WINDOW_AUTOSIZE)?;

    println!("Opening camera...");
    let mut cap = videoio::VideoCapture::new(0, videoio::CAP_ANY)?;
    if !videoio::VideoCapture::is_opened(&cap)? {
        eprintln!("FATAL: Failed to open default camera (index 0). Ensure connection and drivers.");
        return Err("Failed to open camera".into());
    }

    let frame_width = 640.0;
    let frame_height = 480.0;
    let fps = 30.0;
    cap.set(videoio::CAP_PROP_FRAME_WIDTH, frame_width)?;
    cap.set(videoio::CAP_PROP_FRAME_HEIGHT, frame_height)?;
    cap.set(videoio::CAP_PROP_FPS, fps)?;
    println!("Camera opened successfully ({}x{} @ {}fps requested).", frame_width, frame_height, fps);

    // --- Audio Setup ---
    println!("Setting up audio...");
    let host = cpal::default_host();

    // Input Device & Stream
    let input_device = host.default_input_device().ok_or("No default audio input device found")?;
    println!("Using default input device: {}", input_device.name()?);
    // `audio_capture_receiver` will receive Vec<f32> from the cpal input callback
    let (input_stream, mut audio_capture_receiver) = setup_audio_input(&input_device)?;

    // Output Device & Stream
    let output_device = host.default_output_device().ok_or("No default audio output device found")?;
    println!("Using default output device: {}", output_device.name()?);
    // Create ring buffer for audio playback
    let ring_buffer = HeapRb::<f32>::new(AUDIO_BUFFER_SIZE);
    let (audio_producer, audio_consumer) = ring_buffer.split();
    // Setup output stream, it takes the consumer
    let output_stream = setup_audio_output(&output_device, audio_consumer)?;


    // --- Asynchronous Task Setup ---
    // Create MPSC channels

    // Combined channel for Main (Video) / Audio Bridge -> Sender Task
    // This channel will carry SendData enum which can be Video or Audio.
    let (tx_combined_send, rx_combined_send) = mpsc::channel::<SendData>(100);

    // Clone the sender part of the combined channel for the audio bridge task
    let tx_combined_send_for_audio_bridge = tx_combined_send.clone();
    // Bridge audio capture channel (audio_capture_receiver) to the combined sender channel
    let audio_bridge_handle = tokio::spawn(async move {
        while let Some(audio_data) = audio_capture_receiver.recv().await {
             if tx_combined_send_for_audio_bridge.send(SendData::Audio(audio_data)).await.is_err() {
                  eprintln!("Audio bridge: Combined send channel (to sender_task) closed.");
                  break;
             }
        }
         println!("Audio capture bridge task finished.");
    });


    // Receiver -> Main (Video only now, as audio goes directly to playback)
    let (tx_video_recv_main, mut rx_video_recv_main) = mpsc::channel::<(u32, Mat)>(10);
    // Receiver -> Playback Task (Audio)
    let (tx_audio_recv_playback, rx_audio_recv_playback) = mpsc::channel::<Vec<f32>>(100); // Buffer audio frames for playback


    // Spawn audio playback bridge task (MPSC Receiver from network -> RingBuffer Producer for cpal output)
    let playback_bridge_handle = tokio::spawn(async move {
         audio_playback_bridge_task(rx_audio_recv_playback, audio_producer).await;
         println!("Audio playback bridge task finished.");
    });

    // Wrap socket in Arc for sharing
    let socket = Arc::new(socket);
    let socket_for_sender = Arc::clone(&socket);
    let socket_for_receiver = Arc::clone(&socket);
    let key_for_sender = key; // Key is [u8; 32], which is Copy
    let key_for_receiver = key; // Key is [u8; 32], which is Copy

    // Clone the sender part of the combined channel for the main video loop
    let tx_combined_send_for_video = tx_combined_send.clone();

    // Spawn network tasks
    println!("Spawning network tasks...");
    let sender_handle = tokio::spawn(async move {
        // sender_task now uses rx_combined_send to receive both video and audio
        network::sender::sender_task(socket_for_sender, connected_peer_addr, key_for_sender, rx_combined_send).await
    });
    let receiver_handle = tokio::spawn(async move {
        network::receiver::receiver_task(socket_for_receiver, key_for_receiver, tx_video_recv_main, tx_audio_recv_playback).await
    });
    println!("Network tasks spawned.");


     // --- Start Audio Streams ---
     // Streams must be started *after* tasks using their channels/buffers are spawned.
     println!("Starting audio streams...");
     input_stream.play()?;
     output_stream.play()?;
     println!("Audio streams playing.");

    // --- Main Event Loop ---
    let mut video_seq_num_main: u32 = 0; // Used only for sending video frames
    let target_frame_duration = Duration::from_secs_f64(1.0 / fps);

    println!("Starting main video loop... Press ESC in the window to exit.");
    loop {
        let frame_start = Instant::now();

        // --- Capture Video Frame ---
        let mut frame = Mat::default();
        if cap.read(&mut frame)? {
            if !frame.empty() {
                // Send video frame to sender task via the combined channel
                // `frame` is moved here. If needed later in this loop, it should be cloned.
                match tx_combined_send_for_video.try_send(SendData::Video(video_seq_num_main, frame)) {
                    Ok(_) => { video_seq_num_main = video_seq_num_main.wrapping_add(1); },
                    Err(mpsc::error::TrySendError::Full(_)) => { /*eprintln!("Sender channel full, dropping video frame {}", video_seq_num_main);*/ },
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        eprintln!("Networking task (sender) closed the combined channel unexpectedly. Exiting.");
                        break;
                    }
                }
            } else {
                eprintln!("Warning: Captured empty video frame.");
                time::sleep(Duration::from_millis(10)).await; // Avoid busy-looping on empty frames
            }
        } else {
            eprintln!("Warning: Failed to read video frame from camera.");
            time::sleep(Duration::from_millis(100)).await; // Wait a bit longer if camera read fails
        }

        // --- Display Received Video Frame ---
        match rx_video_recv_main.try_recv() {
            Ok((rec_seq_num, decoded_frame)) => {
                if !decoded_frame.empty() {
                    highgui::imshow(window_name, &decoded_frame)?;
                } else {
                    eprintln!("Warning: Received empty decoded video frame {} from receiver.", rec_seq_num);
                }
            },
            Err(mpsc::error::TryRecvError::Empty) => { /* No video frame received yet, normal */ },
            Err(mpsc::error::TryRecvError::Disconnected) => {
                eprintln!("Networking task (receiver) closed the video channel unexpectedly. Exiting.");
                break;
            }
        }

        // --- Handle User Input (Exit Key) ---
        let key_code = highgui::wait_key(1)?; // Keep delay minimal for responsiveness
        if key_code == 27 { // 27 is the ESC key
            println!("ESC key pressed, exiting...");
            break;
        }

        // --- Maintain Target FPS ---
        let elapsed = frame_start.elapsed();
        if elapsed < target_frame_duration {
            time::sleep(target_frame_duration - elapsed).await;
        }
    }

    // --- Cleanup ---
    println!("Exiting main loop...");

    // Explicitly drop the sender for the combined channel to signal tasks that use its receiver.
    // Clones tx_combined_send_for_audio_bridge and tx_combined_send_for_video will also be dropped
    // when their respective tasks end or they go out of scope.
    drop(tx_combined_send);


    // Explicitly drop streams to stop audio threads cleanly before waiting for tasks.
    println!("Stopping audio streams...");
    drop(input_stream);
    drop(output_stream);
    println!("Audio streams stopped.");


    println!("Waiting for tasks to complete...");
    // Wait for bridge tasks. It's good practice to ensure they finish.
    if let Err(e) = tokio::try_join!(audio_bridge_handle, playback_bridge_handle) {
        eprintln!("Error joining audio bridge tasks: {}", e);
    }


    // Wait for network tasks. Use try_join! to propagate panics if tasks fail.
    if let Err(e) = tokio::try_join!(sender_handle, receiver_handle) {
        eprintln!("Error joining network tasks: {}", e);
    }


    println!("Closing OpenCV window...");
    highgui::destroy_window(window_name)?;

    println!("Application finished cleanly.");
    Ok(())
}


// --- Audio Helper Functions ---

/// Sets up the CPAL audio input stream.
fn setup_audio_input(
    device: &cpal::Device,
) -> Result<(cpal::Stream, mpsc::Receiver<Vec<f32>>), Box<dyn Error>> {
    // Configure desired format
    let target_config = StreamConfig {
        channels: AUDIO_CHANNELS,
        sample_rate: SampleRate(AUDIO_SAMPLE_RATE),
        buffer_size: cpal::BufferSize::Default, // Let cpal choose, or set Fixed(AUDIO_FRAME_SIZE)?
    };
    println!("Target input config: {:?}", target_config);

    // Find supported input format
    let supported_input_config_desc = device 
        .supported_input_configs()?
        .find(|c| {
            c.sample_format() == SampleFormat::F32 // Prefer f32
            && c.channels() == target_config.channels
            && c.min_sample_rate() <= target_config.sample_rate && c.max_sample_rate() >= target_config.sample_rate
        })
        .map(|c| c.with_sample_rate(target_config.sample_rate)) // Use target rate if range supported
        .or_else(|| device.default_input_config().ok()) // Fallback to default
        .ok_or("No suitable input config found")?;

    println!("Using supported input config: {:?}", supported_input_config_desc);
    let input_config: StreamConfig = supported_input_config_desc.clone().into();


    // Create channel for sending audio data from callback to sender task
    // Bounded channel to prevent unbounded memory growth if sender is slow
    let (tx_audio_callback, rx_audio_main) = mpsc::channel::<Vec<f32>>(100);

    // Setup resampler if necessary
    let mut input_resampler_opt: Option<SincFixedIn<f32>> = None;
    if input_config.sample_rate.0 != AUDIO_SAMPLE_RATE {
        println!(
            "Input resampling needed: {} Hz -> {} Hz",
            input_config.sample_rate.0, AUDIO_SAMPLE_RATE
        );
        let params = SincInterpolationParameters {
            sinc_len: 64, // Quality vs performance trade-off
            f_cutoff: 0.95,
            interpolation: SincInterpolationType::Linear, // Faster than Cubic
            oversampling_factor: 160, // Standard, high quality
            window: WindowFunction::BlackmanHarris2, // Good general purpose
        };
        input_resampler_opt = Some(SincFixedIn::new(
            AUDIO_SAMPLE_RATE as f64 / input_config.sample_rate.0 as f64, // ratio
            2.0, // max_resample_ratio_relative (increase if ratio > 1)
            params,
            input_config.channels as usize * AUDIO_FRAME_SIZE, // Chunk size matches Opus frame
            input_config.channels as usize, // num_channels
        )?);
    }


    let err_fn = |err| eprintln!("Input stream error: {}", err);
    let actual_input_channels = input_config.channels as usize;

    // Build the input stream
    let stream = device.build_input_stream(
        &input_config,
        move |data: &[f32], _: &cpal::InputCallbackInfo| {
            // Process audio data in the callback
            // This callback runs on a separate audio thread. Avoid blocking!

            // Handle resampling if needed
            let samples_to_send_vec = if let Some(resampler) = &mut input_resampler_opt {
                 // Resampler expects Vec<Vec<f32>> (outer vec for channels)
                 // Assuming MONO for now as per original comments
                 if actual_input_channels != 1 {
                      eprintln!("Input Resampling only implemented for MONO currently!");
                      return;
                 }
                 let input_chunk = vec![data.to_vec()]; // Wrap mono samples
                 match resampler.process(&input_chunk, None) {
                     Ok(resampled_chunks) => {
                        // Assuming MONO output
                        if resampled_chunks.len() == 1 {
                            // Flatten the Vec<Vec<f32>> back to Vec<f32>
                            resampled_chunks.into_iter().next().unwrap_or_default()
                        } else {
                            eprintln!("Resampler produced unexpected channel count");
                            vec![]
                        }
                     }
                     Err(e) => {
                          eprintln!("Resampling error: {}", e);
                         vec![]
                     }
                 }
            } else {
                // No resampling needed, just clone the data
                data.to_vec()
            };

            // Ensure we send exactly AUDIO_FRAME_SIZE chunks
            // The data provided by cpal might be smaller or larger. We need to buffer
            // and chunk it appropriately before sending.
            // *** Simplification for now: Assume cpal gives us chunks that we can send directly
            // *** A proper implementation needs a buffer here.
            if !samples_to_send_vec.is_empty() {
                // Send the processed audio data (non-blocking try_send)
                 // Split into frames of AUDIO_FRAME_SIZE
                 for chunk in samples_to_send_vec.chunks(AUDIO_FRAME_SIZE * actual_input_channels) {
                     if chunk.len() == AUDIO_FRAME_SIZE * actual_input_channels { // Only send full frames
                         match tx_audio_callback.try_send(chunk.to_vec()) { // Use tx_audio_callback
                             Ok(_) => {} // Successfully sent
                             Err(mpsc::error::TrySendError::Full(_)) => {
                                 // eprintln!("Input callback: Audio send channel full. Dropping audio data.");
                             }
                             Err(mpsc::error::TrySendError::Closed(_)) => {
                                 eprintln!("Input callback: Audio send channel (to audio_bridge_task) closed.");
                                 // Stream will be stopped when main cleans up.
                                 break;
                             }
                         }
                    } else if !chunk.is_empty() { // Handle partial chunks if not empty
                         // This indicates cpal is providing data not aligned with AUDIO_FRAME_SIZE.
                         // eprintln!("Partial audio chunk from input/resampler: len {}. Required: {}. Dropping.",
                         // chunk.len(), AUDIO_FRAME_SIZE * actual_input_channels);
                    }
                 }
            }
        },
        err_fn,
        None // Timeout
    )?;

    Ok((stream, rx_audio_main))
}


/// Sets up the CPAL audio output stream.
fn setup_audio_output(
    device: &cpal::Device,
    mut audio_consumer: HeapCons<f32>, // Takes ownership of the ring buffer consumer
) -> Result<cpal::Stream, Box<dyn Error>> {

    // Configure desired format
    let target_config = StreamConfig {
        channels: AUDIO_CHANNELS,
        sample_rate: SampleRate(AUDIO_SAMPLE_RATE),
        buffer_size: cpal::BufferSize::Default,
    };
     println!("Target output config: {:?}", target_config);

    // Find supported output format
    let supported_output_config_desc = device 
        .supported_output_configs()?
        .find(|c| {
            c.sample_format() == SampleFormat::F32
            && c.channels() == target_config.channels
            && c.min_sample_rate() <= target_config.sample_rate && c.max_sample_rate() >= target_config.sample_rate
        })
         .map(|c| c.with_sample_rate(target_config.sample_rate))
         .or_else(|| device.default_output_config().ok())
        .ok_or("No suitable output config found")?;

    println!("Using supported output config: {:?}", supported_output_config_desc);
    let output_config: StreamConfig = supported_output_config_desc.clone().into();

    // Setup resampler if necessary (currently placeholder, warns if needed)
    let mut _output_resampler_opt: Option<SincFixedOut<f32>> = None;
    // ** TODO: Output resampling logic is more complex as we pull from the ring buffer.
    // ** For simplicity, we currently assume output device supports AUDIO_SAMPLE_RATE.
    if output_config.sample_rate.0 != AUDIO_SAMPLE_RATE {
        eprintln!(
            "Output resampling needed ({} Hz -> {} Hz), but NOT YET IMPLEMENTED. Audio might sound wrong.",
            AUDIO_SAMPLE_RATE, output_config.sample_rate.0
        );
        // Implementation would involve creating SincFixedOut and processing data
        // pulled from the ring buffer before writing it to the cpal output buffer.
        // For now, we'll proceed without resampling, which might lead to incorrect pitch/speed.
    }


    let err_fn = |err| eprintln!("Output stream error: {}", err);

    // Build the output stream
    let stream = device.build_output_stream(
        &output_config, // Use the potentially resampled or directly supported config
        move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
            // Read data from the ring buffer and write it to the output buffer 'data'
            // This runs on the audio thread. Avoid blocking!

            // TODO: If resampling is implemented, data from ring_buffer needs to be resampled
            // before being written to 'data'. The amount to pull from ring_buffer would depend
            // on the resampling ratio and the size of 'data'.

            let samples_written = audio_consumer.pop_slice(data);

            // If not enough data in buffer, fill the rest with silence
            if samples_written < data.len() {
                 // eprintln!("Output underrun: filled {} samples, needed {}. Silence inserted.", samples_written, data.len()); // Can be noisy
                data[samples_written..].iter_mut().for_each(|s| *s = 0.0);
            }
        },
        err_fn,
        None 
    )?;

    Ok(stream)
}

/// Task to bridge received audio packets from the MPSC channel (from network receiver)
/// to the ring buffer (for cpal audio output).
async fn audio_playback_bridge_task(
    mut rx_audio_from_network: mpsc::Receiver<Vec<f32>>,
    mut audio_producer_for_playback: HeapProd<f32>,
) {
    println!("Audio playback bridge task started.");
    while let Some(audio_data) = rx_audio_from_network.recv().await {
        let samples_pushed = audio_producer_for_playback.push_slice(&audio_data);
        if samples_pushed < audio_data.len() {
            // Buffer overflow - data is lost. Can happen if network receives data
            // faster than the audio device consumes it, or if buffer is too small.
            eprintln!(
                "Audio playback ring buffer overflow! Dropped {} out of {} samples.",
                audio_data.len() - samples_pushed,
                audio_data.len()
            );
        }
    }
    println!("Audio playback bridge task finished (channel from network receiver closed).");
}