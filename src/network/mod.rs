// File: /Users/davell/Documents/github/pvp/src/network/mod.rs
use openh264::formats::YUVSource;

// Declare the submodules within the network module
pub mod stun;
pub mod hole_punch;
pub mod sender;
pub mod receiver;

/// Header structure for UDP packets containing video frame fragments.
/// Moved from utils.rs as it's specific to the network protocol.
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    pub seq_num: u32,     // Sequence number of the original frame
    pub frag_idx: u16,    // Index of this fragment within the frame
    pub total_frags: u16, // Total number of fragments for this frame
    pub iv: [u8; 16],     // Initialization Vector for encryption
}

/// Helper struct to adapt an OpenCV `Mat` containing YUV I420 data
/// to the `YUVSource` trait required by the `openh264` encoder.
/// Moved from utils.rs as it's specific to the network encoding process.
pub struct MatAsYuv<'a> {
    pub width: usize,
    pub height: usize,
    pub y: &'a [u8], // Y plane data
    pub u: &'a [u8], // U plane data
    pub v: &'a [u8], // V plane data
}

// Implement the YUVSource trait for MatAsYuv
impl<'a> YUVSource for MatAsYuv<'a> {
    /// Returns the dimensions (width, height) of the YUV source.
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    /// Returns the strides (bytes per line) for the Y, U, and V planes.
    /// For I420 format, Y stride is width, U/V strides are width / 2.
    fn strides(&self) -> (usize, usize, usize) {
        (self.width, self.width / 2, self.width / 2)
    }

    /// Returns a slice containing the Y plane data.
    fn y(&self) -> &[u8] { self.y }

    /// Returns a slice containing the U plane data.
    fn u(&self) -> &[u8] { self.u }

    /// Returns a slice containing the V plane data.
    fn v(&self) -> &[u8] { self.v }
}