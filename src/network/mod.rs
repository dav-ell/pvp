// File: /Users/davell/Documents/github/pvp/src/network/mod.rs
use openh264::formats::YUVSource;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

// Declare the submodules within the network module
pub mod stun;
pub mod hole_punch;
pub mod sender;
pub mod receiver;
pub mod relay;

/// Portable `cvt_color` across OpenCV builds.
/// Newer OpenCV (e.g. Homebrew 4.x) requires `AlgorithmHint`; Fedora MinGW 4.7 does not.
pub fn cvt_color(
    src: &impl opencv::core::ToInputArray,
    dst: &mut impl opencv::core::ToOutputArray,
    code: i32,
) -> opencv::Result<()> {
    #[cfg(target_os = "windows")]
    {
        opencv::imgproc::cvt_color(src, dst, code, 0)
    }
    #[cfg(not(target_os = "windows"))]
    {
        use opencv::core::AlgorithmHint;
        opencv::imgproc::cvt_color(src, dst, code, 0, AlgorithmHint::ALGO_HINT_DEFAULT)
    }
}

// --- Configuration ---
pub const AUDIO_SAMPLE_RATE: u32 = 48000;
pub const AUDIO_CHANNELS: u16 = 1; // Mono
// Opus frame size: 20ms @ 48kHz = 960 samples
pub const AUDIO_FRAME_SIZE: usize = (AUDIO_SAMPLE_RATE as usize / 1000) * 20;
// Maximum size for payload chunks before encryption. Leave room for header, IV, padding.
pub const MAX_PAYLOAD_SIZE: usize = 1300;
// Size of the packet header defined below
pub const PACKET_HEADER_SIZE: usize = 1 + 4 + 2 + 2 + 16; // type(1)+seq(4)+idx(2)+total(2)+iv(16) = 25 bytes

/// Enum to identify the type of payload in a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Video = 0,
    Audio = 1,
}

impl PacketType {
    /// Convert from u8 to PacketType, returning None if invalid.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(PacketType::Video),
            1 => Some(PacketType::Audio),
            _ => None,
        }
    }
}

/// Header structure for UDP packets containing video or audio frame fragments.
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    pub packet_type: PacketType,
    pub seq_num: u32,    // Sequence number (video or audio specific)
    pub frag_idx: u16,   // Index of this fragment
    pub total_frags: u16,// Total number of fragments for this seq_num
    pub iv: [u8; 16],    // Initialization Vector for encryption
}

impl PacketHeader {
    /// Serialize the header into a byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PACKET_HEADER_SIZE);
        buf.push(self.packet_type as u8);
        buf.write_u32::<BigEndian>(self.seq_num).unwrap();
        buf.write_u16::<BigEndian>(self.frag_idx).unwrap();
        buf.write_u16::<BigEndian>(self.total_frags).unwrap();
        buf.extend_from_slice(&self.iv);
        buf
    }

    /// Deserialize the header from a byte slice.
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < PACKET_HEADER_SIZE {
            return Err("Packet data too small for header");
        }
        let mut cursor = Cursor::new(data);
        let packet_type_u8 = cursor.read_u8().map_err(|_| "Failed to read packet type")?;
        let packet_type = PacketType::from_u8(packet_type_u8)
            .ok_or("Invalid packet type byte")?;
        let seq_num = cursor.read_u32::<BigEndian>().map_err(|_| "Failed to read seq_num")?;
        let frag_idx = cursor.read_u16::<BigEndian>().map_err(|_| "Failed to read frag_idx")?;
        let total_frags = cursor.read_u16::<BigEndian>().map_err(|_| "Failed to read total_frags")?;
        let mut iv = [0u8; 16];
        // Read IV directly from the original slice, not the cursor which has advanced
        iv.copy_from_slice(&data[cursor.position() as usize..cursor.position() as usize + 16]);

        Ok(PacketHeader {
            packet_type,
            seq_num,
            frag_idx,
            total_frags,
            iv,
        })
    }
}


/// Helper struct to adapt an OpenCV `Mat` containing YUV I420 data
/// to the `YUVSource` trait required by the `openh264` encoder.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_header_size_matches_layout() {
        assert_eq!(PACKET_HEADER_SIZE, 25);
        assert_eq!(1 + 4 + 2 + 2 + 16, PACKET_HEADER_SIZE);
    }

    #[test]
    fn audio_constants_match_documented_voip_params() {
        assert_eq!(AUDIO_SAMPLE_RATE, 48000);
        assert_eq!(AUDIO_CHANNELS, 1);
        assert_eq!(AUDIO_FRAME_SIZE, 960); // 20ms @ 48kHz
        assert_eq!(MAX_PAYLOAD_SIZE, 1300);
    }

    #[test]
    fn packet_type_from_u8() {
        assert_eq!(PacketType::from_u8(0), Some(PacketType::Video));
        assert_eq!(PacketType::from_u8(1), Some(PacketType::Audio));
        assert_eq!(PacketType::from_u8(2), None);
        assert_eq!(PacketType::Video as u8, 0);
        assert_eq!(PacketType::Audio as u8, 1);
    }

    #[test]
    fn packet_header_round_trip() {
        let header = PacketHeader {
            packet_type: PacketType::Audio,
            seq_num: 0x1122_3344,
            frag_idx: 2,
            total_frags: 5,
            iv: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };
        let bytes = header.serialize();
        assert_eq!(bytes.len(), PACKET_HEADER_SIZE);
        assert_eq!(bytes[0], PacketType::Audio as u8);
        let decoded = PacketHeader::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded.packet_type, PacketType::Audio);
        assert_eq!(decoded.seq_num, 0x1122_3344);
        assert_eq!(decoded.frag_idx, 2);
        assert_eq!(decoded.total_frags, 5);
        assert_eq!(decoded.iv, header.iv);
    }

    #[test]
    fn packet_header_rejects_short_and_bad_type() {
        assert!(PacketHeader::deserialize(&[0u8; 10]).is_err());
        let mut bad = vec![0u8; PACKET_HEADER_SIZE];
        bad[0] = 99; // invalid PacketType
        assert!(PacketHeader::deserialize(&bad).is_err());
    }
}