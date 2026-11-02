//! Versioned encrypt-then-MAC envelope for the optional legacy UDP transport.
use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;
const MAGIC: &[u8; 4] = b"PVP2";
const TAG_SIZE: usize = 32;
fn authenticator(key: &[u8; 32]) -> HmacSha256 {
    let mut derive = HmacSha256::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    derive.update(b"PVP-UDP-v2-authentication");
    HmacSha256::new_from_slice(&derive.finalize().into_bytes()).unwrap()
}
pub fn seal(packet: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(4 + packet.len() + TAG_SIZE);
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(packet);
    let mut mac = authenticator(key);
    mac.update(&envelope);
    envelope.extend_from_slice(&mac.finalize().into_bytes());
    envelope
}
pub fn open<'a>(envelope: &'a [u8], key: &[u8; 32]) -> Option<&'a [u8]> {
    if envelope.len() < 4 + TAG_SIZE || !envelope.starts_with(MAGIC) {
        return None;
    }
    let (body, tag) = envelope.split_at(envelope.len() - TAG_SIZE);
    let mut mac = authenticator(key);
    mac.update(body);
    mac.verify_slice(tag).ok()?;
    Some(&body[4..])
}
/// Bounded completed-frame replay protection with wrap-aware sequence ordering.
#[derive(Default)]
pub struct ReplayWindow {
    highest: Option<u32>,
    seen: u128,
}
impl ReplayWindow {
    pub fn accepts(&self, sequence: u32) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if sequence.wrapping_sub(highest) as i32 > 0 {
            return true;
        }
        let age = highest.wrapping_sub(sequence);
        age < 128 && self.seen & (1u128 << age) == 0
    }
    pub fn complete(&mut self, sequence: u32) {
        if !self.accepts(sequence) {
            return;
        }
        if let Some(highest) = self.highest {
            if sequence.wrapping_sub(highest) as i32 > 0 {
                let shift = sequence.wrapping_sub(highest);
                self.seen = if shift < 128 { self.seen << shift } else { 0 };
                self.highest = Some(sequence);
                self.seen |= 1;
            } else {
                self.seen |= 1u128 << highest.wrapping_sub(sequence);
            }
        } else {
            self.highest = Some(sequence);
            self.seen = 1;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticates_every_header_ciphertext_and_tag_byte_and_rejects_old_packets() {
        let key = [42; 32];
        let packet = vec![7; 100];
        let sealed = seal(&packet, &key);
        assert_eq!(open(&sealed, &key), Some(packet.as_slice()));
        assert!(open(&sealed, &[43; 32]).is_none());
        assert!(open(&packet, &key).is_none());
        for index in 0..sealed.len() {
            let mut altered = sealed.clone();
            altered[index] ^= 1;
            assert!(open(&altered, &key).is_none());
        }
        for end in 0..sealed.len() {
            assert!(open(&sealed[..end], &key).is_none());
        }
    }
    #[test]
    fn replay_window_supports_reordering_bounds_and_wrap() {
        let mut window = ReplayWindow::default();
        window.complete(u32::MAX - 1);
        window.complete(1);
        assert!(!window.accepts(1));
        assert!(!window.accepts(u32::MAX - 1));
        assert!(window.accepts(u32::MAX));
        window.complete(u32::MAX);
        assert!(!window.accepts(u32::MAX));
        assert!(!window.accepts(1u32.wrapping_sub(128)));
        window.complete(200);
        assert!(!window.accepts(1));
        assert!(window.accepts(199));
    }
}
