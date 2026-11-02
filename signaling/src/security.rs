//! Strict, bounded WebRTC signaling. Never accept plaintext RTP or SDES keys.
use serde_json::Value;

pub fn encrypted_sdp(sdp: &str) -> bool {
    if sdp.len() > 48_000
        || sdp.lines().next() != Some("v=0")
        || sdp.bytes().enumerate().any(|(i, b)| {
            (b.is_ascii_control() && !matches!(b, b'\n' | b'\r' | b'\t'))
                || (b == b'\r' && sdp.as_bytes().get(i + 1) != Some(&b'\n'))
        })
    {
        return false;
    }
    let mut session_fingerprint = false;
    let mut sections: Vec<(bool, bool)> = Vec::new();
    for line in sdp.lines().map(str::trim) {
        if line.len() > 4096 || line.starts_with("a=crypto:") || relay(line) {
            return false;
        }
        if let Some(media) = line.strip_prefix("m=") {
            let fields: Vec<_> = media.split_whitespace().collect();
            if fields.len() < 4 || sections.len() >= 8 {
                return false;
            }
            let valid = match fields[0] {
                "audio" | "video" => fields[2] == "UDP/TLS/RTP/SAVPF",
                "application" => fields[2] == "UDP/DTLS/SCTP",
                _ => false,
            };
            let port = fields[1].parse::<u16>();
            if !valid || !fields[1].bytes().all(|b| b.is_ascii_digit()) || port.is_err() {
                return false;
            }
            sections.push((port.unwrap_or(0) != 0, session_fingerprint));
        } else if let Some(fp) = line.strip_prefix("a=fingerprint:") {
            let Some(hash) = fp.strip_prefix("sha-256 ") else {
                return false;
            };
            let bytes: Vec<_> = hash.split(':').collect();
            if bytes.len() != 32
                || bytes
                    .iter()
                    .any(|b| b.len() != 2 || !b.bytes().all(|c| c.is_ascii_hexdigit()))
            {
                return false;
            }
            if let Some(section) = sections.last_mut() {
                section.1 = true;
            } else {
                session_fingerprint = true;
            }
        }
    }
    !sections.is_empty() && sections.iter().any(|s| s.0) && sections.iter().all(|s| !s.0 || s.1)
}

fn relay(text: &str) -> bool {
    let words: Vec<_> = text.split_whitespace().collect();
    words
        .windows(2)
        .any(|w| w[0].eq_ignore_ascii_case("typ") && w[1].eq_ignore_ascii_case("relay"))
}

pub fn valid_signal(payload: &Value) -> bool {
    if payload.to_string().len() > 60_000 {
        return false;
    }
    match payload["type"].as_str() {
        Some("offer" | "answer") => payload["sdp"].as_str().is_some_and(encrypted_sdp),
        Some("candidate") => {
            // Unknown JSON fields must not inflate each queued ICE candidate.
            if payload.to_string().len() > 4096 {
                return false;
            }
            let c = &payload["candidate"];
            let Some(text) = c["candidate"].as_str() else {
                return false;
            };
            let words: Vec<_> = text.split_whitespace().collect();
            text.len() <= 2048
                && !text.contains(['\r', '\n', '\0'])
                && !relay(text)
                && words.len() >= 8
                && words[0].starts_with("candidate:")
                && words[0].len() > "candidate:".len()
                && matches!(words[1], "1" | "2")
                && matches!(words[2].to_ascii_lowercase().as_str(), "udp" | "tcp")
                && words[3].parse::<u32>().is_ok()
                && words[3].bytes().all(|b| b.is_ascii_digit())
                && words[5].parse::<u16>().is_ok_and(|p| p > 0)
                && words[5].bytes().all(|b| b.is_ascii_digit())
                && words[6] == "typ"
                && matches!(words[7], "host" | "srflx" | "prflx")
                && (c["sdpMid"].is_null()
                    || c["sdpMid"]
                        .as_str()
                        .is_some_and(|s| s.len() <= 64 && !s.chars().any(char::is_control)))
                && (c["sdpMLineIndex"].is_null()
                    || c["sdpMLineIndex"].as_u64().is_some_and(|i| i < 8))
                && !(c["sdpMid"].is_null() && c["sdpMLineIndex"].is_null())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_plaintext_missing_fingerprint_sdes_and_relay() {
        let fp = std::iter::repeat_n("AB", 32).collect::<Vec<_>>().join(":");
        let sdp =
            format!("v=0\r\na=fingerprint:sha-256 {fp}\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n");
        assert!(encrypted_sdp(&sdp));
        assert!(!encrypted_sdp(&sdp.replace("UDP/TLS/RTP/SAVPF", "RTP/AVP")));
        assert!(!encrypted_sdp(&format!(
            "{sdp}a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:secret\r\n"
        )));
        assert!(!encrypted_sdp("v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"));
        assert!(!encrypted_sdp(&format!(
            "{sdp}a=candidate:1 1 udp 1 1.2.3.4 9 typ\tRELAY\r\n"
        )));
        assert!(!encrypted_sdp(&sdp.replacen("v=0", "v=0unsafe", 1)));
        assert!(!encrypted_sdp(&sdp.replace("m=audio 9", "m=audio +9")));
        assert!(!encrypted_sdp(&sdp.replace("v=0\r\n", "v=0\r")));
        assert!(!encrypted_sdp(&sdp.replace("m=audio 9", "m=audio 00")));
    }

    #[test]
    fn candidates_require_bounded_ports_priorities_and_a_foundation() {
        let candidate = "candidate:1 1 udp 1 127.0.0.1 12345 typ host";
        let signal = |text: &str| {
            serde_json::json!({
                "type": "candidate", "candidate": {"candidate": text, "sdpMid": "0"}
            })
        };
        assert!(valid_signal(&signal(candidate)));
        for bad in [
            candidate.replace("candidate:1", "candidate:"),
            candidate.replace("12345", "0"),
            candidate.replace("12345", "65536"),
            candidate.replace("12345", "+12345"),
            candidate.replace("udp 1", "udp 4294967296"),
            candidate.replace("udp 1", "udp +1"),
        ] {
            assert!(!valid_signal(&signal(&bad)), "accepted: {bad}");
        }
    }
}
