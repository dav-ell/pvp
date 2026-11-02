// File: /Users/davell/Documents/github/pvp/src/config.rs
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};

/// Optional TURN-like relay settings (DigitalOcean pvp-relay).
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// e.g. `143.198.19.179:3478` or `lopixel.space:3478`
    pub server: String,
    /// Shared secret; must match the relay process token.
    pub token: String,
    /// Room id both peers join (max 64 ASCII bytes).
    pub room: String,
    /// If true (default), try UDP hole punch before using the relay.
    pub prefer_p2p: bool,
}

/// Application configuration loaded from `config.json`.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub encryption_key: [u8; 32],
    pub relay: Option<RelayConfig>,
}

/// Reads configuration from a JSON file.
///
/// Required: `encryption_key` — 64-character hex AES-256 key.
/// Optional: `relay` object with `server`, `token`, `room`, `prefer_p2p`.
pub fn load_config(file_path: &str) -> Result<AppConfig, Box<dyn Error>> {
    let json_str = fs::read_to_string(file_path)?;
    let json: Value = serde_json::from_str(&json_str)?;

    let key_hex = json["encryption_key"]
        .as_str()
        .ok_or("encryption_key field not found or not a string in config.json")?;
    let key_bytes = hex::decode(key_hex)?;
    if key_bytes.len() != 32 {
        return Err(format!(
            "Key must be 32 bytes (64 hex chars), but got {} bytes",
            key_bytes.len()
        )
        .into());
    }
    let mut encryption_key = [0u8; 32];
    encryption_key.copy_from_slice(&key_bytes);

    let relay = parse_relay(&json["relay"])?;

    Ok(AppConfig {
        encryption_key,
        relay,
    })
}

fn parse_relay(value: &Value) -> Result<Option<RelayConfig>, Box<dyn Error>> {
    if value.is_null() {
        return Ok(None);
    }
    // Allow disabling with "relay": false or "enabled": false
    if value.as_bool() == Some(false) {
        return Ok(None);
    }
    if !value.is_object() {
        return Err("relay must be an object or omitted".into());
    }
    if value.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
        return Ok(None);
    }

    let server = value
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or("relay.server is required when relay is configured")?
        .to_string();
    let token = value
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or("relay.token is required when relay is configured")?
        .to_string();
    let room = value
        .get("room")
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_string();
    let prefer_p2p = value
        .get("prefer_p2p")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    if server.is_empty() || token.is_empty() {
        return Err("relay.server and relay.token must be non-empty".into());
    }
    if room.is_empty() || room.len() > 64 {
        return Err("relay.room must be 1..=64 characters".into());
    }

    Ok(Some(RelayConfig {
        server,
        token,
        room,
        prefer_p2p,
    }))
}

/// Resolve `host:port` to a SocketAddr (prefer IPv4).
pub fn resolve_relay_addr(server: &str) -> Result<SocketAddr, Box<dyn Error>> {
    let mut addrs = server.to_socket_addrs().map_err(|e| {
        format!(
            "failed to resolve relay server '{}': {} (use IP:PORT if DNS fails)",
            server, e
        )
    })?;
    if let Some(v4) = addrs.find(|a| a.is_ipv4()) {
        return Ok(v4);
    }
    // Re-resolve for IPv6 fallback
    server
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("no addresses for relay server '{}'", server).into())
}

/// Back-compat helper used by unit tests and simple callers.
pub fn read_key_from_json(file_path: &str) -> Result<[u8; 32], Box<dyn Error>> {
    Ok(load_config(file_path)?.encryption_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pvp-config-{}-{}", name, std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("config.json");
        let mut f = fs::File::create(&path).unwrap();
        write!(f, "{}", body).unwrap();
        path
    }

    #[test]
    fn read_key_accepts_64_hex_chars() {
        let hex = "a6e714b117bcda03e0b2270304e9971197facde42a5580a26cb63424c56007dc";
        let path = write_temp("ok", &format!(r#"{{"encryption_key": "{}"}}"#, hex));
        let key = read_key_from_json(path.to_str().unwrap()).expect("valid key");
        assert_eq!(hex::encode(key), hex);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn read_key_rejects_wrong_length() {
        let path = write_temp("bad", r#"{"encryption_key": "deadbeef"}"#);
        let err = read_key_from_json(path.to_str().unwrap()).unwrap_err();
        assert!(
            err.to_string().contains("32 bytes") || err.to_string().contains("64 hex"),
            "unexpected error: {}",
            err
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn read_key_rejects_missing_field() {
        let path = write_temp("missing", r#"{"other": "x"}"#);
        assert!(read_key_from_json(path.to_str().unwrap()).is_err());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn load_config_with_relay() {
        let hex = "a6e714b117bcda03e0b2270304e9971197facde42a5580a26cb63424c56007dc";
        let path = write_temp(
            "relay",
            &format!(
                r#"{{
                "encryption_key": "{}",
                "relay": {{
                    "server": "143.198.19.179:3478",
                    "token": "test-token",
                    "room": "call1",
                    "prefer_p2p": true
                }}
            }}"#,
                hex
            ),
        );
        let cfg = load_config(path.to_str().unwrap()).unwrap();
        let r = cfg.relay.expect("relay present");
        assert_eq!(r.server, "143.198.19.179:3478");
        assert_eq!(r.token, "test-token");
        assert_eq!(r.room, "call1");
        assert!(r.prefer_p2p);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn load_config_relay_disabled() {
        let hex = "a6e714b117bcda03e0b2270304e9971197facde42a5580a26cb63424c56007dc";
        let path = write_temp(
            "relay-off",
            &format!(
                r#"{{"encryption_key":"{}","relay":{{"enabled":false,"server":"x:1","token":"t"}}}}"#,
                hex
            ),
        );
        let cfg = load_config(path.to_str().unwrap()).unwrap();
        assert!(cfg.relay.is_none());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
