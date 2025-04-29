// File: /Users/davell/Documents/github/pvp/src/config.rs
use serde_json::Value;
use std::fs;
use std::error::Error;

/// Reads the AES-256 encryption key from a JSON configuration file.
///
/// Expects a JSON file at the given path with a field "encryption_key"
/// containing a 64-character hexadecimal string.
///
/// # Arguments
///
/// * `file_path` - The path to the JSON configuration file (e.g., "config.json").
///
/// # Returns
///
/// A `Result` containing the 32-byte key array or a `Box<dyn Error>` if reading,
/// parsing, or validation fails.
pub fn read_key_from_json(file_path: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let json_str = fs::read_to_string(file_path)?;
    let json: Value = serde_json::from_str(&json_str)?;
    let key_hex = json["encryption_key"]
        .as_str()
        .ok_or("encryption_key field not found or not a string in config.json")?;
    let key_bytes = hex::decode(key_hex)?;
    if key_bytes.len() != 32 {
        return Err(format!("Key must be 32 bytes (64 hex chars), but got {} bytes", key_bytes.len()).into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}