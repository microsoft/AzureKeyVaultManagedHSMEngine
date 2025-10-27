// Base64 encoding/decoding utilities
// Corresponds to base64.c

use base64::{Engine as _, engine::general_purpose};

/// Encode bytes to URL-safe base64 (no padding)
pub fn encode_url_safe(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Decode URL-safe base64 (no padding)
pub fn decode_url_safe(data: &str) -> Result<Vec<u8>, String> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| format!("Base64 decode error: {}", e))
}

/// Encode bytes to standard base64
pub fn encode_standard(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Decode standard base64
pub fn decode_standard(data: &str) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD
        .decode(data)
        .map_err(|e| format!("Base64 decode error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_safe_encoding() {
        let data = b"Hello, World!";
        let encoded = encode_url_safe(data);
        let decoded = decode_url_safe(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }
}
