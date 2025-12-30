//! Fake TLS 1.3 Handshake

use crate::crypto::{sha256_hmac, random::SECURE_RANDOM};
use crate::error::{ProxyError, Result};
use super::constants::*;
use std::time::{SystemTime, UNIX_EPOCH};

/// TLS handshake digest length
pub const TLS_DIGEST_LEN: usize = 32;
/// Position of digest in TLS ClientHello
pub const TLS_DIGEST_POS: usize = 11;
/// Length to store for replay protection (first 16 bytes of digest)
pub const TLS_DIGEST_HALF_LEN: usize = 16;

/// Time skew limits for anti-replay (in seconds)
pub const TIME_SKEW_MIN: i64 = -20 * 60; // 20 minutes before
pub const TIME_SKEW_MAX: i64 = 10 * 60;  // 10 minutes after

/// Result of validating TLS handshake
#[derive(Debug)]
pub struct TlsValidation {
    /// Username that validated
    pub user: String,
    /// Session ID from ClientHello
    pub session_id: Vec<u8>,
    /// Client digest for response generation
    pub digest: [u8; TLS_DIGEST_LEN],
    /// Timestamp extracted from digest
    pub timestamp: u32,
}

/// Validate TLS ClientHello against user secrets
pub fn validate_tls_handshake(
    handshake: &[u8],
    secrets: &[(String, Vec<u8>)],
    ignore_time_skew: bool,
) -> Option<TlsValidation> {
    if handshake.len() < TLS_DIGEST_POS + TLS_DIGEST_LEN + 1 {
        return None;
    }
    
    // Extract digest
    let digest: [u8; TLS_DIGEST_LEN] = handshake[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN]
        .try_into()
        .ok()?;
    
    // Extract session ID
    let session_id_len_pos = TLS_DIGEST_POS + TLS_DIGEST_LEN;
    let session_id_len = handshake.get(session_id_len_pos).copied()? as usize;
    let session_id_start = session_id_len_pos + 1;
    
    if handshake.len() < session_id_start + session_id_len {
        return None;
    }
    
    let session_id = handshake[session_id_start..session_id_start + session_id_len].to_vec();
    
    // Build message for HMAC (with zeroed digest)
    let mut msg = handshake.to_vec();
    msg[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].fill(0);
    
    // Get current time
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    
    for (user, secret) in secrets {
        let computed = sha256_hmac(secret, &msg);
        
        // XOR digests
        let xored: Vec<u8> = digest.iter()
            .zip(computed.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        
        // Check that first 28 bytes are zeros (timestamp in last 4)
        if !xored[..28].iter().all(|&b| b == 0) {
            continue;
        }
        
        // Extract timestamp
        let timestamp = u32::from_le_bytes(xored[28..32].try_into().unwrap());
        let time_diff = now - timestamp as i64;
        
        // Check time skew
        if !ignore_time_skew {
            // Allow very small timestamps (boot time instead of unix time)
            let is_boot_time = timestamp < 60 * 60 * 24 * 1000;
            
            if !is_boot_time && (time_diff < TIME_SKEW_MIN || time_diff > TIME_SKEW_MAX) {
                continue;
            }
        }
        
        return Some(TlsValidation {
            user: user.clone(),
            session_id,
            digest,
            timestamp,
        });
    }
    
    None
}

/// Generate a fake X25519 public key for TLS
/// This generates a value that looks like a valid X25519 key
pub fn gen_fake_x25519_key() -> [u8; 32] {
    // For simplicity, just generate random 32 bytes
    // In real X25519, this would be a point on the curve
    let bytes = SECURE_RANDOM.bytes(32);
    bytes.try_into().unwrap()
}

/// Build TLS ServerHello response
pub fn build_server_hello(
    secret: &[u8],
    client_digest: &[u8; TLS_DIGEST_LEN],
    session_id: &[u8],
    fake_cert_len: usize,
) -> Vec<u8> {
    let x25519_key = gen_fake_x25519_key();
    
    // TLS extensions
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x2e]); // Extension length placeholder
    extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x24]); // Key share extension
    extensions.extend_from_slice(&[0x00, 0x1d, 0x00, 0x20]); // X25519 curve
    extensions.extend_from_slice(&x25519_key);
    extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // Supported versions
    
    // ServerHello body
    let mut srv_hello = Vec::new();
    srv_hello.extend_from_slice(&TLS_VERSION);
    srv_hello.extend_from_slice(&[0u8; TLS_DIGEST_LEN]); // Placeholder for digest
    srv_hello.push(session_id.len() as u8);
    srv_hello.extend_from_slice(session_id);
    srv_hello.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    srv_hello.push(0x00); // No compression
    srv_hello.extend_from_slice(&extensions);
    
    // Build complete packet
    let mut hello_pkt = Vec::new();
    
    // ServerHello record
    hello_pkt.push(TLS_RECORD_HANDSHAKE);
    hello_pkt.extend_from_slice(&TLS_VERSION);
    hello_pkt.extend_from_slice(&((srv_hello.len() + 4) as u16).to_be_bytes());
    hello_pkt.push(0x02); // ServerHello message type
    let len_bytes = (srv_hello.len() as u32).to_be_bytes();
    hello_pkt.extend_from_slice(&len_bytes[1..4]); // 3-byte length
    hello_pkt.extend_from_slice(&srv_hello);
    
    // Change Cipher Spec record
    hello_pkt.extend_from_slice(&[
        TLS_RECORD_CHANGE_CIPHER, 
        TLS_VERSION[0], TLS_VERSION[1], 
        0x00, 0x01, 0x01
    ]);
    
    // Application Data record (fake certificate)
    let fake_cert = SECURE_RANDOM.bytes(fake_cert_len);
    hello_pkt.push(TLS_RECORD_APPLICATION);
    hello_pkt.extend_from_slice(&TLS_VERSION);
    hello_pkt.extend_from_slice(&(fake_cert.len() as u16).to_be_bytes());
    hello_pkt.extend_from_slice(&fake_cert);
    
    // Compute HMAC for the response
    let mut hmac_input = Vec::with_capacity(TLS_DIGEST_LEN + hello_pkt.len());
    hmac_input.extend_from_slice(client_digest);
    hmac_input.extend_from_slice(&hello_pkt);
    let response_digest = sha256_hmac(secret, &hmac_input);
    
    // Insert computed digest
    // Position: after record header (5) + message type/length (4) + version (2) = 11
    hello_pkt[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN]
        .copy_from_slice(&response_digest);
    
    hello_pkt
}

/// Check if bytes look like a TLS ClientHello
pub fn is_tls_handshake(first_bytes: &[u8]) -> bool {
    if first_bytes.len() < 3 {
        return false;
    }
    
    // TLS record header: 0x16 0x03 0x01
    first_bytes[0] == TLS_RECORD_HANDSHAKE 
        && first_bytes[1] == 0x03 
        && first_bytes[2] == 0x01
}

/// Parse TLS record header, returns (record_type, length)
pub fn parse_tls_record_header(header: &[u8; 5]) -> Option<(u8, u16)> {
    let record_type = header[0];
    let version = [header[1], header[2]];
    
    // We accept both TLS 1.0 header (for ClientHello) and TLS 1.2/1.3
    if version != [0x03, 0x01] && version != TLS_VERSION {
        return None;
    }
    
    let length = u16::from_be_bytes([header[3], header[4]]);
    Some((record_type, length))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_is_tls_handshake() {
        assert!(is_tls_handshake(&[0x16, 0x03, 0x01]));
        assert!(is_tls_handshake(&[0x16, 0x03, 0x01, 0x02, 0x00]));
        assert!(!is_tls_handshake(&[0x17, 0x03, 0x01])); // Application data
        assert!(!is_tls_handshake(&[0x16, 0x03, 0x02])); // Wrong version
        assert!(!is_tls_handshake(&[0x16, 0x03])); // Too short
    }
    
    #[test]
    fn test_parse_tls_record_header() {
        let header = [0x16, 0x03, 0x01, 0x02, 0x00];
        let result = parse_tls_record_header(&header).unwrap();
        assert_eq!(result.0, TLS_RECORD_HANDSHAKE);
        assert_eq!(result.1, 512);
        
        let header = [0x17, 0x03, 0x03, 0x40, 0x00];
        let result = parse_tls_record_header(&header).unwrap();
        assert_eq!(result.0, TLS_RECORD_APPLICATION);
        assert_eq!(result.1, 16384);
    }
    
    #[test]
    fn test_gen_fake_x25519_key() {
        let key1 = gen_fake_x25519_key();
        let key2 = gen_fake_x25519_key();
        
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        assert_ne!(key1, key2); // Should be random
    }
}