//! Cryptographic hash functions
//!
//! ## Protocol-required algorithms
//!
//! This module exposes MD5 and SHA-1 alongside SHA-256. These weaker
//! hash functions are **required by the Telegram Middle Proxy protocol**
//! (`derive_middleproxy_keys`) and cannot be replaced without breaking
//! compatibility. They are NOT used for any security-sensitive purpose
//! outside of that specific key derivation scheme mandated by Telegram.
//!
//! Static analysis tools (CodeQL, cargo-audit) may flag them — the
//! usages are intentional and protocol-mandated.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use md5::Md5;
use sha1::Sha1;
use sha2::Digest;

type HmacSha256 = Hmac<Sha256>;

/// SHA-256
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-256 HMAC
pub fn sha256_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// SHA-1 — **protocol-required** by Telegram Middle Proxy key derivation.
/// Not used for general-purpose hashing.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// MD5 — **protocol-required** by Telegram Middle Proxy key derivation.
/// Not used for general-purpose hashing.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// CRC32
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Middle Proxy key derivation
///
/// Uses MD5 + SHA-1 as mandated by the Telegram Middle Proxy protocol.
/// These algorithms are NOT replaceable here — changing them would break
/// interoperability with Telegram's middle proxy infrastructure.
pub fn derive_middleproxy_keys(
    nonce_srv: &[u8; 16],
    nonce_clt: &[u8; 16],
    clt_ts: &[u8; 4],
    srv_ip: Option<&[u8]>,
    clt_port: &[u8; 2],
    purpose: &[u8],
    clt_ip: Option<&[u8]>,
    srv_port: &[u8; 2],
    secret: &[u8],
    clt_ipv6: Option<&[u8; 16]>,
    srv_ipv6: Option<&[u8; 16]>,
) -> ([u8; 32], [u8; 16]) {
    const EMPTY_IP: [u8; 4] = [0, 0, 0, 0];
    
    let srv_ip = srv_ip.unwrap_or(&EMPTY_IP);
    let clt_ip = clt_ip.unwrap_or(&EMPTY_IP);
    
    let mut s = Vec::with_capacity(256);
    s.extend_from_slice(nonce_srv);
    s.extend_from_slice(nonce_clt);
    s.extend_from_slice(clt_ts);
    s.extend_from_slice(srv_ip);
    s.extend_from_slice(clt_port);
    s.extend_from_slice(purpose);
    s.extend_from_slice(clt_ip);
    s.extend_from_slice(srv_port);
    s.extend_from_slice(secret);
    s.extend_from_slice(nonce_srv);
    
    if let (Some(clt_v6), Some(srv_v6)) = (clt_ipv6, srv_ipv6) {
        s.extend_from_slice(clt_v6);
        s.extend_from_slice(srv_v6);
    }
    
    s.extend_from_slice(nonce_clt);
    
    let md5_1 = md5(&s[1..]);
    let sha1_sum = sha1(&s);
    let md5_2 = md5(&s[2..]);
    
    let mut key = [0u8; 32];
    key[..12].copy_from_slice(&md5_1[..12]);
    key[12..].copy_from_slice(&sha1_sum);
    
    (key, md5_2)
}