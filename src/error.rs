//! Error Types

use std::net::SocketAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    // ============= Crypto Errors =============
    
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    
    // ============= Protocol Errors =============
    
    #[error("Invalid handshake: {0}")]
    InvalidHandshake(String),
    
    #[error("Invalid protocol tag: {0:02x?}")]
    InvalidProtoTag([u8; 4]),
    
    #[error("Invalid TLS record: type={record_type}, version={version:02x?}")]
    InvalidTlsRecord { record_type: u8, version: [u8; 2] },
    
    #[error("Replay attack detected from {addr}")]
    ReplayAttack { addr: SocketAddr },
    
    #[error("Time skew detected: client={client_time}, server={server_time}")]
    TimeSkew { client_time: u32, server_time: u32 },
    
    #[error("Invalid message length: {len} (min={min}, max={max})")]
    InvalidMessageLength { len: usize, min: usize, max: usize },
    
    #[error("Checksum mismatch: expected={expected:08x}, got={got:08x}")]
    ChecksumMismatch { expected: u32, got: u32 },
    
    #[error("Sequence number mismatch: expected={expected}, got={got}")]
    SeqNoMismatch { expected: i32, got: i32 },
    
    // ============= Network Errors =============
    
    #[error("Connection timeout to {addr}")]
    ConnectionTimeout { addr: String },
    
    #[error("Connection refused by {addr}")]
    ConnectionRefused { addr: String },
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    // ============= Proxy Protocol Errors =============
    
    #[error("Invalid proxy protocol header")]
    InvalidProxyProtocol,
    
    // ============= Config Errors =============
    
    #[error("Config error: {0}")]
    Config(String),
    
    #[error("Invalid secret for user {user}: {reason}")]
    InvalidSecret { user: String, reason: String },
    
    // ============= User Errors =============
    
    #[error("User {user} expired")]
    UserExpired { user: String },
    
    #[error("User {user} exceeded connection limit")]
    ConnectionLimitExceeded { user: String },
    
    #[error("User {user} exceeded data quota")]
    DataQuotaExceeded { user: String },
    
    #[error("Unknown user")]
    UnknownUser,
    
    // ============= General Errors =============
    
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Convenient Result type alias
pub type Result<T> = std::result::Result<T, ProxyError>;

/// Result with optional bad client handling
#[derive(Debug)]
pub enum HandshakeResult<T> {
    /// Handshake succeeded
    Success(T),
    /// Client failed validation, needs masking
    BadClient,
    /// Error occurred
    Error(ProxyError),
}

impl<T> HandshakeResult<T> {
    /// Check if successful
    pub fn is_success(&self) -> bool {
        matches!(self, HandshakeResult::Success(_))
    }
    
    /// Check if bad client
    pub fn is_bad_client(&self) -> bool {
        matches!(self, HandshakeResult::BadClient)
    }
    
    /// Convert to Result, treating BadClient as error
    pub fn into_result(self) -> Result<T> {
        match self {
            HandshakeResult::Success(v) => Ok(v),
            HandshakeResult::BadClient => Err(ProxyError::InvalidHandshake("Bad client".into())),
            HandshakeResult::Error(e) => Err(e),
        }
    }
    
    /// Map the success value
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> HandshakeResult<U> {
        match self {
            HandshakeResult::Success(v) => HandshakeResult::Success(f(v)),
            HandshakeResult::BadClient => HandshakeResult::BadClient,
            HandshakeResult::Error(e) => HandshakeResult::Error(e),
        }
    }
}

impl<T> From<ProxyError> for HandshakeResult<T> {
    fn from(err: ProxyError) -> Self {
        HandshakeResult::Error(err)
    }
}

impl<T> From<std::io::Error> for HandshakeResult<T> {
    fn from(err: std::io::Error) -> Self {
        HandshakeResult::Error(ProxyError::Io(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_handshake_result() {
        let success: HandshakeResult<i32> = HandshakeResult::Success(42);
        assert!(success.is_success());
        assert!(!success.is_bad_client());
        
        let bad: HandshakeResult<i32> = HandshakeResult::BadClient;
        assert!(!bad.is_success());
        assert!(bad.is_bad_client());
    }
    
    #[test]
    fn test_handshake_result_map() {
        let success: HandshakeResult<i32> = HandshakeResult::Success(42);
        let mapped = success.map(|x| x * 2);
        
        match mapped {
            HandshakeResult::Success(v) => assert_eq!(v, 84),
            _ => panic!("Expected success"),
        }
    }
    
    #[test]
    fn test_error_display() {
        let err = ProxyError::ConnectionTimeout { addr: "1.2.3.4:443".into() };
        assert!(err.to_string().contains("1.2.3.4:443"));
        
        let err = ProxyError::InvalidProxyProtocol;
        assert!(err.to_string().contains("proxy protocol"));
    }
}