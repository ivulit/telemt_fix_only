//! Client Handler

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{debug, info, warn, error, trace};

use crate::config::ProxyConfig;
use crate::error::{ProxyError, Result, HandshakeResult};
use crate::protocol::constants::*;
use crate::protocol::tls;
use crate::stats::{Stats, ReplayChecker};
use crate::transport::{ConnectionPool, configure_client_socket};
use crate::stream::{CryptoReader, CryptoWriter, FakeTlsReader, FakeTlsWriter};
use crate::crypto::AesCtr;

use super::handshake::{
    handle_tls_handshake, handle_mtproto_handshake, 
    HandshakeSuccess, generate_tg_nonce, encrypt_tg_nonce,
};
use super::relay::relay_bidirectional;
use super::masking::handle_bad_client;

/// Client connection handler
pub struct ClientHandler {
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    replay_checker: Arc<ReplayChecker>,
    pool: Arc<ConnectionPool>,
}

impl ClientHandler {
    /// Create new client handler
    pub fn new(
        config: Arc<ProxyConfig>,
        stats: Arc<Stats>,
        replay_checker: Arc<ReplayChecker>,
        pool: Arc<ConnectionPool>,
    ) -> Self {
        Self {
            config,
            stats,
            replay_checker,
            pool,
        }
    }
    
    /// Handle a client connection
    pub async fn handle(&self, stream: TcpStream, peer: SocketAddr) {
        self.stats.increment_connects_all();
        
        debug!(peer = %peer, "New connection");
        
        // Configure socket
        if let Err(e) = configure_client_socket(
            &stream,
            self.config.client_keepalive,
            self.config.client_ack_timeout,
        ) {
            debug!(peer = %peer, error = %e, "Failed to configure client socket");
        }
        
        // Perform handshake with timeout
        let handshake_timeout = Duration::from_secs(self.config.client_handshake_timeout);
        
        let result = timeout(
            handshake_timeout,
            self.do_handshake(stream, peer)
        ).await;
        
        match result {
            Ok(Ok(())) => {
                debug!(peer = %peer, "Connection handled successfully");
            }
            Ok(Err(e)) => {
                debug!(peer = %peer, error = %e, "Handshake failed");
            }
            Err(_) => {
                self.stats.increment_handshake_timeouts();
                debug!(peer = %peer, "Handshake timeout");
            }
        }
    }
    
    /// Perform handshake and relay
    async fn do_handshake(&self, mut stream: TcpStream, peer: SocketAddr) -> Result<()> {
        // Read first bytes to determine handshake type
        let mut first_bytes = [0u8; 5];
        stream.read_exact(&mut first_bytes).await?;
        
        let is_tls = tls::is_tls_handshake(&first_bytes[..3]);
        
        debug!(peer = %peer, is_tls = is_tls, first_bytes = %hex::encode(&first_bytes), "Handshake type detected");
        
        if is_tls {
            self.handle_tls_client(stream, peer, first_bytes).await
        } else {
            self.handle_direct_client(stream, peer, first_bytes).await
        }
    }
    
    /// Handle TLS-wrapped client
    async fn handle_tls_client(
        &self,
        mut stream: TcpStream,
        peer: SocketAddr,
        first_bytes: [u8; 5],
    ) -> Result<()> {
        // Read TLS handshake length
        let tls_len = u16::from_be_bytes([first_bytes[3], first_bytes[4]]) as usize;
        
        debug!(peer = %peer, tls_len = tls_len, "Reading TLS handshake");
        
        if tls_len < 512 {
            debug!(peer = %peer, tls_len = tls_len, "TLS handshake too short");
            self.stats.increment_connects_bad();
            handle_bad_client(stream, &first_bytes, &self.config).await;
            return Ok(());
        }
        
        // Read full TLS handshake
        let mut handshake = vec![0u8; 5 + tls_len];
        handshake[..5].copy_from_slice(&first_bytes);
        stream.read_exact(&mut handshake[5..]).await?;
        
        // Split stream for reading/writing
        let (read_half, write_half) = stream.into_split();
        
        // Handle TLS handshake
        let (mut tls_reader, tls_writer, _tls_user) = match handle_tls_handshake(
            &handshake,
            read_half,
            write_half,
            peer,
            &self.config,
            &self.replay_checker,
        ).await {
            HandshakeResult::Success(result) => result,
            HandshakeResult::BadClient => {
                self.stats.increment_connects_bad();
                return Ok(());
            }
            HandshakeResult::Error(e) => return Err(e),
        };
        
        // Read MTProto handshake through TLS
        debug!(peer = %peer, "Reading MTProto handshake through TLS");
        let mtproto_data = tls_reader.read_exact(HANDSHAKE_LEN).await?;
        let mtproto_handshake: [u8; HANDSHAKE_LEN] = mtproto_data[..].try_into()
            .map_err(|_| ProxyError::InvalidHandshake("Short MTProto handshake".into()))?;
        
        // Handle MTProto handshake
        let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake(
            &mtproto_handshake,
            tls_reader,
            tls_writer,
            peer,
            &self.config,
            &self.replay_checker,
            true,
        ).await {
            HandshakeResult::Success(result) => result,
            HandshakeResult::BadClient => {
                self.stats.increment_connects_bad();
                return Ok(());
            }
            HandshakeResult::Error(e) => return Err(e),
        };
        
        // Handle authenticated client
        self.handle_authenticated_inner(crypto_reader, crypto_writer, success).await
    }
    
    /// Handle direct (non-TLS) client
    async fn handle_direct_client(
        &self,
        mut stream: TcpStream,
        peer: SocketAddr,
        first_bytes: [u8; 5],
    ) -> Result<()> {
        // Check if non-TLS modes are enabled
        if !self.config.modes.classic && !self.config.modes.secure {
            debug!(peer = %peer, "Non-TLS modes disabled");
            self.stats.increment_connects_bad();
            handle_bad_client(stream, &first_bytes, &self.config).await;
            return Ok(());
        }
        
        // Read rest of handshake
        let mut handshake = [0u8; HANDSHAKE_LEN];
        handshake[..5].copy_from_slice(&first_bytes);
        stream.read_exact(&mut handshake[5..]).await?;
        
        // Split stream
        let (read_half, write_half) = stream.into_split();
        
        // Handle MTProto handshake
        let (crypto_reader, crypto_writer, success) = match handle_mtproto_handshake(
            &handshake,
            read_half,
            write_half,
            peer,
            &self.config,
            &self.replay_checker,
            false,
        ).await {
            HandshakeResult::Success(result) => result,
            HandshakeResult::BadClient => {
                self.stats.increment_connects_bad();
                return Ok(());
            }
            HandshakeResult::Error(e) => return Err(e),
        };
        
        self.handle_authenticated_inner(crypto_reader, crypto_writer, success).await
    }
    
    /// Handle authenticated client - connect to Telegram and relay
    async fn handle_authenticated_inner<R, W>(
        &self,
        client_reader: CryptoReader<R>,
        client_writer: CryptoWriter<W>,
        success: HandshakeSuccess,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let user = &success.user;
        
        // Check user limits
        if let Err(e) = self.check_user_limits(user) {
            warn!(user = %user, error = %e, "User limit exceeded");
            return Err(e);
        }
        
        // Get datacenter address
        let dc_addr = self.get_dc_addr(success.dc_idx)?;
        
        info!(
            user = %user,
            peer = %success.peer,
            dc = success.dc_idx,
            dc_addr = %dc_addr,
            proto = ?success.proto_tag,
            fast_mode = self.config.fast_mode,
            "Connecting to Telegram"
        );
        
        // Connect to Telegram
        let tg_stream = self.pool.get(dc_addr).await?;
        
        debug!(peer = %success.peer, dc_addr = %dc_addr, "Connected to Telegram, performing handshake");
        
        // Perform Telegram handshake and get crypto streams
        let (tg_reader, tg_writer) = self.do_tg_handshake(
            tg_stream, 
            &success,
        ).await?;
        
        debug!(peer = %success.peer, "Telegram handshake complete, starting relay");
        
        // Update stats
        self.stats.increment_user_connects(user);
        self.stats.increment_user_curr_connects(user);
        
        // Relay traffic - передаём Arc::clone(&self.stats)
        let relay_result = relay_bidirectional(
            client_reader,
            client_writer,
            tg_reader,
            tg_writer,
            user,
            Arc::clone(&self.stats),
        ).await;
        
        // Update stats
        self.stats.decrement_user_curr_connects(user);
        
        match &relay_result {
            Ok(()) => debug!(user = %user, peer = %success.peer, "Relay completed normally"),
            Err(e) => debug!(user = %user, peer = %success.peer, error = %e, "Relay ended with error"),
        }
        
        relay_result
    }
    
    /// Check user limits (expiration, connection count, data quota)
    fn check_user_limits(&self, user: &str) -> Result<()> {
        // Check expiration
        if let Some(expiration) = self.config.user_expirations.get(user) {
            if chrono::Utc::now() > *expiration {
                return Err(ProxyError::UserExpired { user: user.to_string() });
            }
        }
        
        // Check connection limit
        if let Some(limit) = self.config.user_max_tcp_conns.get(user) {
            let current = self.stats.get_user_curr_connects(user);
            if current >= *limit as u64 {
                return Err(ProxyError::ConnectionLimitExceeded { user: user.to_string() });
            }
        }
        
        // Check data quota
        if let Some(quota) = self.config.user_data_quota.get(user) {
            let used = self.stats.get_user_total_octets(user);
            if used >= *quota {
                return Err(ProxyError::DataQuotaExceeded { user: user.to_string() });
            }
        }
        
        Ok(())
    }
    
    /// Get datacenter address by index
    fn get_dc_addr(&self, dc_idx: i16) -> Result<SocketAddr> {
        let idx = (dc_idx.abs() - 1) as usize;
        
        let datacenters = if self.config.prefer_ipv6 {
            &*TG_DATACENTERS_V6
        } else {
            &*TG_DATACENTERS_V4
        };
        
        datacenters.get(idx)
            .map(|ip| SocketAddr::new(*ip, TG_DATACENTER_PORT))
            .ok_or_else(|| ProxyError::InvalidHandshake(
                format!("Invalid DC index: {}", dc_idx)
            ))
    }
    
    /// Perform handshake with Telegram server
    /// Returns crypto reader and writer for TG connection
    async fn do_tg_handshake(
        &self,
        mut stream: TcpStream,
        success: &HandshakeSuccess,
    ) -> Result<(CryptoReader<tokio::net::tcp::OwnedReadHalf>, CryptoWriter<tokio::net::tcp::OwnedWriteHalf>)> {
        // Generate nonce with keys for TG
        let (nonce, tg_enc_key, tg_enc_iv, tg_dec_key, tg_dec_iv) = generate_tg_nonce(
            success.proto_tag,
            &success.dec_key,  // Client's dec key
            success.dec_iv,
            self.config.fast_mode,
        );
        
        // Encrypt nonce
        let encrypted_nonce = encrypt_tg_nonce(&nonce);
        
        debug!(
            peer = %success.peer,
            nonce_head = %hex::encode(&nonce[..16]),
            encrypted_head = %hex::encode(&encrypted_nonce[..16]),
            "Sending nonce to Telegram"
        );
        
        // Send to Telegram
        stream.write_all(&encrypted_nonce).await?;
        stream.flush().await?;
        
        debug!(peer = %success.peer, "Nonce sent to Telegram");
        
        // Split stream and wrap with crypto
        let (read_half, write_half) = stream.into_split();
        
        let decryptor = AesCtr::new(&tg_dec_key, tg_dec_iv);
        let encryptor = AesCtr::new(&tg_enc_key, tg_enc_iv);
        
        let tg_reader = CryptoReader::new(read_half, decryptor);
        let tg_writer = CryptoWriter::new(write_half, encryptor);
        
        Ok((tg_reader, tg_writer))
    }
}