//! Bidirectional Relay

use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tracing::{debug, trace, warn};
use crate::error::Result;
use crate::stats::Stats;
use std::sync::atomic::{AtomicU64, Ordering};

const BUFFER_SIZE: usize = 65536;

/// Relay data bidirectionally between client and server
pub async fn relay_bidirectional<CR, CW, SR, SW>(
    mut client_reader: CR,
    mut client_writer: CW,
    mut server_reader: SR,
    mut server_writer: SW,
    user: &str,
    stats: Arc<Stats>,
) -> Result<()>
where
    CR: AsyncRead + Unpin + Send + 'static,
    CW: AsyncWrite + Unpin + Send + 'static,
    SR: AsyncRead + Unpin + Send + 'static,
    SW: AsyncWrite + Unpin + Send + 'static,
{
    let user_c2s = user.to_string();
    let user_s2c = user.to_string();
    
    // Используем Arc::clone вместо stats.clone()
    let stats_c2s = Arc::clone(&stats);
    let stats_s2c = Arc::clone(&stats);
    
    let c2s_bytes = Arc::new(AtomicU64::new(0));
    let s2c_bytes = Arc::new(AtomicU64::new(0));
    let c2s_bytes_clone = Arc::clone(&c2s_bytes);
    let s2c_bytes_clone = Arc::clone(&s2c_bytes);
    
    // Client -> Server task
    let c2s = tokio::spawn(async move {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total_bytes = 0u64;
        let mut msg_count = 0u64;
        
        loop {
            match client_reader.read(&mut buf).await {
                Ok(0) => {
                    debug!(
                        user = %user_c2s, 
                        total_bytes = total_bytes,
                        msgs = msg_count,
                        "Client closed connection (C->S)"
                    );
                    let _ = server_writer.shutdown().await;
                    break;
                }
                Ok(n) => {
                    total_bytes += n as u64;
                    msg_count += 1;
                    c2s_bytes_clone.store(total_bytes, Ordering::Relaxed);
                    
                    stats_c2s.add_user_octets_from(&user_c2s, n as u64);
                    stats_c2s.increment_user_msgs_from(&user_c2s);
                    
                    trace!(
                        user = %user_c2s,
                        bytes = n,
                        total = total_bytes,
                        data_preview = %hex::encode(&buf[..n.min(32)]),
                        "C->S data"
                    );
                    
                    if let Err(e) = server_writer.write_all(&buf[..n]).await {
                        debug!(user = %user_c2s, error = %e, "Failed to write to server");
                        break;
                    }
                    if let Err(e) = server_writer.flush().await {
                        debug!(user = %user_c2s, error = %e, "Failed to flush to server");
                        break;
                    }
                }
                Err(e) => {
                    debug!(user = %user_c2s, error = %e, total_bytes = total_bytes, "Client read error");
                    break;
                }
            }
        }
    });
    
    // Server -> Client task
    let s2c = tokio::spawn(async move {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total_bytes = 0u64;
        let mut msg_count = 0u64;
        
        loop {
            match server_reader.read(&mut buf).await {
                Ok(0) => {
                    debug!(
                        user = %user_s2c,
                        total_bytes = total_bytes,
                        msgs = msg_count,
                        "Server closed connection (S->C)"
                    );
                    let _ = client_writer.shutdown().await;
                    break;
                }
                Ok(n) => {
                    total_bytes += n as u64;
                    msg_count += 1;
                    s2c_bytes_clone.store(total_bytes, Ordering::Relaxed);
                    
                    stats_s2c.add_user_octets_to(&user_s2c, n as u64);
                    stats_s2c.increment_user_msgs_to(&user_s2c);
                    
                    trace!(
                        user = %user_s2c,
                        bytes = n,
                        total = total_bytes,
                        data_preview = %hex::encode(&buf[..n.min(32)]),
                        "S->C data"
                    );
                    
                    if let Err(e) = client_writer.write_all(&buf[..n]).await {
                        debug!(user = %user_s2c, error = %e, "Failed to write to client");
                        break;
                    }
                    if let Err(e) = client_writer.flush().await {
                        debug!(user = %user_s2c, error = %e, "Failed to flush to client");
                        break;
                    }
                }
                Err(e) => {
                    debug!(user = %user_s2c, error = %e, total_bytes = total_bytes, "Server read error");
                    break;
                }
            }
        }
    });
    
    // Wait for either direction to complete
    tokio::select! {
        result = c2s => {
            if let Err(e) = result {
                warn!(error = %e, "C->S task panicked");
            }
        }
        result = s2c => {
            if let Err(e) = result {
                warn!(error = %e, "S->C task panicked");
            }
        }
    }
    
    debug!(
        c2s_bytes = c2s_bytes.load(Ordering::Relaxed),
        s2c_bytes = s2c_bytes.load(Ordering::Relaxed),
        "Relay finished"
    );
    
    Ok(())
}