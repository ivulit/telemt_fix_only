//! Masking - forward unrecognized traffic to mask host

use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::debug;
use crate::config::ProxyConfig;
use crate::transport::set_linger_zero;

const MASK_TIMEOUT: Duration = Duration::from_secs(5);
const MASK_BUFFER_SIZE: usize = 8192;

/// Handle a bad client by forwarding to mask host
pub async fn handle_bad_client(
    mut client: TcpStream,
    initial_data: &[u8],
    config: &ProxyConfig,
) {
    if !config.mask {
        // Masking disabled, just consume data
        consume_client_data(client).await;
        return;
    }
    
    let mask_host = config.mask_host.as_deref()
        .unwrap_or(&config.tls_domain);
    let mask_port = config.mask_port;
    
    debug!(
        host = %mask_host,
        port = mask_port,
        "Forwarding bad client to mask host"
    );
    
    // Connect to mask host
    let mask_addr = format!("{}:{}", mask_host, mask_port);
    let connect_result = timeout(
        MASK_TIMEOUT,
        TcpStream::connect(&mask_addr)
    ).await;
    
    let mut mask_stream = match connect_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(error = %e, "Failed to connect to mask host");
            consume_client_data(client).await;
            return;
        }
        Err(_) => {
            debug!("Timeout connecting to mask host");
            consume_client_data(client).await;
            return;
        }
    };
    
    // Send initial data to mask host
    if mask_stream.write_all(initial_data).await.is_err() {
        return;
    }
    
    // Relay traffic
    let (mut client_read, mut client_write) = client.into_split();
    let (mut mask_read, mut mask_write) = mask_stream.into_split();
    
    let c2m = tokio::spawn(async move {
        let mut buf = vec![0u8; MASK_BUFFER_SIZE];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = mask_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if mask_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    
    let m2c = tokio::spawn(async move {
        let mut buf = vec![0u8; MASK_BUFFER_SIZE];
        loop {
            match mask_read.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = client_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if client_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    
    // Wait for either to complete
    tokio::select! {
        _ = c2m => {}
        _ = m2c => {}
    }
}

/// Just consume all data from client without responding
async fn consume_client_data(mut client: TcpStream) {
    let mut buf = vec![0u8; MASK_BUFFER_SIZE];
    while let Ok(n) = client.read(&mut buf).await {
        if n == 0 {
            break;
        }
    }
}