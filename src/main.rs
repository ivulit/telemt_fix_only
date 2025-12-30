//! Telemt - MTProxy on Rust

use std::sync::Arc;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{info, error, Level};
use tracing_subscriber::{FmtSubscriber, EnvFilter};

mod error;
mod crypto;
mod protocol;
mod stream;
mod transport;
mod proxy;
mod config;
mod stats;
mod util;

use config::ProxyConfig;
use stats::{Stats, ReplayChecker};
use transport::ConnectionPool;
use proxy::ClientHandler;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize logging with env filter
    // Use RUST_LOG=debug or RUST_LOG=trace for more details
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .finish();
    
    tracing::subscriber::set_global_default(subscriber)?;
    
    // Load configuration
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());
    
    info!("Loading configuration from {}", config_path);
    
    let config = ProxyConfig::load(&config_path).unwrap_or_else(|e| {
        error!("Failed to load config: {}", e);
        info!("Using default configuration");
        ProxyConfig::default()
    });
    
    if let Err(e) = config.validate() {
        error!("Invalid configuration: {}", e);
        std::process::exit(1);
    }
    
    let config = Arc::new(config);
    
    info!("Starting MTProto Proxy on port {}", config.port);
    info!("Fast mode: {}", config.fast_mode);
    info!("Modes: classic={}, secure={}, tls={}", 
        config.modes.classic, config.modes.secure, config.modes.tls);
    
    // Initialize components
    let stats = Arc::new(Stats::new());
    let replay_checker = Arc::new(ReplayChecker::new(config.replay_check_len));
    let pool = Arc::new(ConnectionPool::new());
    
    // Create handler
    let handler = Arc::new(ClientHandler::new(
        Arc::clone(&config),
        Arc::clone(&stats),
        Arc::clone(&replay_checker),
        Arc::clone(&pool),
    ));
    
    // Start listener
    let addr: SocketAddr = format!("{}:{}", config.listen_addr_ipv4, config.port)
        .parse()?;
    
    let listener = TcpListener::bind(addr).await?;
    info!("Listening on {}", addr);
    
    // Print proxy links
    print_proxy_links(&config);
    
    info!("Use RUST_LOG=debug or RUST_LOG=trace for more detailed logging");
    
    // Main accept loop
    let accept_loop = async {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let handler = Arc::clone(&handler);
                    tokio::spawn(async move {
                        handler.handle(stream, peer).await;
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    };
    
    // Graceful shutdown
    tokio::select! {
        _ = accept_loop => {}
        _ = signal::ctrl_c() => {
            info!("Shutting down...");
        }
    }
    
    // Cleanup
    pool.close_all().await;
    
    info!("Goodbye!");
    Ok(())
}

fn print_proxy_links(config: &ProxyConfig) {
    println!("\n=== Proxy Links ===\n");
    
    for (user, secret) in &config.users {
        if config.modes.tls {
            let tls_secret = format!(
                "ee{}{}",
                secret,
                hex::encode(config.tls_domain.as_bytes())
            );
            println!(
                "{} (TLS): tg://proxy?server=IP&port={}&secret={}",
                user, config.port, tls_secret
            );
        }
        
        if config.modes.secure {
            println!(
                "{} (Secure): tg://proxy?server=IP&port={}&secret=dd{}",
                user, config.port, secret
            );
        }
        
        if config.modes.classic {
            println!(
                "{} (Classic): tg://proxy?server=IP&port={}&secret={}",
                user, config.port, secret
            );
        }
        
        println!();
    }
    
    println!("===================\n");
}