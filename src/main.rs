//! Telemt - MTProxy on Rust

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{info, error, warn, debug};
use tracing_subscriber::{fmt, EnvFilter};

mod config;
mod crypto;
mod error;
mod protocol;
mod proxy;
mod stats;
mod stream;
mod transport;
mod util;

use crate::config::{ProxyConfig, LogLevel};
use crate::proxy::ClientHandler;
use crate::stats::{Stats, ReplayChecker};
use crate::crypto::SecureRandom;
use crate::transport::{create_listener, ListenOptions, UpstreamManager};
use crate::util::ip::detect_ip;
use crate::stream::BufferPool;

/// Parse command-line arguments.
///
/// Usage: telemt [config_path] [--silent] [--log-level <level>]
///
/// Returns (config_path, silent_flag, log_level_override)
fn parse_cli() -> (String, bool, Option<String>) {
    let mut config_path = "config.toml".to_string();
    let mut silent = false;
    let mut log_level: Option<String> = None;
    
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--silent" | "-s" => {
                silent = true;
            }
            "--log-level" => {
                i += 1;
                if i < args.len() {
                    log_level = Some(args[i].clone());
                }
            }
            s if s.starts_with("--log-level=") => {
                log_level = Some(s.trim_start_matches("--log-level=").to_string());
            }
            "--help" | "-h" => {
                eprintln!("Usage: telemt [config.toml] [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --silent, -s            Suppress info logs (only warn/error)");
                eprintln!("  --log-level <LEVEL>     Set log level: debug|verbose|normal|silent");
                eprintln!("  --help, -h              Show this help");
                std::process::exit(0);
            }
            s if !s.starts_with('-') => {
                config_path = s.to_string();
            }
            other => {
                eprintln!("Unknown option: {}", other);
            }
        }
        i += 1;
    }
    
    (config_path, silent, log_level)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Parse CLI arguments
    let (config_path, cli_silent, cli_log_level) = parse_cli();

    // 2. Load config (tracing not yet initialized — errors go to stderr)
    let config = match ProxyConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            if std::path::Path::new(&config_path).exists() {
                eprintln!("[telemt] Error: Failed to load config '{}': {}", config_path, e);
                std::process::exit(1);
            } else {
                let default = ProxyConfig::default();
                let toml_str = toml::to_string_pretty(&default).unwrap();
                std::fs::write(&config_path, toml_str).unwrap();
                eprintln!("[telemt] Created default config at {}", config_path);
                default
            }
        }
    };
    
    if let Err(e) = config.validate() {
        eprintln!("[telemt] Error: Invalid configuration: {}", e);
        std::process::exit(1);
    }

    // 3. Determine effective log level
    //    Priority: RUST_LOG env > CLI flags > config file > default (normal)
    let effective_log_level = if cli_silent {
        LogLevel::Silent
    } else if let Some(ref level_str) = cli_log_level {
        LogLevel::from_str_loose(level_str)
    } else {
        config.general.log_level.clone()
    };
    
    // 4. Initialize tracing
    let filter = if std::env::var("RUST_LOG").is_ok() {
        // RUST_LOG takes absolute priority
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new(effective_log_level.to_filter_str())
    };
    
    fmt()
        .with_env_filter(filter)
        .init();
    
    // 5. Log startup info (operational — respects log level)
    info!("Telemt MTProxy v{}", env!("CARGO_PKG_VERSION"));
    info!("Log level: {}", effective_log_level);
    info!(
        "Modes: classic={} secure={} tls={}",
        config.general.modes.classic,
        config.general.modes.secure,
        config.general.modes.tls
    );
    info!("TLS domain: {}", config.censorship.tls_domain);
    info!(
        "Mask: {} -> {}:{}",
        config.censorship.mask,
        config.censorship.mask_host.as_deref().unwrap_or(&config.censorship.tls_domain),
        config.censorship.mask_port
    );
    
    if config.censorship.tls_domain == "www.google.com" {
        warn!("Using default tls_domain (www.google.com). Consider setting a custom domain.");
    }
    
    let config = Arc::new(config);
    let stats = Arc::new(Stats::new());
    let rng = Arc::new(SecureRandom::new());
    
    // Initialize ReplayChecker
    let replay_checker = Arc::new(ReplayChecker::new(
        config.access.replay_check_len,
        Duration::from_secs(config.access.replay_window_secs),
    ));
    
    // Initialize Upstream Manager
    let upstream_manager = Arc::new(UpstreamManager::new(config.upstreams.clone()));
    
    // Initialize Buffer Pool (16KB buffers, max 4096 cached ≈ 64MB)
    let buffer_pool = Arc::new(BufferPool::with_config(16 * 1024, 4096));
    
    // Start health checks
    let um_clone = upstream_manager.clone();
    tokio::spawn(async move {
        um_clone.run_health_checks().await;
    });

    // Detect public IP (once at startup)
    let detected_ip = detect_ip().await;
    debug!("Detected IPs: v4={:?} v6={:?}", detected_ip.ipv4, detected_ip.ipv6);

    // 6. Start listeners
    let mut listeners = Vec::new();
    
    for listener_conf in &config.server.listeners {
        let addr = SocketAddr::new(listener_conf.ip, config.server.port);
        let options = ListenOptions {
            ipv6_only: listener_conf.ip.is_ipv6(),
            ..Default::default()
        };
        
        match create_listener(addr, &options) {
            Ok(socket) => {
                let listener = TcpListener::from_std(socket.into())?;
                info!("Listening on {}", addr);
                
                // Determine public IP for tg:// links
                let public_ip = if let Some(ip) = listener_conf.announce_ip {
                    ip
                } else if listener_conf.ip.is_unspecified() {
                    if listener_conf.ip.is_ipv4() {
                        detected_ip.ipv4.unwrap_or(listener_conf.ip)
                    } else {
                        detected_ip.ipv6.unwrap_or(listener_conf.ip)
                    }
                } else {
                    listener_conf.ip
                };

                // 7. Print proxy links (always visible — uses println!, not tracing)
                if !config.show_link.is_empty() {
                    println!("--- Proxy Links ({}) ---", public_ip);
                    for user_name in &config.show_link {
                        if let Some(secret) = config.access.users.get(user_name) {
                            println!("[{}]", user_name);

                            if config.general.modes.classic {
                                println!("  Classic: tg://proxy?server={}&port={}&secret={}", 
                                    public_ip, config.server.port, secret);
                            }

                            if config.general.modes.secure {
                                println!("  DD:      tg://proxy?server={}&port={}&secret=dd{}", 
                                    public_ip, config.server.port, secret);
                            }

                            if config.general.modes.tls {
                                let domain_hex = hex::encode(&config.censorship.tls_domain);
                                println!("  EE-TLS:  tg://proxy?server={}&port={}&secret=ee{}{}", 
                                    public_ip, config.server.port, secret, domain_hex);
                            }
                        } else {
                            warn!("User '{}' in show_link not found in users", user_name);
                        }
                    }
                    println!("------------------------");
                }
                
                listeners.push(listener);
            },
            Err(e) => {
                error!("Failed to bind to {}: {}", addr, e);
            }
        }
    }
    
    if listeners.is_empty() {
        error!("No listeners could be started. Exiting.");
        std::process::exit(1);
    }

    // 8. Accept loop
    for listener in listeners {
        let config = config.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let config = config.clone();
                        let stats = stats.clone();
                        let upstream_manager = upstream_manager.clone();
                        let replay_checker = replay_checker.clone();
                        let buffer_pool = buffer_pool.clone();
                        let rng = rng.clone();
                        
                        tokio::spawn(async move {
                            if let Err(e) = ClientHandler::new(
                                stream, 
                                peer_addr, 
                                config, 
                                stats,
                                upstream_manager,
                                replay_checker,
                                buffer_pool,
                                rng
                            ).run().await {
                                debug!(peer = %peer_addr, error = %e, "Connection error");
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    // 9. Wait for shutdown signal
    match signal::ctrl_c().await {
        Ok(()) => info!("Shutting down..."),
        Err(e) => error!("Signal error: {}", e),
    }

    Ok(())
}