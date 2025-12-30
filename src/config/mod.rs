//! Configuration

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::error::{ProxyError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyModes {
    #[serde(default)]
    pub classic: bool,
    #[serde(default)]
    pub secure: bool,
    #[serde(default = "default_true")]
    pub tls: bool,
}

fn default_true() -> bool { true }

impl Default for ProxyModes {
    fn default() -> Self {
        Self { classic: true, secure: true, tls: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    
    #[serde(default)]
    pub users: HashMap<String, String>,
    
    #[serde(default)]
    pub ad_tag: Option<String>,
    
    #[serde(default)]
    pub modes: ProxyModes,
    
    #[serde(default = "default_tls_domain")]
    pub tls_domain: String,
    
    #[serde(default = "default_true")]
    pub mask: bool,
    
    #[serde(default)]
    pub mask_host: Option<String>,
    
    #[serde(default = "default_mask_port")]
    pub mask_port: u16,
    
    #[serde(default)]
    pub prefer_ipv6: bool,
    
    #[serde(default = "default_true")]
    pub fast_mode: bool,
    
    #[serde(default)]
    pub use_middle_proxy: bool,
    
    #[serde(default)]
    pub user_max_tcp_conns: HashMap<String, usize>,
    
    #[serde(default)]
    pub user_expirations: HashMap<String, DateTime<Utc>>,
    
    #[serde(default)]
    pub user_data_quota: HashMap<String, u64>,
    
    #[serde(default = "default_replay_check_len")]
    pub replay_check_len: usize,
    
    #[serde(default)]
    pub ignore_time_skew: bool,
    
    #[serde(default = "default_handshake_timeout")]
    pub client_handshake_timeout: u64,
    
    #[serde(default = "default_connect_timeout")]
    pub tg_connect_timeout: u64,
    
    #[serde(default = "default_keepalive")]
    pub client_keepalive: u64,
    
    #[serde(default = "default_ack_timeout")]
    pub client_ack_timeout: u64,
    
    #[serde(default = "default_listen_addr")]
    pub listen_addr_ipv4: String,
    
    #[serde(default)]
    pub listen_addr_ipv6: Option<String>,
    
    #[serde(default)]
    pub listen_unix_sock: Option<String>,
    
    #[serde(default)]
    pub metrics_port: Option<u16>,
    
    #[serde(default = "default_metrics_whitelist")]
    pub metrics_whitelist: Vec<IpAddr>,
    
    #[serde(default = "default_fake_cert_len")]
    pub fake_cert_len: usize,
}

fn default_port() -> u16 { 443 }
fn default_tls_domain() -> String { "www.google.com".to_string() }
fn default_mask_port() -> u16 { 443 }
fn default_replay_check_len() -> usize { 65536 }
fn default_handshake_timeout() -> u64 { 10 }
fn default_connect_timeout() -> u64 { 10 }
fn default_keepalive() -> u64 { 600 }
fn default_ack_timeout() -> u64 { 300 }
fn default_listen_addr() -> String { "0.0.0.0".to_string() }
fn default_fake_cert_len() -> usize { 2048 }

fn default_metrics_whitelist() -> Vec<IpAddr> {
    vec![
        "127.0.0.1".parse().unwrap(),
        "::1".parse().unwrap(),
    ]
}

impl Default for ProxyConfig {
    fn default() -> Self {
        let mut users = HashMap::new();
        users.insert("default".to_string(), "00000000000000000000000000000000".to_string());
        
        Self {
            port: default_port(),
            users,
            ad_tag: None,
            modes: ProxyModes::default(),
            tls_domain: default_tls_domain(),
            mask: true,
            mask_host: None,
            mask_port: default_mask_port(),
            prefer_ipv6: false,
            fast_mode: true,
            use_middle_proxy: false,
            user_max_tcp_conns: HashMap::new(),
            user_expirations: HashMap::new(),
            user_data_quota: HashMap::new(),
            replay_check_len: default_replay_check_len(),
            ignore_time_skew: false,
            client_handshake_timeout: default_handshake_timeout(),
            tg_connect_timeout: default_connect_timeout(),
            client_keepalive: default_keepalive(),
            client_ack_timeout: default_ack_timeout(),
            listen_addr_ipv4: default_listen_addr(),
            listen_addr_ipv6: Some("::".to_string()),
            listen_unix_sock: None,
            metrics_port: None,
            metrics_whitelist: default_metrics_whitelist(),
            fake_cert_len: default_fake_cert_len(),
        }
    }
}

impl ProxyConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ProxyError::Config(e.to_string()))?;
        
        let mut config: ProxyConfig = toml::from_str(&content)
            .map_err(|e| ProxyError::Config(e.to_string()))?;
        
        // Validate secrets
        for (user, secret) in &config.users {
            if !secret.chars().all(|c| c.is_ascii_hexdigit()) || secret.len() != 32 {
                return Err(ProxyError::InvalidSecret {
                    user: user.clone(),
                    reason: "Must be 32 hex characters".to_string(),
                });
            }
        }
        
        // Default mask_host
        if config.mask_host.is_none() {
            config.mask_host = Some(config.tls_domain.clone());
        }
        
        // Random fake_cert_len
        use rand::Rng;
        config.fake_cert_len = rand::thread_rng().gen_range(1024..4096);
        
        Ok(config)
    }
    
    pub fn validate(&self) -> Result<()> {
        if self.users.is_empty() {
            return Err(ProxyError::Config("No users configured".to_string()));
        }
        
        if !self.modes.classic && !self.modes.secure && !self.modes.tls {
            return Err(ProxyError::Config("No modes enabled".to_string()));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = ProxyConfig::default();
        assert_eq!(config.port, 443);
        assert!(config.modes.tls);
        assert_eq!(config.client_keepalive, 600);
        assert_eq!(config.client_ack_timeout, 300);
    }
    
    #[test]
    fn test_config_validate() {
        let mut config = ProxyConfig::default();
        assert!(config.validate().is_ok());
        
        config.users.clear();
        assert!(config.validate().is_err());
    }
}