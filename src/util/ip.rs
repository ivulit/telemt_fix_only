//! IP Addr Detect

use std::net::IpAddr;
use std::time::Duration;
use tracing::{debug, warn};

/// Detected IP addresses
#[derive(Debug, Clone, Default)]
pub struct IpInfo {
    pub ipv4: Option<IpAddr>,
    pub ipv6: Option<IpAddr>,
}

impl IpInfo {
    /// Check if any IP is detected
    pub fn has_any(&self) -> bool {
        self.ipv4.is_some() || self.ipv6.is_some()
    }
    
    /// Get preferred IP (IPv6 if available and preferred)
    pub fn preferred(&self, prefer_ipv6: bool) -> Option<IpAddr> {
        if prefer_ipv6 {
            self.ipv6.or(self.ipv4)
        } else {
            self.ipv4.or(self.ipv6)
        }
    }
}

/// URLs for IP detection
const IPV4_URLS: &[&str] = &[
    "http://v4.ident.me/",
    "http://ipv4.icanhazip.com/",
    "http://api.ipify.org/",
];

const IPV6_URLS: &[&str] = &[
    "http://v6.ident.me/",
    "http://ipv6.icanhazip.com/",
    "http://api6.ipify.org/",
];

/// Detect public IP addresses
pub async fn detect_ip() -> IpInfo {
    let mut info = IpInfo::default();
    
    // Detect IPv4
    for url in IPV4_URLS {
        if let Some(ip) = fetch_ip(url).await {
            if ip.is_ipv4() {
                info.ipv4 = Some(ip);
                debug!(ip = %ip, "Detected IPv4 address");
                break;
            }
        }
    }
    
    // Detect IPv6
    for url in IPV6_URLS {
        if let Some(ip) = fetch_ip(url).await {
            if ip.is_ipv6() {
                info.ipv6 = Some(ip);
                debug!(ip = %ip, "Detected IPv6 address");
                break;
            }
        }
    }
    
    if !info.has_any() {
        warn!("Failed to detect public IP address");
    }
    
    info
}

/// Fetch IP from URL
async fn fetch_ip(url: &str) -> Option<IpAddr> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;
    
    let response = client.get(url).send().await.ok()?;
    let text = response.text().await.ok()?;
    
    text.trim().parse().ok()
}

/// Synchronous IP detection (for startup)
pub fn detect_ip_sync() -> IpInfo {
    tokio::runtime::Handle::current().block_on(detect_ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ip_info() {
        let info = IpInfo::default();
        assert!(!info.has_any());
        
        let info = IpInfo {
            ipv4: Some("1.2.3.4".parse().unwrap()),
            ipv6: None,
        };
        assert!(info.has_any());
        assert_eq!(info.preferred(false), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(info.preferred(true), Some("1.2.3.4".parse().unwrap()));
        
        let info = IpInfo {
            ipv4: Some("1.2.3.4".parse().unwrap()),
            ipv6: Some("::1".parse().unwrap()),
        };
        assert_eq!(info.preferred(false), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(info.preferred(true), Some("::1".parse().unwrap()));
    }
}