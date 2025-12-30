//! Transport layer: connection pooling, socket utilities, proxy protocol

pub mod pool;
pub mod proxy_protocol;
pub mod socket;

pub use pool::ConnectionPool;
pub use proxy_protocol::{ProxyProtocolInfo, parse_proxy_protocol};
pub use socket::*;