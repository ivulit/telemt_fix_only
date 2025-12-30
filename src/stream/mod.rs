//! Stream wrappers for MTProto protocol layers

pub mod traits;
pub mod crypto_stream;
pub mod tls_stream;
pub mod frame_stream;

pub use crypto_stream::{CryptoReader, CryptoWriter, PassthroughStream};
pub use tls_stream::{FakeTlsReader, FakeTlsWriter};
pub use frame_stream::*;