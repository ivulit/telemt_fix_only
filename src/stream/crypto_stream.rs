//! Encrypted stream wrappers using AES-CTR

use bytes::{Bytes, BytesMut, BufMut};
use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, ReadBuf};
use crate::crypto::AesCtr;
use parking_lot::Mutex;

/// Reader that decrypts data using AES-CTR
pub struct CryptoReader<R> {
    upstream: R,
    decryptor: AesCtr,
    buffer: BytesMut,
}

impl<R> CryptoReader<R> {
    /// Create new crypto reader
    pub fn new(upstream: R, decryptor: AesCtr) -> Self {
        Self {
            upstream,
            decryptor,
            buffer: BytesMut::with_capacity(8192),
        }
    }
    
    /// Get reference to upstream
    pub fn get_ref(&self) -> &R {
        &self.upstream
    }
    
    /// Get mutable reference to upstream
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.upstream
    }
    
    /// Consume and return upstream
    pub fn into_inner(self) -> R {
        self.upstream
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CryptoReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();
        
        if !this.buffer.is_empty() {
            let to_copy = this.buffer.len().min(buf.remaining());
            buf.put_slice(&this.buffer.split_to(to_copy));
            return Poll::Ready(Ok(()));
        }
        
        // Zero-copy Reader
        let before = buf.filled().len();
        
        match Pin::new(&mut this.upstream).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let after = buf.filled().len();
                let bytes_read = after - before;
                
                if bytes_read > 0 {
                    // Decrypt in-place
                    let filled = buf.filled_mut();
                    this.decryptor.apply(&mut filled[before..after]);
                }
                
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<R: AsyncRead + Unpin> CryptoReader<R> {
    /// Read and decrypt exactly n bytes with Async
    pub async fn read_exact_decrypt(&mut self, n: usize) -> Result<Bytes> {
        let mut result = BytesMut::with_capacity(n);
        
        if !self.buffer.is_empty() {
            let to_take = self.buffer.len().min(n);
            result.extend_from_slice(&self.buffer.split_to(to_take));
        }
        
        // Reread
        while result.len() < n {
            let mut temp = vec![0u8; n - result.len()];
            let read = self.upstream.read(&mut temp).await?;
            
            if read == 0 {
                return Err(Error::new(ErrorKind::UnexpectedEof, "Connection closed"));
            }
            
            // Decrypt
            self.decryptor.apply(&mut temp[..read]);
            result.extend_from_slice(&temp[..read]);
        }
        
        Ok(result.freeze())
    }
}

/// Writer that encrypts data using AES-CTR
pub struct CryptoWriter<W> {
    upstream: W,
    encryptor: AesCtr,
    pending: BytesMut,
}

impl<W> CryptoWriter<W> {
    pub fn new(upstream: W, encryptor: AesCtr) -> Self {
        Self {
            upstream,
            encryptor,
            pending: BytesMut::with_capacity(8192),
        }
    }
    
    pub fn get_ref(&self) -> &W {
        &self.upstream
    }
    
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.upstream
    }
    
    pub fn into_inner(self) -> W {
        self.upstream
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CryptoWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let this = self.get_mut();
        
        if !this.pending.is_empty() {
            match Pin::new(&mut this.upstream).poll_write(cx, &this.pending) {
                Poll::Ready(Ok(written)) => {
                    let _ = this.pending.split_to(written);
                    
                    if !this.pending.is_empty() {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        
        // Pending Null
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        
        // Encrypt
        let mut encrypted = buf.to_vec();
        this.encryptor.apply(&mut encrypted);
        
        // Write Try
        match Pin::new(&mut this.upstream).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(written)) => {
                if written < encrypted.len() {
                    // Partial write — сохраняем остаток в pending
                    this.pending.extend_from_slice(&encrypted[written..]);
                }
               Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                this.pending.extend_from_slice(&encrypted);
                Poll::Ready(Ok(buf.len()))
            }
        }
    }
    
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        
        while !this.pending.is_empty() {
            match Pin::new(&mut this.upstream).poll_write(cx, &this.pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::WriteZero,
                        "Failed to write pending data during flush",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    let _ = this.pending.split_to(written);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        
        Pin::new(&mut this.upstream).poll_flush(cx)
    }
    
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        
        while !this.pending.is_empty() {
            match Pin::new(&mut this.upstream).poll_write(cx, &this.pending) {
                Poll::Ready(Ok(0)) => {
                    break;
                }
                Poll::Ready(Ok(written)) => {
                    let _ = this.pending.split_to(written);
                }
                Poll::Ready(Err(_)) => {
                    break;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        
        Pin::new(&mut this.upstream).poll_shutdown(cx)
    }
}

/// Passthrough stream for fast mode - no encryption/decryption
pub struct PassthroughStream<S> {
    inner: S,
}

impl<S> PassthroughStream<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
    
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PassthroughStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PassthroughStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker, RawWaker, RawWakerVTable};
    use tokio::io::duplex;
    
    /// Mock writer
    struct PartialWriter {
        chunk_size: usize,
        data: Vec<u8>,
        write_count: usize,
    }
    
    impl PartialWriter {
        fn new(chunk_size: usize) -> Self {
            Self {
                chunk_size,
                data: Vec::new(),
                write_count: 0,
            }
        }
    }
    
    impl AsyncWrite for PartialWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize>> {
            self.write_count += 1;
            let to_write = buf.len().min(self.chunk_size);
            self.data.extend_from_slice(&buf[..to_write]);
            Poll::Ready(Ok(to_write))
        }
        
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }
        
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    
    fn noop_waker() -> Waker {
        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(std::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }
    
    #[test]
    fn test_crypto_writer_partial_write_correctness() {
        let key = [0x42u8; 32];
        let iv = 12345u128;
        
        // 10-byte Writer
        let mock_writer = PartialWriter::new(10);
        let encryptor = AesCtr::new(&key, iv);
        let mut crypto_writer = CryptoWriter::new(mock_writer, encryptor);
        
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        
        // 25 byte
        let original = b"Hello, this is test data!";
        
        // First Write
        let result = Pin::new(&mut crypto_writer).poll_write(&mut cx, original);
        assert!(matches!(result, Poll::Ready(Ok(25))));
        
        // Flush before continue Pending
        loop {
            match Pin::new(&mut crypto_writer).poll_flush(&mut cx) {
                Poll::Ready(Ok(())) => break,
                Poll::Ready(Err(e)) => panic!("Flush error: {}", e),
                Poll::Pending => continue,
            }
        }
        
        // Write Check
        let encrypted = &crypto_writer.upstream.data;
        assert_eq!(encrypted.len(), 25);
        
        // Decrypt + Verify
        let mut decryptor = AesCtr::new(&key, iv);
        let mut decrypted = encrypted.clone();
        decryptor.apply(&mut decrypted);
        
        assert_eq!(&decrypted, original);
    }
    
    #[test]
    fn test_crypto_writer_multiple_partial_writes() {
        let key = [0xAB; 32];
        let iv = 9999u128;

        let mock_writer = PartialWriter::new(3);
        let encryptor = AesCtr::new(&key, iv);
        let mut crypto_writer = CryptoWriter::new(mock_writer, encryptor);
        
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        
        let data1 = b"First";
        let data2 = b"Second";
        let data3 = b"Third";
        
        Pin::new(&mut crypto_writer).poll_write(&mut cx, data1).unwrap();
        // Flush
        while Pin::new(&mut crypto_writer).poll_flush(&mut cx).is_pending() {}
        
        Pin::new(&mut crypto_writer).poll_write(&mut cx, data2).unwrap();
        while Pin::new(&mut crypto_writer).poll_flush(&mut cx).is_pending() {}
        
        Pin::new(&mut crypto_writer).poll_write(&mut cx, data3).unwrap();
        while Pin::new(&mut crypto_writer).poll_flush(&mut cx).is_pending() {}
        
        // Assemble
        let mut expected = Vec::new();
        expected.extend_from_slice(data1);
        expected.extend_from_slice(data2);
        expected.extend_from_slice(data3);
        
        // Decrypt
        let mut decryptor = AesCtr::new(&key, iv);
        let mut decrypted = crypto_writer.upstream.data.clone();
        decryptor.apply(&mut decrypted);
        
        assert_eq!(decrypted, expected);
    }
    
    #[tokio::test]
    async fn test_crypto_stream_roundtrip() {
        let key = [0u8; 32];
        let iv = 12345u128;
        
        let (client, server) = duplex(4096);
        
        let encryptor = AesCtr::new(&key, iv);
        let decryptor = AesCtr::new(&key, iv);
        
        let mut writer = CryptoWriter::new(client, encryptor);
        let mut reader = CryptoReader::new(server, decryptor);
        
        // Write
        let original = b"Hello, encrypted world!";
        writer.write_all(original).await.unwrap();
        writer.flush().await.unwrap();
        
        // Read
        let mut buf = vec![0u8; original.len()];
        reader.read_exact(&mut buf).await.unwrap();
        
        assert_eq!(&buf, original);
    }
    
    #[tokio::test]
    async fn test_crypto_stream_large_data() {
        let key = [0x55u8; 32];
        let iv = 777u128;
        
        let (client, server) = duplex(1024);
        
        let encryptor = AesCtr::new(&key, iv);
        let decryptor = AesCtr::new(&key, iv);
        
        let mut writer = CryptoWriter::new(client, encryptor);
        let mut reader = CryptoReader::new(server, decryptor);
        
        // Hugeload
        let original: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        
        // Write
        let write_data = original.clone();
        let write_handle = tokio::spawn(async move {
            writer.write_all(&write_data).await.unwrap();
            writer.flush().await.unwrap();
            writer.shutdown().await.unwrap();
        });
        
        // Read
        let mut received = Vec::new();
        let mut buf = vec![0u8; 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(e) => panic!("Read error: {}", e),
            }
        }
        
        write_handle.await.unwrap();
        
        assert_eq!(received, original);
    }
}