//! AES

use aes::Aes256;
use ctr::{Ctr128BE, cipher::{KeyIvInit, StreamCipher}};
use cbc::{Encryptor as CbcEncryptor, Decryptor as CbcDecryptor};
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, block_padding::NoPadding};
use crate::error::{ProxyError, Result};

type Aes256Ctr = Ctr128BE<Aes256>;
type Aes256CbcEnc = CbcEncryptor<Aes256>;
type Aes256CbcDec = CbcDecryptor<Aes256>;

/// AES-256-CTR encryptor/decryptor
pub struct AesCtr {
    cipher: Aes256Ctr,
}

impl AesCtr {
    pub fn new(key: &[u8; 32], iv: u128) -> Self {
        let iv_bytes = iv.to_be_bytes();
        Self {
            cipher: Aes256Ctr::new(key.into(), (&iv_bytes).into()),
        }
    }
    
    pub fn from_key_iv(key: &[u8], iv: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(ProxyError::InvalidKeyLength { expected: 32, got: key.len() });
        }
        if iv.len() != 16 {
            return Err(ProxyError::InvalidKeyLength { expected: 16, got: iv.len() });
        }
        
        let key: [u8; 32] = key.try_into().unwrap();
        let iv = u128::from_be_bytes(iv.try_into().unwrap());
        Ok(Self::new(&key, iv))
    }
    
    /// Encrypt/decrypt data in-place (CTR mode is symmetric)
    pub fn apply(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }
    
    /// Encrypt data, returning new buffer
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = data.to_vec();
        self.apply(&mut output);
        output
    }
    
    /// Decrypt data (for CTR, identical to encrypt)
    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        self.encrypt(data)
    }
}

/// AES-256-CBC Ciphermagic
pub struct AesCbc {
    key: [u8; 32],
    iv: [u8; 16],
}

impl AesCbc {
    pub fn new(key: [u8; 32], iv: [u8; 16]) -> Self {
        Self { key, iv }
    }
    
    pub fn from_slices(key: &[u8], iv: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(ProxyError::InvalidKeyLength { expected: 32, got: key.len() });
        }
        if iv.len() != 16 {
            return Err(ProxyError::InvalidKeyLength { expected: 16, got: iv.len() });
        }
        
        Ok(Self {
            key: key.try_into().unwrap(),
            iv: iv.try_into().unwrap(),
        })
    }
    
    /// Encrypt data using CBC mode
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() % 16 != 0 {
            return Err(ProxyError::Crypto(
                format!("CBC data must be aligned to 16 bytes, got {}", data.len())
            ));
        }
        
        if data.is_empty() {
            return Ok(Vec::new());
        }
        
        let mut buffer = data.to_vec();
        
        let mut encryptor = Aes256CbcEnc::new((&self.key).into(), (&self.iv).into());
        
        for chunk in buffer.chunks_mut(16) {
            encryptor.encrypt_block_mut(chunk.into());
        }
        
        Ok(buffer)
    }
    
    /// Decrypt data using CBC mode
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() % 16 != 0 {
            return Err(ProxyError::Crypto(
                format!("CBC data must be aligned to 16 bytes, got {}", data.len())
            ));
        }
        
        if data.is_empty() {
            return Ok(Vec::new());
        }
        
        let mut buffer = data.to_vec();
        
        let mut decryptor = Aes256CbcDec::new((&self.key).into(), (&self.iv).into());
        
        for chunk in buffer.chunks_mut(16) {
            decryptor.decrypt_block_mut(chunk.into());
        }
        
        Ok(buffer)
    }
    
    /// Encrypt data in-place
    pub fn encrypt_in_place(&self, data: &mut [u8]) -> Result<()> {
        if data.len() % 16 != 0 {
            return Err(ProxyError::Crypto(
                format!("CBC data must be aligned to 16 bytes, got {}", data.len())
            ));
        }
        
        if data.is_empty() {
            return Ok(());
        }
        
        let mut encryptor = Aes256CbcEnc::new((&self.key).into(), (&self.iv).into());
        
        for chunk in data.chunks_mut(16) {
            encryptor.encrypt_block_mut(chunk.into());
        }
        
        Ok(())
    }
    
    /// Decrypt data in-place
    pub fn decrypt_in_place(&self, data: &mut [u8]) -> Result<()> {
        if data.len() % 16 != 0 {
            return Err(ProxyError::Crypto(
                format!("CBC data must be aligned to 16 bytes, got {}", data.len())
            ));
        }
        
        if data.is_empty() {
            return Ok(());
        }
        
        let mut decryptor = Aes256CbcDec::new((&self.key).into(), (&self.iv).into());
        
        for chunk in data.chunks_mut(16) {
            decryptor.decrypt_block_mut(chunk.into());
        }
        
        Ok(())
    }
}

/// Trait for unified encryption interface
pub trait Encryptor: Send + Sync {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8>;
}

/// Trait for unified decryption interface
pub trait Decryptor: Send + Sync {
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8>;
}

impl Encryptor for AesCtr {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        AesCtr::encrypt(self, data)
    }
}

impl Decryptor for AesCtr {
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        AesCtr::decrypt(self, data)
    }
}

/// No-op encryptor for fast mode
pub struct PassthroughEncryptor;

impl Encryptor for PassthroughEncryptor {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

impl Decryptor for PassthroughEncryptor {
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_aes_ctr_roundtrip() {
        let key = [0u8; 32];
        let iv = 12345u128;
        
        let original = b"Hello, MTProto!";
        
        let mut enc = AesCtr::new(&key, iv);
        let encrypted = enc.encrypt(original);
        
        let mut dec = AesCtr::new(&key, iv);
        let decrypted = dec.decrypt(&encrypted);
        
        assert_eq!(original.as_slice(), decrypted.as_slice());
    }
    
    #[test]
    fn test_aes_cbc_roundtrip() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        
        // Must be aligned to 16 bytes
        let original = [0u8; 32];
        
        let cipher = AesCbc::new(key, iv);
        let encrypted = cipher.encrypt(&original).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        
        assert_eq!(original.as_slice(), decrypted.as_slice());
    }
    
    #[test]
    fn test_aes_cbc_chaining_works() {
        let key = [0x42u8; 32];
        let iv = [0x00u8; 16];
		
        let plaintext = [0xAA_u8; 32];
        
        let cipher = AesCbc::new(key, iv);
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        
        // CBC Corrections
        let block1 = &ciphertext[0..16];
        let block2 = &ciphertext[16..32];
        
        assert_ne!(block1, block2, "CBC chaining broken: identical plaintext blocks produced identical ciphertext");
    }
    
    #[test]
    fn test_aes_cbc_known_vector() {        
        let key = [0u8; 32];
        let iv = [0u8; 16];
        
        // 3 Datablocks
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            // Block 2
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            // Block 3 - different
            0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
            0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        ];
        
        let cipher = AesCbc::new(key, iv);
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        
        // Decrypt + Verify
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        
        // Verify Ciphertexts Block 1 != Block 2
        assert_ne!(&ciphertext[0..16], &ciphertext[16..32]);
    }
    
    #[test]
    fn test_aes_cbc_in_place() {
        let key = [0x12u8; 32];
        let iv = [0x34u8; 16];
        
        let original = [0x56u8; 48]; // 3 blocks
        let mut buffer = original.clone();
        
        let cipher = AesCbc::new(key, iv);
        
        cipher.encrypt_in_place(&mut buffer).unwrap();
        assert_ne!(&buffer[..], &original[..]);
        
        cipher.decrypt_in_place(&mut buffer).unwrap();
        assert_eq!(&buffer[..], &original[..]);
    }
    
    #[test]
    fn test_aes_cbc_empty_data() {
        let cipher = AesCbc::new([0u8; 32], [0u8; 16]);
        
        let encrypted = cipher.encrypt(&[]).unwrap();
        assert!(encrypted.is_empty());
        
        let decrypted = cipher.decrypt(&[]).unwrap();
        assert!(decrypted.is_empty());
    }
    
    #[test]
    fn test_aes_cbc_unaligned_error() {
        let cipher = AesCbc::new([0u8; 32], [0u8; 16]);
        
        // 15 bytes
        let result = cipher.encrypt(&[0u8; 15]);
        assert!(result.is_err());
        
        // 17 bytes
        let result = cipher.encrypt(&[0u8; 17]);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_aes_cbc_avalanche_effect() {
        // Cipherplane
        
        let key = [0xAB; 32];
        let iv = [0xCD; 16];
        
        let mut plaintext1 = [0u8; 32];
        let mut plaintext2 = [0u8; 32];
        plaintext2[0] = 0x01; // Один бит отличается
        
        let cipher = AesCbc::new(key, iv);
        
        let ciphertext1 = cipher.encrypt(&plaintext1).unwrap();
        let ciphertext2 = cipher.encrypt(&plaintext2).unwrap();
        
        // First Blocks Diff
        assert_ne!(&ciphertext1[0..16], &ciphertext2[0..16]);
        
        // Second Blocks Diff
        assert_ne!(&ciphertext1[16..32], &ciphertext2[16..32]);
    }
}