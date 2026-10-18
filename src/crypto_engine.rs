use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
    Aes256Gcm, Nonce,
};
use anyhow::{bail, Result};

const MAGIC: &[u8; 8] = b"AEGIS001";
const NONCE_LEN: usize = 12;

pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        bail!("AES-256-GCM requires a 32-byte key.");
    }

    let cipher = Aes256Gcm::new_from_slice(key)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("Encryption failed."))?;

    let mut output = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

#[allow(dead_code)]
pub fn decrypt(envelope: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        bail!("AES-256-GCM requires a 32-byte key.");
    }
    if envelope.len() < MAGIC.len() + NONCE_LEN + 16 {
        bail!("Encrypted file is too short.");
    }
    if &envelope[..MAGIC.len()] != MAGIC {
        bail!("Invalid AegisForge file header.");
    }

    let nonce_start = MAGIC.len();
    let nonce_end = nonce_start + NONCE_LEN;
    let nonce = Nonce::from_slice(&envelope[nonce_start..nonce_end]);
    let cipher = Aes256Gcm::new_from_slice(key)?;
    cipher
        .decrypt(nonce, &envelope[nonce_end..])
        .map_err(|_| anyhow::anyhow!("Decryption failed: wrong key or file integrity check failed."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trip() {
        let key = [7u8; 32];
        let plaintext = b"AegisForge test payload";
        let encrypted = encrypt(plaintext, &key).unwrap();
        assert_eq!(&encrypted[..8], MAGIC);
        assert_eq!(decrypt(&encrypted, &key).unwrap(), plaintext);
    }

    #[test]
    fn rejects_wrong_key() {
        let encrypted = encrypt(b"payload", &[1u8; 32]).unwrap();
        assert!(decrypt(&encrypted, &[2u8; 32]).is_err());
    }

    #[test]
    fn rejects_invalid_header() {
        assert!(decrypt(b"NOTAEGIS", &[1u8; 32]).is_err());
    }
}
