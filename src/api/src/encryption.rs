// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;

const NONCE_SIZE: usize = 12;

pub struct Encryptor {
    cipher: Aes256Gcm,
}

impl Encryptor {
    pub fn from_env() -> Result<Self, String> {
        let key_b64 = std::env::var("CAUTION_ENCRYPTION_KEY")
            .map_err(|_| "CAUTION_ENCRYPTION_KEY environment variable not set")?;

        let key_bytes = general_purpose::STANDARD
            .decode(&key_b64)
            .map_err(|e| format!("Invalid base64 in CAUTION_ENCRYPTION_KEY: {}", e))?;

        if key_bytes.len() != 32 {
            return Err(format!(
                "CAUTION_ENCRYPTION_KEY must be 32 bytes (256 bits), got {} bytes",
                key_bytes.len()
            ));
        }

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;

        Ok(Self { cipher })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted.len() < NONCE_SIZE {
            return Err("Encrypted data too short".to_string());
        }

        let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))
    }

    pub fn encrypt_json<T: serde::Serialize>(&self, value: &T) -> Result<Vec<u8>, String> {
        let json = serde_json::to_vec(value)
            .map_err(|e| format!("JSON serialization failed: {}", e))?;
        self.encrypt(&json)
    }

    pub fn decrypt_json<T: serde::de::DeserializeOwned>(&self, encrypted: &[u8]) -> Result<T, String> {
        let plaintext = self.decrypt(encrypted)?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| format!("JSON deserialization failed: {}", e))
    }
}

#[allow(dead_code)]
pub fn generate_encryption_key() -> String {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    general_purpose::STANDARD.encode(key)
}
