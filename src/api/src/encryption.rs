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

#[cfg(test)]
impl Encryptor {
    fn from_key(key_b64: &str) -> Result<Self, String> {
        let key_bytes = general_purpose::STANDARD
            .decode(key_b64)
            .map_err(|e| format!("Invalid base64: {}", e))?;

        if key_bytes.len() != 32 {
            return Err(format!("Key must be 32 bytes, got {}", key_bytes.len()));
        }

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;

        Ok(Self { cipher })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_encryptor() -> Encryptor {
        let key = generate_encryption_key();
        Encryptor::from_key(&key).unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let enc = test_encryptor();
        let plaintext = b"hello, world!";

        let encrypted = enc.encrypt(plaintext).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let enc = test_encryptor();
        let plaintext = b"";

        let encrypted = enc.encrypt(plaintext).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large() {
        let enc = test_encryptor();
        let plaintext = vec![0xABu8; 100_000];

        let encrypted = enc.encrypt(&plaintext).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypted_contains_nonce() {
        let enc = test_encryptor();
        let plaintext = b"test data";

        let encrypted = enc.encrypt(plaintext).unwrap();

        // Encrypted data should be at least nonce (12 bytes) + ciphertext + tag (16 bytes)
        assert!(encrypted.len() >= NONCE_SIZE + plaintext.len() + 16);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let enc = test_encryptor();
        let plaintext = b"same data";

        let encrypted1 = enc.encrypt(plaintext).unwrap();
        let encrypted2 = enc.encrypt(plaintext).unwrap();

        // Same plaintext should produce different ciphertext due to random nonce
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same plaintext
        assert_eq!(enc.decrypt(&encrypted1).unwrap(), plaintext);
        assert_eq!(enc.decrypt(&encrypted2).unwrap(), plaintext);
    }

    #[test]
    fn test_wrong_key_rejects() {
        let enc1 = test_encryptor();
        let enc2 = test_encryptor();

        let plaintext = b"secret data";
        let encrypted = enc1.encrypt(plaintext).unwrap();

        // Decrypting with a different key should fail
        let result = enc2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let enc = test_encryptor();

        // Less than NONCE_SIZE bytes
        let result = enc.decrypt(&[0u8; 5]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_decrypt_corrupted_data() {
        let enc = test_encryptor();
        let plaintext = b"test";

        let mut encrypted = enc.encrypt(plaintext).unwrap();
        // Corrupt the ciphertext (after the nonce)
        if encrypted.len() > NONCE_SIZE {
            encrypted[NONCE_SIZE] ^= 0xFF;
        }

        let result = enc.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_json() {
        let enc = test_encryptor();

        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestData {
            name: String,
            value: i32,
        }

        let data = TestData {
            name: "test".to_string(),
            value: 42,
        };

        let encrypted = enc.encrypt_json(&data).unwrap();
        let decrypted: TestData = enc.decrypt_json(&encrypted).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypt_json_complex() {
        let enc = test_encryptor();

        let data = serde_json::json!({
            "access_key": "AKIA...",
            "secret_key": "wJalrX...",
            "nested": {"a": [1, 2, 3]}
        });

        let encrypted = enc.encrypt_json(&data).unwrap();
        let decrypted: serde_json::Value = enc.decrypt_json(&encrypted).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_generate_encryption_key_format() {
        let key = generate_encryption_key();
        let decoded = general_purpose::STANDARD.decode(&key).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_generate_encryption_key_unique() {
        let key1 = generate_encryption_key();
        let key2 = generate_encryption_key();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_from_key_invalid_base64() {
        let result = Encryptor::from_key("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_key_wrong_length() {
        let short_key = general_purpose::STANDARD.encode([0u8; 16]);
        let result = Encryptor::from_key(&short_key);
        match result {
            Err(e) => assert!(e.contains("32 bytes"), "Error should mention key size: {}", e),
            Ok(_) => panic!("Expected error for wrong key length"),
        }
    }
}
