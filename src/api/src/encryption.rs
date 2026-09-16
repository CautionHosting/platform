// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose};
use dterror::{BoxError, CtxError, Location, ResultExt};
use rand::RngCore;

const NONCE_SIZE: usize = 12;

pub struct Encryptor {
    cipher: Aes256Gcm,
}

/// Failure modes for [`Encryptor::from_env`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum EncryptorFromEnvError {
    #[error("CAUTION_ENCRYPTION_KEY environment variable not set [{location}]")]
    MissingKey { location: Location },

    #[error("invalid base64 in CAUTION_ENCRYPTION_KEY [{location}]")]
    InvalidBase64 {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("CAUTION_ENCRYPTION_KEY must be 32 bytes (256 bits), got {got} bytes [{location}]")]
    WrongLength { got: usize, location: Location },

    #[error("failed to create cipher [{location}]")]
    Cipher {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Encryptor::encrypt`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum EncryptError {
    #[error("encryption failed [{location}]")]
    Cipher {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Encryptor::decrypt`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum DecryptError {
    #[error("encrypted data too short [{location}]")]
    TooShort { location: Location },

    #[error("decryption failed [{location}]")]
    Cipher {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Encryptor::encrypt_json`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum EncryptJsonError {
    #[error("JSON serialization failed [{location}]")]
    Serialize {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("encryption failed [{location}]")]
    Encrypt {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`Encryptor::decrypt_json`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum DecryptJsonError {
    #[error("decryption failed [{location}]")]
    Decrypt {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("JSON deserialization failed [{location}]")]
    Deserialize {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl Encryptor {
    pub fn from_env() -> Result<Self, EncryptorFromEnvError> {
        use EncryptorFromEnvErrorCtx as Ctx;

        let key_b64 = std::env::var("CAUTION_ENCRYPTION_KEY").map_err(|_| {
            EncryptorFromEnvError::MissingKey {
                location: std::panic::Location::caller(),
            }
        })?;

        let key_bytes = general_purpose::STANDARD
            .decode(&key_b64)
            .with_context(Ctx::invalid_base64())?;

        if key_bytes.len() != 32 {
            return Err(EncryptorFromEnvError::WrongLength {
                got: key_bytes.len(),
                location: std::panic::Location::caller(),
            });
        }

        let cipher = Aes256Gcm::new_from_slice(&key_bytes).with_context(Ctx::cipher())?;

        Ok(Self { cipher })
    }

    #[tracing::instrument(skip_all, err)]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        use EncryptErrorCtx as Ctx;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| std::io::Error::other(e.to_string()))
            .with_context(Ctx::cipher())?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    #[tracing::instrument(skip_all, err)]
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, DecryptError> {
        use DecryptErrorCtx as Ctx;

        if encrypted.len() < NONCE_SIZE {
            return Err(DecryptError::TooShort {
                location: std::panic::Location::caller(),
            });
        }

        let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| std::io::Error::other(e.to_string()))
            .with_context(Ctx::cipher())
    }

    #[tracing::instrument(skip_all, err)]
    pub fn encrypt_json<T: serde::Serialize>(
        &self,
        value: &T,
    ) -> Result<Vec<u8>, EncryptJsonError> {
        use EncryptJsonErrorCtx as Ctx;

        let json = serde_json::to_vec(value).with_context(Ctx::serialize())?;
        let encrypted = self.encrypt(&json).with_context(Ctx::encrypt())?;

        Ok(encrypted)
    }

    #[tracing::instrument(skip_all, err)]
    pub fn decrypt_json<T: serde::de::DeserializeOwned>(
        &self,
        encrypted: &[u8],
    ) -> Result<T, DecryptJsonError> {
        use DecryptJsonErrorCtx as Ctx;

        let plaintext = self.decrypt(encrypted).with_context(Ctx::decrypt())?;
        serde_json::from_slice(&plaintext).with_context(Ctx::deserialize())
    }
}

#[allow(dead_code)]
pub fn generate_encryption_key() -> String {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    general_purpose::STANDARD.encode(key)
}

/// Failure modes for [`Encryptor::from_key`] (test helper).
#[cfg(test)]
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum EncryptorFromKeyError {
    #[error("invalid base64 [{location}]")]
    InvalidBase64 {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("key must be 32 bytes, got {got} [{location}]")]
    WrongLength { got: usize, location: Location },

    #[error("failed to create cipher [{location}]")]
    Cipher {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[cfg(test)]
impl Encryptor {
    fn from_key(key_b64: &str) -> Result<Self, EncryptorFromKeyError> {
        use EncryptorFromKeyErrorCtx as Ctx;

        let key_bytes = general_purpose::STANDARD
            .decode(key_b64)
            .with_context(Ctx::invalid_base64())?;

        if key_bytes.len() != 32 {
            return Err(EncryptorFromKeyError::WrongLength {
                got: key_bytes.len(),
                location: std::panic::Location::caller(),
            });
        }

        let cipher = Aes256Gcm::new_from_slice(&key_bytes).with_context(Ctx::cipher())?;

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
        assert!(matches!(result, Err(DecryptError::TooShort { .. })));
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
        assert!(matches!(
            result,
            Err(EncryptorFromKeyError::InvalidBase64 { .. })
        ));
    }

    #[test]
    fn test_from_key_wrong_length() {
        let short_key = general_purpose::STANDARD.encode([0u8; 16]);
        let result = Encryptor::from_key(&short_key);
        assert!(
            matches!(result, Err(EncryptorFromKeyError::WrongLength { .. })),
            "expected wrong-length error"
        );
    }
}
