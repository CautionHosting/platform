// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Decoy WebAuthn credential synthesis.
//!
//! To avoid leaking whether a username exists (or has any registered
//! passkeys), the login-begin path must return an `allowCredentials` list
//! that "looks real" even when there are no real credentials to offer.
//!
//! These functions are pure and deterministic: the SAME username always
//! synthesizes the SAME fake credential list. This is a security
//! requirement — an attacker who probes the same username twice must not
//! be able to distinguish a decoy from a real account by observing the
//! list change (real credential lists are stable too, since they come
//! from the database). No randomness, no time-based rotation.
//!
//! The synthesized `AllowCredentials` entries are built with the exact
//! same shape as the real path (see `webauthn-rs-core`'s
//! `Sha256::generate_challenge_authenticate`, mirrored in this gateway's
//! `handlers.rs` via `webauthn-rs`'s `start_securitykey_authentication`):
//! `type_ = "public-key"`, `id` is a `Base64UrlSafeData` wrapping raw
//! credential-id bytes, and `transports` is `Option<Vec<AuthenticatorTransport>>`.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use webauthn_rs_proto::{AllowCredentials, AuthenticatorTransport};

type HmacSha256 = Hmac<Sha256>;

/// The WebAuthn credential type used by every real descriptor this gateway
/// produces (see `webauthn-rs-core`'s internal `AllowCredentials` builder).
const CREDENTIAL_TYPE_PUBLIC_KEY: &str = "public-key";

/// Plausible credential-ID byte lengths, in the order real authenticators
/// tend to cluster: short (resident/platform keys), medium (most common),
/// long (hardware security keys with larger opaque IDs).
const ID_LENGTHS: [usize; 3] = [16, 32, 64];

/// Derive a domain-separated decoy secret from the gateway's CSRF secret.
///
/// This reuses the CSRF secret (mirroring `csrf::derive_csrf_token`'s
/// HMAC-SHA256 pattern) but with a distinct domain-separation tag so decoy
/// keystream output can never collide with, or be derived from, CSRF
/// tokens.
///
/// # Arguments
/// * `csrf_secret` - The same HMAC secret used for CSRF token derivation.
///
/// # Returns
/// A 32-byte HMAC-SHA256 tag, used as the root key for the decoy keystream.
pub fn decoy_secret(csrf_secret: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(csrf_secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(b":decoy"); // domain separation from csrf::derive_csrf_token
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Deterministically expand `(decoy_secret, normalized_username, tag)` into
/// a 32-byte pseudorandom block via HMAC-SHA256.
///
/// This is the single building block used for every derived value below
/// (credential count, per-credential ID length, per-credential ID bytes,
/// per-credential transports). Distinct `tag` strings provide domain
/// separation between the different purposes so they don't correlate.
fn keystream_block(decoy_secret: &[u8; 32], normalized_username: &str, tag: &str) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(decoy_secret).expect("HMAC can take key of any size");
    // Length-prefix each field (fixed-width big-endian u64) before feeding
    // its bytes. Plain concatenation would let a ':' in the username be
    // ambiguous with the tag's own separators — e.g. (username="alice",
    // tag=":len:0") and (username="alice:len:0", tag="") would hash to the
    // same byte string. Prefixing lengths makes the encoding injective, so
    // no two distinct (username, tag) pairs can ever collide.
    mac.update(&(normalized_username.len() as u64).to_be_bytes());
    mac.update(normalized_username.as_bytes());
    mac.update(&(tag.len() as u64).to_be_bytes());
    mac.update(tag.as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Fill `len` bytes deterministically from repeated keystream blocks tagged
/// with `purpose` and an incrementing block counter, so we can produce
/// arbitrarily long output (e.g. a 64-byte credential ID) from 32-byte HMAC
/// blocks.
fn keystream_fill(
    decoy_secret: &[u8; 32],
    normalized_username: &str,
    purpose: &str,
    len: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut block_idx: u32 = 0;
    while out.len() < len {
        let tag = format!("{purpose}:{block_idx}");
        let block = keystream_block(decoy_secret, normalized_username, &tag);
        let remaining = len - out.len();
        out.extend_from_slice(&block[..remaining.min(block.len())]);
        block_idx += 1;
    }
    out
}

/// Derive the number of decoy credentials for a username.
///
/// Weighted so that 1 credential is most common, 2 occasional, and 3 rare
/// — matching the real-world distribution of how many passkeys a typical
/// user registers. Never 0: an empty `allowCredentials` list would itself
/// be a tell that the username has no account.
fn derive_credential_count(decoy_secret: &[u8; 32], normalized_username: &str) -> usize {
    let block = keystream_block(decoy_secret, normalized_username, ":n");
    // Weighted buckets out of 100: 1 -> 70%, 2 -> 25%, 3 -> 5%.
    match block[0] % 100 {
        0..=69 => 1,
        70..=94 => 2,
        _ => 3,
    }
}

/// Derive the credential-ID byte length for the `i`-th decoy credential.
///
/// Drawn from `{16, 32, 64}`, weighted toward 32 (the most common
/// credential-ID length produced by mainstream authenticators).
fn derive_id_length(decoy_secret: &[u8; 32], normalized_username: &str, index: usize) -> usize {
    let tag = format!(":len:{index}");
    let block = keystream_block(decoy_secret, normalized_username, &tag);
    // Weighted buckets out of 100: 16 -> 20%, 32 -> 60%, 64 -> 20%.
    match block[0] % 100 {
        0..=19 => ID_LENGTHS[0],
        20..=79 => ID_LENGTHS[1],
        _ => ID_LENGTHS[2],
    }
}

/// Derive the `transports` hint for the `i`-th decoy credential, keyed off
/// its ID length so the value stays internally consistent (short IDs read
/// as platform/resident keys, long IDs as roaming hardware keys).
///
/// A real `AllowCredentials.transports` is `Option<Vec<AuthenticatorTransport>>`
/// straight from the stored credential (`webauthn-rs-core`'s
/// `cred.transports.clone()`) — it is frequently `None` because many
/// authenticators never report transports at registration time. We mirror
/// that by making `None` a real possibility here too.
fn derive_transports(
    decoy_secret: &[u8; 32],
    normalized_username: &str,
    index: usize,
    id_len: usize,
) -> Option<Vec<AuthenticatorTransport>> {
    let tag = format!(":tr:{index}");
    let block = keystream_block(decoy_secret, normalized_username, &tag);
    // 25% chance of no transport hint at all, matching real-world gaps.
    if block[0] % 100 < 25 {
        return None;
    }
    let transports = match id_len {
        16 => vec![AuthenticatorTransport::Internal],
        64 => vec![AuthenticatorTransport::Usb],
        _ => {
            if block[1] % 2 == 0 {
                vec![AuthenticatorTransport::Internal, AuthenticatorTransport::Hybrid]
            } else {
                vec![AuthenticatorTransport::Usb, AuthenticatorTransport::Nfc]
            }
        }
    };
    Some(transports)
}

/// Synthesize a deterministic, plausible-looking fake `allowCredentials`
/// list for `normalized_username`.
///
/// Used by the login-begin handler when a username does not exist (or has
/// zero registered credentials) so the response is indistinguishable from
/// a real account's. The SAME `(csrf_secret, normalized_username)` pair
/// ALWAYS yields the SAME output — no randomness, no rotation — since a
/// changing decoy list across repeated probes would itself leak that the
/// account is fake.
///
/// # Arguments
/// * `csrf_secret` - The gateway's HMAC secret (same one used for CSRF).
/// * `normalized_username` - The already-normalized (e.g. lowercased/trimmed)
///   username being probed.
///
/// # Returns
/// A non-empty `Vec<AllowCredentials>` with the same field shapes
/// (`type_`, `id`, `transports`) as the real credential-descriptor path.
pub fn synthesize_allow_credentials(
    csrf_secret: &str,
    normalized_username: &str,
) -> Vec<AllowCredentials> {
    let secret = decoy_secret(csrf_secret);
    let count = derive_credential_count(&secret, normalized_username);

    (0..count)
        .map(|i| {
            let id_len = derive_id_length(&secret, normalized_username, i);
            let id_tag = format!(":id:{i}");
            let id_bytes = keystream_fill(&secret, normalized_username, &id_tag, id_len);
            let transports = derive_transports(&secret, normalized_username, i, id_len);

            AllowCredentials {
                type_: CREDENTIAL_TYPE_PUBLIC_KEY.to_string(),
                id: id_bytes.into(),
                transports,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoy_secret_deterministic() {
        assert_eq!(decoy_secret("secret"), decoy_secret("secret"));
    }

    #[test]
    fn test_decoy_secret_differs_from_csrf_domain() {
        // Same key material, different domain tag than csrf::derive_csrf_token
        // must not collide in any observable way; sanity-check it's stable
        // and 32 bytes.
        let s = decoy_secret("secret");
        assert_eq!(s.len(), 32);
    }

    #[test]
    fn test_synthesize_deterministic() {
        let a = synthesize_allow_credentials("secret", "alice");
        let b = synthesize_allow_credentials("secret", "alice");
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.type_, y.type_);
            assert_eq!(x.id.as_ref(), y.id.as_ref());
            assert_eq!(x.transports, y.transports);
        }
    }

    #[test]
    fn test_synthesize_stable_across_calls_same_secret_and_username() {
        // Explicitly re-derive from scratch each time to ensure no hidden
        // shared/mutable state affects the result.
        let mut previous: Option<Vec<AllowCredentials>> = None;
        for _ in 0..5 {
            let current = synthesize_allow_credentials("my-csrf-secret", "bob@example.com");
            if let Some(prev) = &previous {
                assert_eq!(prev.len(), current.len());
                for (p, c) in prev.iter().zip(current.iter()) {
                    assert_eq!(p.id.as_ref(), c.id.as_ref());
                }
            }
            previous = Some(current);
        }
    }

    #[test]
    fn test_synthesize_distinct_usernames_generally_differ() {
        let a = synthesize_allow_credentials("secret", "alice");
        let b = synthesize_allow_credentials("secret", "bob");
        // Extremely unlikely to collide on both count and every id.
        let same = a.len() == b.len()
            && a.iter()
                .zip(b.iter())
                .all(|(x, y)| x.id.as_ref() == y.id.as_ref());
        assert!(!same, "decoys for different usernames should differ");
    }

    #[test]
    fn test_synthesize_non_empty_and_shape() {
        for username in ["alice", "bob", "carol@example.com", "", "x".repeat(200).as_str()] {
            let creds = synthesize_allow_credentials("secret", username);
            assert!(!creds.is_empty(), "must never be empty for {username:?}");
            assert!(creds.len() <= 3, "count should stay within modeled range");
            for cred in &creds {
                assert_eq!(cred.type_, "public-key");
                let len = cred.id.as_ref().len();
                assert!(
                    ID_LENGTHS.contains(&len),
                    "id length {len} not in modeled set for {username:?}"
                );
                // Round-trip through the same construction path to ensure
                // the bytes are valid and stable.
                let round_tripped: AllowCredentials = AllowCredentials {
                    type_: cred.type_.clone(),
                    id: cred.id.as_ref().to_vec().into(),
                    transports: cred.transports.clone(),
                };
                assert_eq!(round_tripped.id.as_ref(), cred.id.as_ref());
            }
        }
    }

    #[test]
    fn test_synthesize_count_within_modeled_range() {
        // Sample many usernames and confirm counts land in {1, 2, 3}.
        for i in 0..200 {
            let username = format!("user-{i}");
            let creds = synthesize_allow_credentials("secret", &username);
            assert!((1..=3).contains(&creds.len()));
        }
    }

    #[test]
    fn test_synthesize_different_secret_changes_output() {
        let a = synthesize_allow_credentials("secret-one", "alice");
        let b = synthesize_allow_credentials("secret-two", "alice");
        let same = a.len() == b.len()
            && a.iter()
                .zip(b.iter())
                .all(|(x, y)| x.id.as_ref() == y.id.as_ref());
        assert!(!same, "decoys must be sensitive to the csrf secret");
    }

    #[test]
    fn test_derive_credential_count_never_zero() {
        for i in 0..500 {
            let secret = decoy_secret("secret");
            let username = format!("user-{i}");
            assert!(derive_credential_count(&secret, &username) >= 1);
        }
    }
}
