// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial

use super::*;

/// The pinned certificate service emits `Nitro.generate(Some(hash), None)`.
/// Bootproof's shared verifier requires a nonce of at least 12 bytes. Until
/// upstream supplies a compatible verification API, do not request derivation
/// or submit unverified certificates to Keymaker.
pub(super) async fn derive(
    _client: &reqwest::Client,
    _org_id: Uuid,
    _count: std::num::NonZeroU8,
) -> Result<([u8; 16], Vec<String>), OrgQuorumError> {
    Err(OrgQuorumError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "WebAuthn quorum creation is blocked: the certificate service emits nonce-less proofs, but the shared verifier requires a nonce; upstream certificate proof verification is required",
    ))
}
