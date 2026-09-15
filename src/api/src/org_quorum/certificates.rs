// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial

use super::*;

/// Bootproof supports the service's nonce-less historical proofs, but certificate
/// proof verification and Caution CA/context checks are not yet integrated here.
/// Do not request derivation or submit unverified certificates to Keymaker.
pub(super) async fn derive(
    _client: &reqwest::Client,
    _org_id: Uuid,
    _count: std::num::NonZeroU8,
) -> Result<([u8; 16], Vec<String>), OrgQuorumError> {
    Err(OrgQuorumError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "WebAuthn quorum creation is blocked: certificate-service proof verification and Caution CA/context checks are not integrated",
    ))
}
