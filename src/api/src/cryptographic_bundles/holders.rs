// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
//! Display-only current registration matches; never used for share authorization.
use super::QuorumBundle;
use dterror::{BoxError, CtxError, Location, ResultExt};
use sequoia_openpgp::{Cert, parse::Parse};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;
use webauthn_rs::prelude::SecurityKey;

#[derive(Debug, Serialize)]
pub struct HolderMetadata {
    custody: &'static str,
    fingerprint: Option<String>,
    username: Option<String>,
}

type Owners = HashMap<Uuid, String>;
#[derive(Default)]
struct Registrations {
    pgp: HashMap<String, Owners>,
    credentials: HashMap<String, Owners>,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("unable to load {kind} quorum holder registrations [{location:?}]")]
struct LoadError {
    kind: &'static str,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

fn fingerprint(cert: &str) -> Option<String> {
    Cert::from_bytes(cert.as_bytes())
        .ok()
        .map(|c| c.fingerprint().to_string())
}

fn credential_identity(bytes: &[u8]) -> Option<String> {
    // Validate the complete library type, then compare only immutable key identity.
    let key: SecurityKey = serde_json::from_slice(bytes).ok()?;
    if key.cred_id().is_empty() {
        return None;
    }
    let value = serde_json::to_value(key).ok()?;
    serde_json::to_string(&(
        value.get("cred")?.get("cred_id")?,
        value.get("cred")?.get("cred")?,
    ))
    .ok()
}

fn unique_owner(owners: &Owners) -> Option<(&Uuid, &String)> {
    (owners.len() == 1).then(|| owners.iter().next()).flatten()
}

impl Registrations {
    async fn load(pool: &PgPool, org: Uuid) -> Result<Self, LoadError> {
        let mut index = Self::default();
        let pgp: Vec<(Uuid, String, String)> = sqlx::query_as(
            "SELECT u.id, u.username, p.public_key FROM organization_members om
             JOIN users u ON u.id = om.user_id JOIN pgp_keys p ON p.user_id = u.id
             WHERE om.organization_id = $1 AND u.is_active = true AND p.removed_at IS NULL",
        )
        .bind(org)
        .fetch_all(pool)
        .await
        .with_context(LoadErrorCtx::new("PGP"))?;
        for (id, name, cert) in pgp {
            if let Some(fp) = fingerprint(&cert) {
                index.pgp.entry(fp).or_default().insert(id, name);
            }
        }
        let credentials: Vec<(Uuid, String, Vec<u8>)> = sqlx::query_as(
            "SELECT u.id, u.username, f.public_key FROM organization_members om
             JOIN users u ON u.id = om.user_id JOIN fido2_credentials f ON f.user_id = u.id
             WHERE om.organization_id = $1 AND u.is_active = true",
        )
        .bind(org)
        .fetch_all(pool)
        .await
        .with_context(LoadErrorCtx::new("WebAuthn"))?;
        for (id, name, bytes) in credentials {
            if let Some(identity) = credential_identity(&bytes) {
                index
                    .credentials
                    .entry(identity)
                    .or_default()
                    .insert(id, name);
            }
        }
        Ok(index)
    }

    fn credential_owner(&self, credentials: &Value) -> Option<String> {
        let credentials = credentials.as_array()?;
        if credentials.is_empty() {
            return None;
        }
        let mut owner = None;
        for credential in credentials {
            let identity = credential_identity(credential.as_str()?.as_bytes())?;
            let matched = unique_owner(self.credentials.get(&identity)?)?;
            if owner.is_some_and(|previous| previous != matched) {
                return None;
            }
            owner = Some(matched);
        }
        owner.map(|(_, name)| name.clone())
    }

    fn holder(&self, holder: &Value) -> HolderMetadata {
        let (custody, key) = if holder.as_object().is_some_and(|h| h.len() == 1) {
            if let Some(key) = holder.get("OpenPGP") {
                ("pgp", Some(key))
            } else if let Some(key) = holder.get("WebAuthn") {
                ("caution_backed", Some(key))
            } else {
                ("unknown", None)
            }
        } else {
            ("unknown", None)
        };
        let fp = key
            .and_then(|k| k.get("cert")?.as_str())
            .and_then(fingerprint);
        let username = match custody {
            "pgp" => fp
                .as_ref()
                .and_then(|fp| unique_owner(self.pgp.get(fp)?).map(|(_, name)| name.clone())),
            "caution_backed" => key
                .and_then(|key| key.get("credential"))
                .and_then(|credentials| self.credential_owner(credentials)),
            _ => None,
        };
        HolderMetadata {
            custody,
            fingerprint: fp,
            username,
        }
    }
}

fn keyring(bundle: &QuorumBundle) -> Option<&Vec<Value>> {
    let payload = bundle.data.get("data").unwrap_or(&bundle.data);
    payload.get("keyring")?.as_array()
}

pub(super) async fn enrich(pool: &PgPool, org: Uuid, bundles: &mut [QuorumBundle]) {
    if !bundles.iter().any(|b| keyring(b).is_some()) {
        return;
    }
    let registrations = match Registrations::load(pool, org).await {
        Ok(index) => index,
        Err(error) => {
            tracing::warn!(%error, "quorum downloads remain available without username matches");
            return;
        }
    };
    for bundle in bundles {
        bundle.holders =
            keyring(bundle).map(|keys| keys.iter().map(|key| registrations.holder(key)).collect());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn unavailable_registrations_omit_metadata_without_changing_bundle() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@localhost/unused")
            .unwrap();
        pool.close().await;
        let org = Uuid::new_v4();
        let data = json!({"keyring": [{"OpenPGP": {"cert": "invalid"}}]});
        let mut bundles = [QuorumBundle {
            id: Uuid::new_v4(),
            organization_id: org,
            data: data.clone(),
            name: None,
            labels: json!({}),
            created_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            holders: None,
        }];
        enrich(&pool, org, &mut bundles).await;
        let response = serde_json::to_value(&bundles[0]).unwrap();
        assert!(response.get("holders").is_none());
        assert_eq!(response["data"], data);
    }

    #[test]
    fn credential_identity_ignores_counters_but_binds_id_and_key() {
        let bytes = include_bytes!("../org_quorum/test-credential.json");
        let original = credential_identity(bytes).unwrap();
        let mut value: Value = serde_json::from_slice(bytes).unwrap();
        value["cred"]["counter"] = json!(1234);
        assert_eq!(
            credential_identity(&serde_json::to_vec(&value).unwrap()).unwrap(),
            original
        );
        value["cred"]["cred_id"] = json!("AQ");
        assert_ne!(
            credential_identity(&serde_json::to_vec(&value).unwrap()).unwrap(),
            original
        );
        value = serde_json::from_slice(bytes).unwrap();
        value["cred"]["cred"]["key"]["EC_EC2"]["x"] =
            value["cred"]["cred"]["key"]["EC_EC2"]["y"].clone();
        assert_ne!(
            credential_identity(&serde_json::to_vec(&value).unwrap()),
            Some(original)
        );
        assert!(credential_identity(b"{}").is_none());
    }

    #[test]
    fn every_binding_must_have_one_same_owner() {
        let credential = include_str!("../org_quorum/test-credential.json");
        let mut other: Value = serde_json::from_str(credential).unwrap();
        other["cred"]["cred_id"] = json!("AQ");
        let other = serde_json::to_string(&other).unwrap();
        let alice = Uuid::new_v4();
        let bob = Uuid::new_v4();
        let mut index = Registrations::default();
        let first = credential_identity(credential.as_bytes()).unwrap();
        let second = credential_identity(other.as_bytes()).unwrap();
        index
            .credentials
            .insert(first.clone(), HashMap::from([(alice, "alice".into())]));
        let bindings = json!([credential, other]);
        assert!(index.credential_owner(&bindings).is_none());
        index
            .credentials
            .insert(second.clone(), HashMap::from([(alice, "alice".into())]));
        assert_eq!(index.credential_owner(&bindings).as_deref(), Some("alice"));
        index
            .credentials
            .get_mut(&second)
            .unwrap()
            .insert(bob, "bob".into());
        assert!(index.credential_owner(&bindings).is_none());
        index.credentials.get_mut(&second).unwrap().remove(&alice);
        assert!(index.credential_owner(&bindings).is_none());
        assert!(index.credential_owner(&json!([])).is_none());
        assert!(
            index
                .credential_owner(&json!([credential, "malformed"]))
                .is_none()
        );
    }

    #[test]
    fn passkey_display_identity_does_not_depend_on_certificate_parsing() {
        let credential = include_str!("../org_quorum/test-credential.json");
        let mut index = Registrations::default();
        index.credentials.insert(
            credential_identity(credential.as_bytes()).unwrap(),
            HashMap::from([(Uuid::new_v4(), "alice".into())]),
        );
        let holder = index.holder(&json!({"WebAuthn": {
            "cert": "truncated certificate",
            "credential": [credential]
        }}));
        assert_eq!(holder.username.as_deref(), Some("alice"));
        assert!(holder.fingerprint.is_none());
    }

    #[test]
    fn invalid_holders_do_not_guess_identity() {
        let index = Registrations::default();
        for value in [
            json!(null),
            json!({"Other": {}}),
            json!({"OpenPGP": {"cert": "invalid"}}),
            json!({"OpenPGP": {}, "WebAuthn": {}}),
        ] {
            let holder = index.holder(&value);
            assert!(holder.username.is_none());
            assert!(holder.fingerprint.is_none());
        }
    }
}
