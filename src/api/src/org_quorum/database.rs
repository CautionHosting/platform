// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
//! Opt-in PostgreSQL and HTTP orchestration tests; not Nitro verification.
use super::*;
use crate::cryptographic_bundles as storage;
use serde_json::{Value, json};

async fn organization(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("INSERT INTO organizations(name) VALUES ('quorum test') RETURNING id")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn member(pool: &PgPool, org: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id, username) VALUES ($1, $2)")
        .bind(id)
        .bind(id.to_string())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organization_members(organization_id, user_id) VALUES ($1, $2)")
        .bind(org)
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn register_pgp(pool: &PgPool, user: Uuid, cert: &str) -> Uuid {
    let fingerprint = Cert::from_bytes(cert.as_bytes())
        .unwrap()
        .fingerprint()
        .to_string();
    sqlx::query_scalar(
        "INSERT INTO pgp_keys(user_id, public_key, fingerprint) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(user)
    .bind(cert)
    .bind(fingerprint)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn pgp_request(user: Uuid, key: Uuid) -> GenerateOrgQuorumBundleRequest {
    GenerateOrgQuorumBundleRequest {
        participants: vec![OrgQuorumParticipantSelection {
            user_id: user,
            key_source: OrgQuorumKeySource::ExistingPgp,
            pgp_key_id: Some(key),
        }],
        ..request()
    }
}

fn request_log() -> Vec<Value> {
    std::fs::read_to_string(std::env::var("QUORUM_TEST_REQUEST_LOG").unwrap())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

async fn participant_queries(pool: &PgPool, org: Uuid, other_org: Uuid, alice: Uuid, bob: Uuid) {
    let cert = certificate();
    let key = register_pgp(pool, alice, &cert).await;
    let mut r = pgp_request(alice, key);
    let holders = resolve_holders(pool, org, &r).await.unwrap();
    assert!(matches!(&holders[..], [Holder::Pgp(value)] if value == &cert));
    assert!(resolve_holders(pool, other_org, &r).await.is_err());
    r.participants[0].user_id = bob;
    assert!(
        resolve_holders(pool, org, &r).await.is_err(),
        "wrong-owner key accepted"
    );
    r.participants[0].user_id = Uuid::new_v4();
    assert!(
        resolve_holders(pool, org, &r).await.is_err(),
        "nonmember accepted"
    );
    r.participants[0].user_id = alice;
    sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(alice)
        .execute(pool)
        .await
        .unwrap();
    assert!(resolve_holders(pool, org, &r).await.is_err());
    assert!(
        !list_participants(pool, org)
            .await
            .unwrap()
            .iter()
            .any(|m| m.user_id == alice)
    );
    sqlx::query("UPDATE users SET is_active = true WHERE id = $1")
        .bind(alice)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("UPDATE pgp_keys SET removed_at = now() WHERE id = $1")
        .bind(key)
        .execute(pool)
        .await
        .unwrap();
    assert!(
        resolve_holders(pool, org, &r).await.is_err(),
        "removed key accepted"
    );
    assert!(
        list_participants(pool, org)
            .await
            .unwrap()
            .iter()
            .find(|m| m.user_id == alice)
            .unwrap()
            .pgp_keys
            .is_empty()
    );
    let key = register_pgp(pool, alice, &cert).await;
    r.participants[0].pgp_key_id = Some(key);
    let local = certificate();
    r.pgp_certificates = vec![local.clone()];
    let holders = resolve_holders(pool, org, &r).await.unwrap();
    assert!(matches!(&holders[..], [Holder::Pgp(a), Holder::Pgp(b)] if a == &local && b == &cert));
    r.pgp_certificates = vec![cert.clone()];
    assert!(
        resolve_holders(pool, org, &r).await.is_err(),
        "local/registered duplicate accepted"
    );
    r.pgp_certificates.clear();
    let bob_key = register_pgp(pool, bob, &cert).await;
    r.participants.push(OrgQuorumParticipantSelection {
        user_id: bob,
        key_source: OrgQuorumKeySource::ExistingPgp,
        pgp_key_id: Some(bob_key),
    });
    assert!(
        resolve_holders(pool, org, &r).await.is_err(),
        "same effective key across users accepted"
    );
    let before = request_log().len();
    assert!(
        generate_org_quorum_bundle(pool, org, alice, r)
            .await
            .is_err()
    );
    assert_eq!(
        request_log().len(),
        before,
        "invalid holders reached Keymaker"
    );
}

async fn credentials(pool: &PgPool, org: Uuid, other_org: Uuid, user: Uuid) {
    let mut r = request();
    r.participants[0].user_id = user;
    assert!(
        resolve_holders(pool, org, &r).await.is_err(),
        "missing credentials accepted"
    );
    // Copy of the gateway's throwaway ES256 timing fixture. Distinct IDs, same
    // public key: this tests snapshot serialization/order, not authentication.
    let template: Value = serde_json::from_str(include_str!("test-credential.json")).unwrap();
    let mut expected = Vec::new();
    for (id, encoded) in [(2u8, "Ag"), (1u8, "AQ")] {
        let mut value = template.clone();
        value["cred"]["cred_id"] = json!(encoded);
        let bytes = serde_json::to_vec(&value).unwrap();
        let parsed: SecurityKey = serde_json::from_slice(&bytes).unwrap();
        expected.push(serde_json::to_string(&parsed).unwrap());
        sqlx::query(
            "INSERT INTO fido2_credentials(user_id, credential_id, public_key) VALUES ($1, $2, $3)",
        )
        .bind(user)
        .bind(vec![id])
        .bind(bytes)
        .execute(pool)
        .await
        .unwrap();
    }
    expected.reverse();
    let holders = resolve_holders(pool, org, &r).await.unwrap();
    assert!(matches!(&holders[..], [Holder::WebAuthn(values)] if values == &expected));
    let assembled = assemble_request(&r, [7; 16], holders, vec![certificate()])
        .unwrap()
        .to_latest();
    assert_eq!(assembled.max, 1);
    assert!(
        matches!(&assembled.keyring[..], [Key::WebAuthn {credential, ..}] if credential.len() == 2)
    );
    let members = list_participants(pool, org).await.unwrap();
    let selected = members.iter().find(|m| m.user_id == user).unwrap();
    assert_eq!(selected.webauthn_credentials, 2);
    let serialized = serde_json::to_value(selected).unwrap();
    assert_eq!(serialized.as_object().unwrap().len(), 4);
    assert!(serialized.get("credential").is_none());
    assert!(
        !list_participants(pool, other_org)
            .await
            .unwrap()
            .iter()
            .any(|m| m.user_id == user)
    );
    let before = request_log().len();
    let error = generate_org_quorum_bundle(pool, org, user, r.clone())
        .await
        .unwrap_err();
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        error
            .message
            .contains("required key-service endpoint or trust policy is not configured")
    );
    assert_eq!(
        request_log().len(),
        before,
        "unconfigured derivation reached Keymaker"
    );
    sqlx::query(
        "UPDATE fido2_credentials SET public_key = $1 WHERE user_id = $2 AND credential_id = $3",
    )
    .bind(b"{}".to_vec())
    .bind(user)
    .bind(vec![1u8])
    .execute(pool)
    .await
    .unwrap();
    assert!(
        resolve_holders(pool, org, &r).await.is_err(),
        "malformed stored credential accepted"
    );
}

async fn storage_roundtrip(pool: &PgPool, org: Uuid, other_org: Uuid, user: Uuid) {
    // Direct storage calls deliberately isolate persistence from API verification.
    // This is NOT a valid Nitro proof and must be rejected by verify_upload.
    let envelope = serde_json::to_value(keymaker_models::Proofed {
        data: keymaker_models::generate_quorum::GenerateQuorumBundle::V1(
            v1::GenerateQuorumResponse {
                threshold: 1,
                max: 1,
                bundle_id: [7; 16],
                label: HashMap::from([("test".into(), "storage".into())]),
                keyring: vec![Key::OpenPGP {
                    cert: certificate(),
                }],
                public_key: certificate(),
                shardfile: "synthetic".into(),
            },
        ),
        necroproof: vec![1u8, 2, 3, 255],
    })
    .unwrap();
    let created = storage::create_quorum_bundle(
        pool,
        org,
        user,
        storage::CreateBundleRequest {
            allow_legacy: false,
            data: envelope.clone(),
            name: Some("before".into()),
            labels: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(created.data, envelope);
    assert_eq!(created.labels, json!({}));
    let listed = storage::list_quorum_bundles(pool, org).await.unwrap();
    assert_eq!(
        listed.iter().find(|b| b.id == created.id).unwrap().data,
        envelope
    );
    assert!(
        storage::get_quorum_bundle(pool, other_org, created.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        storage::list_quorum_bundles(pool, other_org)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        storage::update_quorum_bundle(
            pool,
            other_org,
            created.id,
            storage::UpdateBundleRequest {
                allow_legacy: false,
                data: None,
                name: Some("forbidden".into()),
                labels: None,
            }
        )
        .await
        .unwrap()
        .is_none()
    );
    let updated = storage::update_quorum_bundle(
        pool,
        org,
        created.id,
        storage::UpdateBundleRequest {
                allow_legacy: false,
            data: None,
            name: Some("after".into()),
            labels: Some(json!({"metadata":"edited"})),
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(updated.name.as_deref(), Some("after"));
    assert_eq!(updated.data, envelope);
    let fetched = storage::get_quorum_bundle(pool, org, created.id)
        .await
        .unwrap()
        .unwrap();
    // Reproduce the HTTP wrapper and CLI's download extraction, then a disk round trip.
    let wire: Value = serde_json::from_slice(&serde_json::to_vec(&fetched).unwrap()).unwrap();
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        file.path(),
        serde_json::to_vec_pretty(&wire["data"]).unwrap(),
    )
    .unwrap();
    let downloaded: Value = serde_json::from_slice(&std::fs::read(file.path()).unwrap()).unwrap();
    assert_eq!(downloaded, envelope);
    let error = verify_upload(&downloaded, false).unwrap_err();
    assert_eq!(error.message, "uploaded quorum proof verification failed");
    assert!(
        storage::delete_quorum_bundle(pool, org, created.id)
            .await
            .unwrap()
    );
}

async fn hosted_pgp(pool: &PgPool, org: Uuid, user: Uuid) {
    assert!(std::env::var_os("PUBLIC_CERTIFICATE_SERVICE_URL").is_none());
    assert!(std::env::var_os("PUBLIC_CERTIFICATE_PCR_POLICY_PATH").is_none());
    assert!(std::env::var_os("CAUTION_CA_CERT_PATH").is_none());
    let registered = certificate();
    let key = register_pgp(pool, user, &registered).await;
    let local = certificate();
    for (selection, mode, status) in [
        ("local", "invalid-proof", StatusCode::BAD_GATEWAY),
        ("registered", "invalid-proof", StatusCode::BAD_GATEWAY),
        ("both", "invalid-proof", StatusCode::BAD_GATEWAY),
        ("both", "429", StatusCode::TOO_MANY_REQUESTS),
        ("both", "503", StatusCode::SERVICE_UNAVAILABLE),
        ("both", "timeout", StatusCode::GATEWAY_TIMEOUT),
    ] {
        let mut r = pgp_request(user, key);
        let mut expected_keys = Vec::new();
        if selection != "registered" {
            r.pgp_certificates = vec![local.clone()];
            expected_keys.push(Key::OpenPGP {
                cert: local.clone(),
            });
        }
        if selection == "local" {
            r.participants.clear();
        } else {
            expected_keys.push(Key::OpenPGP {
                cert: registered.clone(),
            });
        }
        let count = expected_keys.len() as u8;
        r.threshold = count;
        r.name = Some("orchestration".into());
        r.labels = json!({"test_response":mode});
        let before = request_log().len();
        eprintln!("hosted PGP orchestration: {selection}, {mode}");
        let error = generate_org_quorum_bundle(pool, org, user, r)
            .await
            .unwrap_err();
        assert_eq!(error.status, status, "{error}");
        if mode == "invalid-proof" {
            assert_eq!(error.message, "Keymaker proof verification failed");
        }
        let log = request_log();
        assert_eq!(log.len(), before + 1, "generation was repeated");
        assert_eq!(log[before]["path"], "/generate_quorum");
        let wire: GenerateQuorumRequest =
            serde_json::from_value(log[before]["body"].clone()).unwrap();
        let wire = wire.to_latest();
        assert_ne!(wire.bundle_id, [0; 16]);
        assert_eq!((wire.threshold, wire.max), (count, count));
        assert_eq!(wire.label["name"], "orchestration");
        assert_eq!(wire.keyring, expected_keys);
        assert!(
            storage::list_quorum_bundles(pool, org)
                .await
                .unwrap()
                .is_empty(),
            "failed generation stored a bundle"
        );
    }
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_org_quorum_db.sh (isolated PostgreSQL and HTTP mock)"]
async fn database_contracts() {
    let url = std::env::var("QUORUM_TEST_DATABASE_URL")
        .expect("use the isolated quorum database test runner");
    let parsed = url::Url::parse(&url).unwrap();
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(parsed.path(), "/caution_quorum_test");
    let pool = PgPool::connect(&url).await.unwrap();
    let org = organization(&pool).await;
    let other = organization(&pool).await;
    let alice = member(&pool, org).await;
    let bob = member(&pool, org).await;
    member(&pool, other).await;
    participant_queries(&pool, org, other, alice, bob).await;
    credentials(&pool, org, other, bob).await;
    storage_roundtrip(&pool, org, other, alice).await;
    hosted_pgp(&pool, org, alice).await;
    holder_display_metadata(&pool).await;
    pool.close().await;
}

async fn holder_display_metadata(pool: &PgPool) {
    let org = organization(pool).await;
    let other = organization(pool).await;
    let alice = member(pool, org).await;
    let outsider = member(pool, other).await;
    let cert = certificate();
    let pgp_id = register_pgp(pool, alice, &cert).await;
    register_pgp(pool, outsider, &cert).await;
    let credential: Value = serde_json::from_str(include_str!("test-credential.json")).unwrap();
    let mut current = credential.clone();
    current["cred"]["counter"] = json!(500);
    sqlx::query(
        "INSERT INTO fido2_credentials(user_id, credential_id, public_key) VALUES ($1, $2, $3)",
    )
    .bind(alice)
    .bind(Uuid::new_v4().as_bytes().to_vec())
    .bind(serde_json::to_vec(&current).unwrap())
    .execute(pool)
    .await
    .unwrap();
    let data = json!({"data": {"version": "V1", "threshold": 2, "max": 2, "keyring": [
        {"OpenPGP": {"cert": cert}},
        {"WebAuthn": {"cert": cert, "credential": [serde_json::to_string(&credential).unwrap()]}}
    ]}, "necroproof": [1, 2, 3]});
    let saved = storage::create_quorum_bundle(
        pool,
        org,
        alice,
        storage::CreateBundleRequest {
            allow_legacy: false,
            data: data.clone(),
            name: None,
            labels: None,
        },
    )
    .await
    .unwrap();
    let loaded = storage::get_quorum_bundle(pool, org, saved.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.data, data);
    let metadata = serde_json::to_value(&loaded).unwrap();
    assert_eq!(metadata["holders"][0]["username"], alice.to_string());
    assert_eq!(metadata["holders"][1]["username"], alice.to_string());
    assert_eq!(metadata["holders"][1]["custody"], "caution_backed");
    assert_eq!(
        metadata["holders"][0]["fingerprint"],
        Cert::from_bytes(cert.as_bytes())
            .unwrap()
            .fingerprint()
            .to_string()
    );
    let listed = storage::list_quorum_bundles(pool, org).await.unwrap();
    assert_eq!(
        serde_json::to_value(&listed[0]).unwrap()["holders"],
        metadata["holders"]
    );
    assert!(
        storage::get_quorum_bundle(pool, other, saved.id)
            .await
            .unwrap()
            .is_none()
    );
    let bob = member(pool, org).await;
    let bob_key = register_pgp(pool, bob, &cert).await;
    let loaded = storage::get_quorum_bundle(pool, org, saved.id)
        .await
        .unwrap()
        .unwrap();
    assert!(serde_json::to_value(loaded).unwrap()["holders"][0]["username"].is_null());
    sqlx::query("UPDATE pgp_keys SET removed_at = now() WHERE id IN ($1, $2)")
        .bind(pgp_id)
        .bind(bob_key)
        .execute(pool)
        .await
        .unwrap();
    let loaded = storage::get_quorum_bundle(pool, org, saved.id)
        .await
        .unwrap()
        .unwrap();
    let metadata = serde_json::to_value(loaded).unwrap();
    assert!(metadata["holders"][0]["username"].is_null());
    assert_eq!(metadata["holders"][1]["username"], alice.to_string());
    sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(alice)
        .execute(pool)
        .await
        .unwrap();
    let loaded = storage::get_quorum_bundle(pool, org, saved.id)
        .await
        .unwrap()
        .unwrap();
    let metadata = serde_json::to_value(loaded).unwrap();
    assert!(metadata["holders"][0]["username"].is_null());
    assert!(metadata["holders"][1]["username"].is_null());
    assert_eq!(metadata["data"], data);
}
