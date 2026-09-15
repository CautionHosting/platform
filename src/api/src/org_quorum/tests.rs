use super::*;

fn request() -> GenerateOrgQuorumBundleRequest {
    GenerateOrgQuorumBundleRequest {
        name: None,
        threshold: 1,
        participants: vec![OrgQuorumParticipantSelection {
            user_id: Uuid::new_v4(),
            key_source: OrgQuorumKeySource::CautionBackedPgp,
            pgp_key_id: None,
        }],
        pgp_certificates: vec![],
        allow_caution_backed_keys: true,
        labels: serde_json::Value::Null,
    }
}

#[test]
fn rejects_duplicate_users_and_invalid_thresholds() {
    let mut r = request();
    assert!(validate_request(&r).is_ok());
    r.participants.push(r.participants[0].clone());
    assert!(validate_request(&r).is_err());
    r.participants.pop();
    for threshold in [0, 2, 255] {
        r.threshold = threshold;
        assert!(validate_request(&r).is_err());
    }
}

#[test]
fn requires_explicit_custody_selection() {
    let mut r = request();
    r.allow_caution_backed_keys = false;
    assert!(validate_request(&r).is_err());
    r.participants[0].key_source = OrgQuorumKeySource::ExistingPgp;
    assert!(validate_request(&r).is_err());
    r.participants[0].pgp_key_id = Some(Uuid::new_v4());
    assert!(validate_request(&r).is_ok());
}

#[test]
fn missing_and_malformed_credentials_fail() {
    assert!(credential_snapshot(vec![]).is_err());
    assert!(credential_snapshot(vec![b"{}".to_vec()]).is_err());
}

#[test]
fn rejects_invalid_pgp_and_participant_limits() {
    assert!(eligible_certificate("not a certificate").is_err());
    let mut r = request();
    r.participants.clear();
    assert!(validate_request(&r).is_err());
    r.pgp_certificates = vec![String::new(); 256];
    assert!(validate_request(&r).is_err());
}

fn certificate() -> String {
    use sequoia_openpgp::{cert::CertBuilder, serialize::Serialize};
    let (cert, _) = CertBuilder::new()
        .add_userid("test holder")
        .add_signing_subkey()
        .add_authentication_subkey()
        .add_storage_encryption_subkey()
        .generate()
        .unwrap();
    let mut bytes = Vec::new();
    cert.armored().serialize(&mut bytes).unwrap();
    String::from_utf8(bytes).unwrap()
}

#[test]
fn assembled_combinations_preserve_id_and_compact_derived_order() {
    let pgp = certificate();
    let derived = [certificate(), certificate()];
    let id = *Uuid::new_v4().as_bytes();
    // Synthetic credential strings only test orchestration, not WebAuthn validity.
    let holders = vec![
        Holder::WebAuthn(vec!["a".into(), "b".into()]),
        Holder::Pgp(pgp.clone()),
        Holder::WebAuthn(vec!["c".into()]),
    ];
    let mixed = assemble_request(&request(), id, holders, derived.to_vec())
        .unwrap()
        .to_latest();
    assert_eq!(mixed.bundle_id, id);
    assert_eq!(mixed.max, 3);
    assert_eq!(
        mixed.keyring,
        vec![
            Key::WebAuthn {
                credential: vec!["a".into(), "b".into()],
                cert: derived[0].clone()
            },
            Key::OpenPGP { cert: pgp.clone() },
            Key::WebAuthn {
                credential: vec!["c".into()],
                cert: derived[1].clone()
            },
        ]
    );
    let pgp_only = assemble_request(&request(), id, vec![Holder::Pgp(pgp)], vec![])
        .unwrap()
        .to_latest();
    assert_eq!(pgp_only.max, 1);
    let web = assemble_request(
        &request(),
        id,
        vec![Holder::WebAuthn(vec!["a".into(), "b".into()])],
        vec![derived[0].clone()],
    )
    .unwrap()
    .to_latest();
    assert_eq!(web.max, 1);
}

#[test]
fn rejects_duplicate_effective_certificates_and_bad_derived_counts() {
    let cert = certificate();
    assert!(
        validate_keyring(&[
            Key::OpenPGP { cert: cert.clone() },
            Key::WebAuthn {
                cert: cert.clone(),
                credential: vec!["a".into()]
            }
        ])
        .is_err()
    );
    assert!(
        assemble_request(
            &request(),
            [1; 16],
            vec![Holder::Pgp(cert.clone())],
            vec![cert]
        )
        .is_err()
    );
    assert!(
        assemble_request(
            &request(),
            [1; 16],
            vec![Holder::WebAuthn(vec!["a".into()])],
            vec![]
        )
        .is_err()
    );
}

#[test]
fn matches_available_response_fields_and_preserves_envelope() {
    use keymaker_models::{Proofed, generate_quorum::GenerateQuorumBundle};
    let cert = certificate();
    let req =
        assemble_request(&request(), [1; 16], vec![Holder::Pgp(cert.clone())], vec![]).unwrap();
    let expected = req.clone().to_latest();
    let mut bundle = v1::GenerateQuorumResponse {
        bundle_id: expected.bundle_id,
        label: expected.label,
        keyring: expected.keyring,
        shardfile: "synthetic shardfile".into(),
        public_key: cert,
    };
    let response = Proofed {
        data: GenerateQuorumBundle::V1(bundle.clone()),
        necroproof: vec![1, 2, 3],
    };
    assert!(check_response(&req, &response).is_ok()); // Field checks only, not proof acceptance.
    let data = serde_json::to_value(&response).unwrap();
    let stored = serde_json::json!({"data": data});
    let roundtrip: GenerateQuorumResponse = serde_json::from_value(stored["data"].clone()).unwrap();
    assert_eq!(roundtrip.necroproof, vec![1, 2, 3]);
    assert_eq!(roundtrip.data, response.data);
    for field in ["id", "labels", "keyring"] {
        bundle = response.data.clone().to_latest();
        match field {
            "id" => bundle.bundle_id = [2; 16],
            "labels" => {
                bundle.label.insert("wrong".into(), "value".into());
            }
            _ => bundle.keyring.clear(),
        }
        assert!(
            check_response(
                &req,
                &Proofed {
                    data: GenerateQuorumBundle::V1(bundle.clone()),
                    necroproof: vec![]
                }
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn webauthn_derivation_remains_explicitly_blocked() {
    let error = certificates::derive(
        &reqwest::Client::new(),
        Uuid::new_v4(),
        std::num::NonZeroU8::new(1).unwrap(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(error.message.contains("certificate-service proof verification"));
}

#[tokio::test]
async fn busy_and_timeout_do_not_retry_generation() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    for (status, delay, expected) in [
        (429, 0, StatusCode::TOO_MANY_REQUESTS),
        (503, 0, StatusCode::SERVICE_UNAVAILABLE),
        (200, 200, StatusCode::GATEWAY_TIMEOUT),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = ["http://", &listener.local_addr().unwrap().to_string()].concat();
        let calls = Arc::new(AtomicUsize::new(0));
        let recorded = calls.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            stream.read(&mut request).unwrap();
            recorded.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(delay));
            let response = [
                "HTTP/1.1 ",
                &status.to_string(),
                " Test\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            ]
            .concat();
            let _ = stream.write_all(response.as_bytes());
        });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(75))
            .build()
            .unwrap();
        let error = post::<_, serde_json::Value>(&client, &url, &serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(error.status, expected);
        server.join().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[path = "database.rs"]
mod database;

mod recipients {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/quorum_certificates.rs"
    ));
}

#[test]
fn rejects_shared_recipients_including_notations_and_expired_keys() {
    for notation in [
        None,
        Some("organization-id@caution.co"),
        Some("bundle-id@caution.co"),
    ] {
        for expired in [false, true] {
            let certs = recipients::shared_recipient(notation, expired);
            for cert in &certs {
                assert!(eligible_certificate(cert).is_ok());
            }
            let keys: Vec<_> = certs
                .into_iter()
                .map(|cert| Key::OpenPGP { cert })
                .collect();
            let error = validate_keyring(&keys).unwrap_err();
            assert!(error.message.contains("share an encryption key"));
        }
    }
    assert!(
        validate_keyring(&[
            Key::OpenPGP {
                cert: certificate()
            },
            Key::OpenPGP {
                cert: certificate()
            }
        ])
        .is_ok()
    );
}

#[test]
fn policy_files_fail_closed_when_missing_or_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keymaker-pcr-policy.json");
    assert_eq!(
        load_policy(&path).unwrap_err().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    for json in [
        "not JSON",
        r#"{"sets":[]}"#,
        r#"{"sets":[{"pcrs":{"0":"ab"}}]}"#,
    ] {
        std::fs::write(&path, json).unwrap();
        assert_eq!(
            load_policy(&path).unwrap_err().status,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    for byte in ["00", "ab"] {
        std::fs::write(
            &path,
            serde_json::json!({"sets":[{"pcrs":{
                "0":byte.repeat(48), "1":byte.repeat(48), "2":byte.repeat(48)
            }}]})
            .to_string(),
        )
        .unwrap();
        assert_eq!(load_policy(&path).is_ok(), byte == "ab");
    }
}
