use super::*;
use sequoia_openpgp::{
    cert::CertBuilder,
    packet::{
        UserID,
        signature::{
            SignatureBuilder,
            subpacket::{NotationData, NotationDataFlags, Subpacket, SubpacketValue},
        },
    },
    serialize::Serialize,
    types::SignatureType,
};

fn test_ca() -> Cert {
    CertBuilder::new()
        .set_creation_time(SystemTime::now() - Duration::from_secs(3 * 86400))
        .set_validity_period(Duration::from_secs(86400))
        .add_userid("temporary Caution CA")
        .generate()
        .unwrap()
        .0
}

fn certificate(ca: &Cert, index: usize, org: [u8; 16], bundle: [u8; 16], mode: &str) -> String {
    let cert = CertBuilder::new()
        .add_userid(format!("Caution public certificate index={index}"))
        .add_signing_subkey()
        .add_authentication_subkey()
        .add_storage_encryption_subkey()
        .generate()
        .unwrap()
        .0;
    let mut signer = ca
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();
    let flags = NotationDataFlags::empty().set_human_readable();
    let mut builder = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_notation(ORG_NOTATION, hex::encode(org), flags.clone(), true)
        .unwrap();
    if mode != "missing" {
        builder = builder
            .set_notation(BUNDLE_NOTATION, hex::encode(bundle), flags.clone(), true)
            .unwrap();
    }
    if mode == "duplicate" {
        builder = builder
            .add_notation(ORG_NOTATION, hex::encode(org), flags, true)
            .unwrap();
    }
    let wrong = UserID::from("different certified user ID");
    let uid = if mode == "bad-signature" {
        &wrong
    } else {
        cert.userids().next().unwrap().userid()
    };
    let mut sig = builder
        .sign_userid_binding(&mut signer, cert.primary_key().key(), uid)
        .unwrap();
    if mode == "unhashed" {
        sig.unhashed_area_mut()
            .add(
                Subpacket::new(
                    SubpacketValue::NotationData(NotationData::new(
                        ORG_NOTATION,
                        hex::encode(org),
                        NotationDataFlags::empty(),
                    )),
                    false,
                )
                .unwrap(),
            )
            .unwrap();
    }
    let cert = cert.insert_packets(sig).unwrap();
    let mut bytes = Vec::new();
    cert.armored().serialize(&mut bytes).unwrap();
    String::from_utf8(bytes).unwrap()
}

fn data(certificates: Vec<String>) -> PublicCertificateBundle {
    PublicCertificateBundle::V1(public_certificate_models::v1::PublicCertificateBundle {
        organization_id: [1; 16],
        bundle_id: [2; 16],
        certificates,
    })
}

#[test]
fn accepts_ca_certified_ordered_context_and_rejects_substitutions() {
    let ca = test_ca();
    // A later-issued holder remains valid under an expired configured CA snapshot.
    let anchor = ca.clone().strip_secret_key_material();
    let certs: Vec<_> = (0..2)
        .map(|i| certificate(&ca, i, [1; 16], [2; 16], "valid"))
        .collect();
    let count = NonZeroU8::new(2).unwrap();
    let at = SystemTime::now();
    assert_eq!(
        verify_certificates(data(certs.clone()), [1; 16], count, &anchor, at).unwrap(),
        ([2; 16], certs.clone())
    );
    assert!(verify_certificates(data(certs.clone()), [3; 16], count, &anchor, at).is_err());
    assert!(
        verify_certificates(
            data(certs.clone()),
            [1; 16],
            NonZeroU8::new(1).unwrap(),
            &anchor,
            at
        )
        .is_err()
    );
    assert!(
        verify_certificates(
            data(certs.clone()),
            [1; 16],
            count,
            &test_ca().strip_secret_key_material(),
            at
        )
        .is_err()
    );
    assert!(
        verify_certificates(
            data(vec![certs[1].clone(), certs[0].clone()]),
            [1; 16],
            count,
            &anchor,
            at
        )
        .is_err()
    );
    assert!(
        verify_certificates(data(vec![certs[0].clone(); 2]), [1; 16], count, &anchor, at).is_err()
    );
    for (org, id, index, mode) in [
        ([3; 16], [2; 16], 0, "valid"),
        ([1; 16], [3; 16], 0, "valid"),
        ([1; 16], [2; 16], 1, "valid"),
        ([1; 16], [2; 16], 0, "missing"),
        ([1; 16], [2; 16], 0, "duplicate"),
        ([1; 16], [2; 16], 0, "bad-signature"),
        ([1; 16], [2; 16], 0, "unhashed"),
    ] {
        let bundle = data(vec![certificate(&ca, index, org, id, mode)]);
        assert!(
            verify_certificates(
                bundle,
                [1; 16],
                NonZeroU8::new(1).unwrap(),
                &anchor,
                SystemTime::now()
            )
            .is_err(),
            "{mode}"
        );
    }
    assert!(
        verify_certificates(
            data(vec!["not a certificate".into()]),
            [1; 16],
            NonZeroU8::new(1).unwrap(),
            &anchor,
            at
        )
        .is_err()
    );
}

#[test]
fn authenticated_payload_binds_hash_and_checked_timestamp() {
    let payload = |timestamp, hash| {
        Value::Map(
            [
                (Value::Text("timestamp".into()), Value::Integer(timestamp)),
                (Value::Text("user_data".into()), Value::Bytes(hash)),
            ]
            .into_iter()
            .collect(),
        )
    };
    assert_eq!(
        verify_payload(payload(1234, vec![7; 32]), &[7; 32]).unwrap(),
        SystemTime::UNIX_EPOCH + Duration::from_millis(1234)
    );
    assert!(verify_payload(payload(1234, vec![8; 32]), &[7; 32]).is_err());
    for timestamp in [-1, i128::from(u64::MAX) + 1] {
        assert!(verify_payload(payload(timestamp, vec![7; 32]), &[7; 32]).is_err());
    }
    assert!(verify_payload(Value::Null, &[7; 32]).is_err());
    let mut set = locksmith::bundle::KeymakerPcrSet {
        pcrs: HashMap::new(),
        expires_at_unix_seconds: Some(2),
    };
    for (millis, expected) in [(1999, true), (2000, false), (2001, false)] {
        assert_eq!(
            valid_at(&set, SystemTime::UNIX_EPOCH + Duration::from_millis(millis)),
            expected
        );
    }
    set.expires_at_unix_seconds = None;
    assert!(valid_at(&set, SystemTime::now()));
}

#[test]
fn rejects_missing_or_malformed_proofs() {
    let policy = KeymakerPcrPolicy::from_json(&format!(
        r#"{{"sets":[{{"pcrs":{{"0":"{p}","1":"{p}","2":"{p}"}}}}]}}"#,
        p = "ab".repeat(48)
    ))
    .unwrap();
    for proof in [vec![], vec![1, 2, 3], vec![0; 32]] {
        assert!(
            verify_proof(
                &PublicCertificateResponse {
                    data: data(vec![]),
                    necroproof: proof
                },
                &policy
            )
            .is_err()
        );
    }
}

#[test]
fn synthetic_proof_gate() {
    const CHILD: &str = "CAUTION_CERTIFICATE_GATE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let data = data(vec![]);
        let mut response = PublicCertificateResponse {
            necroproof: bundle_hash(&data).unwrap(),
            data,
        };
        let mut policy = KeymakerPcrPolicy {
            sets: vec![locksmith::bundle::KeymakerPcrSet {
                pcrs: (0..=2).map(|i| (i, vec![0xab; 48])).collect(),
                expires_at_unix_seconds: None,
            }],
        };
        let enabled = cfg!(feature = "e2e-testing-unsafe")
            && std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1");
        assert_eq!(verify_proof(&response, &policy).is_ok(), enabled);
        response.necroproof[0] ^= 1;
        assert!(verify_proof(&response, &policy).is_err());
        response.necroproof[0] ^= 1;
        response.data = super::tests::data(vec!["altered".into()]);
        assert!(verify_proof(&response, &policy).is_err());
        response.data = super::tests::data(vec![]);
        for invalid in ["expiry", "missing", "extra", "wrong", "empty", "multiple"] {
            let mut bad = policy.clone();
            match invalid {
                "expiry" => bad.sets[0].expires_at_unix_seconds = Some(u64::MAX / 10),
                "missing" => {
                    bad.sets[0].pcrs.remove(&2);
                }
                "extra" => {
                    bad.sets[0].pcrs.insert(3, vec![0xab; 48]);
                }
                "wrong" => bad.sets[0].pcrs.get_mut(&0).unwrap()[0] ^= 1,
                "multiple" => bad.sets.push(bad.sets[0].clone()),
                _ => bad.sets.clear(),
            }
            assert!(verify_proof(&response, &bad).is_err(), "{invalid}");
        }
        policy.sets.clear();
        assert!(verify_proof(&response, &policy).is_err());
        return;
    }
    for flag in [None, Some(""), Some("0"), Some("true"), Some("1")] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "org_quorum::certificates::tests::synthetic_proof_gate",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env_remove("CAUTION_UNSAFE_KEY_SERVICE_E2E");
        if let Some(flag) = flag {
            child.env("CAUTION_UNSAFE_KEY_SERVICE_E2E", flag);
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "flag {flag:?}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn revoked_ca_anchor_rejects_later_certificates() {
    use sequoia_openpgp::{cert::CertRevocationBuilder, types::ReasonForRevocation};
    let ca = test_ca();
    let cert = certificate(&ca, 0, [1; 16], [2; 16], "valid");
    let mut signer = ca
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();
    let revocation = CertRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::KeyCompromised, b"test")
        .unwrap()
        .build(&mut signer, &ca, None)
        .unwrap();
    let ca = ca
        .insert_packets(revocation)
        .unwrap()
        .strip_secret_key_material();
    assert!(
        verify_certificates(
            data(vec![cert]),
            [1; 16],
            NonZeroU8::new(1).unwrap(),
            &ca,
            SystemTime::now()
        )
        .is_err()
    );
}
