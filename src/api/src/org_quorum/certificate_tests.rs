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
    let certs: Vec<_> = (0..2)
        .map(|i| certificate(&ca, i, [1; 16], [2; 16], "valid"))
        .collect();
    let count = NonZeroU8::new(2).unwrap();
    let at = SystemTime::now();
    assert_eq!(
        verify_certificates(data(certs.clone()), [1; 16], count, &ca, at).unwrap(),
        ([2; 16], certs.clone())
    );
    assert!(verify_certificates(data(certs.clone()), [3; 16], count, &ca, at).is_err());
    assert!(
        verify_certificates(
            data(certs.clone()),
            [1; 16],
            NonZeroU8::new(1).unwrap(),
            &ca,
            at
        )
        .is_err()
    );
    assert!(verify_certificates(data(certs.clone()), [1; 16], count, &test_ca(), at).is_err());
    assert!(
        verify_certificates(
            data(vec![certs[1].clone(), certs[0].clone()]),
            [1; 16],
            count,
            &ca,
            at
        )
        .is_err()
    );
    assert!(verify_certificates(data(vec![certs[0].clone(); 2]), [1; 16], count, &ca, at).is_err());
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
                &ca,
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
            &ca,
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
