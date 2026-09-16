use super::*;
use clap::Parser;

#[derive(Parser)]
struct TestCli {
    #[command(subcommand)]
    secret: crate::SecretCommands,
}

#[test]
fn init_and_visible_new_alias_match() {
    for command in ["init", "new"] {
        let parsed = TestCli::try_parse_from([
            "caution",
            command,
            "keys.asc",
            "--threshold",
            "2",
            "--no-upload",
        ])
        .unwrap();
        let crate::SecretCommands::Init(options) = parsed.secret else {
            panic!("wrong command")
        };
        assert_eq!(options.threshold, Some(2));
        assert!(options.no_upload);
    }
}

#[test]
fn endpoint_defaults_and_override_precedence() {
    assert_eq!(endpoint(None, None).unwrap(), None);
    for blank in ["", " \t\n"] {
        assert_eq!(endpoint(None, Some(blank)).unwrap(), None);
        assert_eq!(
            endpoint(Some("https://explicit/"), Some(blank))
                .unwrap()
                .as_deref(),
            Some("https://explicit")
        );
        assert!(endpoint(Some(blank), Some("https://environment")).is_err());
    }
    assert_eq!(
        endpoint(Some("https://explicit/"), Some("https://environment"))
            .unwrap()
            .as_deref(),
        Some("https://explicit")
    );
    assert_eq!(
        endpoint(None, Some("http://localhost:8080"))
            .unwrap()
            .as_deref(),
        Some("http://localhost:8080")
    );
    assert!(endpoint(Some("file:///tmp/keymaker"), None).is_err());
}

#[test]
fn direct_rejects_mixed_and_webauthn() {
    let pgp = Participant {
        user_id: Uuid::new_v4(),
        key_source: "existing_pgp",
        pgp_key_id: Some(Uuid::new_v4()),
    };
    let web = Participant {
        user_id: Uuid::new_v4(),
        key_source: "caution_backed_pgp",
        pgp_key_id: None,
    };
    assert!(validate_direct(true, &[pgp.clone()]).is_ok());
    assert!(validate_direct(false, &[web.clone()]).is_ok());
    for participants in [vec![web.clone()], vec![pgp, web]] {
        assert!(
            validate_direct(true, &participants)
                .unwrap_err()
                .to_string()
                .contains(DIRECT_WEBAUTHN_ERROR)
        );
    }
}

#[test]
fn pgp_override_requires_two_uuids() {
    assert!("bad=value".parse::<PgpSelection>().is_err());
    let user = Uuid::new_v4();
    let key = Uuid::new_v4();
    let parsed = [user.to_string(), key.to_string()]
        .join("=")
        .parse::<PgpSelection>()
        .unwrap();
    assert_eq!(parsed.user, user);
    assert_eq!(parsed.key, key);
}

fn options(users: Vec<Uuid>) -> Options {
    Options {
        keyring: None,
        threshold: None,
        max: None,
        no_upload: false,
        name: None,
        labels: vec![],
        from_org_users: users,
        caution_backed: false,
        pgp_keys: vec![],
        keymaker_url: None,
        keymaker_pcr_policy: None,
    }
}

#[test]
fn selection_requires_explicit_webauthn_and_pgp_ownership() {
    let user = Uuid::new_v4();
    let key = Uuid::new_v4();
    let mut member = Member {
        user_id: user,
        username: "holder".into(),
        pgp_keys: vec![],
        webauthn_credentials: 2,
    };
    let mut opts = options(vec![user]);
    assert!(select_participants(&opts, &[member.clone()], false).is_err());
    opts.caution_backed = true;
    let (holders, certs) = select_participants(&opts, &[member.clone()], false).unwrap();
    assert_eq!(holders.len(), 1);
    assert_eq!(holders[0].key_source, "caution_backed_pgp");
    assert!(certs.is_empty());
    member.pgp_keys.push(RegisteredKey {
        id: key,
        fingerprint: "test".into(),
        public_key: "test certificate".into(),
    });
    opts.pgp_keys.push(PgpSelection { user, key });
    let (holders, certs) = select_participants(&opts, &[member.clone()], false).unwrap();
    assert_eq!(holders[0].key_source, "existing_pgp");
    assert_eq!(certs, vec!["test certificate"]);
    opts.pgp_keys[0].key = Uuid::new_v4();
    assert!(select_participants(&opts, &[member], false).is_err());
}

#[test]
fn selection_without_custody_fails_before_prompting() {
    let user = Uuid::new_v4();
    let member = Member {
        user_id: user,
        username: "holder".into(),
        pgp_keys: vec![],
        webauthn_credentials: 0,
    };
    for interactive in [false, true] {
        let error =
            select_participants(&options(vec![user]), &[member.clone()], interactive).unwrap_err();
        assert!(error.to_string().contains("no usable custody"));
    }
}

#[test]
fn duplicate_users_and_overrides_are_rejected() {
    let user = Uuid::new_v4();
    let member = Member {
        user_id: user,
        username: "holder".into(),
        pgp_keys: vec![],
        webauthn_credentials: 1,
    };
    let mut opts = options(vec![user, user]);
    opts.caution_backed = true;
    assert!(select_participants(&opts, &[member.clone()], false).is_err());
    opts.from_org_users.pop();
    opts.pgp_keys = vec![
        PgpSelection {
            user,
            key: Uuid::new_v4()
        };
        2
    ];
    assert!(select_participants(&opts, &[member], false).is_err());
}

#[test]
fn trust_policy_is_required_and_fake_proofs_are_rejected() {
    assert!(parse_policy(r#"{"sets":[]}"#).is_err());
    assert!(parse_policy(r#"{"sets":[{"pcrs":{"0":"aa"}}]}"#).is_err());
    assert!(load_policy(Path::new("/nonexistent/pr391-policy.json")).is_err());
    let policy_json = serde_json::json!({"sets":[{"pcrs":{"0":"ab".repeat(48),"1":"cd".repeat(48),"2":"ef".repeat(48)}}]}).to_string();
    let policy = parse_policy(&policy_json).unwrap();
    let response = keymaker_models::Proofed {
        data: GenerateQuorumBundle::V1(v1::GenerateQuorumResponse {
            threshold: 1,
            max: 1,
            bundle_id: [1; 16],
            label: HashMap::new(),
            keyring: vec![],
            public_key: String::new(),
            shardfile: String::new(),
        }),
        necroproof: vec![1, 2, 3],
    };
    assert!(locksmith::bundle::load_response(response, &policy).is_err());
}

#[test]
fn local_keyring_keeps_all_holders_and_rejects_duplicates() {
    let make = || {
        let (cert, _) = sequoia_openpgp::cert::CertBuilder::new()
            .add_userid("test holder")
            .add_signing_subkey()
            .add_authentication_subkey()
            .add_storage_encryption_subkey()
            .generate()
            .unwrap();
        let mut bytes = Vec::new();
        cert.armored().serialize(&mut bytes).unwrap();
        String::from_utf8(bytes).unwrap()
    };
    let first = make();
    let second = make();
    let certs = public_certificates(&[first.clone(), second].concat()).unwrap();
    assert_eq!(certs.len(), 2);
    assert!(unique_certificates(&certs).is_ok());
    assert!(unique_certificates(&[first.clone(), first]).is_err());
}

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
                assert!(public_certificates(cert).is_ok());
            }
            assert!(
                unique_certificates(&certs)
                    .unwrap_err()
                    .to_string()
                    .contains("share an encryption key")
            );
        }
    }
}

#[test]
fn quorum_parameters_match_original_selection() {
    // Both hosted and direct creation call this check after proof verification.
    let mut bundle = v1::GenerateQuorumResponse {
        bundle_id: [1; 16],
        label: HashMap::new(),
        keyring: vec![],
        public_key: String::new(),
        shardfile: String::new(),
        threshold: 3,
        max: 5,
    };
    assert!(check_quorum_parameters(&bundle, 3, 5).is_ok());
    bundle.threshold = 1;
    assert!(check_quorum_parameters(&bundle, 3, 5).is_err());
    bundle.threshold = 3;
    bundle.max = 4;
    assert!(check_quorum_parameters(&bundle, 3, 5).is_err());
}
