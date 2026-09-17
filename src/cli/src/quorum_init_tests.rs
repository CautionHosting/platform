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
fn pgp_override_accepts_user_selector_and_requires_key_uuid() {
    assert!("bad=value".parse::<PgpSelection>().is_err());
    let user = Uuid::new_v4();
    let key = Uuid::new_v4();
    let parsed = [user.to_string(), key.to_string()]
        .join("=")
        .parse::<PgpSelection>()
        .unwrap();
    assert_eq!(parsed.user, UserSelector::Id(user));
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
        holders: Vec::new(),
        from_org_users: users.into_iter().map(UserSelector::Id).collect(),
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
    assert!(select_participants(&opts, &[member.clone()], false, false).is_err());
    opts.caution_backed = true;
    let (holders, certs) = select_participants(&opts, &[member.clone()], false, false).unwrap();
    assert_eq!(holders.len(), 1);
    assert_eq!(holders[0].key_source, "caution_backed_pgp");
    assert!(certs.is_empty());
    member.pgp_keys.push(RegisteredKey {
        id: key,
        fingerprint: "test".into(),
        public_key: "test certificate".into(),
    });
    opts.pgp_keys.push(PgpSelection {
        user: UserSelector::Id(user),
        key,
    });
    let (holders, certs) = select_participants(&opts, &[member.clone()], false, false).unwrap();
    assert_eq!(holders[0].key_source, "existing_pgp");
    assert_eq!(certs, vec!["test certificate"]);
    opts.pgp_keys[0].key = Uuid::new_v4();
    assert!(select_participants(&opts, &[member], false, false).is_err());
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
            select_participants(&options(vec![user]), &[member.clone()], interactive, false)
                .unwrap_err();
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
    assert!(select_participants(&opts, &[member.clone()], false, false).is_err());
    opts.from_org_users.pop();
    opts.pgp_keys = vec![
        PgpSelection {
            user: UserSelector::Id(user),
            key: Uuid::new_v4()
        };
        2
    ];
    assert!(select_participants(&opts, &[member], false, false).is_err());
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
            for different_timestamps in [false, true] {
                let certs = recipients::shared_recipient(notation, expired, different_timestamps);
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

#[test]
fn name_label_must_match_explicit_name() {
    let labels = HashMap::from([("name".into(), "prod".into())]);
    assert!(check_name_label(Some("staging"), &labels).is_err());
    assert!(check_name_label(Some("prod"), &labels).is_ok());
    assert!(check_name_label(None, &labels).is_ok());
    assert!(check_name_label(Some("prod"), &HashMap::new()).is_ok());
}

#[test]
fn saved_policy_is_preserved_and_replacement_is_rejected() {
    let dir = std::env::temp_dir().join(format!("quorum-policy-{}", Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("policy.json");
    let value = serde_json::json!({"sets":[{"pcrs":{
        "0":"ab".repeat(48), "1":"cd".repeat(48), "2":"ef".repeat(48)
    }}]});
    let text = value.to_string();
    let policy = parse_policy(&text).unwrap();
    assert!(check_saved_policy(&path, &policy).is_ok());
    save_policy_if_absent(&path, &text, &policy).unwrap();
    let formatted = serde_json::to_string_pretty(&value).unwrap();
    fs::write(&path, &formatted).unwrap();
    check_saved_policy(&path, &policy).unwrap();
    save_policy_if_absent(&path, &text, &policy).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), formatted);
    let other = parse_policy(&text.replace("abab", "acac")).unwrap();
    assert!(check_saved_policy(&path, &other).is_err());
    assert!(save_policy_if_absent(&path, "unused", &other).is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), formatted);
    fs::write(&path, "broken").unwrap();
    assert!(check_saved_policy(&path, &policy).is_err());
    assert!(save_policy_if_absent(&path, &text, &policy).is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "broken");
    fs::remove_dir_all(dir).unwrap();
}

/// Uses downloaded envelopes from the mock stack and a loopback app lookup.
/// No enclave connection or real share release is attempted.
#[cfg(feature = "e2e-testing-unsafe")]
#[tokio::test]
#[ignore = "run make test-quorum-mock"]
async fn downloaded_bundles_require_explicit_noninteractive_holder() {
    let work = PathBuf::from(std::env::var("QUORUM_RECOVERY_TEST_DIR").unwrap());
    let base_url = std::env::var("PUBLIC_CERTIFICATE_SERVICE_URL").unwrap();
    let config_path = work.join("recovery-client.json");
    fs::write(&config_path, serde_json::to_vec(&serde_json::json!({
        "session_id":"mock-recovery", "expires_at":"2099-01-01T00:00:00Z", "server_url":base_url,
    })).unwrap()).unwrap();
    fs::write(
        work.join(".caution/trusted_hashes.json"),
        serde_json::to_vec(&serde_json::json!({
            "pcr0":"ab".repeat(48), "pcr1":"ab".repeat(48), "pcr2":"ab".repeat(48),
        }))
        .unwrap(),
    )
    .unwrap();
    let client = ApiClient {
        base_url,
        client: reqwest::Client::new(),
        config_path,
        deployment_path: None,
        verbose: false,
        qr: false,
        workdir: Some(work.clone()),
    };
    for name in ["webauthn.json", "mixed.json"] {
        let error = crate::secrets::send_shard(
            &client,
            Some("quorum-test".into()),
            Some(work.join(name)),
            None,
            crate::share_release::Options::default(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, crate::secrets::SendShardError::ParseBundle { .. }),
            "{name}: {error}"
        );
    }
}

#[test]
fn selector_parsing_and_uuid_precedence() {
    for blank in ["", "  "] {
        assert!(blank.parse::<UserSelector>().is_err());
    }
    assert_eq!(
        " ALIce ".parse::<UserSelector>().unwrap(),
        UserSelector::Username("alice".into())
    );
    let id = Uuid::new_v4();
    let member = Member {
        user_id: Uuid::new_v4(),
        username: id.to_string(),
        pgp_keys: vec![],
        webauthn_credentials: 1,
    };
    let selector: UserSelector = id.to_string().parse().unwrap();
    assert!(
        selector.resolve(&[member.clone()]).is_err(),
        "UUIDs never fall back to usernames"
    );
    let actual = Member {
        user_id: id,
        username: "alice".into(),
        ..member.clone()
    };
    assert_eq!(selector.resolve(&[member, actual]).unwrap().user_id, id);
    let key = Uuid::new_v4();
    let parsed = format!(" ALICE = {key} ").parse::<PgpSelection>().unwrap();
    assert_eq!(parsed.user, UserSelector::Username("alice".into()));
    for input in [format!("={key}"), "alice=bad-key".into(), "alice".into()] {
        assert!(input.parse::<PgpSelection>().is_err());
    }
    let parsed = TestCli::try_parse_from([
        "caution",
        "init",
        "--from-org-users",
        &format!("alice,{id}"),
        "--pgp-key",
        &format!("alice={key}"),
    ])
    .unwrap();
    let crate::SecretCommands::Init(options) = parsed.secret else {
        panic!("wrong command")
    };
    assert_eq!(
        options.from_org_users,
        vec![UserSelector::Username("alice".into()), UserSelector::Id(id)]
    );
    assert!(
        TestCli::try_parse_from(["caution", "init", "--from-org-users", "alice,,bob"]).is_err()
    );
}

#[test]
fn username_resolution_preserves_order_and_uuid_payloads() {
    let members: Vec<_> = ["alice", "bob"]
        .into_iter()
        .map(|name| Member {
            user_id: Uuid::new_v4(),
            username: name.into(),
            webauthn_credentials: 1,
            pgp_keys: vec![RegisteredKey {
                id: Uuid::new_v4(),
                fingerprint: name.into(),
                public_key: name.into(),
            }],
        })
        .collect();
    let ids = options(vec![members[1].user_id, members[0].user_id]);
    let mut names = options(vec![]);
    names.from_org_users = vec![
        " BOB ".parse().unwrap(),
        UserSelector::Id(members[0].user_id),
    ];
    names.pgp_keys = vec![PgpSelection {
        user: "bob".parse().unwrap(),
        key: members[1].pgp_keys[0].id,
    }];
    let expected = select_participants(&ids, &members, false, false).unwrap();
    let actual = select_participants(&names, &members, false, false).unwrap();
    assert_eq!(
        serde_json::to_value(&actual.0).unwrap(),
        serde_json::to_value(&expected.0).unwrap()
    );
    assert_eq!(actual.1, expected.1);
    // Resolve cross-spelling overrides before the direct-mode WebAuthn guard.
    names.caution_backed = true;
    names.pgp_keys.push(PgpSelection {
        user: "ALICE".parse().unwrap(),
        key: members[0].pgp_keys[0].id,
    });
    assert!(select_participants(&names, &members, true, true).is_ok());
    names.pgp_keys.pop();
    assert!(
        select_participants(&names, &members, true, true)
            .unwrap_err()
            .to_string()
            .contains(DIRECT_WEBAUTHN_ERROR)
    );
    names.from_org_users.push("alice".parse().unwrap());
    assert!(
        select_participants(&names, &members, false, false)
            .unwrap_err()
            .to_string()
            .contains("duplicate organization holder")
    );
    names.from_org_users.pop();
    names.pgp_keys.push(PgpSelection {
        user: UserSelector::Id(members[1].user_id),
        key: members[1].pgp_keys[0].id,
    });
    assert!(
        select_participants(&names, &members, false, false)
            .unwrap_err()
            .to_string()
            .contains("distinct selected users")
    );
    names.pgp_keys.pop();
    names.from_org_users = vec!["alice".parse().unwrap()];
    assert!(
        select_participants(&names, &members, false, false)
            .unwrap_err()
            .to_string()
            .contains("distinct selected users")
    );
    names.pgp_keys = vec![PgpSelection {
        user: "alice".parse().unwrap(),
        key: members[1].pgp_keys[0].id,
    }];
    assert!(
        select_participants(&names, &members, false, false)
            .unwrap_err()
            .to_string()
            .contains("does not belong")
    );
}

#[test]
fn unknown_partial_and_ambiguous_names_are_rejected() {
    let first = Member {
        user_id: Uuid::new_v4(),
        username: "Alice".into(),
        pgp_keys: vec![],
        webauthn_credentials: 1,
    };
    for name in ["unknown", "ali"] {
        assert!(
            name.parse::<UserSelector>()
                .unwrap()
                .resolve(&[first.clone()])
                .err()
                .unwrap()
                .to_string()
                .contains("unknown")
        );
    }
    let second = Member {
        user_id: Uuid::new_v4(),
        username: "alice".into(),
        ..first.clone()
    };
    assert!(
        "alice"
            .parse::<UserSelector>()
            .unwrap()
            .resolve(&[first, second])
            .err()
            .unwrap()
            .to_string()
            .contains("ambiguous")
    );
}

#[test]
fn per_holder_custody_is_explicit_and_mixed() {
    let alice = Uuid::new_v4();
    let bob = Uuid::new_v4();
    let members = vec![
        Member {
            user_id: alice,
            username: "alice".into(),
            pgp_keys: vec![],
            webauthn_credentials: 1,
        },
        Member {
            user_id: bob,
            username: "bob".into(),
            pgp_keys: vec![RegisteredKey {
                id: Uuid::new_v4(),
                fingerprint: "bob-key".into(),
                public_key: "public certificate".into(),
            }],
            webauthn_credentials: 1,
        },
    ];
    let mut options = options(vec![]);
    options.holders = vec!["alice=webauthn".parse().unwrap()];
    assert_eq!(
        select_participants(&options, &members, false, false)
            .unwrap()
            .0[0]
            .key_source,
        "caution_backed_pgp"
    );
    options.holders = vec![
        "alice=webauthn".parse().unwrap(),
        "bob=external-pgp".parse().unwrap(),
    ];
    let (participants, _) = select_participants(&options, &members, false, false).unwrap();
    assert_eq!(participants.len(), 2);
    assert_eq!(participants[0].key_source, "caution_backed_pgp");
    assert_eq!(participants[1].key_source, "existing_pgp");
    assert_eq!(participants[1].pgp_key_id, Some(members[1].pgp_keys[0].id));
    options.holders = vec!["alice=external-pgp".parse().unwrap()];
    assert!(select_participants(&options, &members, false, false).is_err());
    options.holders = vec![
        "alice=webauthn".parse().unwrap(),
        "alice=webauthn".parse().unwrap(),
    ];
    assert!(select_participants(&options, &members, false, false).is_err());
    assert!("alice=pgp".parse::<HolderSelection>().is_err());
}

#[test]
fn holder_flags_parse_and_reject_mixed_selector_styles() {
    assert!(
        TestCli::try_parse_from([
            "caution",
            "init",
            "--holder",
            "alice=webauthn",
            "--holder",
            "bob=external-pgp"
        ])
        .is_ok()
    );
    assert!(
        TestCli::try_parse_from([
            "caution",
            "init",
            "--holder",
            "alice=webauthn",
            "--from-org-users",
            "bob"
        ])
        .is_err()
    );
    assert!(
        TestCli::try_parse_from([
            "caution",
            "init",
            "--holder",
            "alice=webauthn",
            "--caution-backed"
        ])
        .is_err()
    );
}
