//! Current CLI coverage retained from the retired secret-new shell suite.
use super::*;
use std::process::Output;

fn invoke(work: &Path, args: &[&str]) -> Output {
    Command::new(std::env::var("QUORUM_CLI").unwrap())
        .current_dir(work)
        .env_remove("KEYMAKER_URL")
        .stdin(Stdio::null())
        .args(args)
        .output()
        .unwrap()
}

fn succeeds(output: Output) -> Output {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

pub(super) fn run(work: &Path) {
    let directory = work.join("cli-creation");
    fs::create_dir(&directory).unwrap();
    for name in ["alice", "bob"] {
        succeeds(invoke(
            &directory,
            &[
                "secret",
                "keygen",
                "--name",
                name,
                "--email",
                &[name, "@example.test"].concat(),
                "--shoot-self-in-foot",
                &[name, ".asc"].concat(),
            ],
        ));
    }
    let keyring = [
        fs::read(directory.join("alice.asc")).unwrap(),
        fs::read(directory.join("bob.asc")).unwrap(),
    ]
    .concat();
    fs::write(directory.join("holders.asc"), keyring).unwrap();
    let endpoint = std::env::var("KEYMAKER_URL").unwrap();
    let policy = work.join("policies/keymaker-pcr-policy.json");
    // Exercise the supported `new` alias with real CLI-generated public keys.
    let output = succeeds(invoke(
        &directory,
        &[
            "secret",
            "new",
            "holders.asc",
            "--threshold",
            "2",
            "--max",
            "2",
            "--no-upload",
            "--keymaker-url",
            &endpoint,
            "--keymaker-pcr-policy",
            policy.to_str().unwrap(),
        ],
    ));
    let bundle_path = directory.join(".caution/quorum-bundle.json");
    let saved = fs::read(&bundle_path).unwrap();
    let bundle: Value = serde_json::from_slice(&saved).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        bundle
    );
    assert_eq!(bundle["data"]["threshold"], 2);
    assert_eq!(bundle["data"]["max"], 2);
    assert_eq!(bundle["data"]["keyring"].as_array().unwrap().len(), 2);
    for (index, name) in ["alice.asc", "bob.asc"].iter().enumerate() {
        assert_eq!(
            bundle["data"]["keyring"][index]["OpenPGP"]["cert"],
            fs::read_to_string(directory.join(name)).unwrap()
        );
    }
    let incomplete = CertBuilder::new()
        .add_userid("ineligible test holder")
        .add_authentication_subkey()
        .add_storage_encryption_subkey()
        .generate()
        .unwrap()
        .0;
    let mut armor = Vec::new();
    incomplete.armored().serialize(&mut armor).unwrap();
    fs::write(directory.join("ineligible.asc"), armor).unwrap();
    fs::write(directory.join("malformed.asc"), "not a PGP certificate").unwrap();
    let calls = fs::read_to_string(work.join("keymaker-requests.jsonl")).unwrap();
    for (name, message) in [
        ("missing.asc", "unable to read local PGP keyring"),
        ("malformed.asc", "invalid PGP"),
        (
            "ineligible.asc",
            "each PGP holder needs signing, authentication and storage-encryption keys",
        ),
    ] {
        let output = invoke(
            &directory,
            &[
                "secret",
                "init",
                name,
                "--no-upload",
                "--keymaker-url",
                &endpoint,
                "--keymaker-pcr-policy",
                policy.to_str().unwrap(),
            ],
        );
        assert!(!output.status.success(), "invalid input accepted: {name}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(&bundle_path).unwrap(), saved);
    }
    let output = invoke(&directory, &["secret", "new", "holders.asc", "--no-upload"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("--no-upload is only supported with a direct PGP-only Keymaker"));
    assert_eq!(
        fs::read_to_string(work.join("keymaker-requests.jsonl")).unwrap(),
        calls,
        "invalid CLI input reached Keymaker"
    );
    println!("PASS: CLI keygen -> concatenated public keys -> secret new, threshold/count, saved/piped bundle and invalid-input rejection");
}
