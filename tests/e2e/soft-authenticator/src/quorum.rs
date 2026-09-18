//! Opt-in PGP quorum integration; signatures use the registered software passkey.
use super::*;
#[path = "quorum_caution.rs"]
mod caution;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use reqwest::{
    blocking::{Client, Response},
    Method,
};
use sequoia_openpgp::{cert::CertBuilder, serialize::Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
};

fn checked(response: Response) -> Result<Response> {
    if !response.status().is_success() {
        bail!(
            "quorum request -> {}: {}",
            response.status(),
            response.text()?
        );
    }
    Ok(response)
}

struct Session<'a> {
    http: &'a Client,
    authenticator: &'a mut WebauthnAuthenticator<SoftPasskey>,
    origin: &'a Url,
    base: &'a str,
    id: &'a str,
}
impl Session<'_> {
    fn signed(&mut self, method: Method, path: &str, body: &str) -> Result<Response> {
        self.signed_at(method, path, body, "/api")
    }
    fn signed_at(&mut self, method: Method, path: &str, body: &str, prefix: &str) -> Result<Response> {
        let hash = Sha256::digest(body.as_bytes());
        let body_hash: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        let challenge: Value = checked(
            self.http
                .post([self.base, "/auth/sign-request"].concat())
                .header("X-Session-ID", self.id)
                .json(&json!({"method":method.as_str(), "path":path, "body_hash":body_hash}))
                .send()?,
        )?
        .json()?;
        let assertion = self
            .authenticator
            .do_authentication(
                self.origin.clone(),
                serde_json::from_value(challenge.clone())?,
            )
            .map_err(|e| anyhow::anyhow!("request signing failed: {e:?}"))?;
        Ok(self
            .http
            .request(method, [self.base, prefix, path].concat())
            .header("X-Session-ID", self.id)
            .header(
                "X-Fido2-Challenge-Id",
                challenge["challenge_id"]
                    .as_str()
                    .context("missing challenge ID")?,
            )
            .header(
                "X-Fido2-Response",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&assertion)?),
            )
            .header("Content-Type", "application/json")
            .body(body.to_owned())
            .send()?)
    }
    fn get(&self, path: &str) -> Result<Response> {
        Ok(self
            .http
            .get([self.base, "/api", path].concat())
            .header("X-Session-ID", self.id)
            .send()?)
    }
}

pub fn run(
    http: &Client,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
    origin: &Url,
    base: &str,
    id: &str,
    work: &Path,
) -> Result<()> {
    // An authenticated requester must not disguise a real login challenge as release approval.
    let mut login: Value = checked(http.post(format!("{base}/auth/login/begin"))
        .json(&json!({"username":"quorummock"})).send()?)?.json()?;
    login["publicKey"]["userVerification"] = json!("required");
    let forged = json!({"options":login, "context":{"holder":"victim"}, "context_hash":"invented"});
    let response = http.post(format!("{base}/auth/qr-release/begin"))
        .header("X-Session-ID", id).json(&forged).send()?;
    assert_eq!(response.status().as_u16(), 422, "unattested login challenge must not create an approval URL");
    println!("PASS: authenticated relay rejects a substituted real login challenge");

    let (cert, _) = CertBuilder::new()
        .add_userid("temporary quorum holder")
        .add_signing_subkey()
        .add_authentication_subkey()
        .add_storage_encryption_subkey()
        .generate()?;
    let mut bytes = Vec::new();
    cert.armored().serialize(&mut bytes)?;
    let cert = String::from_utf8(bytes)?;
    fs::write(work.join("holder.asc"), &cert)?;
    let mut session = Session {
        http,
        authenticator,
        origin,
        base,
        id,
    };
    let policy_path = work.join("policies/keymaker-pcr-policy.json");
    let policy = fs::read(&policy_path)?;
    fs::remove_file(&policy_path)?;
    let request = json!({"threshold":1, "pgp_certificates":[cert], "participants":[]}).to_string();
    for invalid in [false, true] {
        if invalid {
            fs::write(&policy_path, "{}").unwrap();
        }
        assert_eq!(
            session
                .signed(Method::POST, "/quorum-bundles/from-org-users", &request)?
                .status()
                .as_u16(),
            503
        );
        assert_eq!(
            checked(session.get("/quorum-bundles")?)?.json::<Value>()?,
            json!([])
        );
    }
    fs::write(&policy_path, policy)?;
    // The API creates the test organization; each request uses a fresh challenge.
    let mut first = None;
    for labels in [None, Some(Value::Null), Some(json!({"purpose":"mock-e2e"}))] {
        let mut body = json!({"threshold":1, "pgp_certificates":[cert], "participants":[]});
        if let Some(value) = labels.clone() {
            body["labels"] = value;
        }
        let created: Value = checked(session.signed(
            Method::POST,
            "/quorum-bundles/from-org-users",
            &body.to_string(),
        )?)?
        .json()?;
        assert_eq!(
            created["labels"],
            labels.filter(|v| !v.is_null()).unwrap_or(json!({}))
        );
        let bundle_id = created["id"].as_str().context("missing stored ID")?;
        let path = ["/quorum-bundles/", bundle_id].concat();
        let downloaded: Value = checked(session.get(&path)?)?.json()?;
        assert_eq!(downloaded["data"], created["data"]);
        if first.is_none() {
            first = Some(downloaded["data"].clone());
        }
        let unsigned = http
            .delete([base, "/api", &path].concat())
            .header("X-Session-ID", id)
            .header("X-Fido2-Signed", "true")
            .send()?;
        assert_eq!(unsigned.status().as_u16(), 403);
        assert_eq!(
            unsigned.text()?,
            "This operation requires signature verification"
        );
        assert_eq!(
            checked(session.signed(Method::DELETE, &path, "")?)?
                .status()
                .as_u16(),
            204
        );
        assert_eq!(session.get(&path)?.status().as_u16(), 404);
    }
    let bundle = first.unwrap();
    fs::write(
        work.join("downloaded.json"),
        serde_json::to_vec_pretty(&bundle)?,
    )?;
    let uploaded: Value = checked(session.signed(
        Method::POST,
        "/quorum-bundles",
        &json!({"data":bundle}).to_string(),
    )?)?
    .json()?;
    assert_eq!(uploaded["data"], bundle);
    assert_eq!(uploaded["labels"], json!({}));
    let path = ["/quorum-bundles/", uploaded["id"].as_str().unwrap()].concat();
    checked(session.signed(Method::DELETE, &path, "")?)?;
    let mut altered = bundle.clone();
    altered["data"]["public_key"] = json!("altered");
    assert_eq!(
        session
            .signed(
                Method::POST,
                "/quorum-bundles",
                &json!({"data":altered}).to_string()
            )?
            .status()
            .as_u16(),
        400
    );
    assert_eq!(
        checked(session.get("/quorum-bundles")?)?.json::<Value>()?,
        json!([])
    );

    let cli = std::env::var("QUORUM_CLI")?;
    // A plain directory must persist the bundle and policy too.
    assert!(!work.join("Procfile").exists());
    assert!(!work.join("caution.hcl").exists());
    let result = Command::new(&cli)
        .current_dir(work)
        .stdin(Stdio::null())
        .args([
            "secret",
            "init",
            "holder.asc",
            "--threshold",
            "1",
            "--no-upload",
            "--keymaker-url",
            &std::env::var("KEYMAKER_URL")?,
            "--keymaker-pcr-policy",
            "policies/keymaker-pcr-policy.json",
        ])
        .output()?;
    anyhow::ensure!(
        result.status.success(),
        "direct CLI: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let direct: Value =
        serde_json::from_slice(&fs::read(work.join(".caution/quorum-bundle.json"))?)?;
    assert_eq!(serde_json::from_slice::<Value>(&result.stdout)?, direct);
    assert_eq!(direct["data"]["keyring"][0]["OpenPGP"]["cert"], cert);
    // Resolve a real organization username and PGP override through participant discovery.
    let registered: Value = checked(session.signed_at(
        Method::POST,
        "/pgp-keys",
        &json!({"public_key": cert, "name": "username selection test"}).to_string(),
        "",
    )?)?
    .json()?;
    let key_id = registered["id"].as_str().context("registered key ID")?;
    let members: Value = checked(session.get("/quorum-bundles/participants")?)?.json()?;
    let member = members
        .as_array()
        .context("participant list")?
        .iter()
        .find(|m| {
            m["pgp_keys"]
                .as_array()
                .is_some_and(|keys| keys.iter().any(|k| k["id"] == key_id))
        })
        .context("registered participant")?;
    let username = member["username"].as_str().context("username")?;
    let home = work.join("username-cli-home");
    // dirs::config_dir uses Library/Application Support on macOS and XDG on Linux.
    for directory in [
        home.join("Library/Application Support/caution-cli"),
        home.join(".config/caution-cli"),
    ] {
        fs::create_dir_all(&directory)?;
        fs::write(
            directory.join("config.json"),
            json!({
                "session_id": id, "expires_at": "2099-01-01T00:00:00Z", "server_url": base
            })
            .to_string(),
        )?;
    }
    let fingerprint = member["pgp_keys"][0]["fingerprint"].as_str().context("registered fingerprint")?;
    let grouped = fingerprint.to_lowercase().as_bytes().chunks(4)
        .map(|part| std::str::from_utf8(part).unwrap().to_owned()).collect::<Vec<_>>().join(" ");
    for selector in [key_id.to_owned(), fingerprint.to_owned(), grouped] {
        let result = Command::new(&cli)
            .current_dir(work)
            .stdin(Stdio::null())
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .args([
                "--url",
                base,
                "secret",
                "init",
                "--from-org-users",
                username,
                "--pgp-key",
                &format!("{username}={selector}"),
                "--threshold",
                "1",
                "--no-upload",
                "--keymaker-url",
                &std::env::var("KEYMAKER_URL")?,
                "--keymaker-pcr-policy",
                "policies/keymaker-pcr-policy.json",
            ])
            .output()?;
        anyhow::ensure!(
            result.status.success(),
            "username CLI: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let output = String::from_utf8_lossy(&result.stderr);
        assert!(output.contains(&format!("{username} · External PGP · {fingerprint}")));
        assert!(!output.contains("existing_pgp"));
        assert!(!output.contains(key_id));
        assert!(!output.contains(member["user_id"].as_str().unwrap()));
        let named: Value =
            serde_json::from_slice(&fs::read(work.join(".caution/quorum-bundle.json"))?)?;
        assert_eq!(
            named["data"]["keyring"][0]["OpenPGP"]["cert"],
            member["pgp_keys"][0]["public_key"]
        );
    }
    checked(session.signed_at(Method::DELETE, &format!("/pgp-keys/{key_id}"), "", "")?)?;
    // Removed keys disappear from discovery and fail before the unreachable generator.
    let rejected = Command::new(&cli).current_dir(work).stdin(Stdio::null())
        .env("HOME", &home).env("XDG_CONFIG_HOME", home.join(".config"))
        .args(["--url", base, "secret", "init", "--holder", &format!("{username}=external-pgp"),
            "--pgp-key", &format!("{username}={fingerprint}"), "--threshold", "1", "--no-upload",
            "--keymaker-url", "http://127.0.0.1:9", "--keymaker-pcr-policy", "policies/keymaker-pcr-policy.json"])
        .output()?;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("active registered keys"));
    // The CLI must reject conflicting local inputs before contacting even an unavailable Keymaker.
    let saved_policy_path = work.join(".caution/keymaker-pcr-policy.json");
    let saved_policy = fs::read(&saved_policy_path)?;
    let saved_bundle = fs::read(work.join(".caution/quorum-bundle.json"))?;
    let mut different: Value = serde_json::from_slice(&saved_policy)?;
    different["sets"][0]["pcrs"]["0"] = json!("cd".repeat(48));
    for contents in [serde_json::to_vec(&different)?, b"malformed".to_vec()] {
        fs::write(&saved_policy_path, &contents)?;
        let rejected = Command::new(&cli)
            .current_dir(work)
            .stdin(Stdio::null())
            .args([
                "secret",
                "init",
                "holder.asc",
                "--threshold",
                "1",
                "--no-upload",
                "--keymaker-url",
                "http://127.0.0.1:9",
                "--keymaker-pcr-policy",
                "policies/keymaker-pcr-policy.json",
            ])
            .output()?;
        assert!(!rejected.status.success());
        assert!(
            String::from_utf8_lossy(&rejected.stderr).contains("saved local PCR policy")
                || String::from_utf8_lossy(&rejected.stderr).contains("saved local policy")
        );
        assert_eq!(fs::read(&saved_policy_path)?, contents);
        assert_eq!(
            fs::read(work.join(".caution/quorum-bundle.json"))?,
            saved_bundle
        );
    }
    fs::write(&saved_policy_path, saved_policy)?;
    let rejected = Command::new(&cli)
        .current_dir(work)
        .stdin(Stdio::null())
        .args([
            "secret",
            "init",
            "holder.asc",
            "--threshold",
            "1",
            "--no-upload",
            "--keymaker-url",
            "http://127.0.0.1:9",
            "--keymaker-pcr-policy",
            "policies/keymaker-pcr-policy.json",
            "--name",
            "prod",
            "--label",
            "name=staging",
        ])
        .output()?;
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("--name and label 'name' must match")
    );
    assert_eq!(
        fs::read(work.join(".caution/quorum-bundle.json"))?,
        saved_bundle
    );
    fs::write(
        work.join("secrets.env"),
        "QUORUM_TEST_SECRET=temporary-secret\n",
    )?;
    for source in ["downloaded.json", ".caution/quorum-bundle.json"] {
        let result = Command::new(&cli)
            .current_dir(work)
            .stdin(Stdio::null())
            .args([
                "secret",
                "encrypt",
                "--bundle",
                source,
                "--env-file",
                "secrets.env",
            ])
            .output()?;
        anyhow::ensure!(
            result.status.success(),
            "CLI encryption: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let encrypted = fs::read_to_string(work.join(".caution/secrets/QUORUM_TEST_SECRET.asc"))?;
        anyhow::ensure!(
            encrypted.contains("BEGIN PGP MESSAGE") && !encrypted.contains("temporary-secret")
        );
    }
    // Real local generation behind a request-altering intermediary, with synthetic proofs.
    let mut holders = vec![cert.clone()];
    for _ in 1..5 {
        let (holder, _) = CertBuilder::new()
            .add_userid("temporary downgrade-test holder")
            .add_signing_subkey()
            .add_authentication_subkey()
            .add_storage_encryption_subkey()
            .generate()?;
        let mut bytes = Vec::new();
        holder.armored().serialize(&mut bytes)?;
        holders.push(String::from_utf8(bytes)?);
    }
    fs::write(work.join("five-holders.asc"), holders.concat())?;
    let request = json!({"threshold":3, "pgp_certificates":holders, "participants":[]}).to_string();
    let created: Value =
        checked(session.signed(Method::POST, "/quorum-bundles/from-org-users", &request)?)?
            .json()?;
    assert_eq!(created["data"]["data"]["threshold"], 3);
    assert_eq!(created["data"]["data"]["max"], 5);
    checked(session.signed(
        Method::DELETE,
        &format!("/quorum-bundles/{}", created["id"].as_str().unwrap()),
        "",
    )?)?;

    fs::write(work.join("downgrade-threshold"), "")?;
    let rejected = session.signed(Method::POST, "/quorum-bundles/from-org-users", &request)?;
    assert_eq!(rejected.status().as_u16(), 502);
    assert!(rejected
        .text()?
        .contains("Keymaker response does not match the requested quorum"));
    assert_eq!(
        checked(session.get("/quorum-bundles")?)?.json::<Value>()?,
        json!([])
    );
    let saved = fs::read(work.join(".caution/quorum-bundle.json"))?;
    let rejected = Command::new(&cli)
        .current_dir(work)
        .stdin(Stdio::null())
        .args([
            "secret",
            "init",
            "five-holders.asc",
            "--threshold",
            "3",
            "--no-upload",
            "--keymaker-url",
            &std::env::var("KEYMAKER_URL")?,
            "--keymaker-pcr-policy",
            "policies/keymaker-pcr-policy.json",
        ])
        .output()?;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr)
        .contains("Keymaker response does not match the requested quorum"));
    assert_eq!(fs::read(work.join(".caution/quorum-bundle.json"))?, saved);
    assert_eq!(
        checked(session.get("/quorum-bundles")?)?.json::<Value>()?,
        json!([])
    );
    let downgraded: Value =
        serde_json::from_slice(&fs::read(work.join("downgraded-bundle.json"))?)?;
    assert_eq!(downgraded["data"]["threshold"], 1);
    assert_eq!(downgraded["data"]["max"], 5);
    // The response itself has a valid synthetic proof; rejection was the request mismatch.
    let accepted = Command::new(&cli)
        .current_dir(work)
        .stdin(Stdio::null())
        .args([
            "secret",
            "encrypt",
            "--bundle",
            "downgraded-bundle.json",
            "--env-file",
            "secrets.env",
        ])
        .output()?;
    anyhow::ensure!(
        accepted.status.success(),
        "downgraded proof: {}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    fs::remove_file(work.join("downgrade-threshold"))?;
    caution::run(&mut session, work, &cert)?;
    println!("PASS: signed API create/upload/download/delete, direct CLI, request-threshold downgrade rejection and downloaded-bundle encryption (mock proofs only)");
    Ok(())
}
