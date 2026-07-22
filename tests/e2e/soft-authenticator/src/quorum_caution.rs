//! Caution custody creation only. The mock uses real PGP signatures, synthetic Nitro evidence.
use super::*;
use std::io::Write;

fn keymaker_calls(work: &Path) -> usize {
    fs::read_to_string(work.join("keymaker-requests.jsonl"))
        .unwrap_or_default()
        .lines()
        .count()
}

fn add_passkey(session: &mut Session<'_>) -> Result<Vec<Vec<u8>>> {
    let begin: Value = checked(session.signed_at(
        Method::POST,
        "/passkeys/register/begin",
        r#"{"name":"second test passkey"}"#,
        "",
    )?)?
    .json()?;
    let mut second = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let credential = second
        .do_registration(
            session.origin.clone(),
            serde_json::from_value(begin.clone())?,
        )
        .map_err(|e| anyhow::anyhow!("second registration: {e:?}"))?;
    let mut finish = serde_json::to_value(credential)?;
    finish["session"] = begin["session"].clone();
    checked(
        session
            .http
            .post(format!("{}/passkeys/register/finish", session.base))
            .header("X-Session-ID", session.id)
            .json(&finish)
            .send()?,
    )?;
    let keys: Value = checked(
        session
            .http
            .get(format!("{}/passkeys", session.base))
            .header("X-Session-ID", session.id)
            .send()?,
    )?
    .json()?;
    let mut ids = keys
        .as_array()
        .context("passkey list")?
        .iter()
        .map(|k| hex::decode(k["credential_id"].as_str().unwrap()).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;
    ids.sort();
    assert_eq!(ids.len(), 2);
    Ok(ids)
}

fn seed_other_holder(creator: &str) -> Result<&'static str> {
    // The second holder need not authorize creation. Seed a distinct throwaway
    // public credential, as in the DB suite; creator authorization uses real ceremonies.
    let other = "00000000-0000-4000-8000-000000000002";
    let mut credential: Value = serde_json::from_str(include_str!(
        "../../../../src/api/src/org_quorum/test-credential.json"
    ))?;
    credential["cred"]["cred_id"] = json!("AQ");
    let public_key = hex::encode(serde_json::to_vec(&credential)?);
    let mut child = Command::new("docker")
        .args([
            "exec",
            "-i",
            &std::env::var("QUORUM_DB_CONTAINER")?,
            "psql",
            "-U",
            "postgres",
            "-d",
            "caution_quorum_test",
            "-v",
            "ON_ERROR_STOP=1",
            "-v",
            &format!("creator={creator}"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    write!(child.stdin.take().unwrap(), "INSERT INTO users(id, username) VALUES ('{other}', 'quorumsecond');
        INSERT INTO organization_members(organization_id, user_id)
        SELECT organization_id, '{other}' FROM organization_members WHERE user_id = :'creator'::uuid;
        INSERT INTO fido2_credentials(user_id, credential_id, public_key)
        VALUES ('{other}', decode('01','hex'), decode('{public_key}','hex'));\n")?;
    anyhow::ensure!(child.wait()?.success(), "seed second holder");
    Ok(other)
}

pub(super) fn run(session: &mut Session<'_>, work: &Path, pgp: &str) -> Result<()> {
    let credential_ids = add_passkey(session)?;
    let members: Value = checked(session.get("/quorum-bundles/participants")?)?.json()?;
    let user = members
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["username"] == "quorummock")
        .unwrap()["user_id"]
        .as_str()
        .unwrap();
    let other = seed_other_holder(user)?;
    let participants = json!([
        {"user_id":user, "key_source":"caution_backed_pgp"},
        {"user_id":other, "key_source":"caution_backed_pgp"},
    ]);
    let request = json!({"threshold":2, "participants":participants, "allow_caution_backed_keys":true, "labels":{"purpose":"mock custody"}});
    let before = keymaker_calls(work);
    for mode in [
        "wrong-ca",
        "wrong-org",
        "wrong-bundle",
        "wrong-count",
        "wrong-index",
        "reordered",
        "duplicate",
        "bad-signature",
        "missing-notation",
        "ineligible",
        "wrong-proof",
        "503",
    ] {
        fs::write(work.join("certificate-mode"), mode)?;
        let result = session.signed(
            Method::POST,
            "/quorum-bundles/from-org-users",
            &request.to_string(),
        )?;
        let status = result.status().as_u16();
        let body = result.text()?;
        anyhow::ensure!(
            status == if mode == "503" { 503 } else { 502 },
            "{mode}: {status}: {body}"
        );
        assert_eq!(keymaker_calls(work), before, "{mode} reached Keymaker");
        assert_eq!(
            checked(session.get("/quorum-bundles")?)?.json::<Value>()?,
            json!([])
        );
    }
    fs::remove_file(work.join("certificate-mode"))?;
    let policy_path = work.join("policies/certificate-pcr-policy.json");
    let policy = fs::read(&policy_path)?;
    for invalid in [None, Some(b"{}".as_slice())] {
        match invalid {
            None => fs::remove_file(&policy_path)?,
            Some(bytes) => fs::write(&policy_path, bytes)?,
        }
        assert_eq!(
            session
                .signed(
                    Method::POST,
                    "/quorum-bundles/from-org-users",
                    &request.to_string()
                )?
                .status()
                .as_u16(),
            503
        );
        assert_eq!(keymaker_calls(work), before);
        assert_eq!(
            checked(session.get("/quorum-bundles")?)?.json::<Value>()?,
            json!([])
        );
    }
    fs::write(&policy_path, policy)?;

    for mixed in [false, true] {
        let mut request = request.clone();
        if mixed {
            request["pgp_certificates"] = json!([pgp]);
        }
        let created: Value = checked(session.signed(
            Method::POST,
            "/quorum-bundles/from-org-users",
            &request.to_string(),
        )?)?
        .json()?;
        let path = format!("/quorum-bundles/{}", created["id"].as_str().unwrap());
        let downloaded: Value = checked(session.get(&path)?)?.json()?;
        assert_eq!(downloaded["data"], created["data"]);
        let data = &downloaded["data"]["data"];
        let response: Value =
            serde_json::from_slice(&fs::read(work.join("certificate-response.json"))?)?;
        let service_request: Value =
            serde_json::from_slice(&fs::read(work.join("certificate-request.json"))?)?;
        assert_eq!(service_request["certificate_count"], 2);
        assert_eq!(
            service_request["organization_id"],
            response["data"]["organization_id"]
        );
        assert_eq!(data["bundle_id"], response["data"]["bundle_id"]);
        assert_eq!(data["threshold"], 2);
        assert_eq!(data["max"], if mixed { 3 } else { 2 });
        let offset = usize::from(mixed);
        if mixed {
            assert_eq!(data["keyring"][0]["OpenPGP"]["cert"], pgp);
        }
        for index in 0..2 {
            assert_eq!(
                data["keyring"][offset + index]["WebAuthn"]["cert"],
                response["data"]["certificates"][index]
            );
        }
        let bindings = data["keyring"][offset]["WebAuthn"]["credential"]
            .as_array()
            .unwrap();
        let ids = bindings
            .iter()
            .map(|c| {
                let c: Value = serde_json::from_str(c.as_str().unwrap()).unwrap();
                URL_SAFE_NO_PAD
                    .decode(c["cred"]["cred_id"].as_str().unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(ids, credential_ids);
        assert_eq!(
            data["keyring"][offset + 1]["WebAuthn"]["credential"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let name = if mixed { "mixed.json" } else { "webauthn.json" };
        fs::write(work.join(name), serde_json::to_vec(&downloaded["data"])?)?;
        let encrypted = Command::new(std::env::var("QUORUM_CLI")?)
            .current_dir(work)
            .stdin(Stdio::null())
            .args([
                "secret",
                "encrypt",
                "--bundle",
                name,
                "--env-file",
                "secrets.env",
            ])
            .output()?;
        anyhow::ensure!(
            encrypted.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&encrypted.stderr)
        );
        checked(session.signed(Method::DELETE, &path, "")?)?;
    }
    println!("PASS: signed WebAuthn/mixed creation, CA/context rejection before Keymaker, credential bindings and downloaded-bundle encryption (mock proofs only)");
    Ok(())
}
