//! Frozen historical PGP bundle through the actual importer and signed storage API.
use super::*;

pub(super) fn run(session: &mut Session<'_>, work: &Path) -> Result<()> {
    let fixture = std::path::PathBuf::from(std::env::var("QUORUM_V0_FIXTURES")?);
    let cli = std::env::var("QUORUM_CLI")?;
    let output = work.join("v0-imported.json");
    let source = fs::read(fixture.join("bundle.json"))?;
    let import = || {
        Command::new(&cli)
            .current_dir(work)
            .stdin(Stdio::null())
            .args(["secret", "import-legacy", "--bundle"])
            .arg(fixture.join("bundle.json"))
            .arg("--keyring")
            .arg(fixture.join("alice.private.asc"))
            .arg("--output")
            .arg(&output)
            .output()
    };
    let result = import()?;
    anyhow::ensure!(
        result.status.success(),
        "legacy import: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        !import()?.status.success(),
        "import must refuse overwriting"
    );
    assert_eq!(fs::read(fixture.join("bundle.json"))?, source);
    let imported: Value = serde_json::from_slice(&fs::read(output)?)?;
    assert_eq!(
        imported,
        serde_json::from_slice::<Value>(&fs::read(fixture.join("imported.json"))?)?
    );
    let request = json!({"data":imported, "allow_legacy":true}).to_string();
    assert_eq!(
        session
            .http
            .post([session.base, "/api/quorum-bundles"].concat())
            .header("X-Session-ID", session.id)
            .header("Content-Type", "application/json")
            .body(request.clone())
            .send()?
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        session
            .signed(
                Method::POST,
                "/quorum-bundles",
                &json!({"data":imported}).to_string()
            )?
            .status()
            .as_u16(),
        400
    );
    let stored: Value =
        checked(session.signed(Method::POST, "/quorum-bundles", &request)?)?.json()?;
    let path = [
        "/quorum-bundles/",
        stored["id"].as_str().context("legacy row ID")?,
    ]
    .concat();
    assert_eq!(
        session
            .signed(Method::PATCH, &path, &json!({"data":imported}).to_string())?
            .status()
            .as_u16(),
        400
    );
    checked(session.signed(Method::PATCH, &path, &request)?)?;
    let downloaded: Value = checked(session.get(&path)?)?.json()?;
    assert_eq!(downloaded["data"], imported);
    assert_eq!(
        downloaded["holders"]
            .as_array()
            .context("legacy holder metadata")?
            .len(),
        2
    );
    anyhow::ensure!(
        downloaded["bundle_hash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    );
    let listed: Vec<Value> = checked(session.get("/quorum-bundles")?)?.json()?;
    assert!(
        listed
            .iter()
            .any(|row| row["id"] == stored["id"] && row["data"] == imported)
    );
    fs::write(
        work.join("v0-downloaded.json"),
        serde_json::to_vec_pretty(&downloaded["data"])?,
    )?;
    let inspected = Command::new(&cli)
        .current_dir(work)
        .stdin(Stdio::null())
        .args([
            "secret",
            "inspect",
            "--bundle",
            "v0-downloaded.json",
            "--unverified",
        ])
        .output()?;
    anyhow::ensure!(
        inspected.status.success(),
        "legacy inspect: {}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    assert!(
        String::from_utf8_lossy(&inspected.stderr)
            .contains("Legacy V0 — no Keymaker generation proof")
    );
    fs::write(
        work.join("legacy.env"),
        "LEGACY_ROUNDTRIP=legacy-roundtrip\n",
    )?;
    for allowed in [false, true] {
        let mut command = Command::new(&cli);
        command.current_dir(work).stdin(Stdio::null()).args([
            "secret",
            "encrypt",
            "--bundle",
            "v0-downloaded.json",
            "--env-file",
            "legacy.env",
        ]);
        if allowed {
            command.arg("--allow-legacy");
        }
        let result = command.output()?;
        anyhow::ensure!(
            result.status.success() == allowed,
            "legacy encrypt: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    // A valid V1 shape with an invalid proof must still fail with legacy acceptance.
    let mut invalid: Value = serde_json::from_slice(&fs::read(work.join("downloaded.json"))?)?;
    invalid["necroproof"] = json!([]);
    fs::write(
        work.join("v1-invalid-proof.json"),
        serde_json::to_vec(&invalid)?,
    )?;
    let rejected = Command::new(&cli)
        .current_dir(work)
        .stdin(Stdio::null())
        .args([
            "secret",
            "encrypt",
            "--bundle",
            "v1-invalid-proof.json",
            "--env-file",
            "legacy.env",
            "--allow-legacy",
        ])
        .output()?;
    assert!(!rejected.status.success());
    assert_eq!(
        session
            .signed(
                Method::POST,
                "/quorum-bundles",
                &json!({"data":invalid,"allow_legacy":true}).to_string()
            )?
            .status()
            .as_u16(),
        400
    );
    checked(session.signed(Method::DELETE, &path, "")?)?;
    println!(
        "PASS: V0 import, explicit signed upload/replacement, download, CLI encryption and V1 downgrade rejection"
    );
    Ok(())
}
