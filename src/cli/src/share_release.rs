// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
use crate::{
    ApiClient, auth, output, prompt,
    quorum_init::{InitError, InitErrorCtx as Ctx},
};
use dterror::ResultExt;
use keymaker_models::generate_quorum::{GenerateQuorumResponse, v1::Key};
use locksmith::{
    models::SendSignedEncryptedShardResponse,
    release::{self, *},
};
use sequoia_openpgp::{Cert, cert::CertParser, parse::Parse};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{io::IsTerminal, path::PathBuf, time::Duration};

#[derive(clap::Args, Debug, Default)]
pub(crate) struct Options {
    /// Holder username or full certificate fingerprint; inferred when one candidate matches.
    #[arg(long)]
    pub holder: Option<String>,
    /// Custody enclave HTTP endpoint; identity is checked against --recryptor-pcr-policy.
    #[arg(long)]
    pub recryptor_url: Option<String>,
    /// Independently verified custody enclave PCR0/1/2 JSON policy.
    #[arg(long)]
    pub recryptor_pcr_policy: Option<PathBuf>,
}
pub(crate) type HolderNames = std::collections::BTreeMap<String, String>;

// Names are current registration metadata, never authorization evidence.
fn matched_names(bundle: &Value, rows: &[Value]) -> Option<HolderNames> {
    let keys = bundle.get("data").unwrap_or(bundle).get("keyring")?.as_array()?;
    let mut result = None;
    for row in rows.iter().filter(|row| row.get("data") == Some(bundle)) {
        let metadata = row.get("holders")?.as_array()?;
        if metadata.len() != keys.len() { return None; }
        let mut names = HolderNames::new();
        for (key, meta) in keys.iter().zip(metadata) {
            let (custody, entry) = if let Some(entry) = key.get("OpenPGP") {
                ("pgp", entry)
            } else { ("caution_backed", key.get("WebAuthn")?) };
            let cert = Cert::from_bytes(entry.get("cert")?.as_str()?.as_bytes()).ok()?;
            let fingerprint = cert.fingerprint().to_string();
            if meta.get("custody")?.as_str()? != custody
                || meta.get("fingerprint")?.as_str()? != fingerprint { return None; }
            if let Some(name) = meta.get("username").and_then(Value::as_str) {
                // Never render terminal controls received from display metadata.
                if !name.is_empty() && !name.chars().any(char::is_control) {
                    names.insert(fingerprint, name.to_owned());
                }
            }
        }
        if result.as_ref().is_some_and(|previous| previous != &names) { return None; }
        result = Some(names);
    }
    result
}

pub(crate) async fn holder_names(client: &ApiClient, bundle: &Value) -> HolderNames {
    let Ok(config) = client.require_existing_authenticated_config() else { return HolderNames::new(); };
    let lookup = async {
        let response = client.client.get(format!("{}/api/quorum-bundles", client.base_url))
            .header("X-Session-ID", &config.session_id).send().await.ok()?
            .error_for_status().ok()?;
        let rows: Vec<Value> = response.json().await.ok()?;
        matched_names(bundle, &rows)
    };
    tokio::time::timeout(Duration::from_secs(5), lookup).await.ok().flatten().unwrap_or_default()
}

pub(crate) fn holder_label(keys: &[Key], holder: &str, webauthn: bool, names: &HolderNames) -> String {
    let unique_name = names.get(holder).filter(|name| names.values().filter(|other| *other == *name).count() == 1);
    let kind = if webauthn { "Passkey" } else { "External PGP" };
    let short = if holder.len() > 12 { format!("{}…{}", &holder[..4], &holder[holder.len()-4..]) } else { holder.to_owned() };
    if let Some(name) = unique_name {
        if webauthn { format!("{name} · {kind}") } else { format!("{name} · {kind} · {short}") }
    } else {
        let index = keys.iter().position(|key| {
            let cert = match key { Key::OpenPGP { cert } | Key::WebAuthn { cert, .. } => cert };
            Cert::from_bytes(cert.as_bytes()).is_ok_and(|cert| cert.fingerprint().to_string() == holder)
        }).map_or(0, |index| index + 1);
        format!("Holder {index} · {kind} · {short}")
    }
}

pub(crate) fn select_holder(
    keys: &[Key],
    requested: Option<&str>,
    private_keyring: Option<&std::path::Path>,
    names: &HolderNames,
) -> Result<(String, bool), InitError> {
    let mut holders: Vec<_> = keys
        .iter()
        .map(|key| {
            let (cert, webauthn) = match key {
                Key::OpenPGP { cert } => (cert, false),
                Key::WebAuthn { cert, .. } => (cert, true),
            };
            let cert = Cert::from_bytes(cert.as_bytes())
                .with_context(Ctx::new("invalid holder certificate"))?;
            Ok((cert.fingerprint().to_string(), webauthn))
        })
        .collect::<Result<_, InitError>>()?;
    if let Some(requested) = requested {
        let normalized = requested.replace(' ', "").to_uppercase();
        let fingerprints: Vec<_> = holders.iter().filter(|h| h.0 == normalized).collect();
        let matched: Vec<_> = if fingerprints.is_empty() {
            holders.iter().filter(|h| names.get(&h.0).is_some_and(|name| name == requested)).collect()
        } else { fingerprints };
        return if matched.len() == 1 {
            Ok(matched[0].clone())
        } else {
            Err(InitError::invalid(
                "holder username or fingerprint must match exactly one bundle entry; use a full certificate fingerprint if names are unavailable or ambiguous",
            ))
        };
    }
    if let Some(path) = private_keyring {
        let bytes = std::fs::read(path)
            .with_context(Ctx::new("unable to read private keyring"))?;
        holders = matching_private_holders(holders, &bytes)?;
    }
    if holders.len() == 1 {
        return Ok(holders.remove(0));
    }
    if !std::io::stdin().is_terminal() {
        return Err(InitError::invalid(
            "select a holder with --holder USERNAME_OR_CERTIFICATE_FINGERPRINT",
        ));
    }
    for (index, (fingerprint, webauthn)) in holders.iter().enumerate() {
        eprintln!("{}: {}", index + 1, holder_label(keys, fingerprint, *webauthn, names));
    }
    let selected = prompt::select("Holder: ").with_context(Ctx::new("holder selection"))?;
    holders
        .get(selected.wrapping_sub(1))
        .cloned()
        .ok_or_else(|| InitError::invalid("invalid holder selection"))
}
fn matching_private_holders(
    holders: Vec<(String, bool)>,
    bytes: &[u8],
) -> Result<Vec<(String, bool)>, InitError> {
    let certs = CertParser::from_bytes(bytes)
        .with_context(Ctx::new("invalid private keyring"))?
        .collect::<sequoia_openpgp::Result<Vec<_>>>()
        .with_context(Ctx::new("invalid private keyring"))?;
    let matches: Vec<_> = holders.into_iter().filter(|(fingerprint, webauthn)| {
        !webauthn && certs.iter().any(|cert| {
            cert.is_tsk() && cert.fingerprint().to_string() == *fingerprint
        })
    }).collect();
    if matches.is_empty() {
        return Err(InitError::invalid("private keyring matches no external-PGP holder in this bundle"));
    }
    Ok(matches)
}

async fn post<T: Serialize, R: DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    request: &T,
) -> Result<R, InitError> {
    let response = client
        .post(url)
        .json(request)
        .send()
        .await
        .with_context(Ctx::new("release request failed"))?;
    let mut response = response.error_for_status().with_context(Ctx::new(
        "release request rejected; retry starts a fresh challenge",
    ))?;
    if response
        .content_length()
        .is_some_and(|n| n > 2 * 1024 * 1024)
    {
        return Err(InitError::invalid("release response too large"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(Ctx::new("read release response"))?
    {
        if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
            return Err(InitError::invalid("release response too large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).with_context(Ctx::new("invalid release response"))
}
fn comparison_code(hash: &str) -> String {
    hash.as_bytes().iter().take(16).copied().collect::<Vec<_>>().chunks(4)
        .map(|part| String::from_utf8_lossy(part).to_uppercase()).collect::<Vec<_>>().join(" ")
}

async fn browser_assertion(
    client: &ApiClient,
    prepared: &Attested<Prepared>,
    nonce: &str,
    display: &Value,
) -> Result<webauthn_rs_proto::PublicKeyCredential, InitError> {
    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::new("release relay authentication"))?;
    let request = json!({"prepared": prepared, "nonce": nonce, "display":display});
    let response = client
        .client
        .post(format!("{}/auth/qr-release/begin", client.base_url))
        .header("X-Session-ID", &config.session_id)
        .json(&request)
        .send()
        .await
        .with_context(Ctx::new("begin release relay"))?
        .error_for_status()
        .with_context(Ctx::new("release relay rejected"))?;
    let response: Value = response
        .json()
        .await
        .with_context(Ctx::new("release relay response"))?;
    let token = response["token"]
        .as_str()
        .ok_or_else(|| InitError::invalid("missing relay token"))?;
    let url = response["url"]
        .as_str()
        .ok_or_else(|| InitError::invalid("missing approval URL"))?;
    // The approval UI must be the configured Platform origin, not an arbitrary returned link.
    if !url.starts_with(&format!(
        "{}/qr-release#",
        client.frontend_url().trim_end_matches('/')
    )) {
        return Err(InitError::invalid("unexpected approval origin"));
    }
    auth::render_qr_code(url).with_context(Ctx::new("render release QR"))?;
    output::status(format!(
        "Approve on your phone or open in your browser: {url}"
    ));
    let result = async {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let result: Value = post(
                &client.client,
                &format!("{}/auth/qr-release/status", client.base_url),
                &json!({"token":token}),
            )
            .await?;
            match result["status"].as_str() {
                Some("pending") => {}
                Some("complete") => {
                    return serde_json::from_value(result["assertion"].clone())
                        .with_context(Ctx::new("browser assertion"));
                }
                _ => return Err(InitError::invalid("release approval cancelled")),
            }
        }
    }
    .await;
    let _ = client
        .client
        .post(format!("{}/auth/qr-release/cancel", client.base_url))
        .json(&json!({"token":token}))
        .send()
        .await;
    result
}
pub(crate) async fn recover(
    client: &ApiClient,
    options: &Options,
    bundle: GenerateQuorumResponse,
    holder: String,
    holder_display: String,
    application_id: String,
    address: std::net::SocketAddr,
    destination_policy: Measurements,
    generation_time: Option<std::time::SystemTime>,
) -> Result<SendSignedEncryptedShardResponse, InitError> {
    tokio::select! {
        result = tokio::time::timeout(release::TTL, recover_inner(client, options, bundle, holder, holder_display, application_id, address, destination_policy, generation_time)) =>
            result.with_context(Ctx::new("release attempt expired; start a fresh attempt"))?,
        _ = tokio::signal::ctrl_c() => Err(InitError::invalid("release cancelled")),
    }
}
async fn recover_inner(
    client: &ApiClient,
    options: &Options,
    bundle: GenerateQuorumResponse,
    holder: String,
    holder_display: String,
    application_id: String,
    address: std::net::SocketAddr,
    destination_policy: Measurements,
    generation_time: Option<std::time::SystemTime>,
) -> Result<SendSignedEncryptedShardResponse, InitError> {
    let url = options
        .recryptor_url
        .clone()
        .or_else(|| std::env::var("RECRYPTOR_URL").ok())
        .ok_or_else(|| InitError::invalid("specify --recryptor-url or RECRYPTOR_URL"))?;
    let policy_path = options
        .recryptor_pcr_policy
        .clone()
        .unwrap_or_else(|| PathBuf::from(".caution/recryptor-pcr-policy.json"));
    let policy = crate::quorum_init::load_policy(&policy_path)?;
    // Release uses one current live identity, not a generation-time historical policy.
    if policy.sets.len() != 1 || policy.sets[0].expires_at_unix_seconds.is_some() {
        return Err(InitError::invalid(
            "recryptor live policy requires one non-expiring PCR set",
        ));
    }
    let trusted: Measurements = policy.sets[0]
        .pcrs
        .iter()
        .map(|(&i, v)| (i, hex::encode(v)))
        .collect();
    release::pcrs(&trusted).with_context(Ctx::new("recryptor PCR policy"))?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .with_context(Ctx::new("release HTTP client"))?;
    let begin = BeginRequest {
        version: Version::V1,
        bundle: bundle.clone(),
        holder: holder.clone(),
        destination_policy,
        client_nonce: release::random_nonce(),
    };
    let begun: Attested<Begun> = post(
        &http,
        &format!("{}/v1/releases/begin", url.trim_end_matches('/')),
        &begin,
    )
    .await?;
    release::verify_response(&begun, &trusted, &begin.client_nonce)
        .with_context(Ctx::new("verify custody enclave"))?;
    if begun.data.request_hash != release::hash(&begin).with_context(Ctx::new("begin binding"))? {
        return Err(InitError::invalid("release begin request was substituted"));
    }
    let destination =
        release::crypto::Destination::connect(address, begun.data.context.transport_nonce.clone())
            .await
            .with_context(Ctx::new("connect destination session"))?;
    let key = release::verify_live(
        &destination.attestation,
        &begin.destination_policy,
        &begun.data.context.transport_nonce,
    )
    .with_context(Ctx::new("verify destination enclave"))?;
    let prepare = PrepareRequest {
        version: Version::V1,
        session_id: begun.data.session_id.clone(),
        destination_attestation: destination.attestation.clone(),
        client_nonce: release::random_nonce(),
    };
    let prepared: Attested<Prepared> = post(
        &http,
        &format!("{}/v1/releases/prepare", url.trim_end_matches('/')),
        &prepare,
    )
    .await?;
    release::verify_response(&prepared, &trusted, &prepare.client_nonce)
        .with_context(Ctx::new("verify attested approval challenge"))?;
    if prepared.data.request_hash
        != release::hash(&prepare).with_context(Ctx::new("prepare binding"))?
        || prepared.data.context != begun.data.context
        || prepared.data.session_id != begun.data.session_id
        || prepared.data.destination_key.as_slice() != key
        || prepared.data.destination_attestation_hash
            != release::hash(&destination.attestation)
                .with_context(Ctx::new("destination binding"))?
    {
        return Err(InitError::invalid("release context was substituted"));
    }
    let attested_prepared = prepared;
    let prepared = &attested_prepared.data;
    output::status(format!(
        "Release one share: bundle {}; holder {}",
        hex::encode(prepared.context.bundle_id),
        holder_display
    ));
    output::status(format!(
        "Verified destination {address}; key {}",
        hex::encode(prepared.destination_key)
    ));
    output::status(format!(
        "Release context hash: {}",
        release::hash(&prepared).with_context(Ctx::new("approval hash"))?
    ));
    let context_hash = release::hash(&prepared).with_context(Ctx::new("approval hash"))?;
    let comparison = comparison_code(&context_hash);
    output::status(format!("Compare with browser: {comparison} (release context only; excludes descriptive app labels)"));
    output::status(format!("Application: {application_id}; CLI-reported destination: {address}; custody URL: {url}"));
    let approval = async {
        if client.qr {
            browser_assertion(client, &attested_prepared, &prepare.client_nonce, &json!({
                "application_id":application_id, "destination_address":address.to_string(), "custody_url":url,
            })).await
        } else {
            let client = client.clone();
            let options: auth::LoginBeginResponse = serde_json::from_value(
                serde_json::to_value(&prepared.options)
                    .with_context(Ctx::new("approval options"))?,
            )
            .with_context(Ctx::new("native approval options"))?;
            tokio::task::spawn_blocking(move || {
                let assertion = auth::get_assertion(&client, &options, &client.frontend_url())
                    .with_context(Ctx::new("native release approval"))?;
                serde_json::from_slice(&assertion.response_json)
                    .with_context(Ctx::new("native assertion"))
            })
            .await
            .with_context(Ctx::new("native approval task"))?
        }
    };
    let assertion = tokio::select! {
        result=approval=>result?,
        _=destination.disconnected()=>return Err(InitError::invalid("destination disconnected; start a fresh attempt")),
    };
    let complete = CompleteRequest {
        version: Version::V1,
        session_id: prepared.session_id.clone(),
        assertion,
    };
    let encrypted = post(
        &http,
        &format!("{}/v1/releases/complete", url.trim_end_matches('/')),
        &complete,
    )
    .await?;
    let latest = bundle.data.to_latest();
    let Some(Key::WebAuthn { cert, .. }) = latest
        .keyring
        .get(usize::from(prepared.context.holder_position))
    else {
        return Err(InitError::invalid("unexpected release holder"));
    };
    let generation_time = locksmith::custody::generation_time(generation_time)
        .with_context(Ctx::new("authenticated bundle generation time required"))?;
    release::crypto::verify_request(cert, &encrypted, generation_time)
        .with_context(Ctx::new("verify holder signature"))?;
    destination
        .send(encrypted)
        .await
        .with_context(Ctx::new("send recrypted share"))
}

#[cfg(test)]
mod holder_selection_tests {
    use super::*;
    use sequoia_openpgp::{cert::CertBuilder, serialize::Serialize};

    #[test]
    fn comparison_prefix_matches_browser_format() {
        assert_eq!(comparison_code(&format!("edcd12bf40e1c288{}", "0".repeat(48))), "EDCD 12BF 40E1 C288");
    }

    fn fixture() -> (Vec<Key>, Value, Value) {
        let mut keys = Vec::new();
        let mut metadata = Vec::new();
        for (name, webauthn) in [("alice", false), ("bob", true)] {
            let (cert, _) = CertBuilder::general_purpose(None, Some(name)).generate().unwrap();
            let mut armor = Vec::new();
            cert.armored().serialize(&mut armor).unwrap();
            let cert_text = String::from_utf8(armor).unwrap();
            keys.push(if webauthn { Key::WebAuthn { cert: cert_text, credential: vec!["first".into(), "second".into()] } } else { Key::OpenPGP { cert: cert_text } });
            metadata.push(json!({"custody":if webauthn {"caution_backed"} else {"pgp"},"fingerprint":cert.fingerprint().to_string(),"username":name}));
        }
        let bundle = json!({"data":{"keyring":keys},"necroproof":"proof"});
        let row = json!({"data":bundle,"holders":metadata});
        (keys, bundle, row)
    }

    #[test]
    fn names_select_exact_entries_and_labels_hide_passkey_fingerprints() {
        let (keys, bundle, row) = fixture();
        let names = matched_names(&bundle, &[row]).unwrap();
        let (fp, webauthn) = select_holder(&keys, Some("bob"), None, &names).unwrap();
        assert!(webauthn);
        assert_eq!(holder_label(&keys, &fp, true, &names), "bob · Passkey");
        assert_eq!(select_holder(&keys, Some(&fp), None, &names).unwrap(), (fp.clone(), true));
        assert!(select_holder(&keys, Some("Bob"), None, &names).is_err());
        let pgp = select_holder(&keys, Some("alice"), None, &names).unwrap();
        assert!(holder_label(&keys, &pgp.0, false, &names).starts_with("alice · External PGP · "));
        let duplicate = names.keys().map(|key| (key.clone(), "same".into())).collect();
        assert!(select_holder(&keys, Some("same"), None, &duplicate).is_err());
        assert!(holder_label(&keys, &fp, true, &duplicate).starts_with("Holder 2 · Passkey · "));
        assert_eq!(select_holder(&keys[1..], None, None, &HolderNames::new()).unwrap(), (fp, true));
    }

    #[test]
    fn metadata_must_match_complete_bundle_and_each_holder() {
        let (_, bundle, row) = fixture();
        for field in ["custody", "fingerprint"] {
            let mut altered = row.clone();
            altered["holders"][0][field] = json!("wrong");
            assert!(matched_names(&bundle, &[altered]).is_none());
        }
        let mut altered = row.clone();
        altered["data"]["necroproof"] = json!("different proof");
        assert!(matched_names(&bundle, &[altered]).is_none());
        let mut altered = row.clone();
        altered["holders"].as_array_mut().unwrap().pop();
        assert!(matched_names(&bundle, &[altered]).is_none());
        let mut absent = row.clone();
        absent.as_object_mut().unwrap().remove("holders");
        assert!(matched_names(&bundle, &[absent]).is_none());
        let mut removed = row.clone();
        removed["holders"][0]["username"] = Value::Null;
        assert_eq!(matched_names(&bundle, &[removed]).unwrap().len(), 1);
        let mut renamed = row.clone();
        renamed["holders"][0]["username"] = json!("different");
        assert!(matched_names(&bundle, &[row, renamed]).is_none());
    }

    #[tokio::test]
    async fn names_are_optional_without_session_or_when_api_fails() {
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let client = ApiClient {
            base_url: base_url.clone(), client: reqwest::Client::new(),
            config_path: dir.path().join("config.json"), deployment_path: None,
            verbose: false, qr: false, workdir: None,
        };
        assert!(holder_names(&client, &json!({})).await.is_empty());
        std::fs::write(&client.config_path, json!({"session_id":"test", "expires_at":"2099-01-01T00:00:00Z", "server_url":base_url}).to_string()).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut request = [0; 4096];
            let n = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..n]).starts_with("GET /api/quorum-bundles "));
            stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        assert!(holder_names(&client, &json!({})).await.is_empty());
        server.join().unwrap();
    }

    #[tokio::test]
    #[ignore = "run make test-quorum-mock"]
    async fn real_api_metadata_names_downloaded_holders() {
        let work = PathBuf::from(std::env::var("QUORUM_RECOVERY_TEST_DIR").unwrap());
        for file in ["webauthn.json", "mixed.json"] {
            let bundle: Value = serde_json::from_slice(&std::fs::read(work.join(file)).unwrap()).unwrap();
            let rows: Vec<Value> = serde_json::from_slice(&std::fs::read(work.join(format!("{file}.holders"))).unwrap()).unwrap();
            let names = matched_names(&bundle, &rows).unwrap();
            assert!(!names.is_empty());
            let keys: Vec<Key> = serde_json::from_value(bundle["data"]["keyring"].clone()).unwrap();
            for (fp, name) in &names {
                let selected = select_holder(&keys, Some(name), None, &names);
                if names.values().filter(|other| *other == name).count() == 1 {
                    assert_eq!(&selected.unwrap().0, fp);
                } else { assert!(selected.is_err()); }
            }
        }
    }

    #[test]
    fn keyring_filters_external_private_identities_and_preserves_ambiguity() {
        let (a, _) = CertBuilder::general_purpose(None, Some("a@example.test")).generate().unwrap();
        let (b, _) = CertBuilder::general_purpose(None, Some("b@example.test")).generate().unwrap();
        let holders = vec![(a.fingerprint().to_string(), false), (b.fingerprint().to_string(), false)];
        let mut bytes = Vec::new();
        a.as_tsk().serialize(&mut bytes).unwrap();
        assert_eq!(matching_private_holders(holders.clone(), &bytes).unwrap(), vec![holders[0].clone()]);
        b.as_tsk().serialize(&mut bytes).unwrap();
        assert_eq!(matching_private_holders(holders.clone(), &bytes).unwrap(), holders);
        assert!(matching_private_holders(vec![(a.fingerprint().to_string(), true)], &bytes).is_err());
        let mut public = Vec::new();
        a.serialize(&mut public).unwrap();
        assert!(matching_private_holders(holders.clone(), &public).is_err());
        assert!(matching_private_holders(holders, b"malformed").is_err());
    }

    #[test]
    fn unique_keyring_match_needs_no_prompt_and_explicit_holder_has_precedence() {
        let (cert, _) = CertBuilder::general_purpose(None, Some("holder@example.test")).generate().unwrap();
        let mut public = Vec::new();
        cert.armored().serialize(&mut public).unwrap();
        let keys = vec![Key::OpenPGP { cert: String::from_utf8(public).unwrap() }];
        let mut secret = Vec::new();
        cert.as_tsk().serialize(&mut secret).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private.asc");
        std::fs::write(&path, secret).unwrap();
        let expected = (cert.fingerprint().to_string(), false);
        assert_eq!(select_holder(&keys, None, Some(&path), &HolderNames::new()).unwrap(), expected);
        assert_eq!(select_holder(&keys, Some(&expected.0), Some(&directory.path().join("absent")), &HolderNames::new()).unwrap(), expected);
        assert!(select_holder(&keys, Some("DEADBEEF"), Some(&path), &HolderNames::new()).is_err());
    }
}
