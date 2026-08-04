// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use bootproof_sdk::{
    format::nitro::{Nitro, NitroPcrs},
    VerifiableSignedAttestationFormat,
};
use coset::{CborSerializable, CoseSign1};
use rand::RngCore;
use reqwest::{tls::TlsInfo, Client, StatusCode, Url};
use serde::Deserialize;
use serde_cbor::Value as CborValue;
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PUBLISHER_RETRY: Duration = Duration::from_secs(65);

#[derive(Deserialize)]
struct AttestationResponse {
    #[serde(alias = "document")]
    attestation_document: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserData {
    tls: TlsMetadata,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsMetadata {
    mode: String,
    domain: String,
    certfp: String,
}

fn observed_pcrs(document: &[u8]) -> Result<NitroPcrs> {
    let cose = CoseSign1::from_slice(document)
        .map_err(|error| anyhow::anyhow!("invalid COSE_Sign1 document: {error:?}"))?;
    let payload = cose
        .payload
        .context("attestation document has no payload")?;
    let payload: CborValue = serde_cbor::from_slice(&payload).context("invalid Nitro payload")?;
    let CborValue::Map(payload) = payload else {
        bail!("Nitro payload is not a CBOR map");
    };
    let Some(CborValue::Map(pcrs)) = payload.get(&CborValue::Text("pcrs".into())) else {
        bail!("Nitro payload has no PCR map");
    };

    [0u8, 1, 2]
        .into_iter()
        .map(|index| {
            let Some(CborValue::Bytes(value)) = pcrs.get(&CborValue::Integer(i128::from(index)))
            else {
                bail!("Nitro payload has no PCR{index}");
            };
            ensure!(value.len() == 48, "PCR{index} is not a SHA-384 value");
            ensure!(
                value.iter().any(|byte| *byte != 0),
                "PCR{index} is zero: enclave is in debug mode"
            );
            Ok((index, value.clone()))
        })
        .collect()
}

fn verified_user_data(payload: &CborValue) -> Result<Option<UserData>> {
    let CborValue::Map(payload) = payload else {
        bail!("verified Nitro payload is not a CBOR map");
    };
    let Some(value) = payload.get(&CborValue::Text("user_data".into())) else {
        return Ok(None);
    };
    let CborValue::Bytes(value) = value else {
        bail!("verified Nitro user_data is not bytes");
    };
    Ok(Some(serde_json::from_slice(value).context(
        "verified Nitro user_data is not valid Caddy JSON",
    )?))
}

async fn live_leaf_fingerprint(client: &Client, base_url: &Url) -> Result<String> {
    let health_url = base_url
        .join("/.well-known/caution/health")
        .context("could not build health URL")?;
    let response = client
        .get(health_url)
        .send()
        .await
        .context("verified HTTPS health request failed")?;
    ensure!(
        response.status() == StatusCode::OK,
        "HTTPS health returned {}",
        response.status()
    );
    let cert = response
        .extensions()
        .get::<TlsInfo>()
        .and_then(TlsInfo::peer_certificate)
        .context("HTTPS response did not expose its peer certificate")?;
    Ok(hex::encode(Sha256::digest(cert)))
}

async fn attest(client: &Client, base_url: &Url, live_certfp: &str) -> Result<bool> {
    let mut nonce = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let response = client
        .post(
            base_url
                .join("/attestation")
                .context("could not build attestation URL")?,
        )
        .json(&serde_json::json!({"nonce": general_purpose::STANDARD.encode(&nonce)}))
        .send()
        .await
        .context("attestation request failed")?;
    ensure!(
        response.status().is_success(),
        "attestation returned {}",
        response.status()
    );
    let response: AttestationResponse = response
        .json()
        .await
        .context("invalid attestation response")?;
    let document = general_purpose::STANDARD
        .decode(response.attestation_document)
        .context("attestation document is not base64")?;

    // Feeding the signed document's observed PCRs back to the SDK verifies genuine
    // Nitro attestation without claiming that this URL-only test knows workload identity.
    let nitro = Nitro::new(document.clone(), observed_pcrs(&document)?)
        .context("could not construct Nitro verifier")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    let payload = nitro
        .verify(now, &nonce)
        .context("Nitro certificate, COSE signature, nonce, or PCR verification failed")?;
    let Some(user_data) = verified_user_data(&payload)? else {
        eprintln!("verified attestation has no user_data yet");
        return Ok(false);
    };

    let domain = base_url.host_str().context("CADDY_E2E_URL has no host")?;
    ensure!(
        user_data.tls.mode == "caddy",
        "attested TLS mode is not caddy"
    );
    ensure!(
        user_data.tls.domain == domain,
        "attested domain does not match {domain}"
    );
    ensure!(
        user_data.tls.certfp.len() == 64
            && user_data
                .tls
                .certfp
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "attested certfp is not SHA-256 hex"
    );

    if user_data.tls.certfp != live_certfp {
        eprintln!(
            "verified certfp {} does not yet match live certfp {live_certfp}",
            user_data.tls.certfp
        );
        return Ok(false);
    }

    println!("verified live leaf certfp: {live_certfp}");
    Ok(true)
}

async fn check_http_paths(client: &Client, base_url: &Url) -> Result<()> {
    let mut app_url = base_url.clone();
    app_url.set_path("/");
    app_url.set_query(None);
    app_url.set_fragment(None);
    let response = client
        .get(app_url)
        .send()
        .await
        .context("HTTPS application request failed")?;
    ensure!(
        !response.status().is_server_error(),
        "HTTPS application request returned {}",
        response.status()
    );

    let mut redirect_url = base_url.clone();
    redirect_url
        .set_scheme("http")
        .map_err(|_| anyhow::anyhow!("could not build HTTP redirect URL"))?;
    redirect_url
        .set_port(None)
        .map_err(|_| anyhow::anyhow!("could not clear HTTP redirect port"))?;
    redirect_url.set_path("/__caution_caddy_e2e__");
    redirect_url.set_query(Some("probe=1"));
    redirect_url.set_fragment(None);

    let response = client
        .get(redirect_url)
        .send()
        .await
        .context("HTTP redirect request failed")?;
    ensure!(
        response.status() == StatusCode::PERMANENT_REDIRECT,
        "HTTP request returned {}, expected 308",
        response.status()
    );
    let expected = base_url
        .join("/__caution_caddy_e2e__?probe=1")
        .context("could not build expected redirect URL")?;
    ensure!(
        response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            == Some(expected.as_str()),
        "HTTP redirect Location does not match {expected}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires CADDY_E2E_URL pointing to a live production-mode Nitro enclave"]
async fn caddy_nitro_live() -> Result<()> {
    let base_url =
        Url::parse(&std::env::var("CADDY_E2E_URL").context("CADDY_E2E_URL is required")?)
            .context("CADDY_E2E_URL is invalid")?;
    ensure!(base_url.scheme() == "https", "CADDY_E2E_URL must use HTTPS");
    ensure!(
        base_url.host_str().is_some(),
        "CADDY_E2E_URL must have a host"
    );

    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .tls_info(true)
        .timeout(Duration::from_secs(30))
        .build()
        .context("could not build HTTP client")?;

    check_http_paths(&client, &base_url).await?;
    for attempt in 0..2 {
        let live_certfp = live_leaf_fingerprint(&client, &base_url).await?;
        if attest(&client, &base_url, &live_certfp).await? {
            println!("Caddy live Nitro binding PASSED");
            return Ok(());
        }
        if attempt == 0 {
            eprintln!("waiting for the certificate publisher polling window...");
            tokio::time::sleep(PUBLISHER_RETRY).await;
        }
    }

    bail!("attested certfp did not match the live leaf after the publisher polling window")
}
