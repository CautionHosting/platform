// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
//! Demand-driven public observations. Reported source metadata is not attestation-bound.
use base64::{Engine, engine::general_purpose::STANDARD};
use bootproof_sdk::format::{VerifiableSignedAttestationFormat, nitro::Nitro};
use locksmith::bundle::KeymakerPcrPolicy;
use rand::RngCore;
use serde::Serialize;
use serde_cbor::Value as Cbor;
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

const INTERVAL: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE: usize = 1024 * 1024;

#[derive(Clone, Serialize, Default)]
pub struct Snapshot {
    pub pending: bool,
    pub checked_at: Option<String>,
    pub entries: Vec<Service>,
}
#[derive(Clone, Serialize)]
pub struct Service {
    name: &'static str,
    url: Option<String>,
    readiness: Check,
    attestation: Check,
    measurements: BTreeMap<u8, String>,
    policies: Vec<Policy>,
    service_reported_source: Option<Source>,
}
#[derive(Clone, Serialize)]
struct Source {
    repository: Option<String>,
    commit: Option<String>,
}
#[derive(Clone, Serialize)]
struct Check {
    status: &'static str,
    reason: Option<&'static str>,
}
impl Check {
    fn success() -> Self {
        Self {
            status: "passed",
            reason: None,
        }
    }
    #[track_caller]
    fn failure(reason: &'static str) -> Self {
        Self {
            status: "failed",
            reason: Some(reason),
        }
    }
}
#[derive(Clone, Serialize)]
struct Policy {
    purpose: &'static str,
    result: Check,
    sets: Vec<PolicySet>,
}
#[derive(Clone, Serialize)]
struct PolicySet {
    pcrs: BTreeMap<u8, String>,
    expires_at_unix_seconds: Option<u64>,
}

#[derive(Default)]
struct Cache {
    started: Option<Instant>,
    snapshot: Snapshot,
}
impl Cache {
    fn begin(&mut self, now: Instant) -> bool {
        if self.snapshot.pending
            || self
                .started
                .is_some_and(|t| now.duration_since(t) < INTERVAL)
        {
            return false;
        }
        self.started = Some(now);
        self.snapshot = Snapshot {
            pending: true,
            ..Snapshot::default()
        };
        true
    }
}

pub async fn snapshot() -> Snapshot {
    static CACHE: OnceLock<Arc<Mutex<Cache>>> = OnceLock::new();
    let cache = CACHE
        .get_or_init(|| Arc::new(Mutex::new(Cache::default())))
        .clone();
    cached_snapshot(cache, refresh).await
}

async fn cached_snapshot<F, Fut>(cache: Arc<Mutex<Cache>>, refresh: F) -> Snapshot
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Vec<Service>> + Send,
{
    let mut state = cache.lock().await;
    if state.begin(Instant::now()) {
        let owner = cache.clone();
        tokio::spawn(async move {
            let entries = refresh().await;
            owner.lock().await.snapshot = Snapshot {
                pending: false,
                checked_at: Some(chrono::Utc::now().to_rfc3339()),
                entries,
            };
        });
    }
    state.snapshot.clone()
}

async fn refresh() -> Vec<Service> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .build();
    let (keymaker, key_service) = tokio::join!(
        observe(
            client.as_ref().ok(),
            "Keymaker",
            "KEYMAKER_URL",
            &[("Bundle generation", "KEYMAKER_PCR_POLICY_PATH", false)]
        ),
        observe(
            client.as_ref().ok(),
            "Key service",
            "PUBLIC_CERTIFICATE_SERVICE_URL",
            &[
                (
                    "Certificate issuance",
                    "PUBLIC_CERTIFICATE_PCR_POLICY_PATH",
                    false
                ),
                ("Share release", "RECRYPTOR_PCR_POLICY_PATH", true),
            ]
        )
    );
    vec![keymaker, key_service]
}

fn public_url(raw: &str) -> Option<url::Url> {
    let url = url::Url::parse(raw).ok()?;
    (url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

#[derive(Debug, thiserror::Error, dterror::CtxError)]
#[error("{reason}")]
struct ProbeError {
    reason: &'static str,
    #[location]
    location: dterror::Location,
}
#[track_caller]
fn failure(reason: &'static str) -> ProbeError {
    ProbeError {
        reason,
        location: std::panic::Location::caller(),
    }
}

async fn fetch(request: reqwest::RequestBuilder, limit: usize) -> Result<Value, ProbeError> {
    // The outer timeout includes streaming the complete body, not only headers.
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let mut response = request
            .send()
            .await
            .map_err(|_| failure("Request failed"))?;
        if !response.status().is_success() {
            return Err(failure("Endpoint returned an unsuccessful status"));
        }
        if response.content_length().is_some_and(|n| n > limit as u64) {
            return Err(failure("Response too large"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| failure("Response read failed"))?
        {
            if chunk.len() > limit.saturating_sub(body.len()) {
                return Err(failure("Response too large"));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| failure("Invalid JSON response"))
    })
    .await
    .map_err(|_| failure("Request timed out"))?
}

async fn observe(
    client: Option<&reqwest::Client>,
    name: &'static str,
    url_env: &str,
    policy_config: &[(&'static str, &str, bool)],
) -> Service {
    let url = std::env::var(url_env).ok().and_then(|raw| public_url(&raw));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // Read policies on every refresh, including when the remote endpoint is unavailable.
    let policies: Vec<_> = policy_config
        .iter()
        .map(|(purpose, variable, live)| {
            let loaded = std::env::var(variable)
                .ok()
                .and_then(|path| load_policy(std::path::Path::new(&path)));
            (*purpose, loaded, *live)
        })
        .collect();
    let mut service = Service {
        name,
        url: url.as_ref().map(ToString::to_string),
        readiness: Check::failure("Service URL is missing or invalid"),
        attestation: Check::failure("Service URL is missing or invalid"),
        measurements: BTreeMap::new(),
        policies: vec![],
        service_reported_source: None,
    };
    let mut verified = None;
    if let (Some(client), Some(url)) = (client, url) {
        let base = url.as_str().trim_end_matches('/');
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let health_url = [base, "/health"].concat();
        let attestation_url = [base, "/attestation"].concat();
        let (health, quote) = tokio::join!(
            fetch(client.get(health_url), 16 * 1024),
            fetch(
                client
                    .post(attestation_url)
                    .json(&serde_json::json!({"nonce": STANDARD.encode(nonce)})),
                MAX_RESPONSE
            )
        );
        service.readiness = match health {
            Ok(value)
                if matches!(
                    value.get("status").and_then(Value::as_str),
                    Some("ready" | "ok" | "healthy")
                ) =>
            {
                Check::success()
            }
            Ok(_) => Check::failure("Service is not ready"),
            Err(error) => Check::failure(error.reason),
        };
        service.attestation = match quote {
            Ok(value) => {
                service.service_reported_source = reported_source(&value);
                match authenticate(&value, &nonce, now) {
                    Ok(pcrs) => {
                        service.measurements =
                            pcrs.iter().map(|(i, v)| (*i, hex::encode(v))).collect();
                        verified = Some(pcrs);
                        Check::success()
                    }
                    Err(error) => Check::failure(error.reason),
                }
            }
            Err(error) => Check::failure(error.reason),
        };
    }
    service.policies = policies
        .into_iter()
        .map(|(purpose, policy, live)| {
            evaluate_policy(
                purpose,
                policy.as_ref(),
                live,
                verified.as_ref(),
                now.as_secs(),
            )
        })
        .collect();
    service
}

fn reported_source(value: &Value) -> Option<Source> {
    let source = value.get("manifest")?.get("app_source")?;
    let repository = source
        .get("urls")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find_map(|raw| public_url(raw).map(|u| u.to_string()));
    let commit = source
        .get("commit")
        .and_then(Value::as_str)
        .filter(|s| matches!(s.len(), 40 | 64) && s.bytes().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_owned);
    Some(Source { repository, commit })
}

fn extract_pcrs(payload: &Cbor) -> Option<HashMap<u8, Vec<u8>>> {
    let Cbor::Map(map) = payload else {
        return None;
    };
    let Cbor::Map(pcrs) = map.get(&Cbor::Text("pcrs".into()))? else {
        return None;
    };
    (0..=2)
        .map(|i| match pcrs.get(&Cbor::Integer(i as i128))? {
            Cbor::Bytes(bytes) if bytes.len() == 48 => Some((i, bytes.clone())),
            _ => None,
        })
        .collect()
}

fn authenticate(
    value: &Value,
    nonce: &[u8; 32],
    now: Duration,
) -> Result<HashMap<u8, Vec<u8>>, ProbeError> {
    let invalid = || failure("Attestation authentication failed");
    let bytes = STANDARD
        .decode(
            value
                .get("document")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
    let envelope: Cbor = serde_cbor::from_slice(&bytes).map_err(|_| invalid())?;
    let envelope = match envelope {
        Cbor::Tag(_, inner) => *inner,
        other => other,
    };
    let Cbor::Array(fields) = envelope else {
        return Err(invalid());
    };
    let Some(Cbor::Bytes(payload)) = fields.get(2) else {
        return Err(invalid());
    };
    let candidate: Cbor = serde_cbor::from_slice(payload).map_err(|_| invalid())?;
    let candidate_pcrs = extract_pcrs(&candidate).ok_or_else(invalid)?;
    // SDK requires PCRs to authenticate a quote. These untrusted candidates ONLY
    // satisfy its input; authorization uses configured policies below, after verification.
    let nitro = Nitro::new(bytes, candidate_pcrs).map_err(|_| invalid())?;
    let authenticated = nitro.verify(now, nonce).map_err(|_| invalid())?;
    let pcrs = extract_pcrs(&authenticated).ok_or_else(invalid)?;
    reject_debug(&pcrs)?;
    Ok(pcrs)
}

fn reject_debug(pcrs: &HashMap<u8, Vec<u8>>) -> Result<(), ProbeError> {
    if pcrs.values().any(|v| v.iter().all(|b| *b == 0)) {
        return Err(failure("Debug measurements are not accepted"));
    }
    Ok(())
}

fn evaluate_policy(
    purpose: &'static str,
    policy: Option<&KeymakerPcrPolicy>,
    live: bool,
    measured: Option<&HashMap<u8, Vec<u8>>>,
    now: u64,
) -> Policy {
    let mut result = Policy {
        purpose,
        result: Check::failure("Policy missing or invalid"),
        sets: vec![],
    };
    let Some(policy) = policy else {
        return result;
    };
    result.sets = policy
        .sets
        .iter()
        .map(|set| PolicySet {
            pcrs: set.pcrs.iter().map(|(i, v)| (*i, hex::encode(v))).collect(),
            expires_at_unix_seconds: set.expires_at_unix_seconds,
        })
        .collect();
    if policy.sets.is_empty()
        || policy.sets.iter().any(|s| {
            (0..=2).any(|i| {
                !s.pcrs
                    .get(&i)
                    .is_some_and(|v| v.len() == 48 && v.iter().any(|b| *b != 0))
            })
        })
    {
        return result;
    }
    if live && (policy.sets.len() != 1 || policy.sets[0].expires_at_unix_seconds.is_some()) {
        result.result = Check::failure("Share release requires one non-expiring PCR set");
        return result;
    }
    result.result = match measured {
        None => Check::failure("No authenticated measurements"),
        Some(measured)
            if policy.sets.iter().any(|s| {
                s.expires_at_unix_seconds.is_none_or(|expiry| now < expiry)
                    && s.pcrs
                        .iter()
                        .all(|(i, expected)| measured.get(i) == Some(expected))
            }) =>
        {
            Check::success()
        }
        Some(_) => Check::failure("Authenticated measurements do not match an active policy set"),
    };
    result
}

fn load_policy(path: &std::path::Path) -> Option<KeymakerPcrPolicy> {
    let json = std::fs::read_to_string(path).ok()?;
    KeymakerPcrPolicy::from_json(&json).ok()
}

#[cfg(test)]
#[path = "service_observations_tests.rs"]
mod tests;
