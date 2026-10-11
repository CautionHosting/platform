// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
//! Discovery supplies candidates; only independent reproduction establishes saved trust.
use crate::{ApiClient, output, quorum_init, share_release::terminal_label, verify};
use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{IsTerminal, Write},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Service {
    Keymaker,
    KeyService,
}
impl Service {
    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::Keymaker => "keymaker",
            Self::KeyService => "key-service",
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("{message} [{location:?}]")]
pub(crate) struct Error {
    #[context(borrow = str)]
    message: String,
    #[location]
    location: Location,
    #[source]
    source: Option<BoxError>,
}
impl Error {
    #[track_caller]
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            location: std::panic::Location::caller(),
            source: None,
        }
    }
}
use ErrorCtx as Ctx;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    platform: String,
    service: Service,
    endpoint: String,
    verified_at: String,
    source: serde_json::Value,
    policy: serde_json::Value,
    tls: Option<verify::TrustedTls>,
}
impl Record {
    fn parsed_policy(&self) -> Result<locksmith::bundle::KeymakerPcrPolicy, Error> {
        let text = serde_json::to_string(&self.policy)
            .with_context(Ctx::new("encode saved service policy"))?;
        let policy = quorum_init::parse_policy(&text)
            .with_context(Ctx::new("invalid saved service policy"))?;
        if policy.sets.iter().any(|set| set.pcrs.len() != 3)
            || policy
                .sets
                .iter()
                .filter(|set| set.expires_at_unix_seconds.is_none())
                .count()
                != 1
            || (self.service == Service::KeyService && policy.sets.len() != 1)
            || policy
                .sets
                .iter()
                .enumerate()
                .any(|(i, set)| policy.sets[..i].iter().any(|other| other.pcrs == set.pcrs))
        {
            return Err(Error::invalid(
                "saved service trust requires unique PCR0/1/2 sets with exactly one current set; only Keymaker may retain historical sets with cutoffs",
            ));
        }
        Ok(policy)
    }
    fn policy_text(&self) -> Result<String, Error> {
        self.parsed_policy()?;
        serde_json::to_string_pretty(&self.policy)
            .with_context(Ctx::new("encode saved service policy"))
    }

    fn retain_keymaker_history(&mut self, previous: &Record, cutoff: u64) -> Result<(), Error> {
        if self.service != Service::Keymaker {
            return Ok(());
        }
        let next = self.parsed_policy()?;
        let old = previous.parsed_policy()?;
        let current_index = next
            .sets
            .iter()
            .position(|set| set.expires_at_unix_seconds.is_none())
            .expect("validated current set");
        let current = &next.sets[current_index];
        if old
            .sets
            .iter()
            .any(|set| set.expires_at_unix_seconds.is_none() && set.pcrs == current.pcrs)
        {
            self.policy = previous.policy.clone();
            return Ok(());
        }
        let next_values = self.policy["sets"]
            .as_array()
            .expect("validated policy sets");
        let mut sets = vec![next_values[current_index].clone()];
        for (set, value) in old.sets.iter().zip(
            previous.policy["sets"]
                .as_array()
                .expect("validated policy sets"),
        ) {
            // An explicitly re-approved historical image becomes current again.
            if set.pcrs == current.pcrs {
                continue;
            }
            let mut value = value.clone();
            if set.expires_at_unix_seconds.is_none() {
                value["expires_at_unix_seconds"] = cutoff.into();
            }
            sets.push(value);
        }
        self.policy = serde_json::json!({"sets": sets});
        self.parsed_policy()?;
        Ok(())
    }
}

fn platform_key(raw: &str) -> Result<String, Error> {
    let mut url = reqwest::Url::parse(raw).with_context(Ctx::new("invalid Platform URL"))?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::invalid(
            "Platform URL must not contain credentials, query or fragment",
        ));
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);
    Ok(url.as_str().trim_end_matches('/').to_owned())
}
fn service_url(raw: &str) -> Result<String, Error> {
    let normalized = configured_url(raw)?;
    if !normalized.starts_with("https://") {
        return Err(Error::invalid("discovered hosted services require HTTPS"));
    }
    Ok(normalized)
}
// Existing manually pinned release deployments may use HTTP: protocol messages
// remain attested and bound to the selected destination. Discovery requires HTTPS.
fn configured_url(raw: &str) -> Result<String, Error> {
    let url = reqwest::Url::parse(raw).with_context(Ctx::new("invalid hosted service URL"))?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::invalid(
            "service URL must be HTTP(S) without credentials, query or fragment",
        ));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}
fn record_path(client: &ApiClient, service: Service) -> Result<PathBuf, Error> {
    let platform = platform_key(&client.base_url)?;
    let root = client
        .config_path
        .parent()
        .ok_or_else(|| Error::invalid("CLI configuration directory unavailable"))?;
    Ok(root
        .join("services")
        .join(hex::encode(Sha256::digest(platform.as_bytes())))
        .join([service.id(), ".json"].concat()))
}
fn read_record(client: &ApiClient, service: Service) -> Result<Option<Record>, Error> {
    let path = record_path(client, service)?;
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(Ctx::new("read saved service trust")),
    };
    let record: Record =
        serde_json::from_slice(&bytes).with_context(Ctx::new("invalid saved service trust"))?;
    if record.version != 1
        || record.platform != platform_key(&client.base_url)?
        || record.service != service
        || service_url(&record.endpoint)? != record.endpoint
    {
        return Err(Error::invalid(
            "saved service trust identity does not match selected Platform and service",
        ));
    }
    record.policy_text()?;
    Ok(Some(record))
}
fn save_record(path: &Path, record: &Record) -> Result<(), Error> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::invalid("service trust directory unavailable"))?;
    fs::create_dir_all(parent).with_context(Ctx::new("create service trust directory"))?;
    let mut temp =
        tempfile::NamedTempFile::new_in(parent).with_context(Ctx::new("stage service trust"))?;
    serde_json::to_writer_pretty(&mut temp, record)
        .with_context(Ctx::new("encode service trust"))?;
    temp.flush().with_context(Ctx::new("flush service trust"))?;
    temp.as_file()
        .sync_all()
        .with_context(Ctx::new("sync service trust"))?;
    if path.exists() {
        let mut backup = tempfile::Builder::new()
            .prefix("previous-")
            .suffix(".json")
            .tempfile_in(parent)
            .with_context(Ctx::new("create previous service trust backup"))?;
        let mut old = fs::File::open(path).with_context(Ctx::new("read previous service trust"))?;
        std::io::copy(&mut old, &mut backup)
            .with_context(Ctx::new("back up previous service trust"))?;
        backup
            .as_file()
            .sync_all()
            .with_context(Ctx::new("sync previous service trust"))?;
        backup
            .keep()
            .with_context(Ctx::new("preserve previous service trust"))?;
    }
    temp.persist(path)
        .with_context(Ctx::new("install service trust"))?;
    Ok(())
}

#[derive(Deserialize)]
struct Discovery {
    services: Option<Snapshot>,
}
#[derive(Deserialize)]
struct Snapshot {
    pending: bool,
    entries: Vec<Entry>,
}
#[derive(Deserialize)]
struct Entry {
    id: Option<String>,
    url: Option<String>,
}
fn select_endpoint(snapshot: Snapshot, service: Service) -> Result<String, Error> {
    let mut matches = snapshot
        .entries
        .into_iter()
        .filter(|e| e.id.as_deref() == Some(service.id()));
    let entry = matches.next().ok_or_else(|| Error::invalid("Platform does not advertise this service ID; update Platform or use explicit service configuration"))?;
    if matches.next().is_some() {
        return Err(Error::invalid("Platform advertises duplicate service IDs"));
    }
    service_url(
        entry
            .url
            .as_deref()
            .ok_or_else(|| Error::invalid("hosted service URL is not configured on Platform"))?,
    )
}
async fn discover(client: &ApiClient, service: Service) -> Result<String, Error> {
    let mut url =
        reqwest::Url::parse(&client.base_url).with_context(Ctx::new("invalid Platform URL"))?;
    url.set_path("/.well-known/caution/build-inputs");
    url.set_query(None);
    url.set_fragment(None);
    // A dedicated client never forwards account credentials or follows redirects.
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .with_context(Ctx::new("create discovery client"))?;
    tokio::time::timeout(Duration::from_secs(12), async {
        for attempt in 0..6 {
            let mut response = http.get(url.clone()).send().await.with_context(Ctx::new("fetch hosted service discovery"))?.error_for_status().with_context(Ctx::new("Platform discovery failed"))?;
            if !response.status().is_success() {
                return Err(Error::invalid("discovery requires a successful response; redirects are not accepted"));
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.with_context(Ctx::new("read discovery response"))? {
                if bytes.len() + chunk.len() > 1024 * 1024 { return Err(Error::invalid("discovery response exceeds 1 MiB")); }
                bytes.extend_from_slice(&chunk);
            }
            let discovery: Discovery = serde_json::from_slice(&bytes).with_context(Ctx::new("invalid service discovery JSON"))?;
            let snapshot = discovery.services.ok_or_else(|| Error::invalid("Platform has no service discovery; update Platform or use explicit configuration"))?;
            if !snapshot.pending { return select_endpoint(snapshot, service); }
            if attempt < 5 { tokio::time::sleep(Duration::from_secs(1)).await; }
        }
        Err(Error::invalid("Platform service discovery is pending; retry shortly"))
    }).await.with_context(Ctx::new("service discovery timed out"))?
}

fn setup_required(service: Service) -> Error {
    Error::invalid(["No trusted hosted service configuration. Run caution --url <selected-platform> verify --service ", service.id(), " interactively, or supply an independently verified explicit policy."].concat())
}
fn confirm(message: &str) -> Result<(), Error> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(Error::invalid(
            "service trust setup requires an interactive terminal",
        ));
    }
    if !crate::prompt::confirm(message).with_context(Ctx::new("confirm service trust"))? {
        return Err(Error::invalid(
            "service trust setup cancelled; previous trust unchanged",
        ));
    }
    Ok(())
}

pub(crate) async fn run(client: &ApiClient, service: Service, no_cache: bool) -> Result<(), Error> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(setup_required(service));
    }
    let endpoint = discover(client, service).await?;
    output::status(format_args!(
        "Platform: {}\nHosted {}: {}",
        terminal_label(&client.base_url),
        service.id(),
        terminal_label(&endpoint)
    ));
    let previous = read_record(client, service)?;
    if let Some(previous) = &previous {
        output::status(format_args!(
            "Previously trusted endpoint: {} (verified {})",
            terminal_label(&previous.endpoint),
            terminal_label(&previous.verified_at)
        ));
    }
    // Keep the substantial reproduction future out of each caller's stack layout.
    let image = Box::pin(verify::verify_service(client, &endpoint, no_cache))
        .await
        .with_context(Ctx::new(
            "independent service verification failed; trust unchanged",
        ))?;
    let mut record = Record {
        version: 1,
        platform: platform_key(&client.base_url)?,
        service,
        endpoint,
        verified_at: image.verified_at,
        source: image.source,
        tls: image.tls,
        policy: serde_json::json!({"sets":[{"pcrs":{"0":image.pcrs.pcr0,"1":image.pcrs.pcr1,"2":image.pcrs.pcr2}}]}),
    };
    output::status(record.policy_text()?);
    if let Some(previous) = previous.as_ref().filter(|_| service == Service::Keymaker) {
        let next = record.parsed_policy()?;
        let old = previous.parsed_policy()?;
        if old
            .sets
            .iter()
            .any(|set| set.expires_at_unix_seconds.is_some() && set.pcrs == next.sets[0].pcrs)
        {
            output::status(
                "Warning: this re-approves a retired Keymaker image and removes its previous generation cutoff, including acceptance of proofs generated during its retirement.",
            );
        }
        if !old
            .sets
            .iter()
            .any(|set| set.expires_at_unix_seconds.is_none() && set.pcrs == next.sets[0].pcrs)
        {
            output::status(
                "Saving will retain historical Keymaker sets and retire the outgoing current set at your local approval time.",
            );
        }
    }
    confirm("Save this verified service trust for projects using this Platform? [y/N] ")?;
    if let Some(previous) = &previous {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .with_context(Ctx::new("read local approval time"))?
            .as_secs();
        record.retain_keymaker_history(previous, cutoff)?;
    }
    let path = record_path(client, service)?;
    save_record(&path, &record)?;
    output::status(format_args!("Saved service trust: {}", path.display()));
    Ok(())
}

// Approval occurs after the exact manifest is fetched, before any build executes.
fn validate_source(
    manifest: Option<&enclave_builder::EnclaveManifest>,
) -> Result<&enclave_builder::EnclaveManifest, Error> {
    let manifest = manifest
        .ok_or_else(|| Error::invalid("service verification requires a source manifest"))?;
    let app = manifest
        .app_source
        .as_ref()
        .ok_or_else(|| Error::invalid("service manifest has no application source"))?;
    if app.commit.len() != 40
        || !app.commit.bytes().all(|b| b.is_ascii_hexdigit())
        || app.urls.len() != 1
    {
        return Err(Error::invalid(
            "service verification requires one source repository and an immutable 40-character commit",
        ));
    }
    verify::hosted_source::archive_urls(app)
        .with_context(Ctx::new("validate pinned application source retrieval"))?;
    match &manifest.framework_source {
        enclave_builder::FrameworkSource::GitArchive {
            url,
            commit: Some(commit),
        } if commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()) => {
            verify::hosted_source::pinned_archive(url, commit)
                .with_context(Ctx::new("validate pinned framework archive"))?;
        }
        _ => {
            return Err(Error::invalid(
                "service verification requires a pinned HTTPS framework source",
            ));
        }
    }
    match &manifest.enclave_source {
        enclave_builder::EnclaveSource::GitArchive {
            urls,
            commit: Some(commit),
        } if !urls.is_empty()
            && commit.len() == 40
            && commit.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            for url in urls {
                verify::hosted_source::pinned_archive(url, commit)
                    .with_context(Ctx::new("validate pinned EnclaveOS archive"))?;
            }
        }
        _ => {
            return Err(Error::invalid(
                "service verification requires a pinned HTTPS EnclaveOS source",
            ));
        }
    }
    Ok(manifest)
}

pub(crate) fn approve_source(
    manifest: Option<&enclave_builder::EnclaveManifest>,
) -> Result<(), Error> {
    let manifest = validate_source(manifest)?;
    output::status(
        "The service supplied this unsigned manifest. Review the intended source and build inputs; matching measurements do not establish that the code is safe.",
    );
    let display = serde_json::to_string_pretty(manifest)
        .with_context(Ctx::new("display service build inputs"))?;
    for line in display.lines() {
        output::status(terminal_label(line));
    }
    confirm("Reproduce these source/build inputs and verify the live service? [y/N] ")
}

fn path_present(path: &Path) -> Result<bool, Error> {
    match path.symlink_metadata() {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(Ctx::new("inspect configured service policy path")),
    }
}
fn local_keymaker(explicit: Option<&Path>) -> Result<Option<PathBuf>, Error> {
    let path = quorum_init::policy_path(explicit);
    if explicit.is_some()
        || std::env::var_os("KEYMAKER_PCR_POLICY_PATH").is_some()
        || path_present(&path)?
    {
        Ok(Some(path))
    } else {
        Ok(None)
    }
}
pub(crate) fn keymaker_policy(
    client: &ApiClient,
    explicit: Option<&Path>,
) -> Result<String, Error> {
    if let Some(path) = local_keymaker(explicit)? {
        let text =
            fs::read_to_string(path).with_context(Ctx::new("read configured Keymaker policy"))?;
        return quorum_init::normalize_policy(&text)
            .with_context(Ctx::new("invalid configured Keymaker policy"));
    }
    read_record(client, Service::Keymaker)?
        .ok_or_else(|| setup_required(Service::Keymaker))?
        .policy_text()
}
pub(crate) async fn ensure_keymaker(
    client: &ApiClient,
    explicit: Option<&Path>,
) -> Result<String, Error> {
    if local_keymaker(explicit)?.is_none() && read_record(client, Service::Keymaker)?.is_none() {
        Box::pin(run(client, Service::Keymaker, false)).await?;
    }
    keymaker_policy(client, explicit)
}
pub(crate) async fn release_config(
    client: &ApiClient,
    options: &crate::share_release::Options,
) -> Result<(String, locksmith::bundle::KeymakerPcrPolicy), Error> {
    release_config_at(client, options, Path::new(".")).await
}
async fn release_config_at(
    client: &ApiClient,
    options: &crate::share_release::Options,
    root: &Path,
) -> Result<(String, locksmith::bundle::KeymakerPcrPolicy), Error> {
    let explicit_url = options
        .recryptor_url
        .clone()
        .or_else(|| std::env::var("RECRYPTOR_URL").ok());
    let local = root.join(".caution/recryptor-pcr-policy.json");
    let policy_path = if let Some(path) = options.recryptor_pcr_policy.as_ref() {
        Some(path)
    } else if path_present(&local)? {
        Some(&local)
    } else {
        None
    };
    if let (Some(path), Some(url)) = (policy_path, explicit_url.as_ref()) {
        let policy = quorum_init::load_policy(path)
            .with_context(Ctx::new("read configured share-release policy"))?;
        return Ok((configured_url(url)?, policy));
    }
    let saved = read_record(client, Service::KeyService)?;
    if let Some(path) = policy_path {
        let policy = quorum_init::load_policy(path)
            .with_context(Ctx::new("read configured share-release policy"))?;
        let url = match explicit_url.or_else(|| saved.map(|r| r.endpoint)) {
            Some(url) => url,
            None => discover(client, Service::KeyService).await?,
        };
        return Ok((service_url(&url)?, policy));
    }
    if let Some(url) = &explicit_url {
        if saved
            .as_ref()
            .is_none_or(|r| service_url(url).ok().as_ref() != Some(&r.endpoint))
        {
            return Err(Error::invalid(
                "explicit recryptor URL has no matching saved trust; supply --recryptor-pcr-policy",
            ));
        }
    }
    let record = match saved {
        Some(record) => record,
        None => {
            Box::pin(run(client, Service::KeyService, false)).await?;
            read_record(client, Service::KeyService)?
                .ok_or_else(|| setup_required(Service::KeyService))?
        }
    };
    let policy = quorum_init::parse_policy(&record.policy_text()?)
        .with_context(Ctx::new("load verified share-release policy"))?;
    Ok((record.endpoint, policy))
}

#[cfg(test)]
#[path = "service_trust_tests.rs"]
mod tests;
