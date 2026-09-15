// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::{ApiClient, output, prompt};
use clap::Args;
use dterror::{BoxError, CtxError, Location, ResultExt};
use keymaker_models::generate_quorum::{
    GenerateQuorumBundle, GenerateQuorumRequest, GenerateQuorumResponse,
    v1::{self, Key},
};
use locksmith::bundle::KeymakerPcrPolicy;
use sequoia_openpgp::{
    Cert, cert::CertParser, parse::Parse, policy::StandardPolicy, serialize::Serialize as _,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::IsTerminal,
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

pub(crate) const DIRECT_WEBAUTHN_ERROR: &str = "WebAuthn holders require Platform-mediated Keymaker creation because Platform resolves their credential bindings internally. Remove the Keymaker URL override or select only PGP holders.";

#[derive(Debug, thiserror::Error, CtxError)]
#[error("{message} [{location:?}]")]
pub(crate) struct InitError {
    #[context(borrow = str)]
    message: String,
    #[location]
    location: Location,
    #[source]
    source: Option<BoxError>,
}
impl InitError {
    #[track_caller]
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            location: std::panic::Location::caller(),
            source: None,
        }
    }
}
use InitErrorCtx as Ctx;

#[derive(Args, Debug)]
pub(crate) struct Options {
    /// Optional local public OpenPGP keyring; may accompany organization holders.
    pub keyring: Option<PathBuf>,
    #[arg(long)]
    pub threshold: Option<u8>,
    #[arg(long)]
    pub max: Option<u8>,
    #[arg(long)]
    pub no_upload: bool,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long = "label", value_name = "KEY=VALUE")]
    pub labels: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    pub from_org_users: Vec<Uuid>,
    /// Use WebAuthn for listed users without a --pgp-key override.
    #[arg(long, requires = "from_org_users")]
    pub caution_backed: bool,
    #[arg(
        long = "pgp-key",
        requires = "from_org_users",
        value_name = "USER_ID=KEY_ID"
    )]
    pub pgp_keys: Vec<PgpSelection>,
    /// Call this Keymaker directly (PGP-only); overrides KEYMAKER_URL.
    #[arg(long)]
    pub keymaker_url: Option<String>,
    /// Expected Keymaker PCRs, independently established by the operator.
    #[arg(long, value_name = "FILE")]
    pub keymaker_pcr_policy: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub(crate) struct PgpSelection {
    user: Uuid,
    key: Uuid,
}
impl std::str::FromStr for PgpSelection {
    type Err = InitError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (user, key) = text
            .split_once('=')
            .ok_or_else(|| InitError::invalid("--pgp-key requires USER_ID=KEY_ID"))?;
        Ok(Self {
            user: user
                .parse()
                .with_context(Ctx::new("invalid PGP holder user UUID"))?,
            key: key.parse().with_context(Ctx::new("invalid PGP key UUID"))?,
        })
    }
}

#[derive(Clone, Deserialize)]
struct RegisteredKey {
    id: Uuid,
    fingerprint: String,
    public_key: String,
}
#[derive(Clone, Deserialize)]
struct Member {
    user_id: Uuid,
    username: String,
    pgp_keys: Vec<RegisteredKey>,
    webauthn_credentials: i64,
}
#[derive(Clone, Debug, Serialize)]
struct Participant {
    user_id: Uuid,
    key_source: &'static str,
    pgp_key_id: Option<Uuid>,
}
#[derive(Serialize)]
struct HostedRequest<'a> {
    name: &'a Option<String>,
    threshold: u8,
    participants: &'a [Participant],
    pgp_certificates: &'a [String],
    allow_caution_backed_keys: bool,
    labels: &'a HashMap<String, String>,
}

fn endpoint(
    explicit: Option<&str>,
    environment: Option<&str>,
) -> Result<Option<String>, InitError> {
    explicit.or(environment).map(|value| {
        let url = reqwest::Url::parse(value).with_context(Ctx::new("invalid Keymaker URL"))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
            return Err(InitError::invalid("Keymaker URL must be an HTTP(S) base URL without credentials, query or fragment"));
        }
        Ok(value.trim_end_matches('/').to_owned())
    }).transpose()
}

fn validate_direct(direct: bool, participants: &[Participant]) -> Result<(), InitError> {
    if direct
        && participants
            .iter()
            .any(|p| p.key_source == "caution_backed_pgp")
    {
        return Err(InitError::invalid(DIRECT_WEBAUTHN_ERROR));
    }
    Ok(())
}

fn public_certificates(text: &str) -> Result<Vec<String>, InitError> {
    let parser =
        CertParser::from_bytes(text.as_bytes()).with_context(Ctx::new("invalid PGP keyring"))?;
    let mut result = Vec::new();
    for cert in parser {
        let cert = cert.with_context(Ctx::new("invalid PGP certificate"))?;
        if cert.is_tsk() {
            return Err(InitError::invalid(
                "use public PGP certificates, not a private keyring",
            ));
        }
        let policy = StandardPolicy::new();
        let keys = || {
            cert.keys()
                .with_policy(&policy, None)
                .supported()
                .alive()
                .revoked(false)
        };
        if keys().for_signing().next().is_none()
            || keys().for_authentication().next().is_none()
            || keys().for_storage_encryption().next().is_none()
        {
            return Err(InitError::invalid(
                "each PGP holder needs signing, authentication and storage-encryption keys",
            ));
        }
        let mut bytes = Vec::new();
        cert.armored()
            .serialize(&mut bytes)
            .with_context(Ctx::new("unable to encode PGP certificate"))?;
        result.push(
            String::from_utf8(bytes)
                .with_context(Ctx::new("invalid armored certificate encoding"))?,
        );
    }
    if result.is_empty() {
        return Err(InitError::invalid("keyring contains no PGP holders"));
    }
    Ok(result)
}

fn unique_certificates(certificates: &[String]) -> Result<(), InitError> {
    let mut seen = HashSet::new();
    let mut encryption_keys = HashSet::new();
    for text in certificates {
        let certs = public_certificates(text)?;
        if certs.len() != 1 {
            return Err(InitError::invalid(
                "each PGP holder must contain one certificate",
            ));
        }
        let cert =
            Cert::from_bytes(text.as_bytes()).with_context(Ctx::new("invalid PGP certificate"))?;
        if !seen.insert(cert.fingerprint()) {
            return Err(InitError::invalid("duplicate effective PGP holder"));
        }
        let policy = StandardPolicy::new();
        for key in cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_storage_encryption()
        {
            if !encryption_keys.insert(key.key().fingerprint()) {
                return Err(InitError::invalid(
                    "holders must not share an encryption key",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn policy_path(explicit: Option<&Path>) -> PathBuf {
    explicit
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("KEYMAKER_PCR_POLICY_PATH").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(".caution/keymaker-pcr-policy.json"))
}

pub(crate) fn load_policy(path: &Path) -> Result<KeymakerPcrPolicy, InitError> {
    let text = fs::read_to_string(path).with_context(Ctx::new("missing Keymaker PCR policy: supply --keymaker-pcr-policy, KEYMAKER_PCR_POLICY_PATH or .caution/keymaker-pcr-policy.json"))?;
    parse_policy(&text)
}

fn parse_policy(text: &str) -> Result<KeymakerPcrPolicy, InitError> {
    let policy =
        KeymakerPcrPolicy::from_json(text).with_context(Ctx::new("invalid Keymaker PCR policy"))?;
    if policy.sets.is_empty()
        || policy.sets.iter().any(|set| {
            (0..=2).any(|index| {
                set.pcrs
                    .get(&index)
                    .is_none_or(|p| p.len() != 48 || p.iter().all(|b| *b == 0))
            })
        })
    {
        return Err(InitError::invalid(
            "Keymaker policy must pin non-debug PCR0, PCR1 and PCR2",
        ));
    }
    Ok(policy)
}

pub(crate) fn load_bundle(text: &str) -> Result<GenerateQuorumBundle, InitError> {
    let policy = load_policy(&policy_path(None))?;
    locksmith::bundle::load_json(text, &policy)
        .with_context(Ctx::new("unable to verify proofed v1 quorum bundle"))
}

fn select_participants(
    options: &Options,
    members: &[Member],
    interactive: bool,
) -> Result<(Vec<Participant>, Vec<String>), InitError> {
    let mut overrides = HashMap::new();
    for selection in &options.pgp_keys {
        if !options.from_org_users.contains(&selection.user)
            || overrides.insert(selection.user, selection.key).is_some()
        {
            return Err(InitError::invalid(
                "PGP overrides must name distinct selected users",
            ));
        }
    }
    let mut participants = Vec::new();
    let mut certs = Vec::new();
    let mut seen = HashSet::new();
    for user_id in &options.from_org_users {
        if !seen.insert(user_id) {
            return Err(InitError::invalid("duplicate organization holder"));
        }
        let member = members
            .iter()
            .find(|m| m.user_id == *user_id)
            .ok_or_else(|| {
                InitError::invalid("selected user is not an active organization member")
            })?;
        let mut key_id = overrides.get(user_id).copied();
        let mut webauthn = options.caution_backed && key_id.is_none();
        if key_id.is_none() && !webauthn {
            if member.pgp_keys.len() == 1 {
                key_id = Some(member.pgp_keys[0].id);
            } else if interactive {
                eprintln!("Select custody for {}:", member.username);
                for (index, key) in member.pgp_keys.iter().enumerate() {
                    eprintln!("  {}: PGP {} ({})", index + 1, key.fingerprint, key.id);
                }
                if member.webauthn_credentials > 0 {
                    eprintln!(
                        "  0: Caution-backed WebAuthn ({} registered passkeys, one share)",
                        member.webauthn_credentials
                    );
                }
                let index = prompt::select("Selection: ")
                    .with_context(Ctx::new("unable to read custody selection"))?;
                if index == 0 && member.webauthn_credentials > 0 {
                    webauthn = true;
                } else {
                    key_id = Some(
                        member
                            .pgp_keys
                            .get(index.wrapping_sub(1))
                            .ok_or_else(|| InitError::invalid("invalid custody selection"))?
                            .id,
                    );
                }
            } else {
                return Err(InitError::invalid(
                    "ambiguous custody: specify --pgp-key USER_ID=KEY_ID or explicitly select --caution-backed",
                ));
            }
        }
        if webauthn {
            if member.webauthn_credentials == 0 {
                return Err(InitError::invalid(
                    "selected WebAuthn holder has no registered credentials",
                ));
            }
            participants.push(Participant {
                user_id: *user_id,
                key_source: "caution_backed_pgp",
                pgp_key_id: None,
            });
        } else {
            let key = member
                .pgp_keys
                .iter()
                .find(|key| Some(key.id) == key_id)
                .ok_or_else(|| {
                    InitError::invalid("PGP key does not belong to the selected user")
                })?;
            certs.push(key.public_key.clone());
            participants.push(Participant {
                user_id: *user_id,
                key_source: "existing_pgp",
                pgp_key_id: key_id,
            });
        }
    }
    Ok((participants, certs))
}

async fn checked_response(
    client: &ApiClient,
    response: reqwest::Response,
) -> Result<serde_json::Value, InitError> {
    if !response.status().is_success() {
        let status = response.status();
        let message = client.api_error_message(response).await;
        return Err(InitError::invalid(
            [
                "Quorum service returned HTTP ",
                status.as_str(),
                ": ",
                &message,
                "; generation was not retried",
            ]
            .concat(),
        ));
    }
    response
        .json()
        .await
        .with_context(Ctx::new("invalid quorum response"))
}

pub(crate) async fn run(client: &ApiClient, options: Options) -> Result<(), InitError> {
    let environment = std::env::var("KEYMAKER_URL").ok();
    let endpoint = endpoint(options.keymaker_url.as_deref(), environment.as_deref())?;
    // Reject the explicit mixed/WebAuthn override before requesting credentials or generation.
    if endpoint.is_some()
        && options.caution_backed
        && options
            .from_org_users
            .iter()
            .any(|id| !options.pgp_keys.iter().any(|p| p.user == *id))
    {
        return Err(InitError::invalid(DIRECT_WEBAUTHN_ERROR));
    }
    if endpoint.is_none() && options.no_upload {
        return Err(InitError::invalid(
            "--no-upload is only supported with a direct PGP-only Keymaker",
        ));
    }
    let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let config = if endpoint.is_none() || !options.from_org_users.is_empty() || !options.no_upload {
        Some(
            client
                .ensure_authenticated()
                .await
                .with_context(Ctx::new("quorum initialization requires authentication"))?,
        )
    } else {
        None
    };
    let members: Vec<Member> = if options.from_org_users.is_empty() {
        Vec::new()
    } else {
        client
            .get_protected_json(
                &config.as_ref().expect("authenticated").session_id,
                "/api/quorum-bundles/participants",
                "unable to list quorum participants",
            )
            .await
            .with_context(Ctx::new("unable to discover organization holders"))?
    };
    let (participants, registered) = select_participants(&options, &members, interactive)?;
    validate_direct(endpoint.is_some(), &participants)?;
    let local = if let Some(path) = &options.keyring {
        public_certificates(
            &fs::read_to_string(path).with_context(Ctx::new("unable to read local PGP keyring"))?,
        )?
    } else {
        Vec::new()
    };
    let certificates: Vec<_> = local.iter().chain(&registered).cloned().collect();
    unique_certificates(&certificates)?;
    let count = local.len() + participants.len();
    let (threshold, _) =
        crate::secrets::resolve_quorum_parameters(options.threshold, options.max, count)
            .with_context(Ctx::new("invalid quorum threshold or holder count"))?;
    let mut labels = HashMap::new();
    for label in &options.labels {
        let (key, value) = label
            .split_once('=')
            .filter(|(key, _)| !key.is_empty())
            .ok_or_else(|| InitError::invalid("labels require KEY=VALUE"))?;
        labels.insert(key.to_owned(), value.to_owned());
    }
    let policy_file = policy_path(options.keymaker_pcr_policy.as_deref());
    let policy_text = fs::read_to_string(&policy_file)
        .with_context(Ctx::new("unable to read Keymaker PCR policy"))?;
    let policy = parse_policy(&policy_text)?;
    eprintln!(
        "Initialize quorum: {threshold} of {count}; {}",
        endpoint.as_deref().unwrap_or("Platform-hosted Keymaker")
    );
    for cert in &local {
        let cert = Cert::from_bytes(cert.as_bytes())
            .with_context(Ctx::new("invalid local certificate"))?;
        eprintln!("  Local PGP {}", cert.fingerprint());
    }
    for p in &participants {
        eprintln!(
            "  {}: {}{}",
            p.user_id,
            p.key_source,
            p.pgp_key_id
                .map(|id| [" ", &id.to_string()].concat())
                .unwrap_or_default()
        );
    }
    if interactive
        && !prompt::confirm("Create this quorum? [y/N] ")
            .with_context(Ctx::new("unable to confirm quorum"))?
    {
        return Ok(());
    }
    let (response, uploaded) = if let Some(url) = endpoint {
        let mut label = labels.clone();
        if let Some(name) = &options.name {
            label.entry("name".into()).or_insert_with(|| name.clone());
        }
        let request = GenerateQuorumRequest::V1(v1::GenerateQuorumRequest {
            bundle_id: *Uuid::new_v4().as_bytes(),
            label,
            threshold,
            max: count as u8,
            keyring: certificates
                .iter()
                .cloned()
                .map(|cert| Key::OpenPGP { cert })
                .collect(),
        });
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .with_context(Ctx::new("unable to create Keymaker client"))?;
        let response = http
            .post([url.as_str(), "/generate_quorum"].concat())
            .json(&request)
            .send()
            .await
            .with_context(Ctx::new(
                "Keymaker request failed or timed out; generation was not retried",
            ))?;
        let response: GenerateQuorumResponse =
            serde_json::from_value(checked_response(client, response).await?)
                .with_context(Ctx::new("invalid proofed Keymaker response"))?;
        let expected = request.to_latest();
        let returned = response.data.clone().to_latest();
        if returned.bundle_id != expected.bundle_id
            || returned.keyring != expected.keyring
            || returned.label != expected.label
        {
            return Err(InitError::invalid(
                "Keymaker response does not match the requested quorum",
            ));
        }
        (response, false)
    } else {
        let request = HostedRequest {
            name: &options.name,
            threshold,
            participants: &participants,
            pgp_certificates: &local,
            allow_caution_backed_keys: participants
                .iter()
                .any(|p| p.key_source == "caution_backed_pgp"),
            labels: &labels,
        };
        let response = client
            .signed_post(
                &config.as_ref().expect("authenticated").session_id,
                "/api/quorum-bundles/from-org-users",
                &request,
            )
            .await
            .with_context(Ctx::new(
                "unable to initialize hosted quorum; generation was not retried",
            ))?;
        let stored = checked_response(client, response).await?;
        let response = serde_json::from_value(stored.get("data").cloned().ok_or_else(|| {
            InitError::invalid("Platform response is missing the proofed bundle")
        })?)
        .with_context(Ctx::new("invalid proofed Platform quorum response"))?;
        (response, true)
    };
    let bundle = locksmith::bundle::load_response(response.clone(), &policy)
        .with_context(Ctx::new("Keymaker proof verification failed"))?
        .to_latest();
    if bundle.keyring.len() != count {
        return Err(InitError::invalid(
            "returned quorum holder count differs from selection",
        ));
    }
    let expected_pgp: Vec<_> = local.iter().chain(&registered).collect();
    let actual_pgp: Vec<_> = bundle
        .keyring
        .iter()
        .filter_map(|key| match key {
            Key::OpenPGP { cert } => Some(cert),
            _ => None,
        })
        .collect();
    let expected_kinds: Vec<_> = std::iter::repeat_n(false, local.len())
        .chain(
            participants
                .iter()
                .map(|p| p.key_source == "caution_backed_pgp"),
        )
        .collect();
    let actual_kinds: Vec<_> = bundle
        .keyring
        .iter()
        .map(|key| matches!(key, Key::WebAuthn { .. }))
        .collect();
    let mut expected_labels = labels.clone();
    if let Some(name) = &options.name {
        expected_labels
            .entry("name".into())
            .or_insert_with(|| name.clone());
    }
    if expected_pgp != actual_pgp
        || expected_kinds != actual_kinds
        || bundle.label != expected_labels
    {
        return Err(InitError::invalid(
            "returned quorum custody, certificates or labels differ from selection",
        ));
    }
    Cert::from_bytes(bundle.public_key.as_bytes())
        .with_context(Ctx::new("invalid quorum public key"))?;
    if bundle.shardfile.is_empty() {
        return Err(InitError::invalid("empty quorum shardfile"));
    }
    let json = serde_json::to_string_pretty(&response)
        .with_context(Ctx::new("unable to encode proofed bundle"))?;
    let in_repo = Path::new("caution.hcl").exists()
        || Path::new("Procfile").exists()
        || Path::new(".caution/deployment.json").exists();
    if in_repo {
        fs::create_dir_all(".caution")
            .with_context(Ctx::new("unable to create .caution directory"))?;
        // Save the accepted policy before the bundle; readers never trust policy from a response.
        fs::write(".caution/keymaker-pcr-policy.json", policy_text)
            .with_context(Ctx::new("unable to save accepted PCR policy"))?;
        fs::write(".caution/quorum-bundle.json", &json)
            .with_context(Ctx::new("unable to save proofed bundle"))?;
        output::status("Saved .caution/quorum-bundle.json and .caution/keymaker-pcr-policy.json");
    } else {
        output::data(&json).with_context(Ctx::new("unable to output bundle"))?;
    }
    if !uploaded && !options.no_upload {
        let body = serde_json::json!({"data": response, "name": options.name, "labels": labels});
        let response = client
            .signed_post(
                &config.as_ref().expect("authenticated").session_id,
                "/api/quorum-bundles",
                &body,
            )
            .await
            .with_context(Ctx::new(
                "bundle created; upload failed, do not regenerate it",
            ))?;
        checked_response(client, response).await?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "quorum_init_tests.rs"]
mod tests;
