// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Bounded, verified S3 reads and create-only component publication.

use super::{
    artifact_key, manifest_key, sha256, validate_digest, ArtifactFile, Component,
    ComponentArtifact, ComponentSet, ComponentSpec, MAX_ARTIFACT_SIZE,
};
use aws_sdk_s3::{error::ProvideErrorMetadata, primitives::ByteStream};
use dterror::ResultExt;
use std::collections::BTreeMap;

const MAX_JSON_SIZE: u64 = 128 * 1024;
const CONDITIONAL_ATTEMPTS: usize = 3;

/// Failure in the immutable component object-store flow. Only `NoSuchKey` is a miss.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum StoreError {
    /// An SDK, decoding, or model validation operation failed.
    #[error("could not {operation} component object [{location}]")]
    Operation {
        operation: &'static str,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
    /// Input or downloaded data violates the immutable storage protocol.
    #[error("component store rejected {reason} [{location}]")]
    Invalid {
        reason: &'static str,
        location: dterror::Location,
    },
    /// A pinned object is absent; never silently rebuild an existing descriptor.
    #[error("required component object is missing [{location}]")]
    Missing { location: dterror::Location },
}

#[track_caller]
fn invalid(reason: &'static str) -> StoreError {
    StoreError::Invalid {
        reason,
        location: std::panic::Location::caller(),
    }
}
#[track_caller]
fn missing() -> StoreError {
    StoreError::Missing {
        location: std::panic::Location::caller(),
    }
}

/// An explicitly configured client and bucket; source and destination may use
/// entirely different credentials, endpoints and accounts.
#[derive(Clone)]
pub struct S3ComponentStore {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3ComponentStore {
    /// Bind an existing SDK client. No implicit credentials or region resolution.
    /// Preserve the caller's retry policy, including retries for transient errors.
    pub fn new(client: aws_sdk_s3::Client, bucket: String) -> Self {
        Self { client, bucket }
    }

    #[tracing::instrument(skip_all, err)]
    async fn read_bounded(&self, key: &str, limit: u64) -> Result<Option<Vec<u8>>, StoreError> {
        use StoreErrorCtx as Ctx;
        validate_key(key)?;
        let response = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error)
                if error
                    .raw_response()
                    .is_some_and(|response| response.status().as_u16() == 404)
                    && error.as_service_error().is_some_and(|e| e.is_no_such_key()) =>
            {
                return Ok(None)
            }
            Err(error) => return Err(error).with_context(Ctx::operation("read")),
        };
        let declared = response.content_length();
        if declared.is_some_and(|n| n < 0 || n as u64 > limit) {
            return Err(invalid("object length exceeds bound"));
        }
        let mut body = response.body;
        let mut bytes = Vec::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.with_context(Ctx::operation("stream"))?;
            if chunk.len() as u64 > limit.saturating_sub(bytes.len() as u64) {
                return Err(invalid("stream exceeds bound"));
            }
            bytes.extend_from_slice(&chunk);
        }
        if declared.is_some_and(|n| n as u64 != bytes.len() as u64) {
            return Err(invalid("truncated object"));
        }
        Ok(Some(bytes))
    }

    /// Read a blob only if both its pinned size and raw SHA-256 match. A missing
    /// key is the sole `None` case; all authorization and integrity errors fail.
    #[tracing::instrument(skip_all, err)]
    pub async fn get_verified(
        &self,
        key: &str,
        expected: &ArtifactFile,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        use StoreErrorCtx as Ctx;
        expected
            .validate()
            .with_context(Ctx::operation("validate descriptor"))?;
        match validate_key(key)? {
            Key::Blob(digest) if digest == expected.sha256() => {}
            _ => return Err(invalid("blob key and descriptor disagree")),
        }
        let Some(bytes) = self.read_bounded(key, expected.size()).await? else {
            return Ok(None);
        };
        expected
            .verify(&bytes)
            .with_context(Ctx::operation("verify blob"))?;
        Ok(Some(bytes))
    }

    /// Load a set by a separately trusted digest. Verify raw bytes before JSON.
    #[tracing::instrument(skip_all, err)]
    pub async fn load_set(&self, digest: &str) -> Result<ComponentSet, StoreError> {
        use StoreErrorCtx as Ctx;
        let key = manifest_key(digest).with_context(Ctx::operation("validate manifest key"))?;
        let bytes = self
            .read_bounded(&key, MAX_JSON_SIZE)
            .await?
            .ok_or_else(missing)?;
        if sha256(&bytes) != digest {
            return Err(invalid("manifest digest mismatch"));
        }
        let set: ComponentSet =
            serde_json::from_slice(&bytes).with_context(Ctx::operation("parse manifest"))?;
        let canonical = set
            .canonical_bytes()
            .with_context(Ctx::operation("validate manifest"))?;
        if canonical != bytes {
            return Err(invalid("manifest is not canonical JSON"));
        }
        Ok(set)
    }

    /// Create an object within the fixed component namespace, never overwrite.
    /// Every successful PUT and 412 race requires exact read-back. A 409 conflict
    /// retries only the conditional PUT, without probing a possibly absent key:
    /// S3 may deny that GET when the caller lacks ListBucket. Conditional retries
    /// are bounded independently of the client's transient-request retry policy.
    #[tracing::instrument(skip_all, err)]
    pub async fn put_immutable(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        use StoreErrorCtx as Ctx;
        validate_publication(key, bytes)?;
        for _ in 0..CONDITIONAL_ATTEMPTS {
            match self
                .client
                .put_object()
                .bucket(&self.bucket)
                .key(key)
                .if_none_match("*")
                .body(ByteStream::from(bytes.to_vec()))
                .send()
                .await
            {
                Ok(_) => {}
                Err(error)
                    if matches!(
                        (
                            error.raw_response().map(|r| r.status().as_u16()),
                            error.as_service_error().and_then(|e| e.code())
                        ),
                        (Some(409), Some("ConditionalRequestConflict"))
                    ) =>
                {
                    continue;
                }
                Err(error)
                    if matches!(
                        (
                            error.raw_response().map(|r| r.status().as_u16()),
                            error.as_service_error().and_then(|e| e.code())
                        ),
                        (Some(412), Some("PreconditionFailed"))
                    ) => {}
                Err(error) => {
                    return Err(error).with_context(Ctx::operation("create immutable object"))
                }
            };
            match self.read_bounded(key, bytes.len() as u64).await? {
                Some(actual) if actual == bytes => return Ok(()),
                Some(_) => return Err(invalid("immutable object differs from publication")),
                None => return Err(missing()),
            }
        }
        Err(invalid("conditional publication attempts exhausted"))
    }

    /// Check a separately trusted historical descriptor against the mutable S3
    /// index and all expected blobs. `false` authorizes repair of missing objects
    /// only, using outputs checked against this same descriptor by `publish_build`.
    /// A present substituted index, corrupt blob or access denial always fails,
    /// even when another object is missing. This method never writes.
    #[tracing::instrument(skip_all, err)]
    pub async fn load_accepted_build(
        &self,
        accepted: &ComponentArtifact,
    ) -> Result<bool, StoreError> {
        use StoreErrorCtx as Ctx;
        accepted
            .validate()
            .with_context(Ctx::operation("validate accepted descriptor"))?;
        let mut complete = true;
        match self
            .read_bounded(&build_key(accepted.spec())?, MAX_JSON_SIZE)
            .await?
        {
            Some(bytes) => {
                let actual: ComponentArtifact = serde_json::from_slice(&bytes)
                    .with_context(Ctx::operation("parse accepted build index"))?;
                actual
                    .validate()
                    .with_context(Ctx::operation("validate accepted build index"))?;
                if &actual != accepted {
                    return Err(invalid(
                        "build index differs from trusted accepted descriptor",
                    ));
                }
            }
            None => complete = false,
        }
        for (name, file) in accepted.files() {
            let key = artifact_key(file.sha256(), name)
                .with_context(Ctx::operation("validate accepted blob key"))?;
            if self.get_verified(&key, file).await?.is_none() {
                complete = false;
            }
        }
        Ok(complete)
    }

    #[tracing::instrument(skip_all, err)]
    async fn verify_artifact(&self, artifact: &ComponentArtifact) -> Result<(), StoreError> {
        use StoreErrorCtx as Ctx;
        artifact
            .validate()
            .with_context(Ctx::operation("validate artifact"))?;
        for (name, file) in artifact.files() {
            let key = artifact_key(file.sha256(), name)
                .with_context(Ctx::operation("validate blob key"))?;
            self.get_verified(&key, file).await?.ok_or_else(missing)?;
        }
        Ok(())
    }

    /// Publish complete compiler outputs first, followed by their create-only
    /// per-spec index. Non-reproducible racing builds cannot replace an index.
    #[tracing::instrument(skip_all, err)]
    pub async fn publish_build(
        &self,
        artifact: &ComponentArtifact,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), StoreError> {
        use StoreErrorCtx as Ctx;
        artifact
            .validate()
            .with_context(Ctx::operation("validate build"))?;
        if !artifact.files().keys().eq(files.keys()) {
            return Err(invalid("publication filenames differ"));
        }
        for (name, descriptor) in artifact.files() {
            let bytes = files
                .get(name)
                .ok_or_else(|| invalid("missing publication file"))?;
            descriptor
                .verify(bytes)
                .with_context(Ctx::operation("verify publication"))?;
        }
        for (name, bytes) in files {
            let key = artifact_key(&sha256(bytes), name)
                .with_context(Ctx::operation("validate blob key"))?;
            self.put_immutable(&key, bytes).await?;
        }
        self.put_immutable(&build_key(artifact.spec())?, &canonical_json(artifact)?)
            .await
    }

    /// Reverify all referenced blobs, then publish the complete manifest last.
    /// Returns its immutable digest; this does not select any active set.
    #[tracing::instrument(skip_all, err)]
    pub async fn publish_set(&self, set: &ComponentSet) -> Result<String, StoreError> {
        use StoreErrorCtx as Ctx;
        set.validate()
            .with_context(Ctx::operation("validate set"))?;
        for artifact in set.components().values() {
            self.verify_artifact(artifact).await?;
        }
        self.put_set(set).await
    }

    #[tracing::instrument(skip_all, err)]
    async fn put_set(&self, set: &ComponentSet) -> Result<String, StoreError> {
        use StoreErrorCtx as Ctx;
        let bytes = set
            .canonical_bytes()
            .with_context(Ctx::operation("encode manifest"))?;
        let digest = sha256(&bytes);
        let key = manifest_key(&digest).with_context(Ctx::operation("validate manifest key"))?;
        self.put_immutable(&key, &bytes).await?;
        Ok(digest)
    }

    /// Two-client BYOC relay without CopyObject, overwrites or deletes.
    /// Relay only selected components (including every output of each selected
    /// component), but publish the full pinned manifest unchanged. Unselected
    /// blobs need not exist in either bucket. Missing selections fail before I/O.
    /// Verify the source before each create-only PUT and destination read-back;
    /// never probe missing destination keys or require ListBucket for the relay.
    #[tracing::instrument(skip_all, err)]
    pub async fn ensure_components_from(
        &self,
        source: &Self,
        set: &ComponentSet,
        required: &[Component],
    ) -> Result<(), StoreError> {
        use StoreErrorCtx as Ctx;
        set.validate()
            .with_context(Ctx::operation("validate relay set"))?;
        if required
            .iter()
            .any(|component| !set.components().contains_key(component))
        {
            return Err(invalid("required relay component absent from pinned set"));
        }
        for (component, artifact) in set.components() {
            if !required.contains(component) {
                continue;
            }
            for (name, file) in artifact.files() {
                let key = artifact_key(file.sha256(), name)
                    .with_context(Ctx::operation("validate relay key"))?;
                let bytes = source.get_verified(&key, file).await?.ok_or_else(missing)?;
                self.put_immutable(&key, &bytes).await?;
            }
        }
        self.put_set(set).await?;
        Ok(())
    }
}

enum Key<'a> {
    Blob(&'a str),
    Manifest(&'a str),
    Build,
}

#[tracing::instrument(skip_all, err)]
fn validate_key(key: &str) -> Result<Key<'_>, StoreError> {
    use StoreErrorCtx as Ctx;
    if let Some(rest) = key.strip_prefix("components/v1/blobs/sha256/") {
        let (digest, filename) = rest.split_once('/').ok_or_else(|| invalid("blob path"))?;
        if artifact_key(digest, filename).with_context(Ctx::operation("validate key"))? != key {
            return Err(invalid("blob path"));
        }
        return Ok(Key::Blob(digest));
    }
    for (prefix, is_manifest) in [
        ("components/v1/manifests/sha256/", true),
        ("components/v1/builds/", false),
    ] {
        if let Some(digest) = key
            .strip_prefix(prefix)
            .and_then(|s| s.strip_suffix(".json"))
        {
            validate_digest(digest).with_context(Ctx::operation("validate key digest"))?;
            return Ok(if is_manifest {
                Key::Manifest(digest)
            } else {
                Key::Build
            });
        }
    }
    Err(invalid("key outside component namespace"))
}

#[tracing::instrument(skip_all, err)]
fn canonical_json(value: &impl serde::Serialize) -> Result<Vec<u8>, StoreError> {
    use StoreErrorCtx as Ctx;
    let mut json =
        serde_json::to_value(value).with_context(Ctx::operation("serialize descriptor"))?;
    json.sort_all_objects();
    serde_json::to_vec(&json).with_context(Ctx::operation("encode descriptor"))
}

/// Immutable index key derived from validated canonical spec JSON.
#[tracing::instrument(skip_all, err)]
pub fn build_key(spec: &ComponentSpec) -> Result<String, StoreError> {
    use StoreErrorCtx as Ctx;
    spec.validate()
        .with_context(Ctx::operation("validate spec"))?;
    Ok(format!(
        "components/v1/builds/{}.json",
        sha256(&canonical_json(spec)?)
    ))
}

#[tracing::instrument(skip_all, err)]
fn validate_publication(key: &str, bytes: &[u8]) -> Result<(), StoreError> {
    use StoreErrorCtx as Ctx;
    match validate_key(key)? {
        Key::Blob(digest) => {
            if bytes.is_empty() || bytes.len() as u64 > MAX_ARTIFACT_SIZE || sha256(bytes) != digest
            {
                return Err(invalid("publication blob digest or size"));
            }
        }
        Key::Manifest(digest) => {
            if bytes.len() as u64 > MAX_JSON_SIZE || sha256(bytes) != digest {
                return Err(invalid("publication manifest digest or size"));
            }
            let set: ComponentSet = serde_json::from_slice(bytes)
                .with_context(Ctx::operation("parse publication manifest"))?;
            if set
                .canonical_bytes()
                .with_context(Ctx::operation("validate publication manifest"))?
                != bytes
            {
                return Err(invalid("noncanonical publication manifest"));
            }
        }
        Key::Build => {
            if bytes.len() as u64 > MAX_JSON_SIZE {
                return Err(invalid("publication descriptor size"));
            }
            let artifact: ComponentArtifact = serde_json::from_slice(bytes)
                .with_context(Ctx::operation("parse publication descriptor"))?;
            artifact
                .validate()
                .with_context(Ctx::operation("validate publication descriptor"))?;
            if build_key(artifact.spec())? != key || canonical_json(&artifact)? != bytes {
                return Err(invalid("publication descriptor identity"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::{Component, ComponentSpec};
    use aws_sdk_s3::config::{retry::RetryConfig, BehaviorVersion, Credentials, Region};
    use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    struct Reply {
        method: &'static str,
        status: u16,
        body: Vec<u8>,
        key: Option<String>,
        uploaded: Option<Vec<u8>>,
    }
    impl Reply {
        fn at(mut self, key: &str) -> Self {
            self.key = Some(key.to_owned());
            self
        }
        fn uploading(mut self, bytes: impl AsRef<[u8]>) -> Self {
            assert_eq!(self.method, "PUT");
            self.uploaded = Some(bytes.as_ref().to_vec());
            self
        }
    }
    fn reply(method: &'static str, status: u16, body: impl AsRef<[u8]>) -> Reply {
        Reply {
            method,
            status,
            body: body.as_ref().to_vec(),
            key: None,
            uploaded: None,
        }
    }
    fn missing() -> Reply {
        reply("GET", 404, b"<Error><Code>NoSuchKey</Code></Error>")
    }
    async fn read_chunked(reader: &mut (impl AsyncBufRead + Unpin)) -> Vec<u8> {
        let mut body = Vec::new();
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).await.unwrap() > 0);
            let size = usize::from_str_radix(line.trim().split(';').next().unwrap(), 16).unwrap();
            if size == 0 {
                loop {
                    line.clear();
                    assert!(reader.read_line(&mut line).await.unwrap() > 0);
                    if line == "\r\n" {
                        return body;
                    }
                }
            }
            assert!(body.len() + size < 65536, "fixture upload exceeds bound");
            let start = body.len();
            body.resize(start + size, 0);
            reader.read_exact(&mut body[start..]).await.unwrap();
            let mut crlf = [0; 2];
            reader.read_exact(&mut crlf).await.unwrap();
            assert_eq!(&crlf, b"\r\n");
        }
    }
    fn assert_operation(error: StoreError, expected: &str) {
        match error {
            StoreError::Operation { operation, .. } => assert_eq!(operation, expected),
            other => panic!("expected operation {expected:?}, got {other:?}"),
        }
    }
    fn assert_invalid(error: StoreError, expected: &str) {
        match error {
            StoreError::Invalid { reason, .. } => assert_eq!(reason, expected),
            other => panic!("expected rejection {expected:?}, got {other:?}"),
        }
    }
    struct Fixture {
        store: S3ComponentStore,
        task: tokio::task::JoinHandle<()>,
        finish: tokio::sync::oneshot::Sender<()>,
    }
    impl Fixture {
        async fn new(identity: &'static str, replies: Vec<Reply>) -> Self {
            Self::with_retry_config(identity, replies, RetryConfig::standard().with_max_attempts(1))
                .await
        }
        async fn with_retry_config(
            identity: &'static str,
            replies: Vec<Reply>,
            retry_config: RetryConfig,
        ) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let (finish, finished) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                for response in replies {
                    let (mut stream, _) =
                        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                            .await
                            .unwrap()
                            .unwrap();
                    let mut raw = Vec::new();
                    loop {
                        let mut buf = [0; 4096];
                        let n = stream.read(&mut buf).await.unwrap();
                        assert!(n > 0);
                        raw.extend_from_slice(&buf[..n]);
                        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                        assert!(raw.len() < 65536);
                    }
                    let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                    let request = String::from_utf8(raw[..header_end].to_vec())
                        .unwrap()
                        .to_ascii_lowercase();
                    if let Some(key) = &response.key {
                        let path = request.split_whitespace().nth(1).unwrap();
                        assert_eq!(path.split('?').next().unwrap(), format!("/bucket/{key}"));
                    }
                    if response.method == "PUT" && request.starts_with("get ") {
                        let body = b"<Error><Code>AccessDenied</Code></Error>";
                        let header = format!("HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                        stream.write_all(header.as_bytes()).await.unwrap();
                        stream.write_all(body).await.unwrap();
                        stream.shutdown().await.unwrap();
                        panic!("destination GET before conditional PUT requires missing-key visibility");
                    }
                    assert!(
                        request.starts_with(&format!(
                            "{} /bucket/components/v1/",
                            response.method.to_ascii_lowercase()
                        )),
                        "unexpected method/path"
                    );
                    assert!(
                        request.contains(&format!("credential={}/", identity.to_ascii_lowercase())),
                        "wrong client credentials"
                    );
                    assert!(
                        !request.contains("x-amz-copy-source"),
                        "relay must not use CopyObject"
                    );
                    if response.method == "PUT" {
                        assert!(request.contains("if-none-match: *\r\n"));
                    }
                    if request.contains("expect: 100-continue\r\n") {
                        stream
                            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                            .await
                            .unwrap();
                    }
                    let body = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        let header = |name| {
                            request
                                .lines()
                                .find_map(|line| line.strip_prefix(name))
                                .map(str::trim)
                        };
                        let mut reader = BufReader::new((&raw[header_end..]).chain(&mut stream));
                        let mut body = if header("transfer-encoding:") == Some("chunked") {
                            read_chunked(&mut reader).await
                        } else {
                            let length = header("content-length:")
                                .unwrap_or("0")
                                .parse::<usize>()
                                .unwrap();
                            assert!(length < 65536, "fixture upload exceeds bound");
                            let mut body = vec![0; length];
                            reader.read_exact(&mut body).await.unwrap();
                            body
                        };
                        if header("content-encoding:") == Some("aws-chunked") {
                            let mut encoded = body.as_slice();
                            let decoded = read_chunked(&mut encoded).await;
                            assert!(encoded.is_empty(), "extra bytes after aws-chunked body");
                            body = decoded;
                            assert_eq!(
                                body.len(),
                                header("x-amz-decoded-content-length:")
                                    .unwrap()
                                    .parse::<usize>()
                                    .unwrap()
                            );
                        }
                        body
                    })
                    .await
                    .expect("timed out reading fixture request body");
                    if response.method == "PUT" {
                        assert_eq!(
                            body,
                            response.uploaded.expect("PUT must specify expected bytes"),
                            "wrong uploaded payload"
                        );
                    } else {
                        assert!(body.is_empty(), "unexpected GET request body");
                    }
                    let header = format!("HTTP/1.1 {} Test\r\nContent-Length: {}\r\nContent-Type: application/xml\r\nConnection: close\r\n\r\n", response.status, response.body.len());
                    stream.write_all(header.as_bytes()).await.unwrap();
                    stream.write_all(&response.body).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
                tokio::select! {
                    biased;
                    unexpected = listener.accept() => panic!("unexpected extra request: {unexpected:?}"),
                    _ = finished => {}
                }
            });
            let config = aws_sdk_s3::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new("us-east-1"))
                .credentials_provider(Credentials::new(
                    identity,
                    "fixture-secret",
                    None,
                    None,
                    "fixture",
                ))
                .retry_config(retry_config)
                .endpoint_url(endpoint)
                .force_path_style(true)
                .build();
            Self {
                store: S3ComponentStore::new(
                    aws_sdk_s3::Client::from_conf(config),
                    "bucket".to_owned(),
                ),
                task,
                finish,
            }
        }
        async fn done(self) {
            let _ = self.finish.send(());
            self.task.await.unwrap();
        }
    }
    fn blob() -> (String, ArtifactFile) {
        let file = ArtifactFile::from_bytes(b"good").unwrap();
        (artifact_key(file.sha256(), "init").unwrap(), file)
    }
    fn artifact(component: Component) -> ComponentArtifact {
        let spec = ComponentSpec::new(
            component,
            "a".repeat(40),
            sha256(b"recipe"),
            component.source_subdir().map(|_| sha256(b"source")),
        )
        .unwrap();
        ComponentArtifact::new(
            spec,
            component
                .filenames()
                .iter()
                .map(|name| {
                    (
                        (*name).to_owned(),
                        ArtifactFile::from_bytes(b"good").unwrap(),
                    )
                })
                .collect(),
        )
        .unwrap()
    }
    fn set() -> ComponentSet {
        ComponentSet::new(
            Component::REQUIRED
                .into_iter()
                .map(|c| (c, artifact(c)))
                .collect(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn supplied_client_retries_transient_get_and_put_failures() {
        let (key, file) = blob();
        let fixture = Fixture::with_retry_config(
            "READER_WRITER",
            vec![
                reply("GET", 503, "<Error><Code>SlowDown</Code></Error>").at(&key),
                reply("GET", 200, b"good").at(&key),
                reply("PUT", 503, "<Error><Code>SlowDown</Code></Error>")
                    .at(&key)
                    .uploading(b"good"),
                reply("PUT", 200, b"").at(&key).uploading(b"good"),
                reply("GET", 200, b"good").at(&key),
            ],
            RetryConfig::standard().with_max_attempts(2),
        )
        .await;
        assert_eq!(
            fixture.store.get_verified(&key, &file).await.unwrap(),
            Some(b"good".to_vec())
        );
        fixture.store.put_immutable(&key, b"good").await.unwrap();
        fixture.done().await;
    }

    #[tokio::test]
    async fn only_explicit_no_such_key_is_a_cache_miss() {
        let (key, file) = blob();
        let fixture = Fixture::new(
            "READER",
            vec![
                missing(),
                reply("GET", 403, "<Error><Code>AccessDenied</Code></Error>"),
                reply("GET", 404, "<Error><Code>NoSuchBucket</Code></Error>"),
            ],
        )
        .await;
        assert!(fixture
            .store
            .get_verified(&key, &file)
            .await
            .unwrap()
            .is_none());
        assert!(fixture.store.get_verified(&key, &file).await.is_err());
        assert!(fixture.store.get_verified(&key, &file).await.is_err());
        fixture.done().await;
    }

    #[tokio::test]
    async fn forbidden_response_is_never_a_miss_even_with_no_such_key_code() {
        let (key, file) = blob();
        let fixture = Fixture::new(
            "READER",
            vec![reply("GET", 403, "<Error><Code>NoSuchKey</Code></Error>")],
        )
        .await;
        assert!(fixture.store.get_verified(&key, &file).await.is_err());
        fixture.done().await;
    }

    #[tokio::test]
    async fn corrupt_and_oversized_objects_are_errors_not_misses() {
        let (key, file) = blob();
        let fixture = Fixture::new(
            "READER",
            vec![reply("GET", 200, b"evil"), reply("GET", 200, b"good!")],
        )
        .await;
        assert_operation(
            fixture.store.get_verified(&key, &file).await.unwrap_err(),
            "verify blob",
        );
        assert_invalid(
            fixture.store.get_verified(&key, &file).await.unwrap_err(),
            "object length exceeds bound",
        );
        fixture.done().await;
    }

    #[tokio::test]
    async fn immutable_race_requires_exact_readback() {
        let (key, _) = blob();
        let fixture = Fixture::new(
            "WRITER",
            vec![
                reply("PUT", 412, "<Error><Code>PreconditionFailed</Code></Error>")
                    .uploading(b"good"),
                reply("GET", 200, b"good"),
                reply("PUT", 412, "<Error><Code>PreconditionFailed</Code></Error>")
                    .uploading(b"good"),
                reply("GET", 200, b"evil"),
            ],
        )
        .await;
        fixture.store.put_immutable(&key, b"good").await.unwrap();
        assert_invalid(
            fixture
                .store
                .put_immutable(&key, b"good")
                .await
                .unwrap_err(),
            "immutable object differs from publication",
        );
        fixture.done().await;
    }

    #[tokio::test]
    async fn successful_put_is_also_verified_by_readback() {
        let (key, _) = blob();
        let fixture = Fixture::new(
            "WRITER",
            vec![
                reply("PUT", 200, b"").uploading(b"good"),
                reply("GET", 200, b"evil"),
            ],
        )
        .await;
        assert_invalid(
            fixture
                .store
                .put_immutable(&key, b"good")
                .await
                .unwrap_err(),
            "immutable object differs from publication",
        );
        fixture.done().await;
    }

    #[tokio::test]
    async fn conditional_conflict_retries_without_destination_get() {
        let (key, _) = blob();
        let fixture = Fixture::new(
            "WRITER",
            vec![
                reply(
                    "PUT",
                    409,
                    "<Error><Code>ConditionalRequestConflict</Code></Error>",
                )
                .uploading(b"good"),
                reply("PUT", 200, b"").uploading(b"good"),
                reply("GET", 200, b"good"),
            ],
        )
        .await;
        fixture.store.put_immutable(&key, b"good").await.unwrap();
        fixture.done().await;
        let fixture = Fixture::new(
            "WRITER",
            vec![reply("PUT", 403, "<Error><Code>AccessDenied</Code></Error>").uploading(b"good")],
        )
        .await;
        assert!(fixture.store.put_immutable(&key, b"good").await.is_err());
        fixture.done().await;
    }

    #[tokio::test]
    async fn invalid_inputs_fail_before_network() {
        let fixture = Fixture::new("READER", vec![]).await;
        let (_, file) = blob();
        for key in ["../init", "unrelated/key"] {
            assert_invalid(
                fixture.store.get_verified(key, &file).await.unwrap_err(),
                "key outside component namespace",
            );
            assert_invalid(
                fixture.store.put_immutable(key, b"good").await.unwrap_err(),
                "key outside component namespace",
            );
        }
        let key = "components/v1/blobs/sha256/bad/init";
        assert_operation(
            fixture.store.get_verified(key, &file).await.unwrap_err(),
            "validate key",
        );
        assert_operation(
            fixture.store.put_immutable(key, b"good").await.unwrap_err(),
            "validate key",
        );
        assert_operation(
            fixture.store.load_set("bad").await.unwrap_err(),
            "validate manifest key",
        );
        fixture.done().await;
    }

    #[tokio::test]
    async fn load_set_rejects_noncanonical_manifest_identity() {
        let bytes = serde_json::to_vec_pretty(&set()).unwrap();
        assert_ne!(sha256(&bytes), sha256(&set().canonical_bytes().unwrap()));
        let fixture = Fixture::new("READER", vec![reply("GET", 200, &bytes)]).await;
        assert_invalid(
            fixture.store.load_set(&sha256(&bytes)).await.unwrap_err(),
            "manifest is not canonical JSON",
        );
        fixture.done().await;
    }

    #[tokio::test]
    async fn manifest_digest_is_verified_before_json_parse() {
        let malformed = b"not JSON";
        let fixture = Fixture::new(
            "READER",
            vec![reply("GET", 200, malformed), reply("GET", 200, malformed)],
        )
        .await;
        assert_invalid(
            fixture
                .store
                .load_set(&sha256(b"different"))
                .await
                .unwrap_err(),
            "manifest digest mismatch",
        );
        assert_operation(
            fixture
                .store
                .load_set(&sha256(malformed))
                .await
                .unwrap_err(),
            "parse manifest",
        );
        fixture.done().await;
        let bytes = set().canonical_bytes().unwrap();
        let fixture = Fixture::new("READER", vec![reply("GET", 200, &bytes)]).await;
        assert_eq!(
            fixture.store.load_set(&sha256(&bytes)).await.unwrap(),
            set()
        );
        fixture.done().await;
    }

    #[tokio::test]
    async fn conditional_retry_budget_is_finite() {
        let (key, _) = blob();
        let mut replies = Vec::new();
        for _ in 0..CONDITIONAL_ATTEMPTS {
            replies.push(
                reply(
                    "PUT",
                    409,
                    "<Error><Code>ConditionalRequestConflict</Code></Error>",
                )
                .uploading(b"good"),
            );
        }
        let fixture = Fixture::new("WRITER", replies).await;
        assert_invalid(
            fixture.store.put_immutable(&key, b"good").await.unwrap_err(),
            "conditional publication attempts exhausted",
        );
        fixture.done().await;
    }

    #[tokio::test]
    async fn destination_corruption_refuses_relay_without_overwrite_or_manifest() {
        let (key, _) = blob();
        let source = Fixture::new("SOURCE", vec![reply("GET", 200, b"good").at(&key)]).await;
        let destination = Fixture::new(
            "DESTINATION",
            vec![
                reply("PUT", 412, "<Error><Code>PreconditionFailed</Code></Error>")
                    .at(&key)
                    .uploading(b"good"),
                reply("GET", 200, b"evil").at(&key),
            ],
        )
        .await;
        assert_invalid(
            destination
                .store
                .ensure_components_from(&source.store, &set(), &[Component::Init])
                .await
                .unwrap_err(),
            "immutable object differs from publication",
        );
        source.done().await;
        destination.done().await;
    }

    #[tokio::test]
    async fn source_denial_or_corruption_never_writes_destination() {
        let (key, _) = blob();
        for (response, operation) in [
            (reply("GET", 403, "<Error><Code>AccessDenied</Code></Error>"), "read"),
            (reply("GET", 200, b"evil"), "verify blob"),
        ] {
            let source = Fixture::new("SOURCE", vec![response.at(&key)]).await;
            let destination = Fixture::new("DESTINATION", vec![]).await;
            assert_operation(
                destination
                    .store
                    .ensure_components_from(&source.store, &set(), &[Component::Init])
                    .await
                    .unwrap_err(),
                operation,
            );
            source.done().await;
            destination.done().await;
        }
    }

    #[tokio::test]
    async fn correct_manifest_digest_does_not_authorize_invalid_schema() {
        let bytes = b"{\"schema_version\":99,\"components\":{}}";
        let fixture = Fixture::new("READER", vec![reply("GET", 200, bytes)]).await;
        assert_operation(
            fixture.store.load_set(&sha256(bytes)).await.unwrap_err(),
            "validate manifest",
        );
        fixture.done().await;
    }

    #[tokio::test]
    async fn accepted_history_repairs_missing_index_or_blob_only_with_exact_bytes() {
        let accepted = artifact(Component::Init);
        let index = canonical_json(&accepted).unwrap();
        let index_key = build_key(accepted.spec()).unwrap();
        let (blob_key, _) = blob();
        for (index_missing, blob_missing) in [(true, true), (true, false), (false, true)] {
            let fixture = Fixture::new(
                "PUBLISHER",
                vec![
                    if index_missing {
                        missing().at(&index_key)
                    } else {
                        reply("GET", 200, &index).at(&index_key)
                    },
                    if blob_missing {
                        missing().at(&blob_key)
                    } else {
                        reply("GET", 200, b"good").at(&blob_key)
                    },
                    if blob_missing {
                        reply("PUT", 200, b"").at(&blob_key).uploading(b"good")
                    } else {
                        reply("PUT", 412, "<Error><Code>PreconditionFailed</Code></Error>")
                            .at(&blob_key)
                            .uploading(b"good")
                    },
                    reply("GET", 200, b"good").at(&blob_key),
                    if index_missing {
                        reply("PUT", 200, b"").at(&index_key).uploading(&index)
                    } else {
                        reply("PUT", 412, "<Error><Code>PreconditionFailed</Code></Error>")
                            .at(&index_key)
                            .uploading(&index)
                    },
                    reply("GET", 200, &index).at(&index_key),
                ],
            )
            .await;
            assert!(!fixture.store.load_accepted_build(&accepted).await.unwrap());
            let bad = BTreeMap::from([("init".to_owned(), b"evil".to_vec())]);
            assert_operation(
                fixture
                    .store
                    .publish_build(&accepted, &bad)
                    .await
                    .unwrap_err(),
                "verify publication",
            );
            let good = BTreeMap::from([("init".to_owned(), b"good".to_vec())]);
            fixture.store.publish_build(&accepted, &good).await.unwrap();
            fixture.done().await;
        }
    }

    #[tokio::test]
    async fn accepted_history_rejects_substituted_index_before_fetching_substituted_blob() {
        let accepted = artifact(Component::Init);
        let substituted = ComponentArtifact::new(
            accepted.spec().clone(),
            BTreeMap::from([(
                "init".to_owned(),
                ArtifactFile::from_bytes(b"evil").unwrap(),
            )]),
        )
        .unwrap();
        let fixture = Fixture::new(
            "READER",
            vec![reply("GET", 200, canonical_json(&substituted).unwrap())],
        )
        .await;
        assert!(matches!(
            fixture.store.load_accepted_build(&accepted).await,
            Err(StoreError::Invalid {
                reason: "build index differs from trusted accepted descriptor",
                ..
            })
        ));
        fixture.done().await;
    }

    #[tokio::test]
    async fn accepted_history_warm_reuse_checks_all_outputs() {
        let accepted = artifact(Component::Locksmith);
        let fixture = Fixture::new(
            "READER",
            vec![
                reply("GET", 200, canonical_json(&accepted).unwrap()),
                reply("GET", 200, b"good"),
                reply("GET", 200, b"good"),
            ],
        )
        .await;
        assert!(fixture.store.load_accepted_build(&accepted).await.unwrap());
        fixture.done().await;
    }

    #[tokio::test]
    async fn accepted_history_denial_or_corruption_is_not_repairable_even_after_a_miss() {
        let accepted = artifact(Component::Locksmith);
        for (bad, operation) in [
            (
                reply("GET", 403, "<Error><Code>AccessDenied</Code></Error>"),
                "read",
            ),
            (reply("GET", 200, b"evil"), "verify blob"),
        ] {
            let fixture = Fixture::new("READER", vec![missing(), missing(), bad]).await;
            assert_operation(
                fixture
                    .store
                    .load_accepted_build(&accepted)
                    .await
                    .unwrap_err(),
                operation,
            );
            fixture.done().await;
        }
        for (bad, operation) in [
            (
                reply("GET", 403, "<Error><Code>AccessDenied</Code></Error>"),
                "read",
            ),
            (reply("GET", 200, b"not json"), "parse accepted build index"),
        ] {
            let fixture = Fixture::new("READER", vec![bad]).await;
            assert_operation(
                fixture
                    .store
                    .load_accepted_build(&accepted)
                    .await
                    .unwrap_err(),
                operation,
            );
            fixture.done().await;
        }
    }

    #[tokio::test]
    async fn selected_relay_avoids_missing_destination_get_and_keeps_full_manifest() {
        let set = ComponentSet::new(
            Component::ALL
                .into_iter()
                .map(|c| (c, artifact(c)))
                .collect(),
        )
        .unwrap();
        let selected = [Component::TapFramer, Component::Locksmith];
        let mut source_replies = Vec::new();
        let mut destination_replies = Vec::new();
        for component in [Component::Locksmith, Component::TapFramer] {
            for (name, file) in set.components()[&component].files() {
                let key = artifact_key(file.sha256(), name).unwrap();
                source_replies.push(reply("GET", 200, b"good").at(&key));
                destination_replies.extend([
                    reply("PUT", 200, b"").at(&key).uploading(b"good"),
                    reply("GET", 200, b"good").at(&key),
                ]);
            }
        }
        let manifest = set.canonical_bytes().unwrap();
        let manifest_key = manifest_key(&sha256(&manifest)).unwrap();
        destination_replies.extend([
            reply("PUT", 200, b"")
                .at(&manifest_key)
                .uploading(&manifest),
            reply("GET", 200, &manifest).at(&manifest_key),
        ]);
        let source = Fixture::new("SOURCE", source_replies).await;
        let destination = Fixture::new("DESTINATION", destination_replies).await;
        destination
            .store
            .ensure_components_from(&source.store, &set, &selected)
            .await
            .unwrap();
        source.done().await;
        destination.done().await;
    }

    #[tokio::test]
    async fn selected_relay_rejects_missing_selection_before_network() {
        let source = Fixture::new("SOURCE", vec![]).await;
        let destination = Fixture::new("DESTINATION", vec![]).await;
        assert!(matches!(
            destination
                .store
                .ensure_components_from(&source.store, &set(), &[Component::Steve])
                .await,
            Err(StoreError::Invalid {
                reason: "required relay component absent from pinned set",
                ..
            })
        ));
        source.done().await;
        destination.done().await;
    }
}
