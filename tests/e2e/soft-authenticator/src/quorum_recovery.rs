//! Platform creation -> real key-service issuance/release -> destination decryption.
//! Only attestation and the disposable Keyforkd root are synthetic.
use super::*;
use locksmith::{models::SendSignedEncryptedShardResponse, release::*};
use sequoia_openpgp::{
    self as pgp,
    parse::{stream::*, Parse},
    policy::StandardPolicy,
};
use std::{
    io::Read,
    time::{Duration, SystemTime},
};

async fn post<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    base: &str,
    path: &str,
    body: &impl serde::Serialize,
) -> T {
    let response = http
        .post([base, path].concat())
        .json(body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    assert!(status.is_success(), "{path}: {status}: {text}");
    serde_json::from_str(&text).unwrap()
}

pub(crate) fn run(
    http: &Client,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
    origin: &Url,
    base: &str,
    id: &str,
    work: &Path,
) {
    let mut session = Session {
        http,
        authenticator,
        origin,
        base,
        id,
    };
    // Qualify the exact registered credential through the real UV ceremony.
    let keys: Value = checked(
        http.get([base, "/passkeys"].concat())
            .header("X-Session-ID", id)
            .send()
            .unwrap(),
    )
    .unwrap()
    .json()
    .unwrap();
    let path = [
        "/passkeys/",
        keys[0]["id"].as_str().unwrap(),
        "/recovery-verification",
    ]
    .concat();
    let begin: Value = checked(
        http.post([base, &path, "/begin"].concat())
            .header("X-Session-ID", id)
            .send()
            .unwrap(),
    )
    .unwrap()
    .json()
    .unwrap();
    let assertion = session
        .authenticator
        .do_authentication(
            origin.clone(),
            serde_json::from_value(begin.clone()).unwrap(),
        )
        .unwrap();
    let mut finish = serde_json::to_value(assertion).unwrap();
    finish["session"] = begin["session"].clone();
    let qualified: Value = checked(
        http.post([base, &path, "/finish"].concat())
            .header("X-Session-ID", id)
            .json(&finish)
            .send()
            .unwrap(),
    )
    .unwrap()
    .json()
    .unwrap();
    assert_eq!(qualified["uv_verified"], true);

    let members: Value = checked(session.get("/quorum-bundles/participants").unwrap())
        .unwrap()
        .json()
        .unwrap();
    let user = members
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["username"] == "quorumrecovery")
        .unwrap()["user_id"]
        .clone();
    let external = CertBuilder::new()
        .add_userid("local recovery holder")
        .add_signing_subkey()
        .add_authentication_subkey()
        .add_storage_encryption_subkey()
        .generate()
        .unwrap()
        .0;
    let mut public = Vec::new();
    external.armored().serialize(&mut public).unwrap();
    let request = json!({"threshold":2, "pgp_certificates":[String::from_utf8(public).unwrap()],
        "participants":[{"user_id":user,"key_source":"caution_backed_pgp"}],
        "allow_caution_backed_keys":true});
    let created: Value = checked(
        session
            .signed(
                Method::POST,
                "/quorum-bundles/from-org-users",
                &request.to_string(),
            )
            .unwrap(),
    )
    .unwrap()
    .json()
    .unwrap();
    let path = ["/quorum-bundles/", created["id"].as_str().unwrap()].concat();
    let downloaded: Value = checked(session.get(&path).unwrap())
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(created["data"], downloaded["data"]);
    let bundle_path = work.join("recovery-bundle.json");
    let bundle_text = serde_json::to_string(&downloaded["data"]).unwrap();
    fs::write(&bundle_path, &bundle_text).unwrap();
    let policy = locksmith::bundle::KeymakerPcrPolicy::from_json(
        &fs::read_to_string(work.join("policies/keymaker-pcr-policy.json")).unwrap(),
    )
    .unwrap();
    let proof = serde_json::from_str(&bundle_text).unwrap();
    let (bundle, generated_at) =
        locksmith::bundle::load_response_with_timestamp(proof, &policy).unwrap();
    let data = bundle.clone().to_latest();
    assert_eq!((data.threshold, data.max), (2, 2));
    let derived = downloaded["data"]["data"]["keyring"][1]["WebAuthn"]["cert"]
        .as_str()
        .unwrap();
    let holder = pgp::Cert::from_bytes(derived.as_bytes())
        .unwrap()
        .fingerprint()
        .to_string();
    fs::write(
        work.join("recovery.env"),
        "LOCAL_RECOVERY_SECRET=created-encrypted-recovered\n",
    )
    .unwrap();
    let output = Command::new(std::env::var("QUORUM_CLI").unwrap())
        .current_dir(work)
        .args([
            "secret",
            "encrypt",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--env-file",
            "recovery.env",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "CLI encryption: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let service = std::env::var("PUBLIC_CERTIFICATE_SERVICE_URL").unwrap();
    let release_origin = Url::parse(&std::env::var("KEY_SERVICE_ORIGIN").unwrap()).unwrap();
    let measurements: Measurements = (0..=2).map(|i| (i, "ab".repeat(48))).collect();
    let recovered = tokio::runtime::Runtime::new().unwrap().block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let address = listener.local_addr().unwrap();
            drop(listener);
            let receiver = tokio::spawn(async move {
                locksmith::server::receive_shards_at(address, &bundle, generated_at)
                    .await
                    .unwrap()
            });
            let http = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap();
            let nonce = random_nonce();
            let begun: Attested<Begun> = post(
                &http,
                &service,
                "/v1/releases/begin",
                &BeginRequest {
                    version: Version::V1,
                    bundle: serde_json::from_str(&bundle_text).unwrap(),
                    holder,
                    destination_policy: measurements.clone(),
                    client_nonce: nonce.clone(),
                },
            )
            .await;
            verify_response(&begun, &measurements, &nonce).unwrap();
            assert_eq!(begun.data.context.holder_position, 1);
            assert_eq!(begun.data.context.certificate_index, 0);
            let destination = loop {
                match crypto::Destination::connect(
                    address,
                    begun.data.context.transport_nonce.clone(),
                )
                .await
                {
                    Ok(destination) => break destination,
                    Err(error) => {
                        assert!(
                            !receiver.is_finished(),
                            "receiver failed before release: {error}"
                        );
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            };
            let nonce = random_nonce();
            let prepared: Attested<Prepared> = post(
                &http,
                &service,
                "/v1/releases/prepare",
                &PrepareRequest {
                    version: Version::V1,
                    session_id: begun.data.session_id,
                    destination_attestation: destination.attestation.clone(),
                    client_nonce: nonce.clone(),
                },
            )
            .await;
            verify_response(&prepared, &measurements, &nonce).unwrap();
            let assertion = session
                .authenticator
                .do_authentication(release_origin, prepared.data.options)
                .unwrap();
            let complete = CompleteRequest {
                version: Version::V1,
                session_id: prepared.data.session_id,
                assertion,
            };
            let encrypted = post(&http, &service, "/v1/releases/complete", &complete).await;
            crypto::verify_request(derived, &encrypted, SystemTime::now()).unwrap();
            assert!(matches!(
                destination.send(encrypted).await.unwrap(),
                SendSignedEncryptedShardResponse::Accepted { remaining: 1 }
            ));
            assert!(
                !receiver.is_finished(),
                "destination unlocked below threshold"
            );
            assert_eq!(
                http.post([service.as_str(), "/v1/releases/complete"].concat())
                    .json(&complete)
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .as_u16(),
                403,
                "replayed approval"
            );
            let nonce = random_nonce();
            let destination = crypto::Destination::connect(address, nonce.clone())
                .await
                .unwrap();
            let key = verify_live(&destination.attestation, &measurements, &nonce)
                .unwrap()
                .try_into()
                .unwrap();
            let mut context = prepared.data.context;
            context.holder_position = 0;
            context.holder = external.fingerprint().to_string();
            let encrypted = crypto::recrypt(&context, &data, key, external).unwrap();
            assert!(matches!(
                destination.send(encrypted).await.unwrap(),
                SendSignedEncryptedShardResponse::Accepted { remaining: 0 }
            ));
            receiver.await.unwrap()
        })
        .await
        .expect("continuous recovery timed out")
    });
    // Derive from what the TCP receiver reconstructed, never the known test entropy.
    let seed = keyfork_mnemonic::Mnemonic::try_from_slice(&recovered)
        .unwrap()
        .generate_seed(None);
    let private = keyfork_derive_openpgp::XPrv::new(seed)
        .unwrap()
        .derive_path(&public_cert_service::derivation::default_openpgp_ca_path())
        .unwrap();
    let private = keyfork_derive_openpgp::derive(
        &private,
        &public_cert_service::derivation::public_certificate_key_flags(),
        &pgp::packet::UserID::from("Keymaker-generated key"),
    )
    .unwrap();
    assert_eq!(
        private.fingerprint(),
        pgp::Cert::from_bytes(data.public_key.as_bytes())
            .unwrap()
            .fingerprint()
    );
    let policy = StandardPolicy::new();
    let key = private
        .keys()
        .secret()
        .with_policy(&policy, None)
        .for_storage_encryption()
        .next()
        .unwrap()
        .key()
        .clone()
        .into_keypair()
        .unwrap();
    let mut plaintext = Vec::new();
    DecryptorBuilder::from_file(work.join(".caution/secrets/LOCAL_RECOVERY_SECRET.asc"))
        .unwrap()
        .with_policy(&policy, None, Recipient(key))
        .unwrap()
        .read_to_end(&mut plaintext)
        .unwrap();
    assert_eq!(plaintext, b"created-encrypted-recovered");
    println!("PASS: Platform -> real Keymaker/key-service -> downloaded bundle -> CLI encryption -> passkey release -> threshold recovery -> plaintext (synthetic attestation)");
}

struct Recipient(pgp::crypto::KeyPair);
impl VerificationHelper for Recipient {
    fn get_certs(&mut self, _: &[pgp::KeyHandle]) -> pgp::Result<Vec<pgp::Cert>> {
        Ok(Vec::new())
    }
    fn check(&mut self, _: MessageStructure) -> pgp::Result<()> {
        Ok(())
    }
}
impl DecryptionHelper for Recipient {
    fn decrypt<D>(
        &mut self,
        pkesks: &[pgp::packet::PKESK],
        _: &[pgp::packet::SKESK],
        algorithm: Option<pgp::types::SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> pgp::Result<Option<pgp::Fingerprint>>
    where
        D: FnMut(pgp::types::SymmetricAlgorithm, &pgp::crypto::SessionKey) -> bool,
    {
        for pkesk in pkesks {
            if let Some((algorithm, key)) = pkesk.decrypt(&mut self.0, algorithm) {
                if decrypt(algorithm, &key) {
                    return Ok(None);
                }
            }
        }
        panic!("recovered key must decrypt the CLI ciphertext");
    }
}
