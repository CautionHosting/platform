//! Real key-service HTTP router and Keyforkd, with a disposable test root.
//! This binary is available only through the explicit key-service-e2e feature.
use public_cert_service::{derivation, AppState};
use sequoia_openpgp::{packet::UserID, serialize::SerializeInto};
use std::{fs, path::PathBuf, sync::Arc};

fn main() {
    assert_eq!(
        std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").unwrap(),
        "1"
    );
    let work = PathBuf::from(std::env::args_os().nth(1).expect("temporary directory"));
    keyforkd::test_util::run_test(&[9; 32], move |_| {
        let key = keyforkd_client::Client::discover_socket()
            .unwrap()
            .request_xprv::<keyfork_derive_openpgp::XPrvKey>(&derivation::default_openpgp_ca_path())
            .unwrap();
        let ca = keyfork_derive_openpgp::derive(
            &key,
            &derivation::public_certificate_key_flags(),
            &UserID::from("Caution default OpenPGP CA"),
        )
        .unwrap()
        .strip_secret_key_material();
        fs::write(
            work.join("policies/recovery-ca.asc"),
            ca.armored().to_vec().unwrap(),
        )
        .unwrap();
        let policy = locksmith::bundle::KeymakerPcrPolicy::from_json(
            &fs::read_to_string(work.join("policies/keymaker-pcr-policy.json")).unwrap(),
        )
        .unwrap();
        let mut state = AppState::new();
        state.release = Some(Arc::new(
            locksmith::release::Authorizer::new(
                "localhost",
                &std::env::var("RP_ORIGIN").unwrap(),
                policy,
                ca.clone(),
            )
            .unwrap(),
        ));
        state.expected_ca = Some(ca);
        state.set_issuance_token(Some(
            std::env::var("PUBLIC_CERTIFICATE_SERVICE_TOKEN").unwrap(),
        ));
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                state.check_ready().await.unwrap();
                let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                    .await
                    .unwrap();
                fs::write(
                    work.join("key-service.url"),
                    ["http://", &listener.local_addr().unwrap().to_string()].concat(),
                )
                .unwrap();
                axum::serve(listener, public_cert_service::router(Arc::new(state)))
                    .await
                    .unwrap();
            });
        keyforkd::test_util::Panicable::Ok(())
    })
    .unwrap();
}
