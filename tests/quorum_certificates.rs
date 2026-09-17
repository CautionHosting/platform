// Shared regression fixtures for API and direct CLI holder validation.
use sequoia_openpgp::{
    Packet,
    cert::CertBuilder,
    packet::signature::SignatureBuilder,
    serialize::Serialize,
    types::{KeyFlags, SignatureType},
};
use std::time::{Duration, SystemTime};

pub fn shared_recipient(
    notation: Option<&str>,
    expired: bool,
    different_timestamps: bool,
) -> Vec<String> {
    let created = SystemTime::now() - Duration::from_secs(86400);
    let (donor, _) = CertBuilder::new()
        .set_creation_time(created)
        .add_storage_encryption_subkey()
        .generate()
        .unwrap();
    let shared = donor
        .keys()
        .subkeys()
        .next()
        .unwrap()
        .key()
        .clone()
        .parts_into_public();
    (0..2)
        .map(|index| {
            let mut recipient = shared.clone();
            if different_timestamps {
                recipient
                    .set_creation_time(created + Duration::from_secs(index))
                    .unwrap();
            }
            assert_eq!(recipient.mpis(), shared.mpis());
            assert_eq!(
                recipient.fingerprint() != shared.fingerprint(),
                different_timestamps && index != 0
            );
            // Each holder also has an independent live recipient, so expiration of
            // the shared recipient must not cause an eligibility failure.
            let (cert, _) = CertBuilder::new()
                .add_signing_subkey()
                .add_authentication_subkey()
                .add_storage_encryption_subkey()
                .generate()
                .unwrap();
            let mut signer = cert
                .primary_key()
                .key()
                .clone()
                .parts_into_secret()
                .unwrap()
                .into_keypair()
                .unwrap();
            let mut binding = SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_key_flags(KeyFlags::empty().set_storage_encryption())
                .unwrap();
            if expired {
                binding = binding
                    .set_key_validity_period(Duration::from_secs(1))
                    .unwrap();
            }
            if let Some(name) = notation {
                binding = binding.add_notation(name, "test", None, true).unwrap();
            }
            let signature = binding
                .sign_subkey_binding(&mut signer, None, &recipient)
                .unwrap();
            let cert = cert
                .insert_packets([Packet::from(recipient), Packet::from(signature)])
                .unwrap();
            let mut bytes = Vec::new();
            cert.armored().serialize(&mut bytes).unwrap();
            String::from_utf8(bytes).unwrap()
        })
        .collect()
}
