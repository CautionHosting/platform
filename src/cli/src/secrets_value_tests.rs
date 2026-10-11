// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::{encrypt_env_file, openpgp};
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::SerializeInto;
use std::io::Read;

struct Recipient(openpgp::crypto::KeyPair);

impl VerificationHelper for Recipient {
    fn get_certs(&mut self, _: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _: MessageStructure) -> openpgp::Result<()> {
        Ok(()) // The CLI encrypts unsigned literal data.
    }
}

impl DecryptionHelper for Recipient {
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _: &[openpgp::packet::SKESK],
        algorithm: Option<openpgp::types::SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>>
    where
        D: FnMut(openpgp::types::SymmetricAlgorithm, &openpgp::crypto::SessionKey) -> bool,
    {
        for pkesk in pkesks {
            if let Some((algorithm, key)) = pkesk.decrypt(&mut self.0, algorithm)
                && decrypt(algorithm, &key)
            {
                return Ok(None);
            }
        }
        panic!("ciphertext must be decryptable by the generated test recipient");
    }
}

#[test]
fn encrypt_env_file_preserves_values_without_shell_quoting() {
    let work = tempfile::tempdir().unwrap();
    let env = work.path().join("input.env");
    let bundle = work.path().join("bundle.json");
    let output = work.path().join("secrets");
    let (cert, _) = CertBuilder::new()
        .add_storage_encryption_subkey()
        .generate()
        .unwrap();
    let policy = StandardPolicy::new();
    let key = cert
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
    // Reuse the offline ImportedV0 envelope to exercise the production file path.
    // Its explicit opt-in affects bundle admission, not plaintext handling.
    let mut imported: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/imported-v0.json")).unwrap();
    imported["original"]["public_key"] =
        serde_json::json!(String::from_utf8(cert.armored().to_vec().unwrap()).unwrap());
    std::fs::write(&bundle, serde_json::to_vec(&imported).unwrap()).unwrap();
    std::fs::write(
        &env,
        r#"URL=postgres://user:pass@localhost/db?sslmode=require
SPACES="value with spaces"
QUOTES="say \"hello\" to O'Brien"
BACKSLASH='C:\test\file'
LITERAL='$(echo not-executed); $HOME # literal'
PADDED=" padded "
EMPTY=
QUOTED_EMPTY=''
"#,
    )
    .unwrap();
    let expected = [
        ("URL", "postgres://user:pass@localhost/db?sslmode=require"),
        ("SPACES", "value with spaces"),
        ("QUOTES", "say \"hello\" to O'Brien"),
        ("BACKSLASH", r"C:\test\file"),
        ("LITERAL", "$(echo not-executed); $HOME # literal"),
        ("PADDED", " padded "),
    ];
    let encrypted_count = encrypt_env_file(&env, &bundle, &output, &[], true, None).unwrap();
    for (name, value) in expected {
        let mut plaintext = Vec::new();
        DecryptorBuilder::from_file(output.join(format!("{name}.asc")))
            .unwrap()
            .with_policy(&policy, None, Recipient(key.clone()))
            .unwrap()
            .read_to_end(&mut plaintext)
            .unwrap();
        assert_eq!(plaintext, value.as_bytes(), "decrypted value for {name}");
    }
    assert_eq!(encrypted_count, expected.len());
    assert!(!output.join("EMPTY.asc").exists());
    assert!(!output.join("QUOTED_EMPTY.asc").exists());
}
