# Legacy V0 bundles

Existing PGP V0 bundles require one holder-assisted import and an enclave rebuild.
The existing quorum key, encrypted shares and encrypted secrets are retained.
There is no raw-V0 fallback or earlier-V1 migration.

```sh
caution secret import-legacy --bundle /path/original-v0.json \
  --keyring /path/holder.private.asc
# Smartcard: omit --keyring and use --holder FULL_FINGERPRINT.
# Optional: --output /new/path.json and --upload.
caution secret inspect --bundle .caution/quorum-bundle.json
```

Import refuses existing output files, defaults to `.caution/quorum-bundle.json`,
and preserves the source. Default release lookup prefers this canonical path over
`.caution/secrets/bundle.json`; `--bundle PATH` overrides the lookup. It verifies the original keyring checksum and public
structure, then decrypts only metadata to recover the threshold and actual holder
order. It never reconstructs the secret. Inconsistent source bundles (including
Locksmith's checked-in `bundle-2-of-4.json`) must be restored from a consistent
backup; no checksum repair override is provided.

The tagged ImportedV0 artifact contains the original payload plus the recovered
threshold and ordered certificates. Its identity is a canonical content hash,
not an invented UUID or generation timestamp. Inspection and the Dashboard label
it **Legacy V0 — no Keymaker generation proof**. Import cannot retrospectively
prove how Keymaker generated it.

`--upload` signs the existing Platform upload request, including
`allow_legacy: true`. API creation or data replacement requires that flag in the
signed body; default omission rejects legacy data. Public structural validation
cannot authenticate encrypted metadata. Listing, holder metadata and downloads
reuse the existing endpoints and storage. The Dashboard has no importer.

Image preflight recognizes the explicit `ImportedV0` format and requires only the
non-empty bundle and encrypted secrets below. No Keymaker policy is required.
This packaging check does not validate imported metadata or establish generation
provenance; Locksmith still validates the bundle at startup. V1 images retain
their Keymaker policy requirement. Rebuild the Platform builder to use this check.

Preserve existing ciphertext and package the imported artifact in the application
image using the updated Locksmith runtime:

```dockerfile
COPY .caution/quorum-bundle.json /etc/caution/bundle.json
COPY .caution/secrets/ /etc/caution/secrets/
```

Normalize public/encrypted files to `0644` and directories to `0755` in the build
stage, as in the [operator runbook](secrets-operations.md). Include these files in
the final image; `env::vault` does not copy them. Check any `LOCKSMITH_COMMIT`
override, rebuild/redeploy the affected enclave, and run `caution verify` against
independently trusted source before release. The reviewed, measured image is the
runtime approval of ImportedV0. Its daemon does not load a Keymaker PCR policy.
V1 still requires its policy and verified generation proof.

```sh
# Only for new or changed values. Existing encrypted secrets remain valid.
caution secret encrypt SECRET --env-file /private/app.env --allow-legacy
# Each holder releases after verification of the rebuilt destination:
caution secret send-shard --holder FULL_FINGERPRINT --allow-legacy
# Add --keyring /path/holder.private.asc to use a private-key file.
```

Encryption and release use the same bundle validation path. Every legacy use
requires `--allow-legacy`, including downloaded bundles; it never bypasses V1
parsing or proof failure. Metadata consistency is rechecked
before release. Destination attestation, holder signatures, distinct-holder and
threshold enforcement, and matching the recovered quorum public key remain in
force. The application unlocks only at threshold. Expired nonparticipating holders
do not prevent import, loading or threshold recovery; actual contributions still undergo signing-key and signature checks.
With explicit legacy acceptance, encryption may use the unchanged expired quorum
recipient. Algorithm support, certificate bindings and revocation checks remain
enforced; V1 encryption still requires a live recipient.

## Validation and release

The frozen `tests/fixtures/imported-v0.json` is byte-identical to Locksmith's
`tests/fixtures/v0/imported.json`; both are public test data. Run CLI/API tests,
frontend tests, and `tests/e2e/test_quorum_mock.sh`. The disposable harness exercises
import, signed upload/replacement/download, opt-in enforcement, encryption,
threshold recovery and decryption of both pre-import and new ciphertext, plus
V1 proof rejection with legacy acceptance enabled.

Before claiming production support, record a real Nitro recovery with an existing
legacy bundle and an OpenPGP-card import/release smoke test. Local software-key
and synthetic tests are separate evidence. Publish the aligned Locksmith revision
before building Platform from a clean remote checkout. No new custody, Bootproof,
WebAuthn or V1-generation behavior is introduced.
