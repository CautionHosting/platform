# Quorum creation

`caution secret init` (`new` is a visible alias) creates v1 bundles. **WebAuthn/mixed
creation is currently blocked**: the certificate service emits nonce-less proofs,
but Bootproof's shared verification API requires a nonce. See the pinned
[proof generation](https://codeberg.org/caution/locksmith/src/commit/707bcdcad9204569ec95b82a1cf2401e5489b9d9/crates/public-cert-service/src/derivation.rs#L285)
and [verification contract](https://codeberg.org/caution/bootproof/src/commit/b346db17523ad9b13ef41eb9c14df3328bbd80d1/crates/bootproof-sdk/src/format/nitro.rs#L285). Platform returns HTTP
503 before derivation or Keymaker generation rather than bypassing verification.
The selection and assembly contracts below describe the intended integration.

Hosted creation is the default: CLI → Platform → Keymaker. Platform snapshots
all registered credentials of each WebAuthn holder in credential-ID order. After
the verification blocker is resolved, derivation must provide one certificate
per holder. Multiple passkeys belonging
to one holder still represent one share. Mixed keyrings retain participant order,
the derivation bundle ID and compact certificate indices; local PGP holders come
first.

```sh
caution secret init --from-org-users USER1,USER2 --caution-backed --threshold 2 \
  --keymaker-pcr-policy keymaker-policy.json
# Select registered PGP explicitly for USER1, leaving USER2 WebAuthn:
caution secret init --from-org-users USER1,USER2 --caution-backed \
  --pgp-key USER1=KEY1 --threshold 2 --keymaker-pcr-policy keymaker-policy.json
# Direct PGP-only creation, without upload:
caution secret init public-keyring.asc --threshold 2 \
  --keymaker-url https://keymaker.example --no-upload \
  --keymaker-pcr-policy operator-policy.json
```

Replace USER/KEY placeholders with UUIDs. Repeated `--pgp-key` selects registered
PGP certificates. Without an override, a sole registered PGP certificate is selected;
other cases require an interactive custody choice or explicit noninteractive
selection. `--caution-backed` explicitly selects WebAuthn for users without PGP
overrides. The CLI presents custody and threshold for confirmation when interactive.
The threshold defaults to one; `--max`, if supplied, must equal the holder count.
Labels use repeated `--label KEY=VALUE`. Omitted or null API labels are stored as
`{}`; supplied objects are preserved.

API and direct CLI creation reject duplicate primary identities and shared storage
encryption subkeys, including expired recipients that Keyfork can still select.
Eligibility still requires live signing, authentication and storage-encryption
keys. Both checks recognize the critical `organization-id@caution.co` and
`bundle-id@caution.co` notations.

`--keymaker-url` takes precedence over `KEYMAKER_URL`. Either selects direct mode,
which accepts local and registered PGP certificates only. WebAuthn/mixed direct
requests fail before generation: Platform resolves credential bindings internally.
Discovery exposes organization members, public PGP certificates and credential
counts, never credential bindings. Completed v1 bundles contain public bindings.

Hosted creation stores the complete `{data, necroproof}` envelope. `--no-upload`
is direct-only. Direct creation uploads by default using signed authorization;
the API must also trust that Keymaker's PCRs to accept an upload. Hosted
creation, upload, updates and deletion require fresh FIDO2 signed requests at the
gateway, including in E2E builds. Dashboard deletion signs the canonical
`/quorum-bundles/{id}` path with an empty body; cancelling the passkey prompt
sends no deletion. CLI and dashboard renaming/label edits use the existing signing flow. Downloads and local
files retain the proof envelope. Readers verify before using the public key.

## Trust and service configuration

Platform requires `KEYMAKER_URL` and `KEYMAKER_PCR_POLICY_PATH`. Once the
certificate-verification dependency is resolved, WebAuthn creation will also require `PUBLIC_CERTIFICATE_SERVICE_URL`,
`PUBLIC_CERTIFICATE_PCR_POLICY_PATH` and `CAUTION_CA_CERT_PATH`. PGP-only creation
does not require certificate-service configuration. The certificate endpoint is
`/v1/public-certificates`; Keymaker uses `/generate_quorum`.

Place the independently verified Keymaker policy at
`~/.config/caution/policies/keymaker-pcr-policy.json`. The Makefile and user
systemd API launchers create that dedicated directory if needed and mount it
read-only at `/run/config`. Set the existing API environment variable:

```env
KEYMAKER_PCR_POLICY_PATH=/run/config/keymaker-pcr-policy.json
```

This is a **container path**. A CLI running on the host needs the host file path.
The operator supplies the file; there is no automatic measurement discovery.
An empty mount directory is allowed: missing or invalid policy fails affected
quorum requests closed, without blocking unrelated API operations or startup.
For isolated tests, use `make run-api-test KEYMAKER_POLICY_DIR=/absolute/temp/policies`
with a temporary `keymaker-pcr-policy.json` in that directory.

PCR policy JSON follows Locksmith's shared contract:

```json
{"sets":[{"pcrs":{"0":"<96 hexadecimal characters>","1":"<96 hexadecimal characters>","2":"<96 hexadecimal characters>"},"expires_at_unix_seconds":null}]}
```

Obtain measurements independently from the operator's reviewed build. Missing,
incomplete and debug policies fail closed. Never populate policy from the service
response. CLI policy precedence is `--keymaker-pcr-policy`, then
`KEYMAKER_PCR_POLICY_PATH`, then `.caution/keymaker-pcr-policy.json`. In a project,
initialization saves the accepted policy beside `.caution/quorum-bundle.json`.

The gateway rejects paths changed by backend URL normalization before checking
signatures, including literal and percent-encoded dot-segment aliases.

Service requests have a 60-second timeout and no automatic generation retries.
The CLI allows 125 seconds for the hosted generation HTTP request, including its
response body, after signing completes. QR approval retains its separate
180-second window.
Platform propagates HTTP 429/503 and timeout failures. A timeout may mean generation
completed remotely; investigate before submitting another creation request.

## Dependency and validation boundary

This change pins the shared models and loader from Locksmith PR #15, with its
Bootproof dependencies resolved to Platform's reviewed `b346db1` revision. It does not
change runtime pins or introduce a legacy bundle fallback. Local orchestration and
negative verification tests do not establish production Nitro readiness.

- [Locksmith #10](https://codeberg.org/caution/locksmith/issues/10): structured v1
  generation/validation. The response has no threshold field; Platform validates
  the request and compares returned ID, ordered keyring and labels, but cannot
  independently compare the generated threshold using this contract.
- [Locksmith #11](https://codeberg.org/caution/locksmith/issues/11) and
  [PR #15](https://codeberg.org/caution/locksmith/pulls/15): durable proof loading.
  The pinned verifier's certificate-validation time still needs the upstream fix;
  historical proof acceptance is not a completed production guarantee.
  The pinned shard-submission client also concatenates separate PGP armor blocks,
  while its parser reads only the first. Non-first PGP holders cannot submit;
  multi-holder PGP unlocking remains blocked pending an upstream reconstruction
  fix and a Platform repin. Do not rewrite the proofed envelope to work around it.
- [Locksmith #2](https://codeberg.org/caution/locksmith/issues/2): Keymaker
  serialization/reset lifecycle; no Platform queue or semaphore is added.
- [Locksmith #12](https://codeberg.org/caution/locksmith/issues/12): WebAuthn
  recryption transport. CLI shard submission rejects WebAuthn/mixed bundles instead
  of reaching the upstream unimplemented path. Creation does not deliver unlocking.

Deployment preflight and runtime integration remain separate Platform work.

## Pre-commit validation

Run the opt-in database suite with Docker, Python 3 and the native Rust build
prerequisites installed:

```sh
make test-quorum-db
```

The runner creates its own PostgreSQL 16 container on a random loopback port,
applies all repository migrations with the existing migration runner, and removes
only its own container, volume and temporary files on exit. It does not use an
existing database or the shared `postgres-test` container. On macOS with Homebrew,
use the native library paths when needed:

```sh
export PKG_CONFIG_PATH=/opt/homebrew/opt/nettle@3/lib/pkgconfig:/opt/homebrew/opt/gmp/lib/pkgconfig:/opt/homebrew/opt/openssl@3/lib/pkgconfig
make test-quorum-db
```

The database suite exercises membership/PGP ownership, inactive and removed
holders, duplicate effective keys, ordered stored WebAuthn snapshots, discovery
isolation, and proof-envelope CRUD/download-to-file round trips. Its HTTP mock
records actual hosted PGP requests for local-only, registered-only and combined
holders with no certificate-service configuration. Invalid proofs, HTTP 429/503
and the real 60-second request timeout must produce no stored bundle and no
repeated generation. Allow about a minute for that timeout case.

The synthetic envelope is inserted directly through storage functions solely to
test persistence; the API verifier separately rejects it. Snapshot fixtures are
throwaway public credentials from the gateway's timing tests, not authentication
proofs. These tests do not establish successful cryptographic generation or
successful verified CLI consumption.

Regression commands:

```sh
cargo check -p api -p cli -p gateway --locked
cargo test -p cli --lib --locked
cargo test -p api org_quorum --locked
cargo test -p gateway auth_middleware --locked
cargo test -p gateway quorum_writes --locked
cargo test -p gateway quorum_writes --features e2e-testing-unsafe --locked
npm test --prefix frontend
bash -n tests/e2e/test_org_quorum_db.sh tests/e2e/test_org_user_quorum.sh
```

The existing `make test-e2e-org-user-quorum` live-stack suite now requires a
successful authenticated discovery response containing the expected member,
then checks the exact signature-required 403 for generation, upload and PATCH,
even when forged internal-authentication headers are supplied. An unrelated 401
or an empty discovery list cannot satisfy the assertions.

Validation on 2026-09-15: native compilation, CLI/API/gateway and frontend tests,
and isolated database/HTTP orchestration passed. The full live gateway/API E2E
script and real Nitro/passkey signing flows were not run; upstream proof and
transport blockers above remain unchanged.

Follow-up validation on 2026-09-15: `cargo test -p cli --lib --locked`
passed all 130 tests, including operation-only timeout selection and a loopback
HTTP test confirming that waiting before send does not consume the deadline and
that a stalled response body times out. The latter uses a shortened test timeout;
it does not exercise a real passkey approval. Existing loopback tests require
local network permission outside the restricted sandbox.

`cargo test -p gateway auth_middleware --locked` passed 7 tests;
`cargo test -p gateway proxy::tests --locked` passed 6. The `quorum_writes`
test passed with and without `--features e2e-testing-unsafe`, rejecting unsigned
canonical writes with 403 and literal/encoded dot-segment aliases with 400 across
generation, upload and PATCH. `cargo check -p cli -p gateway --locked` and
`git diff --check` passed. These are local tests, not full-stack or Nitro validation.

