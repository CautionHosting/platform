# Quorum creation

`caution secret init` (`new` is a visible alias) creates proofed V1 bundles.
Hosted creation supports PGP, WebAuthn and mixed holders when the corresponding
services and independent trust files are configured. **WebAuthn/mixed recovery
is not yet supported** (Locksmith #12); the CLI warns before creation. Do not use
these quorums for secrets you need to recover now.

Hosted creation is CLI → Platform → certificate service (Caution holders only)
→ Keymaker. Platform snapshots registered credentials in credential-ID order and
obtains one verified derived certificate per Caution holder. Multiple passkeys
still represent one share. Mixed keyrings retain participant order, the service's
bundle ID and compact certificate indices; local PGP holders come first.

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

Holder selectors in `--from-org-users` and the left side of `--pgp-key` accept
UUIDs or usernames; KEY placeholders remain key UUIDs. For example:

```sh
caution secret init --from-org-users alice,bob --threshold 2 \
  --pgp-key alice=KEY_UUID --keymaker-pcr-policy keymaker-policy.json
```

Selectors are trimmed; usernames match in full, case-insensitively. UUID-shaped
selectors are always treated as UUIDs, never as usernames. Unknown or ambiguous
names fail; use a UUID to disambiguate. Duplicates are rejected after resolution,
including a username and UUID for the same holder or repeated PGP overrides.
The CLI resolves against the active organization participant list and sends UUIDs
to the API, preserving selection order. Confirmation shows username and UUID.
Username/UUID resolution precedes custody prompts and generation; direct-mode
organization selections require authenticated participant discovery too.

Repeated `--pgp-key` selects registered
PGP certificates. Without an override, a sole registered PGP certificate is selected;
other cases require an interactive custody choice or explicit noninteractive
selection. `--caution-backed` explicitly selects WebAuthn for users without PGP
overrides. The CLI presents custody and threshold for confirmation when interactive.
Automatic custody selection rejects members with neither registered PGP keys nor
passkeys with a "no usable custody" error before prompting. Register a PGP key
before selecting such a member.
The threshold defaults to one; `--max`, if supplied, must equal the holder count.
API and CLI creation support 1–254 holders in total, including local certificates
and organization selections. Larger selections fail before key-service requests;
bundle uploads enforce the same holder limit.
Labels use repeated `--label KEY=VALUE`. Omitted or null API labels are stored as
`{}`; supplied objects are preserved. An explicit name and a `name` label must
match; conflicting values are rejected before generation in both API and CLI.

API and direct CLI creation reject duplicate primary identities and shared storage
encryption key material, including expired recipients that Keyfork can still select.
Different key creation timestamps and fingerprints do not make shared material
independent quorum holders. Upload validation applies the same material check.
Eligibility still requires live signing, authentication and storage-encryption
keys. Both checks recognize the critical `organization-id@caution.co` and
`bundle-id@caution.co` notations.

`--keymaker-url` takes precedence over `KEYMAKER_URL`. The CLI treats an empty or
whitespace-only `KEYMAKER_URL` as unset, preserving hosted mode when no flag is
provided; an explicitly empty `--keymaker-url` remains invalid. Either nonempty
override selects direct mode, which accepts local and registered PGP certificates
only. WebAuthn/mixed direct requests fail before generation: Platform resolves
credential bindings internally.
Discovery exposes organization members, public PGP certificates and credential
counts, never credential bindings. Completed v1 bundles contain public bindings.

Hosted creation stores the complete `{data, necroproof}` envelope. `--no-upload`
is direct-only. Direct creation uploads by default using signed authorization;
the API must also trust that Keymaker's PCRs to accept an upload. Hosted
creation, upload, updates and deletion require fresh FIDO2 signed requests at the
gateway, including in E2E builds. Dashboard deletion signs the canonical
`/quorum-bundles/{id}` path with an empty body; cancelling the passkey prompt
sends no deletion. CLI and dashboard renaming/label edits use the existing signing flow. Dashboard
metadata edits display passkey cancellation errors without sending an update. Full bundle
downloads and local bundle files retain the proof envelope. Dashboard public-key and
shard-file downloads read the V1 payload inside the envelope and also support existing
legacy stored payloads; the public-key hash uses the same reader. These individual
file downloads do not include the proof. Readers verify the full bundle before using
the public key; dashboard compatibility does not add legacy cryptographic verification.

## Trust and service configuration

Platform requires `KEYMAKER_URL` and `KEYMAKER_PCR_POLICY_PATH`. WebAuthn/mixed creation additionally requires `PUBLIC_CERTIFICATE_SERVICE_URL`,
`PUBLIC_CERTIFICATE_PCR_POLICY_PATH` and `CAUTION_CA_CERT_PATH`. PGP-only creation
does not require certificate-service configuration.
Store `certificate-pcr-policy.json` and the public `caution-ca.asc` alongside the
Keymaker policy in `~/.config/caution/policies/`; the existing `/run/config`
read-only mount exposes them to the API. Set the three certificate-service
variables in `env.example`. Obtain both the service PCRs and Caution CA independently;
neither is learned from a service response. Missing configuration only fails
Caution-backed creation; PGP creation and unrelated operations remain available.

Platform verifies the AWS proof at its signed timestamp with an absent/null nonce,
checks the generation-time PCR cutoff and binds `user_data` to SHA-256 of the
service's exact CBOR-serialized response data. This serialization differs from
Keymaker's canonical-map hash. It checks organization/count, then each certificate's
CA-certified `Caution public certificate index=N` user ID and exactly one hashed
organization/bundle notation. The index is in the user ID, not a separate notation.
It also checks certificate eligibility and duplicate recipients before Keymaker.
Historical proof verification establishes provenance, not fresh holder approval or
live recryptor authorization. No certificate request is automatically retried.
 The certificate endpoint is
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
response. For `secret init`, policy precedence is `--keymaker-pcr-policy`, then
`KEYMAKER_PCR_POLICY_PATH`, then `.caution/keymaker-pcr-policy.json`. In a project,
initialization saves the accepted policy beside `.caution/quorum-bundle.json` only
when no saved policy exists. Before generation, a differing or malformed saved
policy causes an error: explicitly repair or replace that file to change trust.
Equivalent parsed policies preserve the existing file, including its formatting.
Every PCR value must decode to exactly 48 bytes.

When stdout is redirected, `secret init`/`new` emits the proofed bundle JSON even
inside a project, in addition to saving `.caution/quorum-bundle.json`. Outside a
project it always emits the JSON. Status messages go to stderr.

Uploads of existing proofed V1 bundles validate holder certificate eligibility at
the authenticated generation timestamp; new bundles require eligibility today.
For example, a January bundle can still be restored after one holder's key expires
in June, provided that key was eligible in January. This preserves the original
proof-bound certificates; it does not renew expired keys or guarantee recovery.
The explicitly gated synthetic test proofs have no authenticated timestamp and
retain current-time holder validation.

For existing proofed V1 bundles, `secret encrypt` and `secret send-shard` require
an independently provisioned policy too. These commands have no
`--keymaker-pcr-policy` flag: set `KEYMAKER_PCR_POLICY_PATH` to the policy's host
path, or copy it to `.caution/keymaker-pcr-policy.json` in the working directory.
The environment variable takes precedence. For example:

```sh
export KEYMAKER_PCR_POLICY_PATH=/absolute/path/to/verified-keymaker-policy.json
caution secret encrypt TEST_SECRET --env-file .env.quorum-test
caution secret send-shard --keyring /absolute/path/to/alice.private.asc
```

Legacy/unproofed bundles remain unsupported; supplying a policy does not upgrade
them. Preserve the original bundle and its recovery material. Do not regenerate
an existing quorum to resolve a loading error: a new quorum has a different key
and cannot decrypt secrets encrypted for the original quorum.

The gateway rejects paths changed by backend URL normalization before checking
signatures, including literal and percent-encoded dot-segment aliases.
`API_SERVICE_URL` must use a root URL such as `http://api:8080`; trailing slashes
are normalized away. A path prefix such as `/v1` is rejected at gateway startup.

Service requests have a 60-second timeout and no automatic generation retries.
The CLI allows 125 seconds for the hosted generation HTTP request, including its
response body, after signing completes. QR approval retains its separate
180-second window.
Platform propagates HTTP 429/503 and timeout failures. A timeout may mean generation
completed remotely; investigate before submitting another creation request.

## Dependency and validation boundary

The shared models and loader are pinned to the Locksmith revision recorded in
`Cargo.toml` and `Cargo.lock`. All Bootproof SDK consumers use the historical
verification revision `821b5c63e80f082f6d67ba3695c11416933489ec`, including the existing
ES384 encoding fix. No old-remote patch or local path dependency is required.
The default Locksmith daemon revision is also `93229565410d212a525e91fc2e3d7f3df249ef58`,
matching the API/CLI loader. `LOCKSMITH_COMMIT` still overrides this default.
Existing deployed images require a rebuild/redeployment to use it. Legacy
bundle fallback remains unimplemented.

The required `threshold`/`max` fields intentionally break the previous V1 response
contract while retaining the V1 tag. Updated API/CLI/runtime readers reject old
bundles missing either field; old readers reject the new fields. There is no
fallback or automatic migration. Adding metadata to an existing bundle invalidates
its proof. Coordinate the Keymaker, API/CLI and runtime upgrade, rebuild Keymaker,
and independently verify its new PCR policy before production use. Existing
keys and encrypted material are not migrated by this change.

Stored bundle proofs now validate certificate validity at the signed generation
timestamp, then check the expected PCRs, deterministic nonce and canonical bundle
hash. PCR-policy expiry is a cutoff on generation time, not the current time.
This follows [the timestamp policy in #7](https://codeberg.org/caution/locksmith/issues/7#issuecomment-19223141).
Historical provenance does not establish fresh authorization or replay protection
for live shard transport.

The updated Locksmith receiver takes its threshold from the verified bundle,
requires distinct authenticated holders and share coordinates, and rejects
conflicting client thresholds and malformed contributions without counting them.
Before serving a seed it checks the recovered OpenPGP primary key fingerprint
against the bundle public key. Incorrect recovery fails closed; this does not
prevent denial of recovery by an authorized holder. Unsupported WebAuthn/mixed
keyrings fail before the receiver starts listening. Keymaker rejects invalid
requests before consuming its reboot permit; valid requests retain the existing
one-shot lifecycle. These changes require a rebuilt runtime and Keymaker plus
independently verified measurements; local tests do not establish Nitro readiness.


- [Locksmith #10](https://codeberg.org/caution/locksmith/issues/10): structured v1
  generation/validation. The proof-bound response requires `threshold` and `max`,
  taken from the same values used for shard generation. Platform compares both
  with its request before storage; the CLI checks them against the original
  selection after proof verification in hosted and direct modes. This still
  trusts the measured Keymaker implementation to generate shares correctly.
- [Locksmith #11](https://codeberg.org/caution/locksmith/issues/11) and
  [PR #15](https://codeberg.org/caution/locksmith/pulls/15): durable proof loading.
  Historical certificate verification is implemented. The shared PGP keyring
  reconstruction fix also retains every holder for sender/receiver verification.
  These fixes do not establish successful multi-holder Nitro unlocking. V0
  fallback/upgrade remains deferred under #11 and PR #15.
- [Locksmith #2](https://codeberg.org/caution/locksmith/issues/2): Keymaker
  serialization/reset lifecycle; no Platform queue or semaphore is added.
- [Locksmith #12](https://codeberg.org/caution/locksmith/issues/12): WebAuthn
  recryption transport. CLI shard submission rejects WebAuthn/mixed bundles instead
  of reaching the upstream unimplemented path. Creation does not deliver unlocking.

Artifact preflight and live deployment validation remain separate Platform work.

### Trying PGP recovery

First publish the referenced Bootproof and Locksmith commits before using a
remote/container builder; a host Cargo cache does not make them available inside
the build. Rebuild the Platform API for hosted builds, or rebuild the CLI for
local `caution apps build`. Remove any stale `LOCKSMITH_COMMIT` override from
the builder environment. Neither the runtime pin nor `env::vault` installs the
application's bundle or policy automatically.

In an initialized application repository, with two holders' eligible PGP keys
registered in the dashboard and a real Keymaker configured on Platform:

```sh
# Replace USER1 and USER2 with organization-member UUIDs.
caution secret init --from-org-users USER1,USER2 --threshold 2 \
  --keymaker-pcr-policy /absolute/path/to/verified-keymaker-policy.json
printf 'TEST_SECRET=quorum-smoke-test\n' > .env.quorum-test
caution secret encrypt TEST_SECRET --env-file .env.quorum-test
```

This writes the proofed bundle, policy and encrypted secret under `.caution/`.
Include them in the application's final container image:

```dockerfile
COPY .caution/quorum-bundle.json /etc/caution/bundle.json
COPY .caution/keymaker-pcr-policy.json /etc/caution/keymaker-pcr-policy.json
COPY .caution/secrets/ /etc/caution/secrets/
```

Keep these files in the application's reproducible source inputs and normalize
their file modes in its build stage. Do not use `build.binary`, which discards
the other application files. Add `TEST_SECRET = env::vault("TEST_SECRET")` to
the default unit's HCL `env` map. Keep plaintext and private keyrings out of Git.

After rebuilding and deploying that application in non-debug Nitro mode:

```sh
caution verify --save-pcrs
caution secret send-shard --keyring /absolute/path/to/alice.private.asc
# With a 2-of-2 quorum, the application must remain locked here.
caution secret send-shard --keyring /absolute/path/to/bob.private.asc
# The application should now start with TEST_SECRET available.
```

Each holder uses their own keyring (omit `--keyring` for a supported smart card).
Restart the enclave and repeat to exercise recovery. These are manual test
instructions, not a claim of completed Nitro validation. For the existing local
creation/encryption test with synthetic proofs, run `make test-quorum-mock` from
the Platform repository; it does not exercise shard recovery.

### Historical-proof validation

The historical verifier was checked against the existing signed AWS fixture and
locally signed nonce-less test evidence. Bootproof's 16 SDK tests passed; the
test root is accepted only by private test code. Locksmith's default and unsafe
test suites passed, including generation-time policy cutoffs and default-build
rejection of synthetic proofs.

Platform's CLI tests (131), API quorum tests (11, with one dedicated DB test
ignored), builder unit tests (94), and successful mock quorum E2E passed against
the exact dependency revisions above. The mock exercises API creation, upload,
download, deletion and CLI consumption using synthetic proofs. These runs use
local Git objects for the pinned revisions; they do not establish remote
availability, live Nitro unlocking or deployment readiness.

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

Validation on 2026-09-16: all 10 focused quorum CLI tests and 15 gateway
configuration/authorization/proxy tests passed. `make test-quorum-db` passed
through the certificate-verification blocker, storage round trips and hosted-PGP
failure cases, including the 60-second timeout. `git diff --check` passed.

## Successful mock integration

`make test-quorum-mock` builds native API, gateway and CLI test binaries under
`target/quorum-e2e`, and runs Keymaker's existing non-default test mode. It requires
Docker, Python 3, curl and the native Rust dependencies (on macOS, the pkg-config
paths shown above). API port 8080 must be free; the runner refuses to stop another
stack. PostgreSQL, keys, policies and data are temporary and removed on exit.
The runner uses example configuration and an empty service environment, not the
operator's configuration. Native services read the temporary policy by host path;
container-based tests can use the `KEYMAKER_POLICY_DIR` read-only mount above.

The shared `unsafe-e2e` feature is forwarded only through API/CLI
`e2e-testing-unsafe`. Acceptance additionally requires
`CAUTION_UNSAFE_KEY_SERVICE_E2E=1`, one non-expiring policy set with exactly PCRs
0/1/2 each equal to `ab` repeated 48 times, and a proof equal to the nonce
recomputed from the canonical bundle hash. Never use these values or binaries
in production. Ordinary build targets do not enable this feature.

Certificate-service mock proofs use the same feature/flag/exact-policy gates in
the API, but their bytes equal SHA-256 of the service's CBOR-serialized data, not
a nonce. The test-only path uses the current time for certificate checks because
the synthetic proof has no authenticated timestamp. CA signatures, certificate
eligibility and organization/bundle/index checks are never bypassed. Production
builds reject both synthetic formats, even when the runtime flag is set.

The certificate HTTP mock generates temporary CA-signed PGP certificates; it does
not run the real derivation service or test the custody root. The creator registers
a second software passkey through the gateway; a second holder uses a disposable
public-credential database fixture. WebAuthn-only and mixed creation must preserve
certificate order, compact indices, bundle ID, threshold and both holders' bindings.
The creator's two passkeys remain one share. Wrong CA, signature, context, count,
order, eligibility or proof must result in no Keymaker call and no stored bundle.
Downloaded bundles are consumed by CLI encryption. An isolated CLI test invokes
`send_shard` with these exact files and mock application metadata, requiring the
WebAuthn/mixed recovery-unavailable error before any enclave connection.

The harness also places a loopback proxy before Keymaker, changing a requested
3-of-5 into 1-of-5 before generation. The API rejects the resulting valid synthetic
proof before storage, and the direct CLI rejects it without overwriting its saved
bundle. CLI unit tests cover the common parameter check used by both creation
modes. Locksmith's generation test decrypts all five shares, checks the encrypted
threshold against the response, rejects every pair and reconstructs with every
triple. This is local validation, not a reproduced production/Nitro exploit.

Coverage includes actual gateway challenge signing with a software passkey,
signed API creation/upload, download, unsigned DELETE's signature-specific 403,
signed DELETE, omitted/null/object labels, missing/invalid policy failures with
unrelated reads still working, altered-bundle rejection, direct CLI creation and
CLI encryption with both direct and downloaded bundles. The existing
`make test-quorum-db` HTTP mock retains controlled failure/timeout coverage.

These are synthetic-proof integration tests. Real Nitro validation and production
policy provisioning remain release dependencies. V0 fallback/upgrade remains
with Locksmith PR #15 and #11; WebAuthn recryption remains with #12. This work does
not close those tickets or establish WebAuthn recovery.


Validation on 2026-09-15 against the published pin: `make test-quorum-mock`
passed, including software-passkey signatures and CLI consumption, with no local
Cargo overrides. Normal-build CLI tests (131) and API quorum tests (11) passed.
The synthetic-proof gate was also tested with and without `unsafe-e2e`, including
absent, disabled and enabled runtime flags. These results do not establish Nitro
attestation or WebAuthn recryption readiness.

Certificate integration validation (2026-09-16): the API quorum suite passed
14 tests (the database test runs separately), the CLI suite passed 135 tests,
and `make test-quorum-db` passed, including missing certificate configuration
preventing Keymaker calls and existing HTTP failure/timeout cases. Certificate
checks use locally signed test certificates; no genuine Nitro certificate-service
response or WebAuthn recovery was exercised.

Mock custody validation (2026-09-16): all 15 API quorum tests passed in both
default and `e2e-testing-unsafe` builds, including subprocess-isolated runtime-flag
and policy/proof rejection cases. `make test-quorum-mock` passed the existing PGP
flow, new WebAuthn/mixed creation, negative certificate responses and the CLI
recovery-unavailable check. No local dependency overrides, deployment, genuine
certificate-service derivation, real Nitro evidence or recryptor were used.
Default-feature API/CLI build checks and full locked/offline metadata resolution
for Platform and the standalone test helper also passed.
