# WebAuthn and mixed share recovery

Shared Rust dependencies select Locksmith `cd0f5fd44e252114c3bd160edd84c119b99263d0`,
including the external-PGP signing hash fallback. Rebuild/install the CLI to use
this fix with existing bundles. The enclave runtime pin remains `4851791bda5f8f392f88e474ed5731b287ecd4bc`;
this client-side fix does not require a service redeployment. The new dependency
revision is local until explicitly published; remote builds require publication.

Create with explicit per-holder custody:

```sh
caution secret init --holder alice=external-pgp --holder bob=webauthn \
  --threshold 2 --keymaker-pcr-policy keymaker-pcr-policy.json
```

`--pgp-key USER=KEY` selects one active registered external key by registration
UUID or full fingerprint (40 or 64 hexadecimal characters, case/whitespace
ignored). For example: `--pgp-key alice=0123456789ABCDEF0123456789ABCDEF01234567`.
Missing PGP keys do
not select WebAuthn. The old selectors remain temporarily with a deprecation
warning; old and new styles cannot be combined.

Caution’s enclave holds the PGP private key. Your registered passkey authorizes
re-encryption of your share to the verified application enclave. The private key
is never released. Multiple registered credentials on a holder remain one share.

After independently verifying the application and custody service measurements:

```sh
caution secret send-shard --holder CERTIFICATE_FINGERPRINT \
  --recryptor-url http://CUSTODY_SERVICE:8080 \
  --recryptor-pcr-policy recryptor-pcr-policy.json
# Add the global --qr option for phone/local-browser approval:
caution --qr secret send-shard --holder CERTIFICATE_FINGERPRINT \
  --recryptor-url http://CUSTODY_SERVICE:8080 \
  --recryptor-pcr-policy recryptor-pcr-policy.json
```

The live custody policy has one non-expiring PCR0/1/2 set, in the same JSON shape
as Keymaker policies. Do not obtain trusted PCRs from the endpoint being verified.
The CLI displays the bundle, selected certificate, destination key and release
context hash. Compare browser details with the CLI. Browser approval runs on the
registered Platform origin; the passkey must already be in the bundle snapshot.
Native approval requires USB FIDO2 user verification (PIN/biometric), not touch
alone. External PGP holders may contribute to mixed bundles using `--keyring`
or their supported OpenPGP smartcard.

The distinct browser relay transports a raw assertion. Gateway login is not
permission to release. The custody enclave verifies the assertion, consumes its
three-minute authorization state, and derives/decrypts/re-encrypts one share.
Cancelling, expiry, replay or losing the destination connection requires a fresh
attempt. These operations never consume Keymaker.

Locksmith-enabled application images must include non-empty
`/etc/caution/bundle.json`, `/etc/caution/keymaker-pcr-policy.json`, and encrypted
`/etc/caution/secrets/*.asc`. The builder checks these before EIF staging.
Cryptographic proof verification remains the runtime loader's responsibility.

## Acceptance gate

Run affected Rust and frontend tests, `make test-quorum-db`, and
`make test-quorum-mock`, and `make test-share-release-browser` (install the browser
harness dependencies/Chromium first, or set `PUPPETEER_EXECUTABLE_PATH`). The mock
suite includes actual custody HTTP handlers, software-passkey authorization,
synthetic evidence, WebAuthn-only/mixed threshold recovery, and duplicate-holder
rejection. The browser test uses the actual Vue page and a Chromium virtual
platform authenticator, verifies its signature/UV, and exercises cancellation. USB devices, Touch ID and
cross-device browser behavior still require manual acceptance. StageX API,
custody-service and Locksmith runtime builds must pass before deployment.

Dependency publication requires separate authorization. Local test overrides
must never enter committed dependency manifests or lockfiles. The pinned Locksmith commit must be published before other machines can build
this Platform revision. No local-path dependency is committed.

Then reuse the same external-PGP-bootstrapped custody root and existing WebAuthn
bundle for the consolidated Nitro test. Verify locked-below-threshold and expected
plaintext-at-threshold behavior, native/browser approval, replay rejection, one
share per holder and restart recovery. Generate one mixed bundle with a **fresh
single-use Keymaker**, updating Platform's endpoint and verified policy first.
Record source revisions, PCRs, bundle IDs and results. Existing bundle recovery
and restarts require no Keymaker.

V0/earlier-V1 compatibility, credential rotation, multi-instance coordination and
production root management remain separate. This does not close #7/#10/#11/#12.

## Snapshot lifetimes

WebAuthn custody keys remain authorized by their unchanged proof-bound bundle.
The CLI passes the authenticated generation timestamp to the shared Locksmith
verifier: certificate/subkey eligibility is checked at generation, while the
current transport signature is checked without backdating. External-PGP behavior
is unchanged. Configured Caution CA primary keys are explicit durable anchors;
snapshot expiry alone does not invalidate later certificates. Signature,
revocation, algorithm and certified context checks still apply. Later revocation
discovery and credential/root rotation remain separate work.

## Authenticated browser approval

Before enabling `--qr`, place the independently verified custody-service policy at
`~/.config/caution/policies/recryptor-pcr-policy.json` on the Platform host and set
`RECRYPTOR_PCR_POLICY_PATH=/run/config/recryptor-pcr-policy.json` for the gateway.
The Makefile and systemd gateway launchers mount this directory read-only. Use the
same `{ "sets": [{ "pcrs": { "0": "...", "1": "...", "2": "..." } }] }`
format as the CLI: exactly one non-expiring set of non-debug PCR0/1/2 values.
Missing or invalid configuration disables browser release approval, not login.
Upgrade CLI and gateway together; the old unattested relay request is rejected.

The CLI forwards the complete custody-attested Prepare response and its nonce.
The gateway verifies the live Nitro proof, PCRs, response hash, expiry, RP ID and
required user verification before publishing any approval. Displayed bundle,
holder, destination and context hash are derived only from that verified response.
Requester-provided login challenges and invented display context are rejected.
The gateway relays the resulting assertion; the custody enclave still verifies it
and atomically authorizes the share release.

Native approval serializes client data once, using the frontend origin, and returns
the exact bytes whose hash the authenticator signed, including when `FRONTEND_URL`
and the API URL differ.

Regression checks: `cargo test -p gateway release_relay` and
`cargo test -p cli native_assertion_preserves_frontend_origin`. Repeat the relay
suite with `CAUTION_UNSAFE_KEY_SERVICE_E2E=1` both with and without
`--features e2e-testing-unsafe`; only the feature-enabled build accepts synthetic
proofs under the exact synthetic PCR policy. These checks are not real Nitro or
physical-authenticator validation.

## Holder names in the CLI

`secret send-shard --holder USERNAME` accepts an exact current organization
username or a full certificate fingerprint. Names come from Platform's existing
bundle metadata only when the complete returned bundle matches the locally
verified bundle. They are display/selection aliases, not authorization evidence.

The CLI uses an existing valid session for a best-effort lookup (five-second
timeout), without triggering login for labels. Unavailable or ambiguous names
fall back to numbered holders and shortened fingerprints; full fingerprints remain
valid selectors. Named passkey holders display `username · Passkey`; external PGP
holders also show a shortened fingerprint. Use `--verbose` for the selected full
fingerprint. Multiple passkeys remain one holder and one share.

A sole candidate is selected automatically. Otherwise choose from the list or
supply `--holder`; noninteractive ambiguous selection fails. Private-keyring
inference is unchanged. No username or current registration replaces the
bundle-bound credentials and certificates used to authorize release.

## Approval context and field provenance

The browser groups the destination and your contribution in one approval card,
with a prominent four-group comparison code and approval controls.
**Verification & technical details** opens a drawer, closed by default, with
Destination, Custody and Bundle tabs. Each tab explains the checks and groups its
related values. The drawer fills the screen on phones; Escape or Close returns
to approval without cancelling it.
The CLI and browser display the same grouped 16-hex-character prefix of the full
release-context hash, computed from the prepared response data (excluding its
attestation wrapper). This compares authenticated release context only; it does
not authenticate descriptive app labels or CLI-reported addresses.

- **Authenticated release context:** organization/bundle IDs, holder fingerprint
  and position, certificate index, bundle hash, destination session key,
  attestation hash, approved destination PCRs, protocol and expiry. The gateway
  verifies custody evidence before publishing the approval screen. Its accepted
  custody PCR policy is displayed separately.
- **Platform metadata:** accessible organization/app names, app ID/domain/recorded
  IP/state, and current holder username. Bundle threshold, holder count and eligible
  passkey count are displayed only after matching the stored bundle's deterministic
  hash and selected certificate/position to the authenticated context. Multiple
  passkeys still represent one share. Labels are not attested app identities.
- **CLI-reported context:** actual destination socket address and custody URL.
  These describe the connection attempt; the enclave evidence does not establish
  the hostname or a unique Platform app identity. Recorded IP and reported socket
  are displayed separately, including when they differ.

Optional display fields are passed only to the existing gateway relay. It resolves
records using the authenticated requester and the release organization, retains
an immutable display snapshot for that pending request, and never passes metadata
into authorization. Missing optional records are omitted; an unresolved app shows
**Application name unavailable**;
older CLIs can omit display context. Metadata lookups have a four-second overall
budget and never extend the release's expiry. No secret material, relay tokens or
raw credential snapshots are displayed. A display-only lookup failure does not
prevent otherwise valid approval.

The countdown disables approval and aborts a pending browser credential operation
at expiry. Cancellation and “approval sent” statuses do not claim share delivery
or application unlock. The destination's threshold must still be reached.

### Browser approval states

The approval page shows a compact application/holder/destination summary and a
four-group comparison code above the action. Compare all four groups with the
CLI. The code covers authenticated release context, not Platform labels or
CLI-reported addresses. The drawer retains every technical value for independent
comparison. Hashes and fingerprints are shortened by default: Reveal/Hide toggles
the full value, while Copy always copies the complete value. Compare full PCRs
with an independently trusted policy. Keyboard tabs stay inside the drawer; arrow
keys, Home and End switch categories. Terminal session states close the drawer
and clear its contents.
Missing optional metadata is omitted, and differing recorded/reported addresses
are highlighted. Labels never determine authorization.

Only a pending approval displays request details. Cancellation, expiry and
successful assertion relay clear those details and stop the countdown. An
assertion relayed by the browser is not confirmation of share acceptance or
application readiness: follow the terminal result. A failed submission response
may mean delivery is unknown; the page does not retry it. Inactive links show only
an explanation, while network/server errors are reported separately.

### Terminal approval and results

`send-shard` prints the application, selected holder, destination, quorum and
method (private-key file, OpenPGP smartcard, native passkey or browser passkey).
QR requests reuse the gateway's optional display metadata snapshot; old gateways
remain usable without it. Native/PGP requests use the existing application record
and verified bundle without extra login for labels. Terminal control characters
in metadata are escaped. Full identifiers, evidence hashes and policy values and
paths are available with `--verbose`; browser comparison instructions appear only
for QR approval, after the QR/link so the code remains visible while waiting.

`--holder USERNAME_OR_FINGERPRINT` skips the chooser. A private-keyring file with
one matching external-PGP holder is inferred; an OpenPGP smartcard still uses the
selected holder. No custody choice or cryptographic checks are changed.

The destination policy is loaded from `.caution/trusted_hashes.json`; its recorded
verification timestamp is metadata, not proof that the file was never edited.
After redeploying, complete `caution verify` to establish the expected measurements.

The CLI reports share acceptance and the remaining count, or **Quorum reconstructed
successfully** when the receiver confirms reconstruction. This does not establish
application readiness. If the destination closes the connection without a result,
acceptance is unknown: the application may already be unlocked, but the command
remains a failure. Check its status before retrying. Holder-selection errors are
reported as selection errors rather than malformed bundle JSON.

### Inspect a saved bundle

```sh
caution secret inspect
caution secret inspect --bundle /path/quorum-bundle.json \
  --keymaker-pcr-policy /path/keymaker-pcr-policy.json
caution --verbose secret inspect
# Explicitly view unauthenticated contents, without Platform lookup:
caution secret inspect --unverified
```

Inspection is read-only and does not send a share. It defaults to
`.caution/quorum-bundle.json`; policy precedence is the explicit flag, then
`KEYMAKER_PCR_POLICY_PATH`, then `.caution/keymaker-pcr-policy.json`.
Missing policies and invalid proofs fail; there is no automatic unverified fallback.
`--unverified` cannot be combined with an explicit policy flag.

The compact summary shows the embedded bundle ID prefix, saved name/labels,
threshold, custody and a holder table with shortened certificate fingerprints
and included passkey counts. Multiple passkeys represent one share.
Verified output includes the authenticated generation time: this proves historical
provenance, not live authorization or current application state. Synthetic test
proofs are explicitly marked TEST ONLY and provide no authenticated timestamp.

Verified inspection uses an existing Platform session for best-effort holder names
only when the complete bundle and holder metadata match. It never prompts for login;
offline or unavailable names fall back to Holder N. Names reflect current organization
registrations, not authorization evidence. Dashboard record names/edited labels and
record creation dates are not substituted for saved bundle contents.

`--verbose` replaces shortened fingerprints with full values and adds an
Identifiers & verification section: full Bundle ID, deterministic bundle hash,
public-key SHA-256 and policy path. The public-key hash covers the exact UTF-8
public-key text, matching the Dashboard. Raw proofs, certificates and credential snapshots are not printed. Human-readable
inspection output goes to stderr, following the CLI's existing output convention.

### Matching CLI and Dashboard bundles

Both interfaces identify V1 bundles by their embedded UUID: `Bundle 9fd6da23`, or
`Name · 9fd6da23`. The CLI uses the saved bundle name label; the Dashboard may use
its editable record name. Names can differ; match the embedded ID and full hash.
The Dashboard's Identifiers section exposes full Bundle ID, Bundle hash,
Public key SHA-256 and Platform record ID with Reveal/Copy controls. Hashes and
fingerprints abbreviate to eight leading and eight trailing characters; Copy
always uses the complete value. A Platform record ID identifies a database row,
not the bundle contents. Older records without an embedded ID explicitly use
`Platform record …` as their fallback title.

The API adds optional `bundle_hash` display metadata to existing list/get responses,
using the same canonical Rust hashing function as the CLI. Unsupported records omit
it. Computing/displaying this hash does not verify a proof, and this metadata is not
included in downloaded bundles. Updates and deletes still use the Platform record ID.

Inspection and recovery explain why holder names are unavailable: missing/unreadable
or expired session, mismatched server, failed/timed-out API lookup, unmatched bundle,
or unavailable/inconsistent holder metadata. These are display failures, separate
from local proof verification. A server mismatch prints both servers and suggests an
explicit `--url` command, even without `--verbose`. The CLI never switches servers,
sends the session to a different server, or prompts for login just to retrieve names.
Metadata requests reject redirects rather than forwarding the session.
Unverified inspection skips all metadata lookup. Inspection also skips irrelevant
USB/FIDO2 dependency diagnostics; existing environment warnings remain unchanged.
