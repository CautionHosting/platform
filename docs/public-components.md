# Public components

`GET /.well-known/caution/build-inputs` retains the framework pins and adds
`services: { pending, checked_at, entries }`. The public `/components` page uses
this response without authentication. The dashboard footer links to it. Entries
include stable `id` values `keymaker` and `key-service`; `name` remains a display label.

No new configuration is required:

| Service / purpose | Existing configuration |
| --- | --- |
| Keymaker | `KEYMAKER_URL`, `KEYMAKER_PCR_POLICY_PATH` |
| Key service / certificate issuance | `PUBLIC_CERTIFICATE_SERVICE_URL`, `PUBLIC_CERTIFICATE_PCR_POLICY_PATH` |
| Key service / share release | `RECRYPTOR_PCR_POLICY_PATH` |

URLs must be HTTPS without credentials, queries or fragments. Policy files are
reread during each refresh. Share release retains its requirement for exactly
one non-expiring set containing exactly PCR0/1/2. Keymaker and certificate-issuance
policies may pin additional authenticated PCRs (for example PCR3, PCR4 or PCR8).
Expired sets are displayed but cannot match live quotes.

One process-local snapshot covers both services and is cached for 60 seconds from
completion, including failed checks. The first request, or the first after expiry,
waits for a refresh; concurrent callers wait and reuse the completed result.
Responses contain `pending: false` and `checked_at`, rather than an empty pending
snapshot. A failed check replaces previous success. If a request is cancelled
during refresh, the next caller can retry. Each API process maintains its own
snapshot; there is no background monitoring or persistence.

Checks send a fresh nonce to `/attestation` and separately GET `/health`.
Requests have five-second deadlines, reject redirects and limit JSON responses
to 1 MiB for attestation and 16 KiB for health. No issuance token or incoming
credentials are forwarded. Signatures, certificate chains and nonce are checked
before comparing authenticated PCRs against configured policies. Zero/debug
PCR0/1/2 values are rejected; unused additional PCRs may legitimately be zero.
Observed measurements never become trusted policy entries.

Only service URLs, checks, PCRs/policy cutoffs, checked time and selected source
fields are public. Configuration paths, tokens and arbitrary manifest fields are
excluded. Repository and commit are always **service-reported**: the current
manifest source metadata is not bound to the signed quote. Framework dependency
pins are separate from deployed-service commits.

The page loads once and supports manual Refresh. A refresh inside the cache
interval returns the same snapshot; a cold or expired request waits for checks,
which may take roughly five seconds plus local verification if a service times out.
The page retains pending-response polling for older APIs, within its ten-second
deadline. Readiness and verification are shown separately.

Service cards keep readiness, attestation authentication and each policy result
separate. Transport failures appear as muted **Unavailable** checks, with details
collapsed; policies lacking authenticated measurements show **Not evaluated**.
Actual authentication, configuration and policy failures remain visible in red.
A responding service that is not ready shows **Not ready**, independently of its
attestation. When measurements are unavailable, the evidence section retains
configured policies without empty observation/comparison columns. Browser and CLI
verification actions remain available for valid endpoints, even if Platform could
not reach them. Check times within five seconds of the browser clock display
“Checked just now”. Relative check age refers to the Platform snapshot; the exact
timestamp is available on the time label. Source revisions remain service-reported, while
the compact framework table lists build dependencies.

**Check attestation** opens the existing `/verify?url=…` page in a new tab for
fresh browser verification. The link carries only the endpoint, never an expected
PCR baseline. Import independently trusted measurements in that verifier to check
the intended image. Browser verification does not reproduce source; the copyable
CLI command performs independent build reproduction.

The evidence disclosure compares observed and allowed PCRs for each approved set.
Individual equal values do not establish overall policy acceptance or override
cutoffs. “No expiry” means no policy timestamp cutoff, not certificate expiry.
Only valid all-zero, unpinned measurements outside PCR0/1/2 are collapsed by
default. **Show all PCRs** reveals them; required, policy-pinned, missing and
malformed values remain visible. **Show full values** and copy controls retain
access to complete hashes. Discovery JSON retains every measurement.

Each service card displays its CLI verification command as selectable text with an
adjacent Copy control. Services with stable IDs use `caution --url <this-platform>
verify --service keymaker` (or `key-service`), explicitly selecting the Platform
hosting the page. Older discovery responses without recognized IDs retain the
explicit `--attestation-url` command, which must run from the service checkout.
The browser attestation action remains separate.

## CLI discovery and client trust

With an updated API and CLI, establish trust from any application checkout:

```sh
export CAUTION_BACKEND_URL=https://platform.example.com
caution verify --service keymaker
caution verify --service key-service
```

With `CAUTION_BACKEND_URL` exported, `--url` is optional. An explicit `--url`
overrides the environment variable for that command. Replace the placeholder URL
with your Platform endpoint.

The CLI discovers the selected service, shows its
unsigned source manifest and asks before executing the build. It requires pinned
HTTPS source inputs, independently reproduces PCR0/1/2, challenges the live service
after reproduction, and verifies applicable TLS binding. Review the intended
repository/revision and build inputs: reproduction does not establish code safety.
Platform's advertised measurements and policy sets never become trusted automatically.

Hosted application downloads use HTTPS commit-addressed archive candidates, without
HTTP guesses or Git fallback. HTTPS redirects cannot downgrade to HTTP, including
framework/EnclaveOS downloads and their preflight checks. Direct archive inputs must
use `/archive/<approved-40-character-commit>.tar.gz`; mutable or unsupported archive
URLs fail before any build. Repository URLs are resolved to commit-addressed retrieval
URLs without changing the measured manifest. Source extraction uses a fresh temporary
directory and a separate content-based build cache identity, so legacy download or
reproduction caches cannot satisfy this path. Build commands themselves remain the
approved source's responsibility; this is not a network sandbox for builds.

A second confirmation saves the verified endpoint, PCR policy, source manifest
and verification time under the CLI configuration directory's `services/` folder,
separated by Platform URL and service. Projects on that Platform share this trust.
Updates preserve a previous record. The application's `.caution/trusted_hashes.json`
is untouched. `--no-cache` forces build reproduction again.

Approving a different Keymaker image retains previously verified PCR sets for
historical bundles. The outgoing current set receives a generation cutoff at the
local save-approval time (Unix seconds); earlier historical cutoffs are preserved.
Locksmith checks each cutoff against the bundle's authenticated generation time:
proofs before it remain accepted, while proofs at or after it are rejected for
that retired set. Re-verifying unchanged measurements leaves the policy unchanged.
Explicitly re-approving a retired image warns before saving and makes it current
again, removing its old cutoff, including acceptance of proofs generated during
its retirement. Key-service live trust remains one current, non-expiring set.

History comes only from this client's prior verified trust, not discovery or
backup-file scanning. Provision the previously verified historical policy on fresh
machines and CI; verifying today's image cannot recover missing history. Existing
project policies retain precedence and are not rewritten. This local cutoff is
not an assertion of when Platform deployed the new image.

Hosted `secret init` offers Keymaker setup when no policy exists. Passkey
`secret send-shard` offers key-service setup before starting its release session.
Existing flags/environment settings and project policies take precedence; invalid
explicit inputs fail rather than falling back. Saved endpoints and pins are reused
without a discovery request on every operation. Changes require running the service
verification command again; evidence mismatches never update trust automatically.
Noninteractive commands require already established trust or explicit configuration.
Discovery requests reject redirects and cap responses at 1 MiB. Each request allows
ten seconds for server-side checks, within a twelve-second overall deadline.
Pending responses from older APIs are still retried within that deadline.

A server without service IDs needs an API update or explicit configuration.
Ordinary `caution verify` remains application verification; when using
`--attestation-url` manually, run it from the intended service's checkout because
it writes that checkout's application measurements.

Client setup does not update Platform/gateway policies, CA configuration or policies
packaged in enclaves. Preserve bundle-specific historical Keymaker policies when
upgrading services. See [share recovery](share-recovery.md) for policy precedence.

Validation: `cargo test -p api --locked service_observations`, the existing
`build_inputs` test, gateway `components_is_public_html`, frontend tests/build,
and `node tests/e2e/browser-authenticator/components.mjs` (after the build).
The signed quote fixture uses a historical clock; HTTP and browser observations
are mocked. These checks do not establish live Nitro service correctness.
