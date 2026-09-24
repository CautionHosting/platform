# Public components

`GET /.well-known/caution/build-inputs` retains the framework pins and adds
`services: { pending, checked_at, entries }`. The public `/components` page uses
this response without authentication. The dashboard footer links to it.

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

One process-local snapshot covers both services. A request starts a refresh if
the previous refresh started at least 60 seconds ago; concurrent requests share
that refresh. Pending checks return immediately. Only the latest result is kept;
a failed check replaces success. Each API process maintains its own snapshot.
There is no background monitoring or persistence.

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

The page loads once, supports manual Refresh and follows an initial pending
check for at most ten seconds. A refresh inside the cache interval returns the
same snapshot. Readiness and verification are shown separately.

Example independent verification:

```sh
caution verify --attestation-url 'https://keymaker.example.com/attestation'
caution verify --attestation-url 'https://key-service.example.com/attestation'
```

The published policy describes Platform's trust configuration, not independent
proof of source or trust for a client. Review source and reproduce measurements.

Validation: `cargo test -p api --locked service_observations`, the existing
`build_inputs` test, gateway `components_is_public_html`, frontend tests/build,
and `node tests/e2e/browser-authenticator/components.mjs` (after the build).
The signed quote fixture uses a historical clock; HTTP and browser observations
are mocked. These checks do not establish live Nitro service correctness.
