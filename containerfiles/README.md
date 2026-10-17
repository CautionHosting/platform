# Reusable enclave components

## Operator workflow

From a reviewed platform checkout with no tracked changes, run:

```sh
make up
```

**Tracked-clean contract:** `make up` and `make prepare-components` reject any
staged or unstaged change to a tracked file, including local recipe/config edits.
Commit reviewed changes and rebuild the candidate image from that commit first.
Untracked files are not part of this check or the frozen publication checkout;
keep operator configuration in `~/.config/caution/` rather than editing tracked
defaults. Do not bypass the check: image, source and recipes must identify the
same reviewed commit.

Make still builds the service images, runs migrations and restarts the existing
systemd user services. Before migrations or restarts, a **component-only** step
prepares and validates the API's enclave components. Operators do not calculate
or paste hashes. Gateway, email and metering retain their existing launch commands
and do not read component configuration. There is no platform release controller,
service launcher, activation journal or automatic rollback.

Use the normal Linux/x86_64 Docker/BuildKit host with buildx, Git, GNU Make,
`flock`, Python 3 and the service-build prerequisites. Component publication needs
a local Docker Unix socket. The API image packages the Rust publisher; host
Rust/Cargo and a manual EnclaveOS checkout are not required. First preparation can
compile components and needs build capacity and access to pinned sources.

The publisher sets `GOMAXPROCS=2` on its Docker/Buildx client to mitigate startup
crashes in the bundled Go/musl runtime on high-core
hosts. This does not disable garbage collection or constrain the build daemon
or component compilers. It is a publisher-only mitigation, not a fix to the
underlying runtime packaging or other Docker client invocation paths.

Install the repository's matching systemd user units (including the updated API
unit) through your normal installation procedure. `make up` reloads the units but
does not install or rewrite them or any operator drop-ins. Supply the normal
configuration in `~/.config/caution/`. Configure [`env.example`](../env.example)
as `.env` using literal Docker `KEY=value` syntax, not shell expansion, and keep
it private. `config.json` and `prices.json` remain operator-owned.

The component publisher receives only an explicit allowlist of AWS provider,
region/endpoint/retry settings, bucket names, component mode and the four source
pins. Exported allowlisted values override `.env`; this includes temporary
credentials (`AWS_SESSION_TOKEN`), web-identity/container-provider selectors and
IMDS settings. Database, signing, billing and other application secrets are not
forwarded, nor are arbitrary `AWS_*` variables. See `PUBLISHER_ENV` in
`scripts/prepare-components.py` for the exact list. The SDK provider chain remains
enabled; no credentials are synthesized. Host AWS profile, SSO, token and
credential-process files are not mounted: export resolved credentials if those
providers depend on host files. The runtime reader preflight uses the operator
`.env`, **not** those extra publisher credentials, and has no Docker socket mount.

The component bucket must already exist. Selection is, in order:

1. Nonempty `COMPONENTS_S3_BUCKET`.
2. Nonempty `EIF_S3_BUCKET`.
3. `caution-eif-storage-<AWS_ACCOUNT_ID>` for a configured 12-digit account ID.

Publication needs existing prefix-scoped `s3:ListBucket`, `s3:GetObject` and
`s3:PutObject` authority for `components/v1/`. Sufficient existing deployment
credentials can be reused; a new bucket or role is not required. Preparation does
not create buckets or change IAM, policies or lifecycle settings. Same-bucket
consumers need verified reads only. Alternate source buckets need separately
authorized reader/relay access; `components_source_bucket_name` in
[`infra-bootstrap`](../infra-bootstrap/README.md) does not grant publication
rights. BYOC relay reads with platform credentials and writes verified bytes with
customer credentials. Denial or corruption is never treated as missing output.

## Component preparation and API selection

`make up` serializes its build/prepare/migrate/restart sequence. It builds a
candidate API without retagging the image selected by a previous component
preparation. `scripts/prepare-components.py` checks that image's framework commit
against the clean checkout, captures its immutable image ID, and resolves the
four tool pins with its packaged `prepare-components --print-inputs`. Overrides
must be full immutable commits; otherwise the API image's defaults apply.

The publisher uses a frozen framework checkout and pinned EnclaveOS source.
Unaccepted component specifications compile from source even when S3 advertises
an existing build. Independently retained accepted locks permit warm reuse only
after index and output verification. Missing accepted objects may be rebuilt only
to the same accepted sizes and hashes; substitutions fail closed.

Private component state is stored under `~/.config/caution/`:

- `components/accepted/<sha256>.json`: trusted accepted component locks, checked
  against their filenames before reuse. Preserve these; do not replace them from
  S3 or edit/reformat them.
- `components/build-*/`: component compilation logs, including failed attempts.
- `components.env`: the API image ID, framework/tool pins, component mode, bucket
  and set digest. Generated atomically after successful runtime-reader preflight.

Build-log retention/GC is deliberately deferred. Every preparation may retain a
new `build-*` directory, including logs from successful builds; no age or size
limit is enforced. Monitor local disk usage and archive/remove only reviewed,
inactive log directories under your operator retention policy. Do not remove
`components/accepted/` locks or the selected image as log cleanup. This feature
does not add S3 lifecycle changes or an automatic garbage collector.

The preflight runs the selected API's `--check-components` with its real runtime
credentials and generated selection on the service network. It checks component
read access, pins and recipes without database connections or background workers.
Only after it succeeds is `components.env` replaced; Make then migrates/restarts
as before. Preparation failure preserves the previous API selection and runs no
migrations or restarts. Failure after preparation can leave applied migrations
or partially restarted services: inspect the ordinary service/database state and
use the existing recovery procedure. No database rollback is promised.

Only the API consumes the generated selection: its systemd unit uses
`EnvironmentFile`, while `make run-api` loads it before the normal Docker command.
Both validate components before removing the API container. Pinning **only the
API** image keeps its recipes and component selection together across restarts;
rebuilding a mutable `caution-api` tag alone does not change that selection.
Preserve the selected image. For a direct-Make setup, run `make build-api` and
`make prepare-components` before `make run-api`; preparation alone changes no
services. Existing direct-Make networking, resolver and volume options remain.

On first installation, prepare components **before** starting the updated API
unit. A missing/empty `components.env` or empty image selection is diagnosed
before Docker starts; it never falls back to a mutable tag or source mode. The
unit's optional `EnvironmentFile` permits that diagnostic, not an unprepared
startup. A reboot does not prepare components automatically.

Tap-framer currently remains pinned to the whole platform commit, not a source
subtree hash. Every API release therefore requires paired component preparation
even when tap-framer source is unchanged. `make up` performs that pairing; a
manual image rebuild/restart alone is not a component release.

## E2E component mode

On an isolated test host, `make up-test` (and `up-test-billing`) builds the E2E API
image and prepares `~/.config/caution/components-e2e.env` before API launch.
`TEST_COMPONENT_BUILD_MODE` defaults to `prebuilt`; `run-api-test` loads that
selection and uses its immutable candidate image, source pins and set digest for
both `--check-components` and the API. Missing selections, mode mismatches or
failed checks stop before container replacement. Runtime pin/recipe validation
is not bypassed. The normal systemd `components.env` is not changed.

For an independently built E2E candidate:

```sh
make build-api-e2e API_IMAGE=caution-api-e2e-candidate
make prepare-components API_IMAGE=caution-api-e2e-candidate \
  COMPONENT_BUILD_MODE=prebuilt \
  COMPONENT_ENV_FILE="$HOME/.config/caution/components-e2e.env"
make run-api-test TEST_COMPONENT_BUILD_MODE=prebuilt
```

`TEST_COMPONENT_ENV_FILE` overrides the E2E selection path; use the same path as
`COMPONENT_ENV_FILE` during preparation. The selection output's parent directory
must exist on the same filesystem as `~/.config/caution/` for atomic replacement.
Explicit source tests remain available with
`make up-test TEST_COMPONENT_BUILD_MODE=source`, or
`make run-api-test TEST_COMPONENT_BUILD_MODE=source API_IMAGE=<candidate>`.
Source launch clears stale component digest/bucket settings and still preflights
the candidate. These targets retain their existing destructive test-DB/container
lifecycle: do not run them against live services. Offline mock tests are not
evidence of successful S3, Nitro or BYOC end-to-end execution.

## Explicit source fallback and historical reproduction

```sh
make up COMPONENT_BUILD_MODE=source
```

Source mode skips component publication and explicitly clears stale bucket/digest
values in the generated API selection. Set `COMPONENT_BUILD_MODE=source` in `.env`
for a persistent choice; otherwise a later `make up` uses its configured mode
(prebuilt by default). An unset digest alone is **not** source mode: API startup
fails closed without a valid prebuilt selection. Source-mode host-helper pins
still follow the [TAP build/pin procedure](../src/tap-framer/README.md).

Changing the active selection does not replace existing application EIFs or their
paired host artifacts. Redeployments use the active component set. Independent
CLI reproduction uses the old enclave manifest's framework, source and recipe
inputs, rebuilds component bytes, and verifies measurements; it must not substitute
the current API's selection. The CLI needs the compatible shared-builder code;
downloaded templates cannot upgrade an older binary. Startup preflight is not
live deployment, full-EIF equality or Nitro attestation evidence.

## Canonical component recipes

`Containerfile.init`, `Containerfile.bootproof`, `Containerfile.steve`,
`Containerfile.locksmith`, and `Containerfile.tap-framer` are shared by publication
and source EIF composition. Historical revisions retain their original recipes.
Each standalone recipe exports outputs through `<component>-export`, for example
on a disposable build host:

```sh
docker buildx build --platform linux/amd64 --provenance=false \
  --build-arg SOURCE_DATE_EPOCH=1 --build-arg BOOTPROOF_COMMIT="$BOOTPROOF_COMMIT" \
  -f containerfiles/Containerfile.bootproof --target bootproof-export \
  --output type=local,dest=dist/bootproof .
```

Use full immutable commits. Init expects selected EnclaveOS under `enclave/`;
TAP expects selected framework source under `src/tap-framer/`. Pair recipes with
their selected framework revision. Recipe changes require source qualification
even if outputs are identical. Prebuilt host delivery uses the accepted set's
output digest; normal `make up` needs no manual hash updates. Standalone
publication does not change the selected API configuration or existing enclaves.
