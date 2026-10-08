# Reusable enclave components

## Operator workflow

From a reviewed platform checkout with no tracked changes, run:

```sh
make up
```

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

Install the repository's matching systemd user units (including the updated API
unit) through your normal installation procedure. `make up` reloads the units but
does not install or rewrite them or any operator drop-ins. Supply the normal
configuration in `~/.config/caution/`. Configure [`env.example`](../env.example)
as `.env` using literal Docker `KEY=value` syntax, not shell expansion, and keep
it private. `config.json` and `prices.json` remain operator-owned.

The component publisher receives that `.env` plus exported `AWS_*` values,
including `AWS_SESSION_TOKEN`. Host AWS profile, SSO and credential-process files
are not mounted: export resolved credentials if needed. The runtime reader
preflight uses the operator `.env`, **not** those extra publisher credentials.

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
