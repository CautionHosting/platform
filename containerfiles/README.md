# Platform releases and reusable enclave components

## Operator workflow

From a reviewed platform checkout with no tracked changes, run:

```sh
make up
```

This builds a candidate and prepares its shared components **before** running
migrations or replacing services. API deployment defaults to `prebuilt`: `make up`
generates and activates the component-set digest; operators do not calculate or
paste a hash into `.env`. Leaving `COMPONENT_SET_SHA256` unset no longer selects
source builds: an API launched without a valid prebuilt selection fails closed
unless source mode is explicit. This is a platform-service release operation, not
something run for each application deployment.

Use the existing Linux/x86_64 Docker host with Docker/BuildKit and buildx, Git,
GNU Make, the service-build prerequisites, and native Python 3 (`/usr/bin/python3`
for the installed user units). The Docker endpoint must be a local Unix socket;
a remote Docker context is not supported. Install the platform's systemd user
units, including PostgreSQL, and provide the normal operator configuration under
`~/.config/caution/` first. Release preparation packages and invokes its own Rust
publisher; no host Rust/Cargo installation or manual EnclaveOS checkout is needed.
First-use preparation can compile components and needs build capacity and network
access to the pinned sources and build dependencies.

Configure [`env.example`](../env.example) as `~/.config/caution/.env`, using
literal Docker `KEY=value` syntax, not shell expansion. Keep credentials private.
The publisher receives that file's settings plus exported `AWS_*` values,
including `AWS_SESSION_TOKEN` for temporary credentials. The helper does **not**
mount host AWS profile, SSO or credential-process files; setting `AWS_PROFILE`
alone does not supply those credentials. Export resolved credentials when needed.
Shell-only credentials are for preparation; running services still read the
operator `.env`, so ensure their credentials independently permit consumption.

The component bucket must already exist. Selection is, in order:

1. Nonempty `COMPONENTS_S3_BUCKET`, if explicitly configured.
2. Nonempty `EIF_S3_BUCKET`.
3. `caution-eif-storage-<AWS_ACCOUNT_ID>` for the configured 12-digit account ID.

Preparation needs existing prefix-scoped `s3:ListBucket`, `s3:GetObject` and
`s3:PutObject` authority for `components/v1/`. Sufficient existing deployment
credentials can be reused; a new bucket or role is not required. `make up` never
creates buckets or changes IAM, roles, policies or lifecycle settings. Resolve
permission failures explicitly; do not interpret `AccessDenied` as a missing
artifact. Same-bucket consumers need only verified component reads. An alternate
source bucket needs separately authorized consumer/relay access; the
`components_source_bucket_name` option in
[`infra-bootstrap`](../infra-bootstrap/README.md) does not by itself grant release
publication authority. BYOC relay uses platform credentials for source reads and
separate customer credentials for verified destination writes, not the publisher's
credentials for customer access.

## Preparation, activation and retained state

`make up` serializes releases and captures the clean checkout's exact `HEAD` into
a separate frozen Git snapshot. Untracked files are not release inputs. It builds
API, gateway, email and metering images with unique candidate tags and records
their immutable Docker image IDs; it does not replace the active release by
retagging a shared image name. The candidate API's packaged
`prepare-components --print-inputs` resolves the selected EnclaveOS, bootproof,
STEVE and Locksmith revisions. Optional overrides must be full immutable commits;
otherwise the candidate's defaults apply, not floating upstream versions.

For prebuilt mode, the publisher source-builds specifications not already accepted
locally, even if S3 advertises an existing build. Matching independently retained
accepted locks allow warm reuse after index and binary verification. A genuinely
missing accepted index or output can be rebuilt only to the **same** accepted
sizes and hashes. Substitution, corruption and denial fail closed. An S3 index or
checksum stored beside a binary is not an independent acceptance authority.
Standalone publication does not activate anything; `make up` performs the later
activation after preparation succeeds.

Private release state is retained outside S3 under `~/.config/caution/releases/`:

- `<id>/release.json`: captured framework commit, source inputs, service image
  IDs, component mode, bucket and set digest.
- `<id>/components.env`: generated platform/source pins and component selection,
  loaded **after** the operator `.env` so the selected release wins.
- `<id>/components.lock.json`: canonical accepted set for prebuilt releases.
- `<id>/launch-service.py`: the launcher captured with that platform revision.
- `accepted/<sha256>.json`: retained accepted locks, checked against their filename
  hashes before reuse. Do not edit/reformat them or replace them from S3.
- `current` and `previous`: managed symlinks updated by atomic replacement;
  `previous` is updated after successful activation.
- `pending.json`: journal for an incomplete activation; `release.lock` prevents
  concurrent release/recovery operations.

The helper creates private files/directories with a restrictive umask. Preserve
this trusted local state and the referenced Docker images; do not prune them as
part of an upgrade. Hashes detect changed lock bytes, not a compromised operator
account able to replace both a lock and its name. The ordinary `.env`,
`config.json` and `prices.json` remain operator-owned, not frozen release copies.

Before migration, `make up` runs the candidate API's `--check-components` command
with its immutable image and the runtime operator/generated environment files.
This checks component read access, selection, source pins and recipes without
starting database connections or background workers. Publisher credentials from
the shell do not substitute for the runtime reader's credentials. This is a
component preflight, not a check of every downstream runtime dependency.

Only after preparation and this preflight succeed does `make up` journal
activation, run migrations, select the candidate and restart services. It installs managed
`90-caution-release.conf` drop-ins for already-installed API, gateway, email and
metering user units. Both those units and direct `make run-*` launches use the
selected image IDs and generated component environment. Direct launches refuse to
replace systemd-managed running services and require an existing selected release;
they are not another way to prepare one. Do not edit the managed drop-ins or
generated files, or override their release launcher with an operator drop-in.
Existing API/gateway units keep the shared `caution-data-dir` volume; direct Make
launches keep their shared `CAUTION_DATA_DIR` bind mount. The email endpoint
remains loopback-only at `127.0.0.1:8082`. Unrecognized `ExecStartPre` commands in
installed units or drop-ins are rejected before preparation, rather than silently
removed; resolve those customizations explicitly before retrying. Direct Make
launches also
retain their `NETWORK` override, API DNS options, and 60-second metering cadence;
installed units retain their default network/resolver and configured cadence.
The four concurrently built service images use exclusive shared Cargo dependency
cache mounts, so separate Cargo processes cannot corrupt each other’s checkouts.
Rebuilding a mutable `caution-api` tag alone does not update the active release.
Completion requires the expected image IDs and service health checks; those
checks do not prove EIF reproduction or downstream account permissions.

## Source mode and interrupted activation

For an explicit source-build release:

```sh
make up COMPONENT_BUILD_MODE=source
```

This still captures the candidate images and source pins, but skips component
publication and writes empty digest/bucket values into the generated overlay,
clearing an older prebuilt selection from `.env`. To make this persistent, set
`COMPONENT_BUILD_MODE=source` in the operator `.env`; otherwise a later `make up`
uses its configured mode (prebuilt by default). Simply unsetting a digest or
editing `.env` does not change an already selected release. Source mode retains
the source-build host-helper pin requirements linked below.

A **preparation** failure runs no migrations or service restarts and leaves the
active release selected. A failure **during activation** may already have applied
migrations or restarted some services. It retains the journal and previous release
information and blocks the next `make up`. Inspect
`~/.config/caution/releases/pending.json` and the service logs, verify that the
previous service version is compatible with the current database schema, then run:

```sh
make recover-release
```

Recovery stops the candidate services, restores the previous selection and managed
drop-in state, and restarts previously active units. With no prior managed release,
it restores the pre-activation unit path. This is recovery from an incomplete
activation, not a general rollback command. **It does not roll back database
migrations or restore edits to operator configuration files.** Check schema
compatibility and restore any separately changed operator settings before recovery.
Do not delete the journal to bypass this check. No component deletion, retention
policy or artifact cleanup is part of release or recovery.

Release selection does not replace existing application EIFs or their paired host
artifacts. CLI independent source reproduction remains separate from API prebuilt
deployment: use the historical manifest's framework, source and recipe inputs,
rebuild and compare component bytes and measurements. Current API defaults and
release pins must not replace historical verification inputs. A CLI needs the
compatible shared-builder implementation; downloaded templates do not upgrade an
older installed binary. Release health alone is not evidence that this verification
or a live deployment has passed.

## Canonical component recipes

`Containerfile.init`, `Containerfile.bootproof`, `Containerfile.steve`,
`Containerfile.locksmith`, and `Containerfile.tap-framer` are the canonical recipes
used by component publication and source EIF builds. The EIF template only
composes them; historical revisions retain their original inline recipes.

For low-level recipe inspection (not the normal `make up` workflow), each recipe
exports binaries through its `<component>-export` target. Run standalone builds
on a disposable host with Docker/BuildKit. For example, from the repository root:

```sh
docker buildx build --platform linux/amd64 --provenance=false \
  --build-arg SOURCE_DATE_EPOCH=1 --build-arg BOOTPROOF_COMMIT="$BOOTPROOF_COMMIT" \
  -f containerfiles/Containerfile.bootproof --target bootproof-export \
  --output type=local,dest=dist/bootproof .
```

Use full immutable Git revisions for `BOOTPROOF_COMMIT`, `STEVE_COMMIT`, and
`LOCKSMITH_COMMIT`. Init expects the selected EnclaveOS tree under `enclave/` in
the build context; TAP expects the selected framework's `src/tap-framer/`.
See [TAP build and pin verification](../src/tap-framer/README.md) for its Make
targets and the independently reviewed `host.sha256` used by source-mode host
bootstrap. Prebuilt releases use their accepted component-set output digest
instead; ordinary `make up` does not require a manual host hash update.

Always pair recipes with their selected framework revision. A recipe change
changes component identity and must be source-qualified as a new specification
before activation, even when rebuilt binaries are identical. `make up` performs
that preparation and selects the matching release. Standalone publication alone
does not activate a set or change existing deployments.
