# Frontend Sentry releases

Use a separate Vue/JavaScript project in the existing Sentry organization. Configure
its allowed origins and disable IP storage. No DSN means no browser reporting.

## Server configuration

Add these values to your existing **`~/.config/caution/.env`**, outside the checkout.
It is the only hand-edited environment file. Use literal `KEY=value` lines, without
shell quotes, `export`, interpolation, or inline comments:

```dotenv
VITE_SENTRY_DSN=https://<public-key>@<sentry-host>/<project-id>
VITE_SENTRY_ENVIRONMENT=production
SENTRY_URL=https://<sentry-host>/
SENTRY_ORG=<organization-slug>
SENTRY_PROJECT=<frontend-project-slug>
SENTRY_AUTH_TOKEN=<release-and-source-map-upload-token>
```

Omit `SENTRY_URL` for sentry.io. Keep `VITE_PADDLE_SANDBOX` in the same file when
needed. Make derives the release from the Git commit; do not add release variables.
The source must be a regular file owned by the invoking user, with owner-only
permissions: `chmod 600 ~/.config/caution/.env`. Symlink sources are rejected.
Never put the upload token in a `VITE_*` variable or Docker build arguments.

`scripts/platform_env.py` generates per-invocation files in private temporary
directories, with mode `0600`, and removes them on completion or normal interruption:

- `frontend.env`: only the approved public build settings above.
- `frontend-sentry.env`: only the private upload settings.
- `runtime.env`: backend settings, without `VITE_*`, upload settings, or `SENTRY_RELEASE`.
  Backend `SENTRY_DSN_*` settings and other runtime values are preserved.

The original `.env` is never sourced, exported wholesale, or rewritten. Each service
start reads it afresh, including direct systemd restarts. `make setup` installs the
runtime helper and units; `make up` refreshes them before restarting services.
Do not manually maintain the generated files. If migrating from separate frontend
files, move their settings into `.env`; old files are not read implicitly.

Exported frontend settings override file values; an explicitly empty
`VITE_SENTRY_DSN` disables reporting. `CAUTION_ENV_FILE` selects a different source
for build and direct script invocations; `make up` requires the standard home path
so builds, component preparation, migrations and installed services agree.
The API test target retains its existing lower-priority checkout `.env` overlay;
it is parsed and filtered too, and must also have owner-only permissions.
`make admin` imports only literal AWS settings when its existing AWS fallback is needed.

## Build and deploy

```sh
make up
```

With Sentry configured, this builds a unique private frontend export, validates it,
uploads its source maps, and packages **those same assets** into the gateway image.
Missing credentials, invalid artifacts, upload failure or interruption abort before
migration/service restart. Without a DSN, it validates/packages a disabled build
without requiring upload credentials or contacting Sentry.

The uploader runs separately in a disposable container using the lockfile-pinned
CLI. Its root filesystem and retained artifact mount are read-only; credentials
are supplied only to that container. Host Node/npm installation is not required.
The frontend bundle build remains offline after dependency installation.

For a build/upload without replacing services:

```sh
make build-frontend-release
# Or also package the gateway image, without starting/restarting services:
make build-gateway-release
```

Exports are retained under `out/frontend-releases/` in unique private directories.
Retain them for as long as the corresponding release can serve traffic, then remove
unneeded exports manually. Serve only `release/dist/`, never `sentry-artifacts/`.

To retry a retained export without rebuilding, pass its printed release directory
as `FRONTEND_RELEASE_DIR`, keeping the original public build settings and release.
An older export also requires `VITE_SENTRY_RELEASE=<its-full-commit>`. Validation and
upload still run before packaging; an earlier successful upload is not assumed.
The retained manifest binds all public build settings, including the DSN and Paddle
mode, so configuration changes require a fresh build rather than stale reuse.
Advanced callers can explicitly override a generated frontend file with
`FRONTEND_ENV_FILE` or `FRONTEND_SENTRY_ENV_FILE`; these files accept only the keys
for that purpose, and the private override must also have owner-only permissions.
`FRONTEND_RELEASES_DIR` overrides the retention root.

Low-level `build-frontend-artifacts`, `build-frontend-dist`, and `build-gateway`
targets remain build-only: they require explicitly exported public settings and do
not load these files or upload maps. Direct Docker/npm builds also require an
explicit full-commit `VITE_SENTRY_RELEASE` when Sentry is enabled.

Before calling a real destination validated, trigger a controlled dashboard error
and confirm its release and readable source locations in the frontend Sentry
project. Local tests and successful artifact upload alone do not prove ingestion
or server-side symbolication.
