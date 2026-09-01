# Caution admin explorer

`caution-admin` is an experimental, read-only terminal explorer for platform
operators. The pilot runs only when `ENVIRONMENT=development`; it refuses to
start in production.

The tool is a normal Rust workspace binary, not a StageX artifact, container
image, service, or end-user `caution` command. With the development stack
running, build and launch it from the server checkout:

```bash
make admin
```

If `DATABASE_URL` and `ENVIRONMENT=development` are explicitly set, `make
admin` uses the URL directly and does not require an API container. Otherwise
it discovers the development environment and database URL from a running local
`api` container. For example, after opening an SSH tunnel to the development
database:

```bash
ENVIRONMENT=development \
DATABASE_URL='postgresql://USER:PASSWORD@127.0.0.1:15432/caution' \
make admin
```

Use the development database credentials for `USER` and `PASSWORD`; do not put
them in the repository.

Press `/` to search by username, email, organization name, app name, or exact
UUID; valid UUID representations are normalized before lookup. Select a result
with the arrow keys or `j`/`k`, press Enter to open it, and follow its listed
relationships. Backspace returns to the exact previous screen. Press `?` for
the complete key reference.

The header shows the path used to reach the current resource, for example
`Search “alice” › User alice › Apps via organizations › App alice-api`.
Healthy states are green, transitional states yellow, and failed or suspended
states red; the status text is always shown as well as its colour.
Summary rows show status first, followed by email, app count, organization, or
relationship provenance as applicable. Users without an email show `no email`.
Panel content has a one-cell left inset; rows remain single-height.
Long detail values are shown with an ellipsis so later fields remain visible;
use the headless JSON commands to retrieve their full allowlisted values.

The pilot exposes these relationships:

- user to organization and apps;
- organization to users and apps;
- app to organization and users with access.

Organization pages also summarize the derived credit balance and state, the
current BYOC plan, billing source, effective capacity, and any pending plan
change. App pages show their organization, fully managed or BYOC mode,
provider/account/resource metadata, region, public IP, allowlisted domain, and
DNS state.

Membership roles and the organization used by transitive relationships are
shown on relationship results. Queries are bounded and the database connections
are configured read-only. The explorer selects only the allowlisted `domain`
value from app configuration and never selects raw configuration, credential
configuration or secrets, authentication material, or tokens.

## Headless access

The same binary has small commands for diagnostics and tests:

```bash
make admin ADMIN_ARGS='search alice --json'
make admin ADMIN_ARGS='list user --json'
make admin ADMIN_ARGS='show user <uuid> --json'
make admin ADMIN_ARGS='follow user <uuid> apps --json'
```

`list` and `follow` accept `--limit` (1 to 200) and `--offset`. Human-readable
tabular output is the default; `--json` produces machine-readable output.
Failures identify the operation and call site and print their complete typed
source chain. `show` and `follow` fail when their source UUID does not exist
rather than treating a missing resource as an empty relationship.

This pilot does not replace `utils/admin`. Continue using that script for legal
document and other mutating administration workflows.

The implementation keeps database resource queries, relationship traversal,
row decoding, terminal control, and Ratatui rendering in small focused modules.
