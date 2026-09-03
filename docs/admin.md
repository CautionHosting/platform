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
relationships. Backspace returns to the exact previous screen, except while
typing a search, where it deletes a character. Search matches literally:
`%` and `_` are escaped rather than treated as wildcards. Result tables use
50-row pages: press `n`/Page Down and `p`/Page Up to move between them. Press
`s` to cycle the meaningful table columns; the active column is marked in the
header. Apps and app relationships initially use operational state order, with
running apps first. Page, sort, selection, and query are restored by Back and
preserved by refresh. Press `?` for the complete key reference.
Esc cancels a global search and restores the screen it was opened from.
The selected row uses one shared charcoal highlight across every list and table
without replacing resource and status colours.

The `AWS` entry is a read-only account snapshot. It scans enabled regions for
Caution app hosts, builders, EBS volumes, and public IPv4 addresses, then
compares them with Platform records. `Findings` is this read-only comparison;
it is not AWS Config, Terraform drift, or persisted data. Diagnostics, partial
scan errors, costs, BYOC status, and unrelated AWS resources do not appear as
findings. A running EC2 host does not prove that a Nitro Enclave process is
running; that requires host-local `nitro-cli` inspection and is intentionally
outside this tool.

Findings are intentionally conservative and directional. `App expects EC2;
none observed` means Platform says a running or stopped app should have a
particular EC2 host, but a complete scan did not observe it. `EC2 has no
Platform match` means AWS has a Caution-tagged host whose IDs and tags match no
Platform app or build. Other
findings name terminated-app hosts, AWS/Platform state differences, association
errors, provider-account errors, and orphan builders. Pending and terminating
Platform apps do not produce host presence/state findings. Exact Platform
instance IDs are authoritative; tags are secondary evidence and never hide an
absent expected host.

Observed EC2 instances are correlated against all AWS-backed Platform apps
before account filtering. Absence and provider-account checks are then limited
to non-BYOC apps. A malformed mapping is reported as `Invalid provider account
mapping`; a valid differing account is reported as `Provider account mismatch`,
never as “untracked.” A failed regional
instance scan suppresses absence findings for that region, while findings based
on observed resources remain visible. Partial totals use `N+`; scan failures
stay in the coverage panel rather than appearing as findings. Findings sort
Critical before Warning. The concise list shows only level, issue, and subject;
press Enter for the structured Platform expectation, AWS observation, scope,
next step, AWS host, and linked Platform resources. Press `s` to sort by level,
issue, or subject.

The AWS overview keeps account, principal, regional coverage, and refresh time
in a non-selectable detail panel. `COMPLETE`, `PARTIAL`, and `STALE` describe
snapshot quality, not account health. Only the six sections below it are
selectable.
Host rows lead with the actual AWS state and label Platform state separately;
they never replace host state with a synthetic `failed` status. Every app-host
or builder row opens an AWS host screen with account, region/AZ, type, launch
time, network fields, allowlisted tags, Platform correlation, and finding
reasons. Linked Platform Apps or Organizations appear in their own navigable
panel. Finding details separately show `Platform expected`, `AWS observed`,
optional scope, and a read-only next step. AWS-only findings explicitly show
that no Platform resource is linked.

AWS data is loaded only when `AWS` is first opened and cached for the terminal
session. Loading runs in the background with a visible progress indicator, so
`q`/Ctrl-C remains responsive; Backspace cancels the request. Leaving and
reopening the screen does not call AWS again; press `r` to refresh. Regional or
Cost Explorer failures are shown as unavailable or partial, never as zero. If
inventory cannot be loaded, Findings explicitly says that no scan was performed.
A refresh that only partially fails still replaces the cached data, because the
newer partial view is more accurate than the older one; the affected sections
are marked partial. Only a refresh that fails completely keeps the last
successful snapshot, marked stale. Open findings and list selection survive
wording, severity, and label changes when their resource and host identity is
unchanged.

Builder reconciliation loads every active build plus terminal builds created in
the last seven days. An older observed builder is still reported as an orphan,
but without historical Platform build linkage.

`make admin` uses the normal AWS SDK credential chain. When no explicit AWS
credential environment or profile is set, it sources
`~/.config/caution/.env` in the recipe subshell if that file exists. Set
`CAUTION_ADMIN_SKIP_AWS_ENV=1` to suppress that fallback. The minimum read-only
permissions are:

- `sts:GetCallerIdentity`;
- `ec2:DescribeRegions`, `ec2:DescribeInstances`, `ec2:DescribeVolumes`, and
  `ec2:DescribeAddresses`;
- `ce:GetCostAndUsage` and `ce:GetCostForecast`.

The Costs section uses unblended month-to-date cost through yesterday and the
remaining-month mean forecast. Cost Explorer data is normally delayed, each
paginated request is billable, and tag attribution requires the `ManagedBy`
and `org_id` cost-allocation tags to be activated. Untagged cost is retained as
`Unattributed`. `ManagedBy` and `org_id` are queried and displayed as separate
attribution dimensions, each with its own unattributed total; denied or
unavailable queries remain visibly unavailable.

BYOC lists one Organization row for every current non-canceled subscription,
including subscriptions with no configured app. Rows show organization and
subscription status, plan, effective capacity, billing source, pending
changes, and whether the API deployment gate currently permits another app.
That gate uses the same legacy-credit, Paddle catalog, enterprise-expiry, and
pending-capacity rules as the API. Opening a row uses the existing Organization
and Apps navigation.
Customer AWS accounts are not queried, and credential configuration or secrets
are never selected. BYOC apps remain excluded from managed-account missing-host
findings.

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

`search`, `list`, and `follow` accept `--limit` (1 to 200) and `--offset`.
Human-readable tabular output is the default; terminal control and Unicode bidi
formatting characters are escaped while other Unicode is preserved. `--json`
is unchanged and produces the original machine-readable values.
Failures identify the operation and call site and print their complete typed
source chain. `show` and `follow` fail when their source UUID does not exist
rather than treating a missing resource as an empty relationship.

This pilot does not replace `utils/admin`. Continue using that script for legal
document and other mutating administration workflows.

The implementation keeps database resource queries, relationship traversal,
row decoding, terminal control, and Ratatui rendering in small focused modules.
Allowlisted SQL ordering lives in `db/order.rs`; table paging and in-memory AWS
ordering live in `state/table.rs`.
