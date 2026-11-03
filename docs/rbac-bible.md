# RBAC Bible

Single source of truth for the role-based access control work on the platform:
the current-state inventory, the target model, decisions, and open questions.
Update it as work lands. (Consolidates the earlier owner-permission scan and the
organization ownership-check index.)

Line numbers are as of 2026-11-03.

## How we got here

Goal: split organization users into **owners** (god powers) and **users** that
carry roles determining which operations they may perform. This document starts
from the completed scan of where owner permissions and organization access
checks currently live.

## Vocabulary

Terms as we intend them; tighten once the model is settled.

* **Organization** — tenancy boundary. A user belongs to exactly one
  organization today (`migrations/046_one_organization_per_user.sql`).
* **Owner** — an organization member with god powers over that organization.
* **User** — an organization member without god powers. Holds one or more
  **roles** that grant specific operations.
* **Role** — named bundle of operations a user-role holder may perform.
* **Operation** — a permission-checked action (HTTP route or a step within one).

## Current state

### Schema

`organization_members.role` is the enum `user_role ('owner','member')`
(`src/api/migrations/001_initial.sql:135`). `organization_invitations.role` is
the same enum with `DEFAULT 'member'` (`044_organization_invitations.sql:7`,
reset by `060_invitation_default_member_role.sql`). A user belongs to exactly
one organization (`046_one_organization_per_user.sql`). The `admin` and
`viewer` roles were removed by `061_remove_admin_role.sql` and
`062_remove_viewer_role.sql` (existing rows become `member`); `viewer` never
granted anything different from `member`.

Rust mirror `types::UserRole` (`src/api/src/types.rs:7-35`) exposes the only two
predicates in the codebase:

```rust
fn can_manage_org(&self) -> bool { matches!(self, Owner) }
fn is_owner(&self)       -> bool { matches!(self, Owner) }
```

There is no per-route role layer. Route groups in `main.rs` (auth / legal /
onboarding) only authenticate; role checks are ad hoc inside handlers, and most
handlers do not check a role at all.

### The checks themselves

| Site | Mechanism | Result |
|------|-----------|--------|
| `src/api/src/main.rs:245` `check_org_access` | `SELECT role FROM organization_members WHERE org=$1 AND user=$2` | caller's `UserRole`, or `Forbidden` |
| `src/api/src/main.rs:293` `get_user_primary_org` | `SELECT organization_id FROM organization_members WHERE user_id=$1` | caller's org id, or `NotFound` |
| `src/api/src/middleware.rs:256` `ensure_user_has_org` | `EXISTS (... organization_members WHERE user_id=$1)` + onboarding | ok / `MissingOrganization` / `NotOnboarded` |
| `src/api/src/middleware.rs:335` `onboarding_middleware` | calls `ensure_user_has_org` | applied to the whole `resource_routes` group |
| `src/api/src/organizations.rs:100` `user_has_organization` | `EXISTS (... organization_members WHERE user_id=$1)` | bool |
| `src/api/src/main.rs:269` `can_manage_org` | `UserRole::can_manage_org` | owner (admin removed) |
| `src/api/src/main.rs:273` `is_owner` | `UserRole::is_owner` | owner only |
| `src/api/src/types.rs:28,32` `UserRole::{can_manage_org,is_owner}` | `matches!` on the enum | the two role predicates |
| `src/api/src/subscriptions.rs:40` `require_billing_manager` | `check_org_access` + `can_manage_org` | owner (admin removed) |

### Owner grant sites

Where a user is given the `owner` role.

| # | Site | What happens |
|---|------|--------------|
| 1 | `src/api/src/organizations.rs:307-314` (`create_organization_for_user`) | Creator of a new organization is inserted as `UserRole::Owner`. |
| 2 | `organizations.rs:927-948` (`invite_member`) | Invitations now default to `UserRole::Member` (changed 2026-11-03); `InviteMemberRequest` has only `email` (`src/api/src/validated_types.rs:142-152`), so the inviter still cannot choose the role. |
| 3 | `src/api/src/organizations.rs:1255-1274` (`add_member`) | Inserts `payload.role`; `validate_role` accepts `"owner"` (`validation.rs:182-183`, `validated_types.rs:128-140`). Granting `owner` requires an owner caller. |
| 4 | `src/api/src/organizations.rs:1336-1355` (`update_member`) | `UPDATE ... SET role = $1::user_role`; `payload.role` may be `"owner"`. Granting `owner` requires an owner caller, and an existing owner cannot be demoted. |
| 5 | `src/gateway/src/db.rs:216-247` (`create_default_organization`) | Signup path: creates the user's default org and inserts them as `'owner'`. |
| 6 | `src/gateway/src/db.rs:520-533` (`accept_invitation_and_create_user`) | Invitation signup: inserts `invitation.role`, which is `owner` because of (2) and the migration default. |
| 7 | `src/api/migrations/044_organization_invitations.sql:7` | Invitation role default was `'owner'`; changed to `'member'` by `migrations/060_invitation_default_member_role.sql`. |
| 8 | `src/api/migrations/001_initial.sql:135` | Defines the `owner` variant of `user_role`. |

Test/fixture grants (not production paths, but assume the role):
`src/api/src/middleware/db_tests.rs:53,101`,
`src/api/src/provider_account_db_tests.rs:46`,
`src/api/src/organizations/db_tests.rs:84`,
`src/gateway/src/db/organization_tests.rs:150`,
`src/caution-admin/src/db/aws.rs:244-245`.

Not owner grants: `role_arn` / `Role:` matches are AWS IAM roles and deployment
`live`/`candidate` roles, unrelated to org RBAC.

### Role-specific gates

All gates are owner-only now that `admin` was removed. `owner only` uses
`is_owner`; the manager gate (`can_manage_org` / `require_billing_manager`) is
currently equivalent to `is_owner` but is kept as a separate name for the RBAC
replacement.

**owner only** (`is_owner`)

| Handler | Site |
|---------|------|
| `organizations::delete_organization` | `organizations.rs:530-538` (`is_owner`) |

**manager gate** (`can_manage_org` / `require_billing_manager`, currently owner)

| Handler | Site |
|---------|------|
| `organizations::update_organization` | `organizations.rs:447-455` |
| `organizations::update_org_settings` | `organizations.rs:670-678` |
| `organizations::invite_member` | `organizations.rs:824-832` |
| `organizations::list_active_invitations` | `organizations.rs:1015-1023` |
| `organizations::cancel_invitation` | `organizations.rs:1090-1098` |
| `organizations::add_member` | `organizations.rs` (manager gate; granting `owner` additionally requires an owner caller) |
| `organizations::update_member` | `organizations.rs` (manager gate; granting `owner` requires an owner caller; an existing owner cannot be demoted) |
| `organizations::remove_member` | `organizations.rs` (manager gate; removing an owner requires an owner caller; the last owner cannot be removed) |
| `subscriptions::perform_checkout` | `subscriptions.rs:541` |
| `subscriptions::subscribe` | `subscriptions.rs:720` |
| `subscriptions::change_subscription_tier` | `subscriptions.rs:1059` |
| `subscriptions::cancel_subscription` | `subscriptions.rs:1294` |

### Membership-only checks via `check_org_access`

No role discrimination: any member passes.

| Handler | Site |
|---------|------|
| `organizations::get_organization` | `organizations.rs:379` |
| `organizations::get_org_settings` | `organizations.rs:592` |
| `organizations::list_members` | `organizations.rs:745` |
| `fully_managed_capacity::join_waitlist` | `fully_managed_capacity.rs:630` |

### Scope-to-primary-org via `get_user_primary_org`

Resolves the caller's own org and filters the operation to it: an implicit
membership test, not a role test.

| Module | Handlers (line) |
|--------|-----------------|
| `billing.rs` | `get_billing_usage` 360, `get_billing_invoices` 678, `get_payment_methods` 1068, `delete_payment_method` 1208, `set_primary_payment_method` 1358, `get_paddle_client_token` 1462, `paddle_transaction_completed` 1911, `get_credit_balance` 2326, `purchase_credits` 2593 & 2911, `get_credit_ledger` 2993, `redeem_credit_code` 3092 |
| `cryptographic_bundles/handlers.rs` | `list_quorum_bundles` 61, `create_quorum_bundle` 149, `get_quorum_bundle` 209, `update_quorum_bundle` 286, `delete_quorum_bundle` 353, `list_secrets_bundles` 413, `create_secrets_bundle` 466, `get_secrets_bundle` 525, `update_secrets_bundle` 590, `delete_secrets_bundle` 654 |
| `org_quorum/handlers.rs` | `list_org_quorum_participants` 70, `create_org_user_quorum_bundle` 266 |
| `main.rs` | `list_cloud_credentials` 928, `create_cloud_credential` 995, `get_cloud_credential` 1058, `delete_cloud_credential` 1125, `set_default_cloud_credential` 1195, `create_managed_onprem_resource` 1423, `get_builder_config` 2152, `set_builder_config` 2236 |
| `resources.rs` | `create_resource` 132, `list_resources` 325 |
| `subscriptions.rs` | `get_subscription` 320 (plus the manager gates above) |
| `eif_download.rs` | `download_eif` 486 |

### Membership enforced in SQL (joins / EXISTS)

No helper call; the query itself restricts rows to the caller's organization.

| Handler | Site |
|---------|------|
| `main.rs::deploy_logic` | `main.rs:3897` `EXISTS (... organization_members WHERE user_id=$1 AND organization_id=$2)` |
| `app_deployments::destroy::begin_destroy` | `destroy.rs:684` join on caller's org |
| `app_deployments::handlers::query_rows_with` | `handlers.rs:237` join on membership |
| `app_deployments::history::history_page` | `history.rs:159` join on membership |
| `app_deployments::switch::switch_row_sql` | `switch.rs:281` join on membership |
| `resources::get_resource` | `resources.rs:454` join on membership |
| `resources::proxy_attestation` | `resources.rs:585` join on membership |
| `resources::rename_resource` | `resources.rs:716` join on membership |
| `resources::delete_resource` | `resources.rs:904` join on membership |
| `resources::app_destroyed` | `resources.rs:1031` join on membership |
| `gateway::db::get_user_for_app_by_ssh_key` | `gateway/src/db.rs:1278` SSH key holder must be a member of the app's org |
| `org_quorum::resolve_holders` | `org_quorum/mod.rs:484` each requested participant must be an active member |
| `organizations::list_organizations` | `organizations.rs:167` list scoped to memberships |
| `organizations::invite_member` | `organizations.rs:840` "already a member" check |
| `organizations::list_members` | `organizations.rs:759` member listing |
| `middleware::ensure_user_has_org` | `middleware.rs:264` |
| `organizations::user_has_organization` | `organizations.rs:106` |

### NOT ownership checks (reads of `organization_members` for other reasons)

Listed so the inventory is honest; these do not gate caller access.

| Site | Purpose |
|------|---------|
| `cryptographic_bundles/holders.rs:66,80` `Owners::load` | enumerate org members as candidate key holders |
| `org_quorum/mod.rs:110` `list_participants` | list members for the quorum UI |
| `gateway/src/db.rs:1965` `user_requires_pin` | read `organizations.settings->>'require_pin'` |
| `onboarding.rs:150` `get_user_status` | report `has_organization` to the dashboard gate |
| `metering/src/balance.rs:132`, `handlers/dunning.rs:271,336,391`, `handlers/webhooks.rs:658,763,894,982`, `handlers/billing.rs:150` | pick a user as billing/notification contact |
| `drift-detector/src/db.rs:327` | iterate organizations to scan |
| `caution-admin/src/db/relations.rs:*`, `db/aws.rs:244` | read-only explorer / test fixtures |
| `org_quorum/database.rs:25` | test helper |

### Coverage gaps

Only the role-specific gates above apply an actual role test. The
`check_org_access`, `get_user_primary_org`, and SQL-join sites permit any member,
regardless of role: any plain member can currently perform these operations.

## Target model

RBAC adds roles to non-owner members. `owner` stays god-mode and is not an RBAC
role; `member` stays the baseline membership (a member with no roles can do
nothing beyond the exempt routes once enforcement is on).

### Data model

Implemented in `migrations/063_rbac_tables.sql` (applied and verified live on
PostgreSQL 18.6, idempotent).

Route-based rules: a rule is `effect + method + path`, where `path` is the axum
route template (e.g. `/resources/{id}/deployments`), not a regex.

```sql
CREATE TABLE rbac_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name),
    UNIQUE (organization_id, id)  -- FK target for rbac_member_roles
);

CREATE TABLE rbac_role_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES rbac_roles(id) ON DELETE CASCADE,
    effect TEXT NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow','deny')),
    method TEXT NOT NULL CHECK (method IN
        ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','*')),
    path TEXT NOT NULL,
    objects JSONB,  -- per path-param allowed values, e.g. {"id": ["*"]};
                    -- required when `path` has parameters, omitted otherwise
    priority INTEGER NOT NULL DEFAULT 0 CHECK (priority >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (role_id, effect, method, path)
);

CREATE TABLE rbac_member_roles (
    organization_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id, role_id),
    FOREIGN KEY (organization_id, user_id)
        REFERENCES organization_members (organization_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, role_id)
        REFERENCES rbac_roles (organization_id, id) ON DELETE CASCADE
);
```

The FKs guarantee a role is only assigned to an actual member and only within
the organization that owns the role (roles are per-organization, no global
built-ins). All three tables carry `updated_at` with the standard trigger.

### Enforcement

Implemented in `src/api/src/rbac.rs` and layered on the `resource_routes` group
(after auth/legal/onboarding).

* A middleware after auth + onboarding on the organization-scoped route group.
* Read `Method` and `axum::extract::MatchedPath` (available by default in axum
  0.8) from request extensions. `MatchedPath` is the route template, so rules
  match structurally and path parameters never need parsing.
* Owners short-circuit to allow. Everyone else: collect every rule matching
  `method + path + objects` across the member's roles. No match denies.
  Otherwise the matching rule with the lowest `priority` (closest to 0)
  decides; if several equal-lowest rules match, a `deny` wins so conflicts
  fail closed. `method = '*'` matches any method.
* No exempt routes. Anything the evaluation above does not admit is denied. The
  UI seeds every new role with an allow for `/users/me` so members can load
  their own account. Public, onboarding, organization-bootstrap, and internal
  route groups sit outside this middleware by construction rather than by
  exemption.
* Object constraints are admission-only. A rule for a path with parameters must
  carry `objects` covering every parameter (rule creation fails if absent); a
  path without parameters (for example a list route) needs none. At request
  time the middleware reads the actual values with
  `axum::extract::RawPathParams` and admits only when each parameter matches
  its array (`["*"]` means any; values are arrays, a bare string never
  matches). No resource state is read and list responses are never filtered.
* Path matching starts as exact route-template equality; a trailing `/*`
  wildcard could be added later.

### Management API

Under `/organizations/{id}`, implemented in `src/api/src/rbac/routes.rs`. These
are ordinary RBAC-gated routes (owners bypass; a member needs a matching rule)
and every handler also requires membership in the org in the path, so a rule
scoped `["*"]` cannot cross tenants.

* `GET/POST /roles`
* `GET/PATCH/DELETE /roles/{role_id}`
* `GET/POST /roles/{role_id}/rules`
* `GET/PATCH/DELETE /roles/{role_id}/rules/{rule_id}`
* `GET/POST /members/{user_id}/roles`
* `DELETE /members/{user_id}/roles/{role_id}`

Rule validation (in the handler, before insert/update): `effect` is
`allow|deny`; `method` is a known method or `*`; `path` is an absolute route
template; when the path has parameters, `objects` is required and must cover
exactly those parameters with arrays of strings, and is omitted otherwise;
`priority >= 0`.

### Open decisions

* (none)

## Decision log

Record decisions here as they are made, newest first.

* **2026-11-03** — A member may hold any number of roles (join table).
* **2026-11-03** — Allow + deny with priorities: among matching rules the
  lowest priority (closest to 0) wins; equal-priority conflicts resolve to deny
  (fail closed); no match denies. Priority is non-negative, default 0.
* **2026-11-03** — Roles are per-organization only (no global built-ins).
  `rbac_roles.organization_id` is `NOT NULL` and a composite FK on
  `rbac_member_roles` prevents assigning a role across organizations.
* **2026-11-03** — Role/rule management routes are ordinary RBAC-gated routes,
  so a rule may grant them; no separate router group. Escalation is bounded:
  owner-only checks (`is_owner`) still guard granting ownership, demoting or
  removing an owner, and deleting the organization. Assignments record
  `granted_by` for attribution.
* **2026-11-03** — Every parameter in a rule's path requires an `objects`
  entry; non-object params such as an org id use `["*"]` uniformly.
* **2026-11-03** — Object scoping is admission-only. Rules for parameterized
  paths must declare `objects` (creation fails if absent); paths without
  parameters need none. Lists are not filtered and no resource state is
  consulted.
* **2026-11-03** — Route/rule drift: no special handling for now. Rules are
  plain strings and a typo simply fails closed; validation (against a route
  inventory) can be added later.
* **2026-11-03** — No baseline backfill. Owners bypass RBAC and existing
  memberships are expected to all be `owner`, so there is nothing to migrate;
  non-owner members created later must be given roles explicitly.
* **2026-11-03** — Deny by default with no exempt routes. A new role is seeded
  by the UI with an allow for `/users/me`; everything else needs an explicit
  rule.

## Open questions / blockers

* `invite_member` cannot assign a non-owner role: `InviteMemberRequest` has no
  role field (`validated_types.rs:142-152`). Invitations now default to
  `member`, but there is still no way to invite straight to owner.
* Granting and removing ownership are owner-only and irreversible
  server-side: `add_member`/`update_member` reject a non-owner caller granting
  `owner`; `update_member` rejects demoting an owner; `remove_member` rejects an
  admin removing an owner and refuses to remove the last owner. The dashboard's
  "cannot be undone" and owner-only rules now hold at the API.
* Removing `admin` folded its manager powers into owner-only for now; the RBAC
  user roles are meant to reintroduce finer-grained privileges.
* Existing `admin` rows were mapped to `member` by migration 061 (least
  privilege); confirm, or map them to `owner` instead.
* Last-owner invariant is enforced server-side for removal (`remove_member`)
  and demotion (`update_member`); the dashboard rule
  (`frontend/src/utils/organizations.js`) mirrors it.
* No route currently distinguishes `member` from any other user role (the
  others were removed).

## Progress log

Newest first.

* **2026-11-03** — Added the RBAC management API (`rbac/routes.rs`): roles CRUD,
  rules CRUD, and GET/POST/DELETE for member role assignments. Handlers verify
  org membership in the path; rule shape is validated before write. 4 route
  unit tests plus handler SQL checked live on PostgreSQL 18.6.
* **2026-11-03** — `objects` values must be arrays (`["*"]` or a value list);
  a bare string never matches (fails closed). Matcher test added.
* **2026-11-03** — Implemented RBAC enforcement: `src/api/src/rbac.rs` (matcher
  + middleware, 7 unit tests) layered on `resource_routes` after onboarding.
  Owner bypass; otherwise deny-by-default with lowest-priority-wins and
  equal-priority deny-wins. Verified the membership+rules query live on
  PostgreSQL 18.6 (owner, role-bearing member, role-less member).
* **2026-11-03** — Added `updated_at` (with the standard trigger) to
  `rbac_role_rules` and `rbac_member_roles`, matching `rbac_roles`. Migration 063
  includes idempotent `ALTER ... ADD COLUMN IF NOT EXISTS` so already-migrated
  databases pick it up on re-run; verified live (upgrade path and fresh apply,
  triggers fire).
* **2026-11-03** — Added `migrations/063_rbac_tables.sql`: `rbac_roles`,
  `rbac_role_rules`, `rbac_member_roles`. Verified live on PostgreSQL 18.6:
  applies and re-runs cleanly; unique/cross-org/non-member/effect/method/
  priority/objects/path constraints reject bad input; role deletion cascades to
  rules and assignments; `updated_at` trigger fires.
* **2026-11-03** — Removed the `viewer` role (it never granted anything
  different from `member`): `UserRole` and the enum are now `owner`/`member`,
  with `062_remove_viewer_role.sql` reassigning viewers to `member`. Verified
  live on PostgreSQL 18.6: fresh set idempotent (3 passes) and a legacy database
  with `admin`/`viewer` rows migrated correctly, with 061/062 re-running
  cleanly.
* **2026-11-03** — Verified migrations live against PostgreSQL 18.6. Fresh
  database applied the full set three times (idempotent); a simulated legacy
  database with `admin` rows migrated correctly (admins to `member`, enum
  swapped to owner/member/viewer, defaults reset) and 061 re-ran cleanly. The
  test exposed and fixed two 061 bugs: enum-literal coercion
  (`role = 'admin'` -> `role::text = 'admin'`) and `ALTER COLUMN TYPE` failing
  on the old default (now drops and re-adds the default).
* **2026-11-03** — Removed the `admin` role: `UserRole` and the `user_role`
  enum now hold `owner`, `member`; migrations `061_remove_admin_role.sql` and
  `062_remove_viewer_role.sql` reassign existing admins/viewers to `member`.
  Manager gates are owner-only until the RBAC roles land.
* **2026-11-03** — Aligned `remove_member` with the dashboard: only an owner
  may remove an owner, and the last owner cannot be removed.
* **2026-11-03** — Enforced owner-only granting of ownership
  (`add_member`, `update_member`) and blocked demotion of an existing owner in
  `update_member`, so the dashboard's non-reversible promotion is true at the
  API.
* **2026-11-03** — Invitations now default to `member` (not `owner`); added
  migration `060_invitation_default_member_role.sql`. Dashboard lets owners
  promote a user to owner, stated as permanent/non-reversible; promotion is
  gated in the UI by `canPromoteOrganizationMemberToOwner`.
* **2026-11-03** — Removed the owner/admin gate from EIF download
  (`eif_download.rs`): any member of the org may now download.
* **2026-11-03** — Consolidated the owner-permission scan and ownership-check
  index into this document.
* **2026-11-03** — Completed owner-permission scan; indexed all current
  organization ownership/access checks.
