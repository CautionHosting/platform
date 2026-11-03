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

`organization_members.role` is the enum
`user_role ('owner','admin','member','viewer')`
(`src/api/migrations/001_initial.sql:135-151`). `organization_invitations.role`
is the same enum with `DEFAULT 'owner'`
(`src/api/migrations/044_organization_invitations.sql:7`). A user belongs to
exactly one organization (`046_one_organization_per_user.sql`).

Rust mirror `types::UserRole` (`src/api/src/types.rs:7-35`) exposes the only two
predicates in the codebase:

```rust
fn can_manage_org(&self) -> bool { matches!(self, Owner | Admin) }
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
| `src/api/src/main.rs:269` `can_manage_org` | `UserRole::can_manage_org` | owner or admin |
| `src/api/src/main.rs:273` `is_owner` | `UserRole::is_owner` | owner only |
| `src/api/src/types.rs:28,32` `UserRole::{can_manage_org,is_owner}` | `matches!` on the enum | the two role predicates |
| `src/api/src/subscriptions.rs:40` `require_billing_manager` | `check_org_access` + `can_manage_org` | owner or admin |

### Owner grant sites

Where a user is given the `owner` role.

| # | Site | What happens |
|---|------|--------------|
| 1 | `src/api/src/organizations.rs:307-314` (`create_organization_for_user`) | Creator of a new organization is inserted as `UserRole::Owner`. |
| 2 | `organizations.rs:927-948` (`invite_member`) | Invitations now default to `UserRole::Member` (changed 2026-11-03); `InviteMemberRequest` has only `email` (`src/api/src/validated_types.rs:142-152`), so the inviter still cannot choose the role. |
| 3 | `src/api/src/organizations.rs:1255-1274` (`add_member`) | Inserts `payload.role`; `validate_role` accepts `"owner"` (`validation.rs:182-183`, `validated_types.rs:128-140`). A manager can add a member directly as owner. |
| 4 | `src/api/src/organizations.rs:1336-1355` (`update_member`) | `UPDATE ... SET role = $1::user_role`; `payload.role` may be `"owner"`. A manager can promote any member to owner. No guard prevents demoting the last owner. |
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

**owner only**

| Handler | Site |
|---------|------|
| `organizations::delete_organization` | `organizations.rs:530-538` (`is_owner`) |

**owner or admin** (`can_manage_org` / `require_billing_manager`)

| Handler | Site |
|---------|------|
| `organizations::update_organization` | `organizations.rs:447-455` |
| `organizations::update_org_settings` | `organizations.rs:670-678` |
| `organizations::invite_member` | `organizations.rs:824-832` |
| `organizations::list_active_invitations` | `organizations.rs:1015-1023` |
| `organizations::cancel_invitation` | `organizations.rs:1090-1098` |
| `organizations::add_member` | `organizations.rs:1236-1244` |
| `organizations::update_member` | `organizations.rs:1326-1334` |
| `organizations::remove_member` | `organizations.rs:1406-1414` |
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
regardless of role: a `viewer` can currently perform these operations.

## Target model

_To be defined. Placeholder for the owners-vs-users design._

Open sub-questions feeding this section:

* Is `owner` a distinct membership kind, or a role like any other with all
  operations attached?
* Do `admin`/`member`/`viewer` survive? What roles replace them?
* Where is authorization enforced: a router layer, per-handler guards, or a
  declarative operation catalogue?
* Is a role a fixed enum (compile-time) or data-driven (DB rows)?
* Can a user hold multiple roles, or exactly one?

## Decision log

Record decisions here as they are made, newest first.

* (none yet)

## Open questions / blockers

* `invite_member` cannot assign a non-owner role: `InviteMemberRequest` has no
  role field (`validated_types.rs:142-152`). Invitations now default to
  `member`, but there is still no way to invite straight to owner.
* Promotion to owner is enforced only in the dashboard UI
  (`frontend/src/utils/organizations.js` `canPromoteOrganizationMemberToOwner`,
  `Dashboard.vue`). The API's `update_member` still accepts `owner|admin` and any
  role, so an admin can promote (or change roles) through the API.
* `can_manage_org` treats `admin` identically to `owner`; the split must decide
  `admin`'s fate.
* Last-owner invariant is frontend-only (`frontend/src/utils/organizations.js`);
  the API allows an admin to remove an owner and allows removing the last owner.
* No route currently distinguishes `member` from `viewer`.

## Progress log

Newest first.

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
