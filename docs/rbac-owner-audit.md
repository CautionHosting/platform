# RBAC audit: where owner permissions are granted

Scan of the platform ahead of splitting organization users into `owner`
(god powers) and `user` (roles that grant specific operations).

## Current model

There is a single role axis already in the schema:

* `organization_members.role` is the enum `user_role`:
  `('owner', 'admin', 'member', 'viewer')`
  (`src/api/migrations/001_initial.sql:135-151`).
* `organization_invitations.role` is the same enum, `DEFAULT 'owner'`
  (`src/api/migrations/044_organization_invitations.sql:7`).
* A user belongs to exactly one organization
  (`src/api/migrations/046_one_organization_per_user.sql`).

Rust mirror: `types::UserRole` (`src/api/src/types.rs:7-35`) with the only two
predicates in the whole codebase:

```rust
fn can_manage_org(&self) -> bool { matches!(self, Owner | Admin) }
fn is_owner(&self)       -> bool { matches!(self, Owner) }
```

Org membership is looked up by `check_org_access`
(`src/api/src/main.rs:245-267`), which returns the caller's `UserRole` for an
`(org_id, user_id)` pair or `Forbidden`. Authenticated routes are grouped in
`main.rs` by middleware only (auth / legal / onboarding); there is **no
per-route role layer**. Role checks are ad hoc inside individual handlers, and
most handlers do no role check at all.

## 1. Places where a user is given the `owner` role

These are the true grant sites. Each one either hardcodes `owner` or accepts a
role string that may be `owner`.

| # | Site | What happens |
|---|------|--------------|
| 1 | `src/api/src/organizations.rs:307-314` (`create_organization_for_user`) | Creator of a new organization is inserted as `UserRole::Owner`. |
| 2 | `src/api/src/organizations.rs:927-948` (`invite_member`) | Every invitation is written with a hardcoded `UserRole::Owner`. `InviteMemberRequest` has only `email` (`src/api/src/validated_types.rs:142-152`), so the inviter cannot choose the role and cannot avoid granting owner. |
| 3 | `src/api/src/organizations.rs:1255-1274` (`add_member`) | Inserts `payload.role`; `validate_role` accepts `"owner"` (`src/api/src/validation.rs:182-183`, `validated_types.rs:128-140`). A manager can add a member directly as owner. |
| 4 | `src/api/src/organizations.rs:1336-1355` (`update_member`) | `UPDATE ... SET role = $1::user_role`; `payload.role` may be `"owner"`. A manager can promote any member to owner. No guard prevents demoting/altering the last owner. |
| 5 | `src/gateway/src/db.rs:216-247` (`create_default_organization`) | Signup path: creates the user's default org and inserts them as `'owner'`. |
| 6 | `src/gateway/src/db.rs:520-533` (`accept_invitation_and_create_user`) | Invitation signup: inserts `invitation.role`, which is `owner` because of (2) and the migration default. |
| 7 | `src/api/migrations/044_organization_invitations.sql:7` | Schema default `role user_role NOT NULL DEFAULT 'owner'`. |
| 8 | `src/api/migrations/001_initial.sql:135` | Defines the `owner` variant of `user_role`. |

Test/fixture grants (not production paths, but they assume the role):
`src/api/src/middleware/db_tests.rs:53,101`,
`src/api/src/provider_account_db_tests.rs:46`,
`src/api/src/organizations/db_tests.rs:84`,
`src/gateway/src/db/organization_tests.rs:150`,
`src/caution-admin/src/db/aws.rs:244-245`.

Not owner grants: the many `role_arn` / `Role:` matches are AWS IAM roles and
deployment `live`/`candidate` roles, unrelated to org RBAC.

## 2. Owner-only ("god power") gates

Only two handlers distinguish `owner` from `admin`:

| Site | Operation | Gate |
|------|-----------|------|
| `src/api/src/organizations.rs:530-538` (`delete_organization`) | Soft-deletes the organization | `is_owner` |
| `src/api/src/eif_download.rs:490-498` (`download_eif`) | Downloads a built EIF | `can_manage_org(&role) \|\| is_owner(&role)` (the `is_owner` term is redundant; the effect is owner-or-admin) |

The frontend adds one more owner-only rule that the API does **not** enforce:
only an owner may remove another owner, and the caller cannot remove themself
(`frontend/src/utils/organizations.js:90-110`,
`frontend/src/views/Dashboard.vue:2776-2789`). The API's `remove_member`
(`organizations.rs:1399-1432`) has no such check, so an admin can remove an
owner server-side.

## 3. Manager (`owner` | `admin`) gates

Helpers: `can_manage_org` and `require_billing_manager`.

| Site | Operation |
|------|-----------|
| `organizations.rs:447-455` | `update_organization` (rename) |
| `organizations.rs:670-678` | `update_org_settings` |
| `organizations.rs:824-832` | `invite_member` |
| `organizations.rs:1015-1023` | `list_active_invitations` |
| `organizations.rs:1090-1098` | `cancel_invitation` |
| `organizations.rs:1236-1244` | `add_member` |
| `organizations.rs:1326-1334` | `update_member` (role change, incl. to owner) |
| `organizations.rs:1406-1414` | `remove_member` |
| `subscriptions.rs:545` | `checkout_subscription` |
| `subscriptions.rs:900` | `subscribe` |
| `subscriptions.rs:1063` | `change_subscription_tier` |
| `subscriptions.rs:1298` | `cancel_subscription` |

Read-only membership checks (no role discrimination, any member passes)
`check_org_access`:
`organizations.rs:379` (`get_organization`), `592` (`get_org_settings`),
`745` (`list_members`);
`fully_managed_capacity.rs:630` (`join_waitlist`);
`main.rs:245` definition.

## 4. Routes with no role check

Most organization-scoped routes never call `check_org_access`. They authorize
only by joining `organization_members` on the caller's id (or by resolving the
caller's primary org), so **any member, including `viewer`, can perform the
operation**. Examples by module:

* `resources.rs` — create/rename/delete resources, builder-config, attestation
  (authz via `INNER JOIN organization_members`).
* `deployment.rs`, `app_deployments/*` (handlers, destroy, switch), `ec2.rs`,
  `managed_dns.rs`, `component_artifacts.rs`, `eif_download.rs` (beyond the
  download gate).
* `cloud_credentials.rs` — list/create/get/delete credentials, set default.
* `cryptographic_bundles/handlers.rs`, `org_quorum/handlers.rs`
  (`org_quorum/mod.rs:484` only checks membership for quorum participants).
* `billing.rs` — all of it: usage, invoices, payment methods (delete,
  set-primary), credit purchase/redeem/ledger, Paddle client token. No
  `require_billing_manager` calls anywhere in `billing.rs`.
* `users.rs` — `/users/me` self-service (expected to stay role-free).

## 5. Implications for the owners-vs-users split

* The `owner` variant is granted in exactly the sites in section 1. Introducing
  a separate `owner` membership (distinct from role-bearing `user`) touches
  those inserts plus the `organization_invitations` schema default.
* `invite_member` currently forces every invitee to owner (site 2) and
  `InviteMemberRequest` has no role field. This must change if roles are to be
  assigned to non-owners.
* `can_manage_org` treats `admin` like `owner`. Decide whether `admin` survives
  as a "user" role or is folded into owner.
* Most routes have no authorization beyond org membership (section 4). A
  role-driven authorization layer will need to be added at the router (grouped
  in `src/api/src/main.rs:5890-6222`) or per handler; today only the handlers in
  sections 2 and 3 enforce anything.
* The last-owner invariant is frontend-only today; the API will need to enforce
  "cannot remove or demote the last owner" once owners are privileged.
