# RBAC Bible

Living design + progress document for the role-based access control work on the
platform. It is the single place to track the target model, decisions, the
current-state inventory, and open questions. Update it as work lands.

Related: `docs/rbac-owner-audit.md` (initial owner-permission scan),
`docs/rbac-ownership-index.md` (index of every current ownership/access check).

## How we got here

Goal: split organization users into **owners** (god powers) and **users** that
carry roles determining which operations they may perform. This document starts
from the completed scan of where owner permissions currently live.

## Vocabulary

Terms as we intend them; tighten once the model is settled.

* **Organization** — tenancy boundary. A user belongs to exactly one
  organization today (`migrations/046_one_organization_per_user.sql`).
* **Owner** — an organization member with god powers over that organization.
* **User** — an organization member without god powers. Holds one or more
  **roles** that grant specific operations.
* **Role** — named bundle of operations a user-role holder may perform.
* **Operation** — a permission-checked action (HTTP route or a step within one).

## Current state (from the scan)

Schema axis today: `organization_members.role` is the enum
`user_role ('owner','admin','member','viewer')`, plus
`organization_invitations.role` with `DEFAULT 'owner'`.

Only two predicates exist (`src/api/src/types.rs:28-34`):
`can_manage_org` = owner|admin, `is_owner` = owner. Membership is resolved by
`check_org_access` (`src/api/src/main.rs:245`). There is no per-route role
layer; most handlers do no role check at all.

### Owner grant sites

| # | Site | Note |
|---|------|------|
| 1 | `organizations.rs:307-314` | org creator becomes owner |
| 2 | `organizations.rs:927-948` | every invite hardcoded to owner |
| 3 | `organizations.rs:1255-1274` | `add_member` accepts role `owner` |
| 4 | `organizations.rs:1336-1355` | `update_member` can promote to owner |
| 5 | `gateway/src/db.rs:216-247` | signup default org owner |
| 6 | `gateway/src/db.rs:520-533` | invitation signup uses `invitation.role` |
| 7 | `migrations/044_organization_invitations.sql:7` | default `'owner'` |
| 8 | `migrations/001_initial.sql:135` | enum definition |

### Owner-only gates (god powers)

| Site | Operation |
|------|-----------|
| `organizations.rs:530-538` | `delete_organization` |
| `eif_download.rs:490-498` | `download_eif` (owner-or-admin in effect) |

### Manager (`owner`|`admin`) gates

Org settings, invitations, and member management in `organizations.rs`; plus
`checkout_subscription`, `subscribe`, `change_subscription_tier`,
`cancel_subscription` in `subscriptions.rs` (via `require_billing_manager`).

### Routes with no role check

Everything else: `resources.rs`, `deployment.rs`, `app_deployments/*`, `ec2.rs`,
`managed_dns.rs`, `component_artifacts.rs`, `cloud_credentials.rs`,
`cryptographic_bundles/*`, `org_quorum/*`, and all of `billing.rs`. These
authorize on organization membership alone, so a `viewer` can currently act.

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
  role field (`validated_types.rs:142-152`). Needs a decision before
  non-owner invites are possible.
* `can_manage_org` treats `admin` identically to `owner`; the split must decide
  `admin`'s fate.
* Last-owner invariant is frontend-only (`frontend/src/utils/organizations.js`);
  the API allows an admin to remove an owner and allows removing the last owner.
* No route currently distinguishes `member` from `viewer`.

## Progress log

Newest first.

* **2026-11-03** — Completed owner-permission scan; recorded in
  `docs/rbac-owner-audit.md`. Started this document.
