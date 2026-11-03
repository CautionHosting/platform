# Organization ownership checks: index

Every place the platform currently verifies that a caller has access to an
organization (or to something scoped to one). "Ownership check" here means the
membership/access test, not only the `owner` role; role-specific gates are
called out separately.

Companion docs: `docs/rbac-bible.md`, `docs/rbac-owner-audit.md`.

Line numbers are as of 2026-11-03.

## 0. The checks themselves

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

## 1. Role-specific gates

### owner only

| Handler | Site |
|---------|------|
| `organizations::delete_organization` | `organizations.rs:530-538` (`is_owner`) |
| `eif_download::download_eif` | `eif_download.rs:490-498` (`can_manage_org \|\| is_owner`, i.e. owner-or-admin) |

### owner or admin (`can_manage_org` / `require_billing_manager`)

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

## 2. Membership-only checks via `check_org_access`

No role discrimination: any member passes.

| Handler | Site |
|---------|------|
| `organizations::get_organization` | `organizations.rs:379` |
| `organizations::get_org_settings` | `organizations.rs:592` |
| `organizations::list_members` | `organizations.rs:745` |
| `fully_managed_capacity::join_waitlist` | `fully_managed_capacity.rs:630` |

## 3. Scope-to-primary-org via `get_user_primary_org`

Resolves the caller's own org and then filters the operation to it. This is an
implicit membership test (the org is derived from the caller), not a role test.

| Module | Handlers (line) |
|--------|-----------------|
| `billing.rs` | `get_billing_usage` 360, `get_billing_invoices` 678, `get_payment_methods` 1068, `delete_payment_method` 1208, `set_primary_payment_method` 1358, `get_paddle_client_token` 1462, `paddle_transaction_completed` 1911, `get_credit_balance` 2326, `purchase_credits` 2593 & 2911, `get_credit_ledger` 2993, `redeem_credit_code` 3092 |
| `cryptographic_bundles/handlers.rs` | `list_quorum_bundles` 61, `create_quorum_bundle` 149, `get_quorum_bundle` 209, `update_quorum_bundle` 286, `delete_quorum_bundle` 353, `list_secrets_bundles` 413, `create_secrets_bundle` 466, `get_secrets_bundle` 525, `update_secrets_bundle` 590, `delete_secrets_bundle` 654 |
| `org_quorum/handlers.rs` | `list_org_quorum_participants` 70, `create_org_user_quorum_bundle` 266 |
| `main.rs` | `list_cloud_credentials` 928, `create_cloud_credential` 995, `get_cloud_credential` 1058, `delete_cloud_credential` 1125, `set_default_cloud_credential` 1195, `create_managed_onprem_resource` 1423, `get_builder_config` 2152, `set_builder_config` 2236 |
| `resources.rs` | `create_resource` 132, `list_resources` 325 |
| `subscriptions.rs` | `get_subscription` 320 (plus the manager gates in section 1) |
| `eif_download.rs` | `download_eif` 486 (plus the role gate in section 1) |

## 4. Membership enforced in SQL (joins / EXISTS)

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

## 5. NOT ownership checks (reads of `organization_members` for other reasons)

Listed so the index is honest; these do not gate caller access.

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

## Coverage gaps

Routes that resolve the caller's org (section 3) or join membership (section 4)
still permit any member, regardless of role. Only sections 1 and 2 apply an
actual role test. See `docs/rbac-bible.md` for the planned authorization layer.
