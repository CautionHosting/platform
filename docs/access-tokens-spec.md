# Organization Access Tokens Specification

Status: **normative**. This specification is the single source of truth for the
platform's organization access tokens. It supersedes the former "Organization
Access Tokens Bible".

It describes the token principal model, token format and storage, validation at
the gateway, the trust-boundary protocol, the authorization model, the token
lifecycle, the management API, attribution, and the consumer (CLI) contract.

## 1. Scope

This specification covers:

* the definition and semantics of an organization access token (OAT);
* the token principal as a non-user identity;
* token generation, storage, validation, and revocation;
* the gateway -> API trust-boundary protocol for token principals;
* how tokens are authorized through RBAC;
* the owner-only management API and the token identity endpoint;
* attribution and audit requirements;
* the CLI access-token contract.

It does not cover interactive authentication (passkey, session, SSH-signed
requests), which is defined elsewhere. RBAC role and rule semantics are defined
in the RBAC specification; this document only states how tokens consume them.

## 2. Conformance and terminology

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY**, and
**OPTIONAL** are to be interpreted as described in RFC 2119.

* **Organization access token (OAT)** - a bearer credential that authenticates a
  non-interactive caller to exactly one organization.
* **Token principal** - the identity an OAT authenticates as: an organization,
  not a person. It carries `(token_id, organization_id)` and no user id.
* **Personal access token (PAT)** - a user-bound token that would inherit a
  user's identity and roles. **Explicitly rejected** (section 4.1).
* **Mint / revoke** - create / invalidate a token. Minting returns the plaintext
  once; only a hash is stored.
* **Trust boundary** - the gateway -> API hop. The API trusts only requests
  bearing the internal service secret plus gateway-set identity headers.

## 3. Current authentication context

The gateway is the only authentication front door. It accepts `session`,
`ssh_signed`, and `passkey`, each resolving to a **user id**. The gateway proxies
to the API with a hardcoded allowlist of identity headers built from middleware
extensions, never from caller input (`trusted_identity_headers`,
`src/gateway/src/handlers/proxy.rs`), together with
`X-Internal-Service-Secret`.

The API's `auth_middleware` accepts the internal secret and resolves the caller
into an `AuthContext`. OATs add a fourth method and a non-user principal to this
boundary.

## 4. Principal model

### 4.1 Org-owned, not user-bound

TOKEN-D1. A token MUST authenticate as an **org-owned principal**, not as a
user. A token MUST NOT resolve to an existing user id, and the API MUST NOT
fabricate a synthetic user for it.

Rejected alternatives: a user-bound PAT (the token would live and die with a
person and inherit their ownership) and an org-owned token with implicit owner
powers (too large a blast radius, and it would bypass RBAC).

TOKEN-D2. A token principal is bound to exactly one organization. The creator is
attribution only, not authority.

### 4.2 Tagged principal

TOKEN-P1. `AuthContext` MUST be a tagged value with two variants: a user
principal `{ user_id, auth_method, signed_request_id }` and a token principal
`{ token_id, organization_id }`.

TOKEN-P2. A token principal MUST carry no user id. Helpers that require a user
id MUST treat a token principal according to their natural failure mode.

TOKEN-P3. For a token principal, `auth_method` MUST be `token`.

TOKEN-P4. A token MUST be a **member-equivalent** of its own organization and
MUST never be an owner:

* `check_org_access` MUST return `member`-equivalent access for a token exactly
  when the requested organization equals the token's organization, and
  `Forbidden` otherwise;
* `get_user_primary_org` MUST return the token's organization;
* the org-in-path membership guards MUST succeed for a token only for its own
  organization.

## 5. Token format and storage

TOKEN-F1. A token MUST be opaque. It MUST NOT be a JWT and MUST NOT carry signed
claims.

TOKEN-F2. The plaintext token MUST be `caut_oat_` followed by the base64url
(no padding) encoding of 32 random bytes (256 bits).

TOKEN-F3. The API MUST store only `sha256(plaintext)` as lowercase hex, in
`organization_access_tokens.token_hash`, and MUST enforce uniqueness on that
column.

TOKEN-F4. The plaintext MUST be returned exactly once, at mint time, and MUST
NOT be stored or logged.

TOKEN-F5. `sha256` is sufficient because the token is a 256-bit random value.
No password KDF is required. A non-secret token-id prefix for UI/admin lookup
MAY be added later.

## 6. Validation

TOKEN-V1. The **gateway** MUST validate tokens. Token validation in the API is
not permitted, so the API is never exposed to bearer material and there is one
auth front door.

TOKEN-V2. The gateway MUST authenticate a token presented as
`Authorization: Bearer <token>`. It MUST reject tokens presented as cookies.

TOKEN-V3. On a bearer request, the gateway MUST look up the stored token by
`sha256(bearer)` and MUST reject the request when the hash is unknown, the token
is revoked (`revoked_at IS NOT NULL`), or the token is expired
(`expires_at` in the past).

TOKEN-V4. The gateway MUST update `last_used_at` best-effort on successful
validation, mirroring session handling. A failure to update `last_used_at` MUST
NOT fail the request.

TOKEN-V5. The gateway MUST strip any caller-supplied identity headers and MUST
set token identity headers only after validation.

TOKEN-V6. Token auth failures SHOULD be rate-limited separately from session
failures.

## 7. Trust-boundary protocol

TOKEN-B1. The gateway MUST propagate an **explicit token principal** to the API.
It MUST NOT synthesize a service user.

TOKEN-B2. For a token-authenticated request, the gateway MUST forward, with the
internal service secret:

* `X-Caution-Token-ID` - the token id;
* `X-Caution-Organization-ID` - the token's organization id;
* `X-Caution-Auth-Method: token`.

TOKEN-B3. For a token-authenticated request, the gateway MUST NOT send
`X-Authenticated-User-ID`. It MUST remove any stale user id header.

TOKEN-B4. The API MUST accept `X-Caution-Token-ID` together with
`X-Caution-Organization-ID` (with a valid internal secret) and construct a token
principal. When neither a token id nor a user id is present, the API MUST reject
the request with `MissingUserId`.

TOKEN-B5. The API's recognized auth methods MUST include `token` alongside
`passkey`, `session`, and `ssh_signed`.

## 8. Authorization

TOKEN-A1. Token permissions MUST be expressed as RBAC roles. A token MUST carry
zero or more `rbac_roles` of its own organization, and the RBAC matcher MUST
decide its requests exactly as it decides a member's requests.

TOKEN-A2. Rejected alternatives: token-inline rules (a second permission
surface) and coarse fixed scopes (a third, drift-prone model).

TOKEN-A3. The set of roles attached to a token MUST be **fixed at mint**. There
MUST be no endpoint to edit a token's roles; changing the set means minting a
new token and revoking the old one.

TOKEN-A4. Immutability applies **only to the token-to-role association**. The
roles themselves MUST stay live and mutable: editing a held role's rules or
deleting the role MUST change the token's effective permissions, exactly as it
changes a user's.

TOKEN-A5. A token's roles MUST NOT be required to be a subset of its creator's
effective roles. Whoever may mint may attach any role in the organization.
Consequently, minting is itself a role-granting operation and the mint gate
(section 10) is the sole escalation control.

TOKEN-A6. A token MUST receive **no owner bypass**. A token is only as powerful
as its assigned rules. An `allow * on *` rule is the only way to make a token
owner-equivalent, and that MUST be a deliberate, visible choice in the RBAC
editor.

TOKEN-A7. **When an owner presents a token, the request MUST authenticate as the
token, not the owner session.** The token principal MUST win over any session or
signed request also present, so an owner can test a token's real authority. The
account-level owner bypass MUST NOT apply.

TOKEN-A8. A token MUST be bound to one organization. Any organization the token
resolves or is checked against MUST equal the token's organization; a mismatch
MUST be denied (section 4.1, TOKEN-P4). This is the only scoping rule, because a
token must not cross tenants.

TOKEN-A9. There MUST be no per-route allowlist or exemption list for tokens.
Because a token principal has no user id, any route or helper that requires a
user id MUST fail on its own: `/users/me`, passkey/credential management,
`/auth/*`, legal acceptance, onboarding, and every membership check keyed on
`user_id`.

TOKEN-A10. A route MUST work for a token only if it does not need a user id (or
has a token variant). Where a CLI flow genuinely needs a person-scoped route, an
access-token variant of that route MUST be added rather than special-casing the
original. The token identity endpoint (section 11.1) is the token variant of
`/users/me`.

TOKEN-A11. Person-scoped handlers MUST reject token principals with HTTP `403`
(for example via a `UserPrincipal` extractor), so no per-route allowlist is
needed.

### 8.1 Token-authorized passkey routes

TOKEN-A12. Tokens MUST be able to drive `apps switch` and the quorum-bundle
routes. For these routes a valid token principal MUST substitute for the FIDO2
signed request.

TOKEN-A13. The gateway MUST NOT force a FIDO2 assertion when the request is
authenticated by a token; the passkey requirement MUST be waived for a token
principal.

TOKEN-A14. The gateway MUST be the sole signature gate for these routes. The API
MUST NOT re-check the passkey signature; it MUST accept a token principal and
record whatever `signed_request_id` was forwarded (present for a passkey flow,
absent for a token).

TOKEN-A15. Authorization for these routes is unchanged: a token still needs a
matching RBAC rule and the org-bound rule, and owner bypass never applies
(TOKEN-A6).

TOKEN-A16. Passkey-capable behavior MUST be preserved: a human session with a
passkey assertion MUST still authorize these routes.

## 9. Lifecycle

TOKEN-L1. **Expiry.** A token's expiry is optional but strongly recommended. It
is a toggle at mint. When on, the value MUST default to 90 days. When an
operator turns expiry off, the UI SHOULD show an explicit warning. There is no
tenant-configurable maximum-lifetime cap.

TOKEN-L2. **Rotation.** Rotation MUST be *recreate, no overlap*: mint a
replacement and revoke the old token. There is no overlapping-validity window;
because revocation is immediate, callers must swap in the new value.

TOKEN-L3. **Limits.** There MUST be no per-organization token-count cap. Each
token MUST carry a name and MAY carry a description.

TOKEN-L4. **Last used.** The system MUST track `last_used_at` (best-effort, like
sessions) so operators can find stale tokens.

TOKEN-L5. **Revocation.** Revocation MUST set `revoked_at` and MUST NOT delete
the token row. The row, its role assignment, and its attribution MUST survive;
the gateway MUST reject the token on the next request. There is no soft-delete
recycle or purge.

## 10. Minting

TOKEN-M1. Only an **owner** of the organization MAY mint a token, enforced by a
hard `is_owner` check and not merely by an RBAC rule. No RBAC rule MAY delegate
token minting.

TOKEN-M2. Rationale: minting attaches arbitrary roles (TOKEN-A5), so a
delegated member permitted to mint could create a principal holding any role.
This mirrors the other hard owner-only powers (granting ownership, removing an
owner, deleting the organization).

TOKEN-M3. Mint validation MUST reject:

* an empty name after trimming, or a name longer than 100 characters;
* a description longer than 500 characters after trimming;
* an expiry outside `1..=3650` days when expiry is requested;
* any requested role id that is not a role of the same organization.

TOKEN-M4. Duplicate requested role ids MUST be de-duplicated before attachment.

TOKEN-M5. Minting MUST be atomic: the token row and all of its role rows MUST be
written in a single transaction, and the plaintext MUST be generated by a
cryptographically secure random source.

TOKEN-M6. The mint response MUST include the token id, name, `expires_at`, the
attached `role_ids`, and the plaintext token. It MUST NOT include the hash.

## 11. Management API

The management API is implemented in `src/api/src/access_tokens/handlers.rs` and
mounted under `/organizations/{id}`. Every handler MUST verify the caller is an
owner of the organization in the path.

TOKEN-API-1. The following routes MUST be provided:

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/organizations/{id}/access-tokens` | list tokens (metadata and roles; never the secret) |
| `POST` | `/organizations/{id}/access-tokens` | mint a token |
| `GET` | `/organizations/{id}/access-tokens/{token_id}` | read one token |
| `DELETE` | `/organizations/{id}/access-tokens/{token_id}` | revoke a token (`204`, or `404` when unknown/already revoked) |

TOKEN-API-2. The list and get responses MUST contain token metadata
(`id`, `organization_id`, `name`, `description`, `created_by`, `expires_at`,
`last_used_at`, `revoked_at`, `created_at`) and the attached roles
(`id`, `name`). They MUST NOT contain the secret or its hash.

TOKEN-API-3. A create request MUST accept `name`, optional `description`, optional
`expires_in_days`, and optional `role_ids`.

TOKEN-API-4. Invalid mint input MUST produce `400`; access failures MUST produce
`403`; unknown or already-revoked tokens MUST produce `404`.

TOKEN-API-5. These routes are RBAC-gated like other organization routes (owners
bypass; a member would need a matching rule), but the handler's owner check is
the effective gate, so no rule can delegate minting (TOKEN-M1).

TOKEN-API-6. `GET /access-tokens/me` (section 11.1) MUST sit outside the
RBAC-gated group so a token can always read its own identity.

### 11.1 Token identity endpoint

TOKEN-I1. `GET /access-tokens/me` MUST report the token's `token_id`,
`organization_id`, `name`, `expires_at`, and (immutable) roles.

TOKEN-I2. It MUST return `401` when called by a user principal (not a token),
and `401` when the presenting token no longer exists.

### 11.2 Consumers

TOKEN-C1. The CLI MUST accept a token from an environment variable
(`CAUTION_ACCESS_TOKEN`) and present it as `Authorization: Bearer`.

TOKEN-C2. When a token is set, the CLI MUST skip interactive login, MUST drop
any empty session header, and MUST resolve its organization from
`GET /access-tokens/me`.

TOKEN-C3. The CLI's token-capable commands MUST be exactly the organization
routes the API accepts tokens on. Existing session and SSH-signed paths MUST
remain unchanged.

## 12. Attribution and audit

TOKEN-X1. A token MUST record `created_by` (user id) with `ON DELETE SET NULL`.

TOKEN-X2. A token MUST survive its creator's removal from the organization. It
MUST be deleted when its organization is deleted (cascade). Operators SHOULD be
able to see "created by <user no longer a member>".

TOKEN-X3. Requests authenticated by a token MUST be attributable as *token X of
org Y*, not as the creator. The audit actor MUST be a principal (user or token);
token actions MUST NOT be attributed to `created_by`.

TOKEN-X4. The bearer value and its hash MUST never be logged.

TOKEN-X5. Where an actor column is a user-id foreign key and the actor is a
token, the value MUST be NULL until the principals table (section 13) lands. The
deployment-events `auth_method` enum MUST accept `token`.

## 13. Actor principals (proposed, not yet normative)

This section is a **proposal** and is not yet part of the normative model.

To give both humans and tokens a first-class "who did this", a `principals`
table is proposed:

```sql
CREATE TABLE principals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind TEXT NOT NULL CHECK (kind IN ('user','token')),
    user_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    token_id UUID REFERENCES organization_access_tokens(id) ON DELETE SET NULL,
    label TEXT NOT NULL,               -- denormalized actor label captured at creation
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((user_id IS NOT NULL) <> (token_id IS NOT NULL))
);
```

TOKEN-PR-1. Scope MUST be actor/attribution columns only
(`compute_resources.created_by`, `cloud_credentials.created_by`,
`quorum_bundles`/`secrets_bundles.created_by`, `app_deployments.pushed_by`,
`deployment_events` actor, `rbac_member_roles.granted_by`,
`credit_codes.redeemed_by`, `organization_access_tokens.created_by`,
`signed_request_audit`, `eif_builds`, `fully_managed_capacity`). Identity and
ownership foreign keys MUST NOT be converted.

TOKEN-PR-2. The recommended migration makes `principals.id` equal to `users.id`
for user principals and the token id for token principals, inserts a guard row
per user, and changes only the FK targets (no data rewrite).

TOKEN-PR-3. The recommended tombstone behavior keeps the principal row and its
denormalized `label` after token deletion, with `token_id` set NULL on delete
(or stored as a plain UUID with no FK).

## 14. Data model

Defined in `migrations/064_organization_access_tokens.sql`.

TOKEN-DM1. `organization_access_tokens` MUST store `id`, `organization_id`
(FK to organizations, cascade), `token_hash` (unique), `name`, optional
`description`, optional `created_by`, optional `expires_at`, optional
`last_used_at`, optional `revoked_at`, `created_at`, and `updated_at`
(standard trigger). `expires_at` NULL means no expiry.

TOKEN-DM2. `organization_access_tokens` MUST be uniquely addressable by
`(organization_id, id)`.

TOKEN-DM3. `organization_access_token_roles` MUST be keyed by
`(organization_id, token_id, role_id)`, with composite foreign keys to
`organization_access_tokens (organization_id, id)` and
`rbac_roles (organization_id, id)`, both `ON DELETE CASCADE`, so a token and its
roles stay in the same organization.

TOKEN-DM4. `organization_access_token_roles` MUST have no `UPDATE` path. Rows
are only inserted by the mint transaction and removed by cascade.

## 15. Non-goals

TOKEN-N1. No user-bound tokens (PATs).

TOKEN-N2. No implicit owner powers and no owner bypass for tokens.

TOKEN-N3. No token-inline rules and no coarse fixed-scope model.

TOKEN-N4. No per-route token allowlist; person-scoped routes are out of reach by
construction.

## 16. Conformance criteria

An implementation conforms when:

1. tokens are opaque `caut_oat_` values hashed at rest (section 5) and validated
   at the gateway (section 6);
2. the gateway propagates an explicit token principal with `X-Caution-Token-ID`
   and `X-Caution-Organization-ID` and no user id (section 7);
3. the API constructs a token principal that is a non-owner member-equivalent of
   its own organization (section 4);
4. authorization reuses RBAC roles fixed at mint, with no owner bypass and no
   subset requirement (section 8);
5. lifecycle rules in section 9 hold;
6. minting is owner-only with the validation in section 10;
7. the management and identity endpoints in section 11 behave as specified;
8. attribution follows section 12.

## Appendix A. Requirement-to-source map (non-normative)

| Requirement | Source |
|-------------|--------|
| Token generation/hash/mint | `src/api/src/access_tokens/handlers.rs` |
| Management + identity handlers | `src/api/src/access_tokens/handlers.rs` |
| Bearer extraction + validation | `src/gateway/src/auth_middleware.rs` (`access_token_auth_middleware`, `bearer_token`) |
| Token lookup | `src/gateway/src/db.rs` (`validate_access_token`, `hash_access_token`) |
| FIDO2 waiver | `src/gateway/src/auth_middleware.rs` (`fido2_sign_middleware`) |
| Trust-boundary headers | `src/gateway/src/handlers/proxy.rs` (`trusted_identity_headers`) |
| API principal | `src/api/src/main.rs` (`AuthContext`, `check_org_access`, `get_user_primary_org`, `UserPrincipal`) |
| API auth parse | `src/api/src/middleware.rs` (`auth_middleware`, `parse_auth_method`) |
| RBAC over tokens | `src/api/src/rbac/mod.rs` (`rbac_middleware`) |
| Schema | `src/api/migrations/064_organization_access_tokens.sql`, `065_deployment_events_token_auth.sql` |
| CLI token path | `src/cli/src/lib.rs` (`CAUTION_ACCESS_TOKEN`) |
| Frontend | `frontend/src/utils/accessTokens.js` |

## Appendix B. Design decisions (non-normative)

Numbered decisions retained as stable anchors. Code comments reference these by
identifier.

* **D1** - Token principal is org-owned (not user-bound, not an implicit owner).
* **D2 / D2a / D2b** - Authorization reuses RBAC roles; the token-to-role
  association is immutable, the roles stay live; no creator-subset requirement.
* **D3** - The gateway validates tokens.
* **D4** - Tokens are opaque and hashed at rest (`sha256`, `caut_oat_` prefix).
* **D5** - The gateway propagates an explicit `Principal::Token`; no synthetic
  service users.
* **D6** - No route allowlist; a token has no user id, so person-scoped routes
  fail naturally; add token route variants where needed.
* **D7** - Expiry optional (default 90 days), recreate-no-overlap rotation, no
  per-org count cap, `last_used_at` tracking, revoke (not delete).
* **D8** - Owner-only minting via a hard `is_owner` gate.
* **D9** - Bearer-only transport; token wins over session; no CSRF for bearer;
  separate rate limiting.
* **D10** - `created_by` plus principal-aware audit attribution; never log the
  secret.
* **D11** - Token cascades with its organization; survives its creator's
  removal; `created_by ON DELETE SET NULL`.
* **D12** - No owner bypass for tokens; an owner presenting a token
  authenticates as the token.
* **D13** - Tokens authorize the passkey-required routes (`apps switch`,
  quorum bundles); the gateway is the sole signature gate.
* **D14** - Principals table for actor attribution (proposed; section 13).

## Appendix C. Implementation status (non-normative)

Landed: migration `064_organization_access_tokens.sql` (tokens plus immutable
token-role join) and `065_deployment_events_token_auth.sql`; gateway bearer
validation and token identity headers; the owner-only management API and
`GET /access-tokens/me`; the API principal refactor (`AuthContext` user/token);
the CLI token path; and the frontend token management tab.

Token-enabled routes so far: `GET /access-tokens/me`, the organization read
routes, the resource and deployment routes (including deploy, deployment
destroy, EIF download, the attestation proxy, and builder config), `/credentials`,
the quorum/secrets bundle routes, `/quorum-bundles/participants`,
`POST /resources/managed-onprem`, and `POST` deployment switch. Actor columns
(`created_by`, `pushed_by`, `actor_user_id`) are NULL for tokens pending the
principals table (section 13), and `deployment_events.auth_method` accepts
`token`.

Still user-only or blocked:

* `fully_managed_capacity::join_waitlist` - the waitlist table's `user_id` is
  `NOT NULL` (`043`), so it needs the same nullable-actor change.
* Person/account routes (users, onboarding, legal), billing/subscriptions, and
  the token-management and RBAC/org-management routes, by design or policy.

Outstanding design questions: whether the RBAC editor UI is the right place to
manage token roles or tokens get their own page; and user-facing naming
("access token" vs "API token" vs "service account").
