# Organization Access Tokens Bible

Single source of truth for the organization-based access token work: the
current-state inventory of the auth stack, the target model, the starting
parameters, and the decisions still open. Update it as work lands.

Status: **design in progress. Nothing implemented.** Starting parameters and
recommendations below are proposals awaiting confirmation.

Line numbers and file references are as of 2026-11-09, verified against the
working tree this session (branch `ryansquared/rudimentary-rbac`).

## How we got here

The platform authenticates people only. Every request that reaches the API is
traced back to a `users.id`: a passkey-signed call, an authenticated session, or
an SSH-signed request. RBAC (`docs/rbac-bible.md`) then decides what that *user*
may do, keyed off their organization membership and roles.

There is no way for non-interactive callers - CLI, CI, scripts, third-party
integrations, "service accounts" - to act on behalf of an **organization**
without borrowing a person's passkey or session. We want a first-class
credential for that: an **organization access token**.

## Vocabulary

Terms as we intend them; tighten once the model is settled.

* **Organization access token (OAT)** - a bearer credential that authenticates a
  non-interactive caller to exactly one organization. Working name.
* **Token principal** - the identity an OAT authenticates as. Distinct from a
  user. Its form is [D1](#d1-token-principal-user-bound-vs-org-owned).
* **Personal access token (PAT)** - the *rejected-by-default alternative*: a
  token that authenticates as an existing user and inherits that user's roles.
* **Mint / revoke** - create / delete a token. Issuance returns the plaintext
  once; only a hash is stored.
* **Trust boundary** - the gateway `->` API hop. The API trusts only requests
  bearing the internal service secret plus gateway-set identity headers.

## Current state

### Auth front door

The **gateway** is the only authentication front door
(`src/gateway/src/auth_middleware.rs`). It accepts exactly three methods:

| Method | Where set | Anchor |
|--------|-----------|--------|
| `session` | cookie `caution_session` or `X-Session-ID` header, validated against `auth_sessions` | `auth_middleware.rs:604` |
| `ssh_signed` | SSH signature over the request | `auth_middleware.rs:962` |
| `passkey` | WebAuthn-signed request | `auth_middleware.rs:1496` |

Every method resolves to a **user id**. The gateway proxies to the API with a
hardcoded allowlist of identity headers built from middleware extensions, never
from caller input (`src/gateway/src/handlers/proxy.rs:210`
`trusted_identity_headers`): `X-Authenticated-User-ID`, `X-Caution-Auth-Method`
(`passkey|session|ssh_signed`), `X-Caution-Signed-Request-Id`, plus
`X-Internal-Service-Secret`.

### The API side of the boundary

`src/api/src/middleware.rs` `auth_middleware` accepts the internal secret and
resolves the caller into `AuthContext { user_id, auth_method, signed_request_id }`
(`src/api/src/main.rs:209`). `parse_auth_method` (`middleware.rs:19`) recognizes
only `passkey|session|ssh_signed`. It rejects a missing user id
(`MissingUserId`) - **there is no principal that is not a user**.

Session tokens are opaque and DB-backed: `auth_sessions (session_id PK,
credential_id, user_id, expires_at, created_at, last_used_at)`
(`src/api/migrations/001_initial.sql:326`, `057_session_user_id.sql`), validated
per request and reaped by `run_cleanups` (`src/gateway/src/db.rs:1114`). The
hashed-opaque-token precedent is
`webauthn_reset_tokens (token_hash PK, user_id, expires_at, used_at)`
(`053_webauthn_reset_tokens.sql`): plaintext returned once, SHA-256 hash at rest.

### Authorization

RBAC is layered on the `resource_routes` group after auth + legal + onboarding
(`src/api/src/main.rs:6150`): `rbac_middleware` (`src/api/src/rbac/mod.rs:184`)
reads the caller's org membership and role rules, lets **owners bypass**, and
otherwise denies unless a matching rule allows. The lookup is hardcoded to
`om.user_id = $1` and `rbac_member_roles.user_id`. Membership-only checks
(`check_org_access`, `src/api/src/main.rs:240`) and the org-in-path guards on
RBAC handlers likewise take a `user_id`. `rbac_member_roles` FK-targets
`organization_members (organization_id, user_id)`, so a non-user principal has
no place to hang a role assignment today.

## Starting parameters

Defaults we will assume unless a decision below changes them.

1. **Name.** "Organization access token" (OAT). Route namespace
   `/organizations/{id}/access-tokens`.
2. **Binding.** One token belongs to exactly one organization. No cross-org
   tokens, no user-scoped tokens.
3. **Format.** Opaque 32-byte random value, base64url, prefixed `caut_oat_`.
   Not a JWT.
4. **At rest.** Store `sha256(token)` as the primary key; return plaintext once
   at mint time. Never store or log the plaintext. (Mirrors
   `webauthn_reset_tokens`.)
5. **Transport.** `Authorization: Bearer <token>`. Never a cookie, so no
   ambient authority and no CSRF token.
6. **Validation point.** The gateway terminates token auth and reports it across
   the trust boundary as a new `AuthMethod::Token` / `"token"`, alongside a token
   id and organization id. The API never sees the bearer value.
7. **Revocation.** Immediate and hard: deleting the row invalidates the token on
   the next request (DB lookup per request, like sessions).
8. **Audit.** Tokens record `created_by`, `created_at`, `last_used_at`, and are
   attributable in request history; the plaintext is shown exactly once.
9. **Deny by default.** A token with no roles can do nothing beyond a minimal
   self endpoint. Tokens never get owner god-mode implicitly.
10. **Roles fixed at mint.** A token's RBAC roles are chosen when it is created
    and cannot be changed afterward; changing authority means mint + revoke.

## Significant decisions

Each needs a call before implementation. D1-D7 are settled; the rest carry a
recommendation and remain open.

### D1. Token principal: user-bound vs org-owned - DECIDED (org-owned)

What the token authenticates *as*. Decided 2026-11-09: **org-owned**, not
user-bound. A token authenticates as the organization that owns it; it is not a
credential for a person.

* **A. User-bound (PAT). REJECTED.** Gateway would resolve the token to an
  existing `user_id`; everything downstream unchanged. Cheapest, but not
  "organization-based": the token lives and dies with a person and would inherit
  their ownership.
* **B. Org-owned service principal. CHOSEN.** Token resolves to
  `(organization_id, token_id)`. The API gains a `Principal::Token` as an
  alternative to `Principal::User`; it survives the creator leaving and is
  auditable as a machine identity.
* **C. Org-owned + implicit owner. REJECTED.** Token acts as org owner. An org
  owner credential that never re-authenticates is too large a blast radius, and
  it would bypass the RBAC model entirely.

Consequences: the token is bound to exactly one organization; the creator is
attribution only, not the authority (see D10, D11); the API must accept a
non-user principal (see D5); no owner bypass (see D12).

### D2. Authorization source for a token - DECIDED (RBAC roles, immutable)

How a token's permissions are expressed. Decided 2026-11-09: **reuse RBAC roles,
chosen at creation, immutable thereafter.** The token carries zero or more
`rbac_roles` of its own organization; the same matcher that serves users decides
its requests.

* **A. Assign RBAC roles to the token. CHOSEN.** Reuse `rbac_roles` /
  `rbac_role_rules`. One permission model, one editor.
* **B. Token-inline rules. REJECTED.** Second permission surface to validate and
  render.
* **C. Coarse fixed scopes. REJECTED.** A third model divorced from RBAC and
  prone to scope creep.

Because `rbac_member_roles` FK-targets `organization_members`, this needs a
separate assignment table for tokens (for example
`organization_access_token_roles (organization_id, token_id, role_id)`), not a
row in `rbac_member_roles`.

**Immutability (D2a).** Decided 2026-11-09: immutability applies **only to the
token-to-role association**, not to the roles themselves. The set of roles
attached to a token is fixed at mint: there is no "edit token roles" endpoint,
and changing that set means minting a new token and revoking the old one (the
rotation flow in D7). The roles stay live and mutable: editing a held role's
rules or deleting the role **does** change the token's effective permissions,
exactly as it changes them for a user holding the same role. Enforcement: no
`UPDATE` path on the association rows; writes are the inserts performed by the
mint transaction plus cascade deletes from token/role removal.

**No subset requirement (D2b).** Decided 2026-11-09: a token's roles do **not**
need to be a subset of the creator's effective roles. Whoever may mint may attach
any role in the organization. Consequence: minting is itself a role-granting
operation, so the mint authorization gate (D8) is the sole control against
privilege escalation. If minting is not owner-only, the rule that permits
`POST /organizations/{id}/access-tokens` effectively grants the ability to hold
any role, and must be treated and labelled as such.

### D3. Where tokens are validated - DECIDED (gateway)

Decided 2026-11-09: **the gateway validates tokens.** The gateway looks up
`sha256(bearer)`, checks expiry and revocation, and forwards a token principal to
the API over the internal secret. The API never receives or validates bearer
material.

* **A. Gateway. CHOSEN.** Preserves the invariant that the API is not
  internet-facing for credential material, and keeps one auth front door.
* **B. API. REJECTED.** Token validation in `src/api/src/middleware.rs` would
  make the API directly exposed to bearer credentials and split auth authority
  across two services.

Consequences: the gateway gains a bearer-token auth path alongside
passkey/session/SSH (`src/gateway/src/auth_middleware.rs`), and the token lookup
runs on the gateway's database path (`src/gateway/src/db.rs`, next to
`validate_auth_session`). The API side is D5.

### D4. Token format and storage - DECIDED (opaque, hash-at-rest)

Decided 2026-11-09: tokens are **opaque and hashed at rest**. A 256-bit random
value, base64url, prefixed `caut_oat_`; only `sha256(plaintext)` is stored.

* **A. Opaque, hash-at-rest. CHOSEN.** Instant revocation, no signing-key
  management or rotation, matches sessions and reset tokens.
* **B. JWT. REJECTED.** Stateless validation saves one indexed lookup, but
  revocation needs a denylist anyway and key rotation becomes a project.

`sha256` is sufficient for a 256-bit random value (nothing to brute-force, so no
slow KDF). A public, non-secret token-id prefix for UI/admin lookup is optional
and can be added later.

### D5. Principal propagation across the trust boundary - DECIDED (explicit principal)

Decided 2026-11-09: propagate an **explicit token principal**. No synthetic
service-user rows.

* **A. Explicit `Principal::Token`. CHOSEN.** New headers
  (`X-Caution-Token-ID`, `X-Caution-Organization-ID`) plus `AuthMethod::Token`;
  `AuthContext` becomes a principal (user or token); `rbac_middleware`,
  `check_org_access`, and the org-in-path guards take a `Principal` and branch on
  it.
* **B. Synthetic service user. REJECTED.** Minting hidden `users` rows would leak
  into user listings, notifications, and billing-contact queries.

Key point: a token principal carries **no user id**. The gateway sends no
`X-Authenticated-User-ID` for token requests, and the API must not fabricate one.
`AuthContext` is therefore a tagged value (`Principal::User { user_id, .. }` or
`Principal::Token { token_id, organization_id, .. }`). Helpers that need a user
id (`check_org_access`, `rbac_middleware`, `get_user_primary_org`, the
org-in-path guards) take the principal and treat "no user id" as their natural
failure. See D6.

### D6. Org scoping and which routes a token may reach - DECIDED (no allowlist)

Decided 2026-11-09: **no per-route safeguards or exemption lists.** A token
principal simply has **no user id**, so any route or helper that requires a user
id fails on its own: `/users/me`, passkey/credential management, `/auth/*`, legal
acceptance, onboarding, and every membership check keyed on `user_id`. There is
deliberately no curated deny-list to keep in sync.

* Token is bound to one org; the org in any path must equal the token's org
  (`/organizations/{id}/...`) and mismatch is rejected before RBAC. This is the
  one scoping rule, because the token must not cross tenants.
* Everything else falls out of "no user id". A route works for a token only if
  it does not need one (or has a token variant, below).
* Where a CLI flow genuinely needs a person-scoped route, add an **access-token
  variant** of that route rather than special-casing the original. Example: a
  token identity endpoint (`GET /access-tokens/me` returning org, name, roles)
  replaces `/users/me` for tokens.

### D7. Lifecycle, limits, and rotation - DECIDED

Decided 2026-11-09:

* **Expiry.** Tokens expire. Set at mint, **default 90 days**. The proposed
  tenant-configurable maximum-lifetime cap is dropped. Open micro-point: whether a
  non-expiring token may be requested (default expiry implies every token has
  one); assume not unless told otherwise.
* **Rotation.** **Recreate, no overlap.** Rotating means minting a replacement
  and revoking the old token; there is no overlapping-validity window. Because
  revocation is immediate, the old token stops working at once, so callers must
  swap in the new value.
* **Limits.** **No per-org token count cap.** Each token carries a name and
  optional description for operators.
* **Last used.** Track `last_used_at`, updated best-effort like sessions
  (`auth_sessions.last_used_at`), so operators can find stale tokens.
* **Revocation.** Hard delete; no soft-delete/recycle.

### D8. Who may mint a token

D2b decided there is **no subset requirement**: whoever may mint may attach any
role. Minting is therefore a role-granting operation, and the mint gate is the
only control against escalation.

* **A. Owner-only (recommended for v1).** Fewest sharp edges; `is_owner` gate.
  An owner already has god powers, so letting them mint any role grants nothing
  new.
* **B. RBAC-gated.** Any member with a matching rule may mint, attaching any
  role. Capable and consistent with the rest of RBAC, but the rule permitting
  `POST /organizations/{id}/access-tokens` must be understood as granting
  "create a principal with arbitrary roles", i.e. near-owner escalation.

**Recommendation: A for v1.** B remains possible, but if chosen the mint rule
should be treated with the same care as ownership grants and documented as such.
Ties directly to [To-fix #2 in the RBAC bible](rbac-bible.md) (delegated members
have no UI).

### D9. Transport details and precedence

* `Authorization: Bearer` only; reject tokens presented as cookies.
* If a request carries both a valid session and a bearer token, the **token
  wins** and the session is ignored (or, stricter: reject the mix). Recommendation:
  token wins, matching the gateway's existing "signature middleware takes
  precedence" shape.
* No CSRF requirement for bearer requests; keep CSRF for cookie sessions.
* Rate-limit token auth failures separately from session failures.

### D10. Audit, attribution, and secrets in logs

* `created_by` (user id) and, if rotating, `replaced_by`/`replaces`.
* Requests authenticated by a token should be attributable in
  `signed_request_audit`/deployment history as *token X of org Y*, not silently
  as the creator. Recommendation: extend the audit actor to a principal
  (`user` or `token`); do not attribute token actions to `created_by`.
* Never log the bearer or its hash.

### D11. Org/creator deletion semantics

* Token is deleted when its organization is deleted (FK cascade).
* Token **survives** its creator's removal from the org (org-owned per D1), but
  operators should be able to see "created by <user no longer a member>".
  Recommendation: `created_by REFERENCES users(id) ON DELETE SET NULL`, matching
  `rbac_member_roles.granted_by`.

### D12. Relationship to owner bypass

Owners bypass RBAC. Tokens must **not** inherit any bypass. A token is only ever
as powerful as its assigned rules; an `allow * on *` rule is the only way to
make a token owner-equivalent, and that is a deliberate, visible choice in the
RBAC editor.

## Data model sketch (not final)

Illustrative only; principal plumbing (D5) still open.

```sql
CREATE TABLE organization_access_tokens (
    token_hash TEXT PRIMARY KEY,              -- sha256(plaintext)
    id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,          -- mint default now()+90d (see D7)
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- D2: roles chosen at mint, immutable. Separate from rbac_member_roles, which
-- FK-targets organization_members. Composite FKs keep role and token in the
-- same organization. No UPDATE path: rows are inserted by the mint transaction
-- and removed only by cascade.
CREATE TABLE organization_access_token_roles (
    organization_id UUID NOT NULL,
    token_id UUID NOT NULL,
    role_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, token_id, role_id),
    FOREIGN KEY (organization_id, token_id)
        REFERENCES organization_access_tokens (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, role_id)
        REFERENCES rbac_roles (organization_id, id) ON DELETE CASCADE
);
```

This needs `organization_access_tokens` to carry a `UNIQUE (organization_id, id)`
(like `rbac_roles`) as the composite FK target.

## Open questions / blockers

* D1-D7 are settled. D8 (mint gate) is the escalation control and the next
  keystone; D9-D12 still carry recommendations.
* Expiry micro-point (D7): confirm non-expiring tokens are not offered, and
  whether the 90-day default is changeable per token at mint.
* CLI survey (needed for D6): identify every CLI flow that today calls a
  person-scoped route (`/users/me`, quorum approval, passkey-signed deploys,
  etc.) and decide which needs an access-token route variant. Not yet surveyed.
* Whether the RBAC editor UI is the right place to manage token roles, or
  tokens get their own page.
* Naming: "access token" vs "API token" vs "service account" in user-facing
  copy; the route/table names above follow "access token".

## Decision log

Record decisions here as they are made, newest first.

* **2026-11-09** - D7 confirmed. Tokens expire (default 90 days, set at mint).
  Rotation is **recreate with no overlap** (mint new + revoke old). **No per-org
  token cap.** Track `last_used_at`. Hard delete on revocation.

* **2026-11-09** - D5 and D6 locked in. The gateway forwards an **explicit token
  principal** (token id + org id, no user id; no synthetic service users), and
  D6 adds **no route allowlist**: person-scoped routes fail naturally because a
  token has no user id. CLI flows that need such a route get an access-token
  route variant instead.

* **2026-11-09** - D3 and D4 confirmed. Tokens are validated at the **gateway**
  (not the API), and are **opaque, hash-at-rest** (`sha256`, `caut_oat_` prefix),
  not JWTs.

* **2026-11-09** - D2a and D2b clarified. Immutability applies only to the
  token-to-role **association**; a role's rules can be edited after and the
  change applies to every holder, tokens included. A token's roles need **not**
  be a subset of the creator's, so minting grants arbitrary roles and the mint
  gate (D8) is the sole escalation control.

* **2026-11-09** - A token's **RBAC roles are chosen at creation and are
  immutable** (D2). Authority is the same `rbac_roles` model as users, via a
  separate token-role assignment table; changing a token means mint + revoke,
  not edit. Sub-decisions D2a/D2b recorded below.

* **2026-11-09** - Tokens are **org-scoped, not user-scoped** (D1). A token
  authenticates as a service principal of its organization; the creator is
  attribution only. Rejects user-bound PATs and any implicit owner power.

## Progress log

Newest first.

* **2026-11-09** - Confirmed D7: default 90-day expiry, recreate-with-no-overlap
  rotation, no per-org token cap, `last_used_at` tracking, hard-delete
  revocation.

* **2026-11-09** - Locked in D5 (explicit token principal across the gateway->API
  boundary) and D6 (no allowlist; fail via missing user id; add token route
  variants where CLI needs them).

* **2026-11-09** - Confirmed D3 (gateway validation) and D4 (opaque,
  hash-at-rest). Recorded consequences for the gateway auth path and lookup.

* **2026-11-09** - Resolved D2a (association immutable only; roles stay live) and
  D2b (no creator-subset requirement). Reworked D8 to match.
* **2026-11-09** - Decided D2: token RBAC roles chosen at creation, immutable.
  Added the token-role assignment table to the data-model sketch.
* **2026-11-09** - Decided D1: org-owned service principal (org-scoped, not
  user-scoped). Dependent sections updated.
* **2026-11-09** - Created this document: auth/RBAC current-state inventory,
  starting parameters, and the open decisions above. No implementation.
