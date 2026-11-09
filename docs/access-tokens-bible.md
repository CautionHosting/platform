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

## Significant decisions

Each needs a call before implementation. Recommendation given; **all open**.

### D1. Token principal: user-bound vs org-owned

What the token authenticates *as*.

* **A. User-bound (PAT).** Gateway resolves the token to an existing `user_id`;
  everything downstream is unchanged. Cheapest. But it is not
  "organization-based": the token lives and dies with a person, inherits their
  ownership, and a departing admin's token is a standing backdoor.
* **B. Org-owned service principal (recommended).** Token resolves to
  `(organization_id, token_id)`. The API gains a `Principal::Token` as an
  alternative to `Principal::User`. Matches "organization-based"; survives the
  creator leaving; auditable as a machine identity.
* **C. Org-owned + implicit owner.** Token acts as org owner. Rejected: an
  org owner credential that never re-authenticates is a large blast radius.

**Recommendation: B.** It is the only option that is actually org-based, and it
composes with the existing per-org RBAC roles instead of inventing a parallel
permission system. Cost: the API must accept a non-user principal (see D5).

### D2. Authorization source for a token

How a token's permissions are expressed.

* **A. Assign RBAC roles to the token (recommended).** Reuse `rbac_roles` /
  `rbac_role_rules`. A token carries zero or more roles; the *same* matcher
  decides. One permission model, one editor.
* **B. Token-inline rules.** Rules attached directly to the token, no roles.
  More flexible, second permission surface to validate and render.
* **C. Coarse fixed scopes.** `read` / `write` / `deploy` etc. Simple, but a
  third model divorced from RBAC and prone to scope creep.

**Recommendation: A.** Because `rbac_member_roles` FK-targets members, this
requires either a generalized assignment table
(`rbac_principal_roles (organization_id, principal_kind, principal_id, role_id)`)
or token-specific rows. That schema move is the main cost and a decision in its
own right.

**Escalation bound (join with D8).** If a token's roles must be a subset of the
minting user's effective roles, a low-privilege member cannot mint a token more
powerful than themselves. This is the single most important safety rule; the
alternative (any creator may grant any role) turns token creation into
privilege escalation.

### D3. Where tokens are validated

* **A. Gateway (recommended).** The gateway looks up `sha256(bearer)`, checks
  expiry, and forwards a token principal over the internal secret. Preserves the
  invariant that the API is never internet-facing for credential material and
  keeps one auth front door.
* **B. API.** Token validation in `src/api/src/middleware.rs`. Cheaper
  plumbing (no gateway change; `parse_auth_method` already forwards
  `auth_method`), but it makes the API directly exposed to bearer credentials
  and splits auth authority across two services.

**Recommendation: A.** Consistency with passkey/session/SSH outweighs the extra
gateway code. B is a real fallback if gateway work is gated.

### D4. Token format and storage

Opaque-hashed vs JWT/stateless.

* **A. Opaque, hash-at-rest (recommended).** Instant revocation, no signing-key
  management or rotation, matches sessions and reset tokens.
* **B. JWT.** Stateless validation, no per-request DB read, but revocation needs
  a denylist anyway and key rotation becomes a project.

**Recommendation: A.** Tokens are long-lived and revocation matters more than
saving one indexed lookup. `sha256` is sufficient for a 256-bit random value (no
slow KDF needed; there is nothing to brute-force). A public, non-secret token-id
prefix is optional for UI/admin lookup and can be added later.

### D5. Principal propagation across the trust boundary

Once a token is a non-user principal, the gateway `->` API contract must carry
it, and the API's user-keyed helpers must accept it.

* **A. Explicit `Principal::Token` (recommended).** New headers
  (`X-Caution-Token-ID`, `X-Caution-Organization-ID`) plus `AuthMethod::Token`;
  `AuthContext` becomes an enum/tagged struct; `rbac_middleware`,
  `check_org_access`, and the org-in-path guards take a `Principal` and branch on
  it. Clean semantics; touches the auth, onboarding, and RBAC layers.
* **B. Synthetic service user.** Mint a hidden `users` row per token (or per
  org) so the entire stack keeps working unchanged, then assign it roles as a
  member. Smallest diff, but it pollutes the user space, fakes membership, and
  will leak into user listings, notifications, and billing contact queries
  unless carefully filtered.

**Recommendation: A**, with **B explicitly rejected** as a long-term model. A is
more work but the fake-user path accretes special cases indefinitely.

### D6. Org scoping and which routes a token may reach

* Token is bound to one org, and the org in any path must equal the token's org
  (`/organizations/{id}/...`); mismatch is rejected before RBAC.
* Person-scoped and account-lifecycle routes are **not** token-reachable:
  `/users/me`, passkey/credential management, `/auth/*`, legal acceptance, and
  onboarding. A token is not a person and must not manage passkeys, accept
  terms, or register accounts.
* A minimal token identity route (e.g. `GET /access-tokens/me` returning org,
  name, roles) replaces `/users/me` for tokens; the RBAC seeding UI's
  `/users/me` allow rule does not apply to tokens.

**Recommendation: adopt as stated.** Open sub-question: whether any CLI flows
that today call `/users/me` should get a token-scoped equivalent.

### D7. Lifecycle, limits, and rotation

* **Expiry.** Optional vs required. Recommendation: optional expiry, default 90
  days, tenant-configurable cap (e.g. 1 year); non-expiring allowed only for
  owners. (Alternative: always required. Pick one.)
* **Rotation.** Recommend a "create new + revoke old" flow now; an overlapping
  rotation window can come later.
* **Limits.** Per-org token count cap and per-token name/description.
* **Last used.** Track `last_used_at`, updated best-effort like sessions
  (`auth_sessions.last_used_at`), so operators can find stale tokens.
* **Revocation.** Hard delete; no soft-delete/recycle in v1.

### D8. Who may mint a token, and the escalation bound

* **A. Owner-only (recommended for v1).** Fewest sharp edges; `is_owner` gate.
* **B. RBAC-gated.** Any member with a matching rule may mint, but only roles
  that are a **subset of their own effective rules** (D2 escalation bound). More
  capable, more invariants to enforce and test.

**Recommendation: A for v1, then B** once the subset check is implemented and
tested. Ties directly to [To-fix #2 in the RBAC bible](rbac-bible.md) (delegated
members have no UI).

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
* Token **survives** its creator's removal from the org (org-owned in D1-B), but
  operators should be able to see "created by <user no longer a member>".
  Recommendation: `created_by REFERENCES users(id) ON DELETE SET NULL`, matching
  `rbac_member_roles.granted_by`.

### D12. Relationship to owner bypass

Owners bypass RBAC. Tokens must **not** inherit any bypass. A token is only ever
as powerful as its assigned rules; an `allow * on *` rule is the only way to
make a token owner-equivalent, and that is a deliberate, visible choice in the
RBAC editor.

## Data model sketch (not final)

Illustrative only; blocked on D1/D2.

```sql
CREATE TABLE organization_access_tokens (
    token_hash TEXT PRIMARY KEY,              -- sha256(plaintext)
    id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ,                   -- NULL = no expiry (see D7)
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Role assignment and gateway/API principal plumbing are intentionally omitted
until D1/D2/D5 are settled.

## Open questions / blockers

* D1 principal model is the keystone; D2, D5, D8, D12 all depend on it.
* Does any existing CLI flow assume user auth in a way that blocks token use
  (e.g. `/users/me`, quorum approval, passkey-signed deploys)? Not yet surveyed.
* Whether the RBAC editor UI is the right place to manage token roles, or
  tokens get their own page.
* Naming: "access token" vs "API token" vs "service account" in user-facing
  copy; the route/table names above follow "access token".

## Decision log

Record decisions here as they are made, newest first.

* (none yet)

## Progress log

Newest first.

* **2026-11-09** - Created this document: auth/RBAC current-state inventory,
  starting parameters, and the open decisions above. No implementation.
