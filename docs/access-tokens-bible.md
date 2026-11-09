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

Each needs a call before implementation. D1-D13 are settled; the design has no
remaining open decisions (micro-points and validation tasks are tracked under
Open questions).

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

* **Expiry.** Not required, but **strongly recommended**. Expiry is a toggle at
  mint; when on, the value defaults to **90 days**. When an operator turns expiry
  off (a non-expiring token), show an explicit warning note in the UI. The
  proposed tenant-configurable maximum-lifetime cap is dropped.
* **Rotation.** **Recreate, no overlap.** Rotating means minting a replacement
  and revoking the old token; there is no overlapping-validity window. Because
  revocation is immediate, the old token stops working at once, so callers must
  swap in the new value.
* **Limits.** **No per-org token count cap.** Each token carries a name and
  optional description for operators.
* **Last used.** Track `last_used_at`, updated best-effort like sessions
  (`auth_sessions.last_used_at`), so operators can find stale tokens.
* **Revocation.** Hard delete; no soft-delete/recycle.

### D8. Who may mint a token - DECIDED (owner-only)

Decided 2026-11-09: **owners only**, enforced by an `is_owner` check, not merely
by RBAC rules.

* **A. Owner-only. CHOSEN.** An owner already has god powers, so letting them
  mint a token with any role grants nothing new. Because minting attaches
  arbitrary roles (D2b), it must not be reachable by a delegated member.
* **B. RBAC-gated. REJECTED.** A member with a matching `POST .../access-tokens`
  rule could create a principal holding any role, i.e. near-owner escalation.

Enforcement note: today the role-management routes are ordinary RBAC-gated
routes (a member reaches them only with a matching rule; owners bypass), and the
**UI** shows role controls to owners only (`isOwner`). Token minting is stricter
than that: a hard `is_owner` gate, so no RBAC rule can delegate it. This mirrors
the owner-only powers already enforced server-side for granting ownership,
demoting/removing an owner, and deleting the organization.

### D9. Transport details and precedence - DECIDED

Decided 2026-11-09, as recommended:

* `Authorization: Bearer` only; reject tokens presented as cookies.
* If a request carries both a valid session and a bearer token, the **token
  wins** and the session is ignored, matching the gateway's existing
  "signature middleware takes precedence" shape. See D12 for the owner case.
* No CSRF requirement for bearer requests; keep CSRF for cookie sessions.
* Rate-limit token auth failures separately from session failures.

### D10. Audit, attribution, and secrets in logs - DECIDED

Decided 2026-11-09, as recommended:

* `created_by` (user id) and, if rotating, `replaced_by`/`replaces`.
* Requests authenticated by a token are attributable in
  `signed_request_audit`/deployment history as *token X of org Y*, not as the
  creator. The audit actor becomes a principal (`user` or `token`); token actions
  are not attributed to `created_by`.
* Never log the bearer or its hash.

### D11. Org/creator deletion semantics - DECIDED

Decided 2026-11-09, as recommended:

* Token is deleted when its organization is deleted (FK cascade).
* Token **survives** its creator's removal from the org (org-owned per D1), but
  operators should be able to see "created by <user no longer a member>".
  `created_by REFERENCES users(id) ON DELETE SET NULL`, matching
  `rbac_member_roles.granted_by`.

### D12. Relationship to owner bypass - DECIDED (no bypass; token wins for owners)

Decided 2026-11-09:

* Owners bypass RBAC for **user** sessions. Tokens do **not** inherit any bypass.
  A token is only ever as powerful as its assigned rules; an `allow * on *` rule
  is the only way to make a token owner-equivalent, and that is a deliberate,
  visible choice in the RBAC editor.
* **When an owner presents a token, authenticate as the token, not the owner
  session.** This is mandatory: it is how an owner tests a newly created token
  and sees its real authority instead of their own god-mode. In other words, the
  token principal always wins over session/owner identity (D9); an owner using a
  token is a token, so the token's rules decide and the account-level owner
  bypass does not apply.

### D13. Tokens authorize passkey-required routes - DECIDED

Decided 2026-11-09: **`apps switch` and the quorum-bundle routes must be
drivable by a token.** The token is the authorization: for these routes a valid
token principal substitutes for the FIDO2 signed request.

* **Gateway.** `requires_fido2_signature` (`auth_middleware.rs:986`) must not
  force an assertion when the request is authenticated by a token. Token auth is
  evaluated, and the passkey requirement is waived for a token principal.
* **API.** Handlers that demand `auth.signed_request_id` (currently
  `app_deployments/switch.rs:330`) must accept a token principal instead,
  recording the **token** as the actor rather than a `signed_request_audit` row
  (D10). The same applies to the quorum-bundle handlers that today only run under
  a signed request.
* **Authorization unchanged.** The token still needs a matching RBAC rule (deny
  by default) and the org-in-path rule; owner bypass never applies to tokens
  (D12). So a token can switch or manage bundles only if an owner attached a role
  granting those routes.
* **Assurance note.** This lowers the request-level assurance for these
  operations from "human passkey" to "org token". That is the intent of tying
  them to a token. Holder-approval ceremonies *inside* quorum creation
  (key-service / WebAuthn / PGP) are a separate layer and are unaffected.
* **Passkey still works.** These routes remain passkey-capable: a human session
  with a passkey assertion still authorizes them exactly as today.

## CLI access-token survey (D6)

Scan of `src/cli` (the `caution` binary) for where tokens need specialization.
Verified against source 2026-11-09.

### How the CLI authenticates today

Three mechanisms, chosen per call:

1. **Session** (`X-Session-ID`) for most calls, from `caution login` (passkey or
   QR). Stored in the CLI config (`ApiClient` / `require_existing_authenticated_config`).
2. **Passkey-signed request** (`/auth/sign-request` + assertion) for routes the
   gateway marks passkey-required (`requires_fido2_signature`,
   `src/gateway/src/auth_middleware.rs:986`).
3. **SSH-signed request** (`--this-is-a-ci-machine`) for `GET`/`DELETE` on
   `/resources/{app}[/deployments[/{deployment}]]` only
   (`is_ssh_signed_resource_request`, `auth_middleware.rs:732`; note it does
   not cover `/ssh-keys`, which is passkey-required). This is the existing
   non-interactive CI path.

The gateway's passkey-required set is: `PATCH`/`DELETE` `/quorum-bundles/*`,
`POST` `/quorum-bundles` and `/quorum-bundles/from-org-users`,
`PATCH`/`PUT` `/organizations/*/settings`, `POST`/`DELETE` `/ssh-keys*`,
`POST` `/pgp-keys` and `DELETE` `/pgp-keys/*`, `POST` `/passkeys/register/begin`
and `DELETE` `/passkeys/*`, and deployment switch. A token cannot satisfy these;
they demand a FIDO2 assertion.

### Command classification

| Command | Endpoint(s) | Scope | Token readiness |
|---------|-------------|-------|-----------------|
| `login`/`register`/`logout` | `/auth/*` | person | Not applicable (interactive) |
| `account id` | `GET /api/organizations` | person (membership list) | **Needs org-from-token** |
| `init`/`teardown` (BYOC) | `/api/resources`, `/api/resources/managed-onprem` | org (primary org) | **Needs org-from-token** |
| `apps create` | `POST /api/resources` | org (primary org) | **Needs org-from-token** |
| `apps list` | `GET /api/resources` | org (primary org) | **Needs org-from-token** |
| `apps get` | `GET /api/resources/{id}`, `/history` | org (membership) | Works with a rule (id-scoped) |
| `apps rename` | `PATCH /api/resources/{id}` | org (membership) | Works with a rule (id-scoped) |
| `apps destroy` | `DELETE /api/resources/{id}` | org (membership) | Works with a rule (id-scoped) |
| `apps download-eif` | `GET /api/resources/{id}/eif/download` | org (primary org) | **Needs org-from-token** |
| `apps switch` | `POST /api/resources/{id}/deployments/{d}/switch` | org, passkey-required | Token-authorized (D13) |
| `credentials add/list/remove/set-default` | `/api/credentials` | org (primary org) | **Needs org-from-token** |
| `capacity` | `POST /api/organizations/{id}/fully-managed/waitlist` | org (RBAC) | Works once token membership is accepted (org is in the path) |
| `secret` (bundle create/upload/rename/labels) | `/api/quorum-bundles*` | org, passkey-required | Token-authorized (D13) |
| `secret encrypt` / `inspect` | local | n/a | n/a |
| `ssh-keys *`, `pgp-keys *` | gateway `/ssh-keys`, `/pgp-keys` | account | Not applicable (a token is not a person) |
| `account`/`verify` attestation | public endpoints, `/.well-known/...` | public | No auth needed |
| `git push caution` (deploy) | gateway SSH server | account/org SSH key | Unrelated to tokens (stays SSH) |

### What actually needs new server work

Three categories:

1. **Token-principal membership (D5), pervasive.** Every user-keyed org helper
   must accept a `Principal::Token`: `check_org_access`, the
   `om.user_id = $1` membership joins, `get_user_primary_org`, and the
   org-in-path guards. Routes scoped by an id in the path
   (`GET`/`PATCH`/`DELETE` `/api/resources/{id}`) then work with a rule.
2. **Org-from-token.** Routes that resolve the caller's own org
   (`get_user_primary_org`) have no user to resolve from: creating/listing
   resources (`src/api/src/resources.rs:132,325`), `/api/credentials`
   (`src/api/src/main.rs:929,996,...`), EIF download
   (`src/api/src/eif_download.rs:480`), managed-onprem creation
   (`main.rs:1424`), and builder config (`main.rs:2153,2237`). These need the
   org taken from the token, exposed via an identity endpoint such as
   `GET /access-tokens/me` and/or `get_user_primary_org` generalized to the
   principal.
3. **Token-authorized passkey routes (D13).** `apps switch` and the
   quorum-bundle routes must accept a token principal in place of the FIDO2
   assertion: waive `requires_fido2_signature` for a token, and let the relevant
   handlers (`app_deployments/switch.rs:330`; quorum-bundle writes) run under a
   token actor instead of `signed_request_id`.

Everything account-scoped (SSH keys, PGP keys, passkeys, `/users/me`,
`/user/username`, `/api/user/status`) is intentionally out of reach and needs no
variant.

### Client-side work (no new route)

The CLI needs a token credential path: accept a token (flag or env such as
`CAUTION_ACCESS_TOKEN`), send `Authorization: Bearer`, skip login/session
requirements, and resolve org/identity from the token identity endpoint. Existing
session and SSH-signed paths stay.

## Data model sketch (not final)

Illustrative only; principal plumbing per D5.

```sql
CREATE TABLE organization_access_tokens (
    token_hash TEXT PRIMARY KEY,              -- sha256(plaintext)
    id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ,                   -- NULL = no expiry; mint default
                                              -- now()+90d when expiry is on (D7)
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

* All decisions D1-D13 are settled.
* D7 expiry: implemented as an expiry toggle at mint (default 90 days when on);
  turning it off is allowed but the UI must warn.
* CLI survey (D6) is complete: see [CLI access-token survey](#cli-access-token-survey-d6).
  Server gaps: generalize user-keyed org helpers to the token principal (D5),
  provide org-from-token for primary-org routes (create/list resources,
  credentials, EIF download, managed-onprem, builder config), and token-authorize
  the passkey routes `apps switch` and quorum-bundle writes (D13). Everything
  else is CLI client work (send Bearer, resolve identity from token).
* Whether the RBAC editor UI is the right place to manage token roles, or
  tokens get their own page.
* Naming: "access token" vs "API token" vs "service account" in user-facing
  copy; the route/table names above follow "access token".

## Decision log

Record decisions here as they are made, newest first.

* **2026-11-09** - D13 decided: `apps switch` and the quorum-bundle routes are
  **drivable by a token**. A token principal substitutes for the FIDO2 signed
  request on those routes; the token still needs a matching RBAC rule, and the
  operation is audited to the token. This deliberately lowers request assurance
  from "human passkey" to "org token" for these operations.

* **2026-11-09** - D7 expiry refined: expiry is **optional but strongly
  recommended**, an on/off toggle at mint defaulting to 90 days, with a UI
  warning when turned off (non-expiring token).

* **2026-11-09** - D9, D10, D11 confirmed as recommended (bearer-only transport
  with token-over-session precedence; principal-aware audit attribution; org
  cascade delete with `created_by ON DELETE SET NULL`).
* **2026-11-09** - D12 decided: tokens get **no owner bypass**, and when an owner
  presents a token the **token wins** over the owner session, so owners can test
  a token's real authority. Mandatory.

* **2026-11-09** - D8 confirmed: **owners only** mint tokens, via a hard
  `is_owner` gate (not delegable through an RBAC rule). Needed because minting
  attaches arbitrary roles (D2b).

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

* **2026-11-09** - Implementation started. Landed: migration
  `064_organization_access_tokens.sql` (tokens + immutable token-role join);
  gateway bearer validation (`db::validate_access_token`/`hash_access_token`,
  `access_token_auth_middleware` as the outermost auth layer,
  `AuthMethod::Token`, token identity headers on the proxy); and the owner-only
  management API (`GET/POST /organizations/{id}/access-tokens`,
  `GET/DELETE .../access-tokens/{token_id}`). `api` and `gateway` compile.

  Remaining (not yet implemented): (a) the API principal generalization so the
  API accepts `X-Caution-Token-ID`/`X-Caution-Organization-ID` instead of
  requiring a user id (`AuthContext`, `parse_auth_method`, `check_org_access`,
  `rbac_middleware`, `get_user_primary_org`); until then a token request gets a
  clean 401 at the API (`MissingUserId`). (b) `GET /access-tokens/me`. (c) D13
  handler support on `switch`/quorum routes. (d) CLI token path. (e) frontend.
  (f) tests.

* **2026-11-09** - Decided D13: tokens authorize the passkey-required routes
  (`apps switch`, quorum bundles). Updated the CLI survey and server-work list
  accordingly.

* **2026-11-09** - Completed the D6 CLI survey (section added), then corrected
  it: the main server work is the pervasive token-principal generalization of
  user-keyed org helpers, plus org-from-token for primary-org routes. Only
  passkey-required routes (`apps switch`, quorum-bundle writes) need a route
  variant or stay human-only.

* **2026-11-09** - Refined D7 expiry: optional (toggle, default 90 days) with a
  warning when disabled. Made `expires_at` nullable again in the sketch.

* **2026-11-09** - Confirmed D9/D10/D11; decided D12 (token wins over owner
  session so owners can test tokens; no owner bypass for tokens). All decisions
  D1-D12 now settled.

* **2026-11-09** - Confirmed D8: owner-only token minting (`is_owner`), not
  RBAC-delegable. Noted that role routes are RBAC-gated today but token minting
  is stricter.

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
