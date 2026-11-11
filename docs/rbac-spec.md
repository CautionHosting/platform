# Role-Based Access Control (RBAC) Specification

Status: **normative**. This specification is the single source of truth for the
platform's role-based access control. It supersedes the former "RBAC Bible".

It describes the intended and implemented behavior of the RBAC subsystem:
the organization membership model, per-organization roles and route-based rules,
the request evaluation algorithm, the management API, and the ownership
invariants that bound privilege escalation.

## 1. Scope

This specification covers:

* the `owner` / `member` organization membership model and its role predicates;
* per-organization RBAC roles and their route-based rules;
* the assignment of roles to organization members;
* the request-time authorization algorithm enforced on the
  organization-scoped route group;
* the RBAC management HTTP API;
* the ownership invariants that are **not** expressible as RBAC rules.

It does not cover: authentication (see the authentication and access-token
specifications), billing semantics, or the AWS IAM / deployment `live` /
`candidate` concepts that also use the word "role". Those are unrelated to
organization RBAC.

## 2. Conformance and terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **MAY**, and **OPTIONAL** are to be interpreted as
described in RFC 2119.

* **Organization** - the tenancy boundary. A user belongs to exactly one
  organization (`046_one_organization_per_user.sql`).
* **Member** - a row in `organization_members`, joining one user to one
  organization.
* **Owner** - a member whose membership role is `owner`. Owners hold god powers
  over the organization and bypass RBAC. `owner` is **not** an RBAC role.
* **Member (role)** - a member whose membership role is `member`, the RBAC
  baseline. After enforcement, a member with no RBAC roles can reach nothing
  beyond the routes that sit outside the RBAC middleware.
* **RBAC role** - a named, organization-owned bundle of rules.
* **Rule** - an `effect + method + path (+ objects + priority)` tuple inside a
  role.
* **Operation** - a permission-checked action, modeled as an HTTP
  `method + route-template` pair.

The membership role enum is `user_role ('owner','member')`
(`001_initial.sql`). The former `admin` and `viewer` roles were removed
(`061_remove_admin_role.sql`, `062_remove_viewer_role.sql`); existing rows were
reassigned to `member`.

## 3. Membership model

RBAC-M1. A user MUST belong to exactly one organization.

RBAC-M2. Every organization member MUST have a membership role of `owner` or
`member`.

RBAC-M3. The only role predicates exposed by the membership model are:

* `is_owner` - true iff the membership role is `owner`;
* `can_manage_org` - true iff the membership role is `owner` (kept as a distinct
  name for the RBAC-replacement seam).

RBAC-M4. An `owner` member MUST bypass RBAC evaluation entirely (see RBAC-A1).

RBAC-M5. The following operations MUST be owner-only and MUST NOT be delegated
through any RBAC rule:

* granting the `owner` role (`add_member`, `update_member`);
* demoting an existing owner (`update_member`);
* removing an owner (`remove_member`);
* removing the last owner (`remove_member`);
* deleting the organization (`delete_organization`).

These checks are hard `is_owner` gates. A rule can therefore never be used to
escalate to ownership.

## 4. Data model

Roles and rules are per-organization. There are no global built-in roles
(decision D-RBAC-3). Schemas are defined in `migrations/063_rbac_tables.sql`.

### 4.1 `rbac_roles`

RBAC-D1. A role MUST carry `organization_id`, `name`, and optional
`description`, and MUST be unique by `(organization_id, name)`.

RBAC-D2. A role MUST be uniquely addressable by `(organization_id, id)` so that
it can be a composite foreign-key target.

RBAC-D3. A role MUST be deleted when its organization is deleted (cascade).

### 4.2 `rbac_role_rules`

RBAC-D4. A rule MUST carry `role_id`, `effect`, `method`, `path`, optional
`objects`, and `priority`.

RBAC-D5. `effect` MUST be `allow` or `deny`.

RBAC-D6. `method` MUST be one of `GET`, `POST`, `PUT`, `PATCH`, `DELETE`,
`HEAD`, `OPTIONS`, or `*`.

RBAC-D7. `path` MUST be `*`, `/`, or start with `/`.

RBAC-D8. `objects`, when present, MUST be a JSON object.

RBAC-D9. `priority` MUST be greater than or equal to `0`.

RBAC-D10. A rule MUST be unique by `(role_id, effect, method, path)`.

RBAC-D11. A rule MUST be deleted when its role is deleted (cascade).

RBAC-D12. `rbac_role_rules` and `rbac_member_roles` MUST carry `updated_at`
maintained by the standard `update_updated_at()` trigger, matching
`rbac_roles`.

### 4.3 `rbac_member_roles`

RBAC-D13. An assignment MUST be keyed by `(organization_id, user_id, role_id)`.
A member MAY hold any number of roles.

RBAC-D14. An assignment MUST reference an existing member via the composite
foreign key `(organization_id, user_id) -> organization_members`.

RBAC-D15. An assignment MUST reference a role in the same organization via the
composite foreign key `(organization_id, role_id) -> rbac_roles`. This MUST make
cross-organization role assignment impossible.

RBAC-D16. An assignment MUST record `granted_by` (user id) as attribution, with
`ON DELETE SET NULL`. Attribution is not authority and MUST NOT affect
evaluation.

RBAC-D17. An assignment MUST be deleted when its member or role is deleted
(cascade).

## 5. Authorization model

The enforcement point is `rbac_middleware` (`src/api/src/rbac/mod.rs`), layered
on the organization-scoped `resource_routes` group after authentication, legal,
and onboarding.

### 5.1 Owner bypass and rule collection

RBAC-A1. If the caller is a user whose membership role is `owner`, the request
MUST be allowed with no further rule evaluation.

RBAC-A2. Otherwise the middleware MUST collect the effective rule set:

* for a **user** caller: all rules of all roles assigned to that user's
  membership;
* for a **token** caller: all rules of all roles attached to the token.

RBAC-A3. A token MUST NOT receive the owner bypass, regardless of any RBAC rule
(see the access-token specification). Owners are the only principals with a
bypass.

RBAC-A4. If the request has no matched route template, the request MUST be
denied.

### 5.2 Evaluation and precedence

RBAC-A5. A request MUST be denied when no collected rule matches it.

RBAC-A6. Among matching rules, the rule with the lowest `priority` (closest to
`0`) MUST decide the outcome.

RBAC-A7. When several matching rules share the lowest priority, a `deny` rule
MUST win (conflicts MUST fail closed).

RBAC-A8. A denied request MUST produce HTTP `403 Forbidden`. A failure to load
rules MUST produce HTTP `500`.

### 5.3 Rule matching

RBAC-A9. A rule matches on method when `method` is `*` or is equal to the
request method.

RBAC-A10. A rule matches on path when:

* `path` is `*` (matches any route), or
* `path` ends in `*` and the request's route template starts with the prefix
  before the trailing `*` (for example `/resources/*`), or
* `path` equals the request's route template exactly.

Path comparison MUST be against the axum route template (for example
`/resources/{id}/deployments`), not the concrete request path, so path
parameters are never parsed for matching.

RBAC-A11. A rule with no `objects` MUST match any path-parameter values.

RBAC-A12. A rule with `objects` MUST match only when, for every key in the
object, the corresponding request path parameter exists and matches the allowed
value array. A value array element matches when it is the string `*` or equals
the parameter value. Only arrays are valid; a bare string, number, or nested
object MUST never match (fail closed).

### 5.4 Object constraints are admission-only

RBAC-A13. Object constraints MUST be evaluated against the actual request path
parameters (`RawPathParams`). The middleware MUST NOT read resource state and
MUST NOT filter list responses.

RBAC-A14. For a path with parameters, a rule MUST declare `objects` covering
every parameter; rule creation MUST fail when it is absent or does not cover
exactly the path's parameters. For a path without parameters, `objects` MUST be
omitted.

RBAC-A15. Non-object path parameters (for example an organization id) MUST use
`["*"]` uniformly.

### 5.5 Coverage

RBAC-A16. There MUST be no exempt routes inside the RBAC middleware. Any route
the evaluation does not admit MUST be denied.

RBAC-A17. Public, onboarding, organization-bootstrap, and internal route groups
MUST sit outside the RBAC middleware by construction rather than by exemption.
In particular, the organization-bootstrap group (including
`/organizations` list/create and `/access-tokens/me`) is not RBAC-gated.

RBAC-A18. The role editor SHOULD seed every new role with an allow rule for
`/users/me` so a role-bearing member can load their own account.

## 6. Management API

The management API is implemented in `src/api/src/rbac/handlers.rs` and mounted
under `/organizations/{id}`.

RBAC-P1. The following routes MUST be provided. They are ordinary RBAC-gated
routes: owners bypass; a member reaches them only with a matching rule.
Every handler MUST additionally require membership in the organization named in
the path, so a broadly scoped rule (for example `["*"]`) cannot cross tenants.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/organizations/{id}/roles` | list roles |
| `POST` | `/organizations/{id}/roles` | create a role with its rules |
| `GET` | `/organizations/{id}/roles/{role_id}` | read a role with its rules |
| `PUT` | `/organizations/{id}/roles/{role_id}` | replace a role (name, description, full rule set) |
| `DELETE` | `/organizations/{id}/roles/{role_id}` | delete a role |
| `GET` | `/organizations/{id}/roles/{role_id}/rules` | list rules |
| `POST` | `/organizations/{id}/roles/{role_id}/rules` | create a rule |
| `GET` | `/organizations/{id}/roles/{role_id}/rules/{rule_id}` | read a rule |
| `PATCH` | `/organizations/{id}/roles/{role_id}/rules/{rule_id}` | update a rule |
| `DELETE` | `/organizations/{id}/roles/{role_id}/rules/{rule_id}` | delete a rule |
| `GET` | `/organizations/{id}/members/{user_id}/roles` | list a member's roles |
| `POST` | `/organizations/{id}/members/{user_id}/roles` | attach a role |
| `DELETE` | `/organizations/{id}/members/{user_id}/roles/{role_id}` | detach a role |
| `GET` | `/routes` | the protected-route inventory (see RBAC-P5) |

RBAC-P2. `POST /roles` and `PUT /roles/{role_id}` MUST accept the complete role,
including a `rules` array, validate all rules together, reject duplicates within
the set (the `(effect, method, path)` tuple covered by the table unique
constraint), and write the role and its rules in a single transaction.

RBAC-P3. `PUT /roles/{role_id}` MUST be a full replacement of name, description,
and the complete rule set.

RBAC-P4. Every rule written through the API MUST pass `validate_rule`
(section 7). A validation failure MUST be reported with the offending rule's
index and a typed, descriptive error.

RBAC-P5. `GET /routes` MUST return the `method + route-template` inventory of the
protected routes (`src/api/src/rbac/inventory.rs`). This inventory is
maintained by hand alongside the `resource_routes` group; a rule's `path` is
not validated against it on write, so route/rule drift fails closed rather than
being rejected.

RBAC-P6. Writes MUST NOT branch on unique-constraint violations. Inserts MUST
use `ON CONFLICT ... DO NOTHING`, and updates MUST check for a collision first,
so a conflict surfaces as a no-row result rather than a database error.

## 7. Rule validation

`validate_rule` MUST reject a rule unless all of the following hold. Each
failure MUST map to a distinct error variant:

RBAC-V1. `effect` is `allow` or `deny`.
RBAC-V2. `method` is a known method or `*`.
RBAC-V3. `path` is non-empty and is `*` or starts with `/`.
RBAC-V4. `priority` is greater than or equal to `0`.
RBAC-V5. When the path has no `{param}` placeholders, `objects` MUST be absent.
RBAC-V6. When the path has placeholders, `objects` MUST be present, be a JSON
object, cover exactly the set of placeholders (no more, no fewer), and map each
placeholder to an array of strings.

The set validator additionally MUST reject duplicate `(effect, method, path)`
tuples within one create/replace payload.

## 8. Non-goals

RBAC-N1. Object-level or dynamic ownership is not supported. `objects` is a
static per-parameter list; no resource state is consulted.

RBAC-N2. List responses are not filtered by RBAC. A rule grants or denies the
listing operation as a whole.

RBAC-N3. Deadline/expiry, role inheritance, and built-in global roles are not
part of the model.

## 9. Conformance criteria

An implementation conforms when:

1. it enforces RBAC-A5 through RBAC-A15 for user principals, and RBAC-A3 plus
   RBAC-A2 for token principals;
2. owner bypass matches RBAC-A1 and never applies to tokens (RBAC-A3);
3. the ownership invariants in RBAC-M5 are enforced server-side;
4. the management API in section 6 is available and tenant-scoped per RBAC-P1;
5. rule validation matches section 7;
6. the schema matches section 4.

## Appendix A. Requirement-to-source map (non-normative)

| Requirement | Source |
|-------------|--------|
| Membership predicates | `src/api/src/types.rs` (`UserRole`) |
| Evaluation + matching | `src/api/src/rbac/mod.rs` (`decide`, `rule_matches`, `path_matches`) |
| Middleware + rule collection | `src/api/src/rbac/mod.rs` (`rbac_middleware`) |
| Middleware layering | `src/api/src/main.rs` (`resource_routes`, layer stack) |
| Route inventory | `src/api/src/rbac/inventory.rs` |
| Management API | `src/api/src/rbac/handlers.rs` |
| Rule validation | `src/api/src/rbac/handlers.rs` (`validate_rule`) |
| Schema | `src/api/migrations/063_rbac_tables.sql` |
| Owner-only invariants | `src/api/src/organizations.rs` |

## Appendix B. Design decisions (non-normative)

Numbered decisions retained as stable anchors. Code comments reference these by
identifier.

* **D-RBAC-1** - A member may hold any number of roles (join table).
* **D-RBAC-2** - Allow + deny with priorities: among matching rules the lowest
  priority wins; equal-priority conflicts resolve to deny (fail closed); no
  match denies. Priority is non-negative, default 0.
* **D-RBAC-3** - Roles are per-organization only; no global built-ins.
  `rbac_roles.organization_id` is `NOT NULL` and a composite FK on
  `rbac_member_roles` prevents cross-organization assignment.
* **D-RBAC-4** - Role/rule management routes are ordinary RBAC-gated routes, so
  a rule may grant them; there is no separate router group. Escalation is
  bounded by the owner-only checks in RBAC-M5.
* **D-RBAC-5** - Every parameter in a rule's path requires an `objects` entry;
  non-object parameters such as an org id use `["*"]`.
* **D-RBAC-6** - Object scoping is admission-only; lists are not filtered and no
  resource state is consulted.
* **D-RBAC-7** - Rule paths support `*` (any route) and trailing-`*` prefixes
  (`/resources/*`); the path check accepts `*` and `/`.
* **D-RBAC-8** - Route/rule drift has no special handling; a typo fails closed.
  `GET /routes` exposes a hand-maintained inventory for the editor.
* **D-RBAC-9** - No baseline backfill. Owners bypass RBAC and existing
  memberships are expected to be `owner`, so nothing needed migrating; non-owner
  members created later must be given roles explicitly.
* **D-RBAC-10** - Deny by default with no exempt routes. A new role is seeded by
  the UI with an allow for `/users/me`.

## Appendix C. Implementation status (non-normative)

Landed and verified against PostgreSQL 18.6: schema (`063_rbac_tables.sql`),
enforcement middleware and matcher (unit-tested), the management API, the route
inventory, and the frontend role editor.

Outstanding work, grouped:

* **Functional.** New members have no roles: invitations default to `member` and
  nothing is assigned on acceptance, so an invited user is denied everything
  (including `/users/me`) until an owner assigns a role. Decide whether to
  auto-assign a baseline role on acceptance or to add a role field to
  `InviteMemberRequest`. Also: the role-management routes are RBAC-gated but the
  dashboard shows role controls only to owners (`isOwner`), so a delegated
  member has no UI; and enforcement has no rollout switch (feature flag or
  log-only mode) for soak and rollback.
* **Deferred by decision.** No object-level ownership (RBAC-N1); route/rule
  drift is hand-synced (RBAC-P5).
* **Verification.** No end-to-end HTTP run (auth -> RBAC middleware -> handler)
  and no DB-backed tests for the handlers; unit tests plus manual `psql` only.
* **Cleanup.** The UI only performs whole-role replace; role lists show no rule
  counts; no operator-facing docs for writing rules; and RBAC inputs temporarily
  reuse the `.email-input` class pending a scoped width fix.
