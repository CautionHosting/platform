# Legal document publishing & re-acceptance

How to publish a new/updated legal document (Terms of Service, Privacy Notice, or any
other document type) and get users re-prompted, tracked, and notified.

## Concepts

- **`legal_documents`** is the source of truth. Each row is one version of one document
  type. Exactly one row per `document_type` can be `is_active = true` at a time
  (`idx_legal_documents_one_active_per_type`).
- **`document_type` is an open string, not a fixed enum.** `terms_of_service` and
  `privacy_notice` are the two types in use today, but the mechanism works for any type —
  adding a new one (e.g. a DPA) needs no code change, only a publish.
- **`blocking` vs `ack`** — per-document flags, set at publish time:
  - `requires_blocking_reacceptance = true` ("blocking"): the API hard-rejects every
    request with `403 legal_acceptance_required` for a user who hasn't accepted the
    current active version. This is enforced server-side (`legal_middleware`, wired on
    the main authenticated router in `src/api/src/main.rs`), not just a UI nag — verified
    by hitting a protected endpoint directly with `curl`, bypassing the modal entirely.
  - `requires_acknowledgment = true` ("ack"): the modal still prompts the user, but the
    API is not gated. Nothing stops a user ignoring the prompt.
  - A document can be neither, either, or both. `terms_of_service` defaults to
    blocking-only; `privacy_notice` defaults to ack-only. Any other `document_type`
    requires you to pass `--blocking`/`--ack` explicitly — there's no default.
- **Signup already accepts whatever's active.** New users get an event recorded at signup
  for every currently-active document type (`src/gateway/src/db.rs::create_user`), so
  they never see the modal for documents that existed before they registered.
- **Title** is optional per document (`legal_documents.title`). If unset, the UI falls
  back to a humanized `document_type` (e.g. `data_processing_agreement` →
  "Data Processing Agreement").
- **"No record for this type" means two different things — the code has to tell them
  apart.** A user with zero legal events at all predates legal tracking entirely and is
  deliberately never retroactively gated. A user *with* other legal history (e.g. accepted
  ToS at signup) but no event for a specific type just means that type is newer than them —
  they *must* be gated, otherwise a newly-published document type would never gate anyone.
  This is `user_predates_legal_tracking()` in `src/api/src/legal.rs`, threaded into
  `compute_document_status`. Get this wrong and either legacy accounts get incorrectly
  locked out, or new document types silently gate no one — there's a regression test
  (`test_new_document_type_gates_user_with_other_legal_history`) guarding the latter.

## Publishing a new version

Source content lives in the `caution/website` repo (e.g. `terms.md`, `privacy.md`). A
publish ties a `legal_documents` row to a specific commit + file in that repo via a
content hash, so re-publishing identical content is rejected (idempotent).

```bash
./utils/admin publish-legal-doc \
  --website-repo /path/to/caution/website \
  --document-type terms_of_service \
  --source-path terms.md \
  --commit <git-sha-in-website-repo> \
  --version 2026-08-01 \
  --url https://caution.co/terms.html \
  --effective-at 2026-08-01 \
  --blocking true
```

This does two things:
1. **Ingest + activate** — inserts the new row (content-hash deduped against prior
   versions of the same `document_type`), deactivates the previous active row of that
   type, activates the new one. Existing users become "pending" for it immediately.
2. **Notify dry-run** — shows how many verified-email users would be emailed. Nothing is
   sent yet.

Publishing a new **document type** for the first time needs `--title`, `--blocking`, and
`--ack` (no defaults exist for unknown types):

```bash
./utils/admin publish-legal-doc \
  --website-repo /path/to/caution/website \
  --document-type dpa \
  --source-path dpa.md \
  --commit <sha> --version 2026-09-01 \
  --url https://caution.co/dpa.html --effective-at 2026-09-01 \
  --title "Data Processing Agreement" \
  --blocking true --ack false
```

### Sending the notification email

`publish-legal-doc` only dry-runs the notify step. Re-run with `--confirm` to actually
send, or use `send-legal-notices` standalone against an existing document:

```bash
./utils/admin publish-legal-doc ... --confirm      # same args as above, plus --confirm
# or, for a document already published:
./utils/admin send-legal-notices <document-id> --send --confirm
```

Only users with a **verified email** are eligible. Re-running is a no-op for anyone
already sent to (deduped by document + recipient) — safe to re-run after a partial
failure.

### Idempotent republish

Publishing identical content again (same `document_type` + same file bytes) fails with
"already exists" — this is the content-hash dedupe working as intended, not a bug.

## Checking status

```bash
./utils/admin list-legal-docs                   # all versions, active flags, blocking/ack
./utils/admin user-legal-status <user-id>        # one user's event history + current status
```

## What a user sees

- **Blocking or ack document pending**: full-screen modal on next dashboard login, listing
  every pending document with a link to review it and an "Accept and continue" button.
  Declining offers "Back to review" or "Log out" — the app is inert behind it.
- **Only ack-pending, non-blocking**: same modal, but the API isn't gated — declining and
  navigating away doesn't get re-blocked by the server (only by seeing the modal again on
  next login).
- **No email on file**: still gets the modal; just never receives the notification email.

## Testing changes

- `tests/e2e/test_legal_tracking.sh` (via `make test-e2e-legal`) covers the full flow
  end-to-end, including a synthetic third document type (`dpa`) to prove the mechanism
  generalizes — not just that the two built-in types still work.
- For manual verification against a running dev stack, see the `caution-orbstack` /
  `caution-local-dev` skills for bringing the stack up, then exercise the flow through the
  dashboard + `utils/admin` as above. To confirm blocking is enforced *server-side* (not
  just the modal), grab a pending user's session (`caution_session` cookie value = the
  `auth_sessions.session_id`) and hit a protected endpoint directly:
  ```bash
  curl -i -H "X-Session-ID: <session-id>" http://localhost:8000/api/billing/subscription
  # expect 403 {"code":"legal_acceptance_required","document_type":"..."}
  ```

## Known limitation

Signup has no user-facing acceptance screen — `create_user` silently records an event for
every currently-active document type (including any newly-added one) without ever showing
the user what they're agreeing to. This is a UX gap worth revisiting if a document type
needs an actual, visible confirmation at signup rather than an implicit one, but it is not
a blocking-enforcement bug: the events recorded are real and match what the login-gate
modal would have collected.
