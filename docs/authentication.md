# Passkey usage history

The Authentication page's **Last used** value records successful passkey
verification for login (including QR login) or a signed operation (including
QR signing). Ordinary requests through an existing session do not update it.
Registration alone does not count. Signing counts once the gateway verifies
and records the assertion, even if the operation subsequently fails; merely
forwarding an assertion from a phone does not count.

Usage is stored on the credential and survives logout and expired-session
cleanup. The gateway rejects login or signing if it cannot persist the usage
timestamp, before issuing a session or executing the signed operation.
Concurrent writes cannot move the timestamp backwards.

**Usage unknown** means no verification timestamp is available. It does not
mean the key has never been used. Migration `053_passkey_last_used.sql` recovers
the latest retained signing-audit timestamp for each user and credential.
Historical logins without retained verification evidence cannot be recovered,
so backfilled history may omit later logins. Session activity, credential
creation, and general modification timestamps are deliberately not used.

Apply the additive database migration before deploying the updated gateway
and frontend. Rebuild the frontend before packaging the gateway. The
`/passkeys` response retains its nullable `last_used_at` timestamp string;
the value now describes credential verification rather than session activity.

## Regression checks

Run `cargo test -p gateway` and, from `frontend`, `npm test` and `npm run build`.
The database regressions are opt-in: set `DATABASE_URL` to a disposable
Postgres instance whose role can create databases, then run
`cargo test -p gateway passkey_usage_tests -- --ignored`. Each test creates
its own database and checks backfill, session-independent retention, monotonic
writes, and persistence errors. Never point these tests at a deployed database.
