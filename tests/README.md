# Testing

This repo uses several test tiers. Prefer the fastest tier that covers the change, and run broader tiers before merging risky changes.

## Fast Rust tests

```sh
make test-fast
```

`make test-fast` runs `cargo test --workspace`. It is intended for unit tests and lightweight route/middleware tests that do not require Docker, AWS, Paddle, or a live Postgres instance.

New behavior should usually start here:

- Pure logic belongs in crate unit tests.
- Auth, validation, and route wiring should use small Axum/Tower harnesses where possible.
- Tests that intentionally avoid touching the database should use lazy pools pointed at an unreachable local address and assert the middleware/route returns before a DB query.

## Integration tests

Use integration-style tests when behavior depends on migrated database state or multiple services. Prefer reusable fixtures over ad hoc setup in each test.

Recommended fixture shape:

- migrated test Postgres
- user/session/org helpers
- authenticated request helper
- cleanup scoped to the test database/schema

## End-to-end tests

The shell e2e tests under `tests/e2e/` exercise full service flows and are heavier than `make test-fast`.

Current targets include:

```sh
make test-e2e
make test-e2e-legal
make test-e2e-billing
make test-e2e-billing-gates
make test-e2e-byoc
make test-e2e-builder
```

Use e2e tests for full CLI/service/cloud flows. Keep auth, billing, ownership, and validation edge cases in fast Rust tests when practical so failures are localized and quick to reproduce.
