# Certificate-service hardening validation

2026-09-18: implementation is uncommitted; no deployment or live Nitro run.

- Platform base: `b9a3188751f839d0b00195dd4983f290b0087fab`; changed implementation/config/test snapshot SHA-256: `67ed74076dbe77646ab9ea6eb36d2261842a1ccb7b4026c2d015867e66b09a94`.
- Locksmith base: `cd0f5fd44e252114c3bd160edd84c119b99263d0`; changed implementation/config/test snapshot SHA-256: `deb9fde4dbd59a92f89f5985331cb415c4f5f9dff69db5e4b47fbb92091a0331`.
- API quorum tests: 18 passed, one separate database test intentionally ignored.
- Existing `make test-quorum-mock`: passed in an isolated copy with local Cargo patches for the edited Locksmith and model crates. Includes disposable PostgreSQL, signed mixed/WebAuthn creation, recovery, relay rejection, token-authenticated certificate requests and no token forwarded to Keymaker.
- Locksmith default/unsafe library suites: 38/39 passed; certificate-service suites: 18/19 passed. Production service binary check and encrypted deployment-input regression passed.

Actual Platform dependency pins were preserved. See Locksmith's
`docs/hardening-validation.md` for snapshot file lists and test details, and
`docs/service-hardening.md` for exact provisioning, deployment and manual tests.

Keep the same root bundle and CA. Configure the shared backend/vault token,
redeploy Platform and the combined certificate/recryptor service, recover its
existing root, update verified PCR policies, and repeat recovery after restart.
These local/synthetic results do not establish real Nitro acceptance.
