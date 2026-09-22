# Deploying secrets: operator runbook

For existing unversioned PGP bundles, follow [Legacy V0 import and recovery](legacy-v0.md).

Status, 21 September 2026: implemented at Platform [`e38a05b`](https://codeberg.org/caution/platform/commit/e38a05bf54dcd51f48971cbf2ca70884ffd8e812),
Locksmith [`2da3be5`](https://codeberg.org/caution/locksmith/commit/2da3be50bebd2dfdc4d0d3a94d05f55be02e910c)
and Bootproof [`821b5c6`](https://codeberg.org/caution/bootproof/commit/821b5c63e80f082f6d67ba3695c11416933489ec).
Platform's client and default enclave-runtime pins are aligned.

Current V1 creation, proof verification, PGP/passkey/mixed recovery, native and
browser approval, issuance bearer authentication and certified holder-index
checks are implemented. Local/synthetic validation is recorded in
[share recovery](share-recovery.md); consolidated live acceptance at these exact
revisions is **not yet recorded**. Legacy bundle migration uses the separate
[import guide](legacy-v0.md). ImportedV0 needs no Keymaker policy in the CLI,
runtime or image preflight. Rebuild the Platform builder to use the format-aware
check; V1 still requires its independently trusted generation-proof policy.

The local V1 contract patch additionally requires critical, CA-signed
organization/bundle notations in API and recryptor verification. Issuance already
sets these flags; nonconforming certificates previously accepted will now fail.
This patch is not yet published or deployed. Before shipping it, publish Locksmith,
align Platform's dependency/mock/runtime pins and verify the rebuilt service PCRs.

## 1. Caution: provision Keymaker and custody

Use separate initialized Caution application checkouts for **Keymaker** and the
**combined certificate service + recryptor**. Build reviewed, non-debug images.
Keymaker uses Locksmith's root `Containerfile` and `caution.hcl`; deploy with
`git push caution HEAD:main`, then establish its PCR policy with `caution verify`.
Distribute independently verified policies; never trust PCRs copied from a
failing endpoint.

**Remaining: deploy and validate Keymaker's automatic enclave-reboot lifecycle.**
The default `selfnuke` build already schedules reboot after accepting a valid
generation request. Until return-to-service is demonstrated, provision a fresh
Keymaker for each new quorum. Serialization belongs to Keymaker. Recovery and
secret updates using an existing bundle consume no Keymaker.

For custody upgrades, retain the existing external-PGP root bundle, CA and holder
keys. For a new root only, collect independent Caution holders' public keys in
`root-holders.asc`; this example is 2-of-2:

```sh
caution secret init root-holders.asc --threshold 2 \
  --keymaker-url "$ROOT_KEYMAKER_URL" \
  --keymaker-pcr-policy /path/to/verified-keymaker-policy.json --no-upload
jq -r '.data.public_key' .caution/quorum-bundle.json > .caution/caution-ca.asc
```

Keep private keys with their holders. Preserve the public/proofed bundle and its
policy for every restart. The root must be recoverable without the custody
service: do not bootstrap it with that service's passkeys. Production root
ceremony, named custodians, organizational recovery drills and long-term rotation
procedures are later work; this first test retains the actual quorum and enclave
security boundaries without fixing those organizational arrangements.

## 2. Caution: deploy and unlock certificate service + recryptor

In the dedicated **whole Locksmith checkout**, use
[`examples/certificate-service`](https://codeberg.org/caution/locksmith/src/commit/2da3be50bebd2dfdc4d0d3a94d05f55be02e910c/examples/certificate-service).
Install its `caution.hcl` at the checkout root. Preserve existing configuration
on upgrades; for initial setup, copy its release-config example and set the exact
registered Platform RP ID and HTTPS origin.

Required `.caution/` inputs:

| Inputs | Purpose |
| --- | --- |
| `quorum-bundle.json`, `keymaker-pcr-policy.json`, `caution-ca.asc` | Existing custody root and its verified generation policy/public CA |
| `release-config.json`, `release-keymaker-pcr-policy.json` | Platform RP/origin and approved generation policies for application bundles |
| `secrets/PUBLIC_CERTIFICATE_SERVICE_TOKEN.asc` | Encrypted issuance token |

Generate a private 32-byte hex token and encrypt it with `caution secret encrypt
PUBLIC_CERTIFICATE_SERVICE_TOKEN --env-file /private/path/custody.env`.
Set the identical value in the Platform API's private environment. The
[token provisioning recipe](https://codeberg.org/caution/locksmith/src/commit/2da3be50bebd2dfdc4d0d3a94d05f55be02e910c/docs/service-hardening.md)
has the exact commands. Never commit plaintext tokens or private keys.

Commit reviewed public/encrypted deployment inputs, then:

```sh
python3 examples/certificate-service/check-inputs.py
git push caution HEAD:main
caution verify
caution secret send-shard --bundle .caution/quorum-bundle.json
# Repeat with each required root holder's own card or --keyring.
```

`caution verify` saves trusted application PCRs automatically. The HTTP service
starts after root recovery; `/health` should return 200. Serve
issuance over HTTPS. Its bearer token grants issuance admission only; passkey
authorization is still required for share release. HTTPS termination sees the
token and is part of that trust boundary.

## 3. Caution: configure Platform

Rebuild/redeploy API, gateway, CLI and application images at the aligned revisions;
review any `LOCKSMITH_COMMIT` override. Configure:

| Process | Configuration |
| --- | --- |
| API: generation | `KEYMAKER_URL`, `KEYMAKER_PCR_POLICY_PATH` |
| API: issuance | `PUBLIC_CERTIFICATE_SERVICE_URL` (HTTPS), `PUBLIC_CERTIFICATE_SERVICE_TOKEN`, `PUBLIC_CERTIFICATE_PCR_POLICY_PATH`, `CAUTION_CA_CERT_PATH` |
| Gateway: browser approval | `RECRYPTOR_PCR_POLICY_PATH` |

API certificate and gateway recryptor policies trust the verified custody image.
The CA file is its existing public root. Mount policy/CA files read-only and
recreate affected processes to load changed environment or mounts. Endpoints
remain operator-configured. Give holders the custody URL and its verified
recryptor policy; the live custody policy has one non-expiring PCR0/1/2 set.

## 4. Application owner and holders: deploy a secret

**Dashboard alternative:** in **Secrets → Create quorum bundle**, choose
organization members (PGP/passkey/mixed), optionally adding external holders with
**Add PGP holder** one public certificate at a time. Both types can coexist, up to
10 holders total in the dashboard (CLI/API limits are unchanged). Set the **Quorum
threshold**, initially 2, between 1 and the selected holder count; review and
authorize creation with your passkey. Download the complete
bundle JSON and place it at `.caution/quorum-bundle.json` in the initialized app
checkout, alongside the independently verified `.caution/keymaker-pcr-policy.json`.
Continue below at `caution secret encrypt`; do not generate a second bundle.
The new bundle opens at the top of the searchable list with **Use this bundle**
guidance: download, policy prerequisites, a copyable encryption example and links
to packaging and holder approvals. Reopen that disclosure on any existing bundle.
It is guidance only; it does not track deployment or recovery completion.
The dashboard only creates the bundle; encryption, image packaging, deployment
and holder recovery still follow the CLI steps below. On an uncertain creation
result, use **Check bundles** before a new attempt. See
[dashboard creation](org-user-quorums.md#dashboard-creation) for limits and details.

In an initialized application checkout, register the holders' PGP keys/passkeys
with Platform first. This example selects two organization users and requires both:

```sh
# Use hosted creation; a local KEYMAKER_URL would select direct PGP-only mode.
env -u KEYMAKER_URL caution secret init \
  --holder alice=external-pgp --holder bob=webauthn --threshold 2 \
  --keymaker-pcr-policy /path/to/verified-keymaker-policy.json
caution secret encrypt DATABASE_URL --env-file /private/path/app.env
```

Credentials are snapshotted into the bundle; multiple passkeys still count as one
holder. Copy these inputs into the final application image:

```dockerfile
COPY .caution/quorum-bundle.json /etc/caution/bundle.json
COPY .caution/keymaker-pcr-policy.json /etc/caution/keymaker-pcr-policy.json
COPY .caution/secrets/ /etc/caution/secrets/
```

Normalize public/encrypted file modes to `0644` and directories to `0755` in the
build stage. Add `DATABASE_URL = env::vault("DATABASE_URL")` to the default unit's
HCL `env` map. `env::vault` does not copy files; do not use `build.binary`, which
discards them. Commit the public/encrypted inputs, keeping plaintext outside Git.

```sh
git push caution HEAD:main
caution verify
caution secret send-shard --holder alice
# Bob runs separately; compare the CLI/browser approval codes before approving.
caution --qr secret send-shard --holder bob \
  --recryptor-url "$CUSTODY_URL" \
  --recryptor-pcr-policy /path/to/verified-recryptor-policy.json
```

Use certificate fingerprints if username lookup is unavailable. Alice uses her
own smartcard or `--keyring`; omit `--qr` for Bob's native USB FIDO2 approval.
The application remains locked below threshold and starts with the decrypted
environment at threshold. Wait for receiver acknowledgement, not just browser
approval. See [share recovery](share-recovery.md) for troubleshooting.

## Restarts, acceptance and remaining work

| Event | Operator action |
| --- | --- |
| Application enclave restart | Holders recover the same application bundle again |
| Custody HTTP-process restart | Root remains in Keyfork; restart pending approvals |
| Custody enclave restart | Caution root holders recover first; retry application approvals afterward |
| New secret value, same bundle | Encrypt, rebuild/deploy, verify new app PCRs, recover quorum |

Custody lasts for the enclave lifetime. Retain the existing root/CA on upgrades;
update service policies only after verifying the replacement image.
