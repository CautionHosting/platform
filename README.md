**GitHub users:** This repo is mirrored from <a href="https://codeberg.org/caution/platform" target="_blank">Codeberg</a>. Please open issues and PRs there.

**Hosted version:** A hosted deployment is available in closed alpha at <a href="https://dashboard.caution.co" target="_blank">dashboard.caution.co</a>. To request a registration code, <a href="mailto:info@caution.co?subject=Caution%20Alpha%20Access&body=Hi%2C%0A%0AI%20was%20reviewing%20your%20docs%20at%20https%3A%2F%2Fcodeberg.org%2Fcaution%2Fplatform%20and%20noticed%20that%20you%20are%20also%20offering%20a%20closed%20alpha%20for%20hosted%20deployments.%20Can%20I%20please%20get%20a%20code%20to%20try%20it%20out%3F%0A%0AMy%20details%3A%0AMy%20name%3A%20%0AMy%20company%20name%3A%0A%0AThank%20you">contact info@caution.co</a>.

# Caution Platform

> **Warning: Alpha Software**
>
> This software is in early alpha. It may introduce backwards-incompatible changes, has not undergone security audits, and is not production ready. Use at your own risk.

This software is a cloud hosting management platform that builds and deploys [verifiable](#verifiable-enclaves) secure enclaves using the AWS Nitro System, based on <a href="https://git.distrust.co/public/enclaveos" target="_blank">EnclaveOS</a>.

### Verifiable Enclaves

An enclave is **verifiable** when you can independently confirm that the code running inside it matches the source code you expect. This is achieved through:

1. **Reproducible builds** — Reproducible builds force software to be bit-for-bit identical when built from the same source code, and eliminate certain categories of supply chain attacks. It allows for integrity verification, without which software is opaque and difficult to verify.
2. **Cryptographic attestation** — The enclave hardware generates a signed attestation document containing measurements (PCR hashes) of the running code.
3. **Independent verification** — You can compare your locally-built measurements against the attestation from a running enclave to prove they match.

## Getting Started

### Prerequisites

- Docker with <a href="https://docs.docker.com/engine/storage/containerd/#enable-containerd-image-store-on-docker-engine" target="_blank">containerd</a> enabled
- GNU Make
- Bash
- x86_64 system for running the platform services; the CLI also supports macOS on Apple silicon

### 1. Bootstrap AWS infrastructure

Follow the [bootstrapping guide](infra-bootstrap/README.md) to create the required AWS infrastructure (S3 buckets, IAM user, DynamoDB table).

### 2. Run the platform

Set up `.env` file using the credentials from bootstrapping:

```bash
cp env.example $HOME/.config/caution/.env
# Edit .env with your AWS credentials and bucket names from bootstrapping
```

Install the CLI with the local host toolchain. This is the default on every
supported platform and supports local PC/SC for Locksmith shard submission:

```bash
make install-cli
```

To explicitly build and install the reproducible StageX CLI on Linux/x86_64:

```bash
make install-cli-stagex
```

See [src/cli/README.md](src/cli/README.md) for additional installation options,
native dependencies, signature verification, and the current StageX PC/SC
limitation.

Start the platform services:

```bash
make up
```

### 3. Deploy an app

1. Register using Passkey (via terminal or web browser):

   ```bash
   caution register
   ```

2. Add an SSH key (can be done in browser as well):

   ```bash
   caution ssh-keys add --title <name_of_key> --key <pub_key_string>
   ```

3. Initialize a project within a Dockerized repo:

   ```bash
   caution init
   ```

   This writes a `caution.hcl` template when one does not already exist and
   configures the `caution` git remote. Caution remote builds run Docker from
   the repository root, using `build.containerfile` when configured, then a
   repo-root `Containerfile`, then a repo-root `Dockerfile`. Put setup,
   compilation, asset builds, and runtime packaging in that Containerfile or
   Dockerfile so the build inputs are explicit and reproducible.

   The <a href="https://codeberg.org/Caution/hello-world-enclave" target="_blank">hello-world-enclave</a> repo is a good test app to deploy.

4. Build and deploy:
   ```bash
   git push caution main
   ```

   Long-running builds use protocol-level SSH keepalives so quiet deployment
   phases do not require client-side keepalive configuration.

#### Enclave-terminated HTTPS (TLS mode, implemented by Caddy)

To terminate standard HTTPS inside the enclave without changing clients, select
TLS mode on the HTTP ingress. The enclave currently implements this mode with
Caddy:

```hcl
network {
  ingress {
    cidr_ipv4   = "0.0.0.0/0"
    port        = 8080
    ip_protocol = "tcp"
  }
  egress { cidr_ipv4 = "0.0.0.0/0" }

  http {
    domain = "app.example.com"
    port   = 8080
    e2e_encryption { mode = "tls" }
  }
}
```

The domain must resolve directly to the deployed host, the HTTP port must have
an ingress rule, and outbound egress is required for Let's Encrypt. Disable any
CDN or proxy TLS termination. Caddy publishes the verified leaf certificate
SHA-256 fingerprint in authenticated Nitro `user_data`. For a source-backed
`mode = "tls"` deployment, `caution verify` validates the fresh Nitro evidence
and expected PCRs, compares that fingerprint with the live WebPKI-validated
leaf, and saves the verified PCRs and TLS binding to
`.caution/trusted_hashes.json`. Certificate changes can take up to 60 seconds
to appear in new attestations.

Run the opt-in live binding test against any production-mode Caddy deployment:

```bash
make CADDY_E2E_URL=https://app.example.com test-live-caddy-nitro
```

This checks HTTPS, redirects, health, Nitro authenticity, and the signed
certificate binding. It does not establish workload identity; use
`caution verify` with independently trusted source or PCRs for that.

For STEVE-protected HTTP deployments, plaintext application routing is denied
by default. Legacy fallback requires an explicit opt-in:

```hcl
e2e_encryption {
  enabled                  = true
  key_exchange             = "xwing-draft10"
  allow_plaintext_fallback = true
}
```

The platform health and attestation endpoints remain available outside the
application route. In fail-closed mode the application HTTP port is not exposed
through a host or enclave VSOCK proxy; STEVE reaches it over enclave-local TCP.

### 4. Verify a deployed app

Use the public `/verify` page to authenticate fresh nonce-bound Nitro evidence
and inspect its PCR0, PCR1, and PCR2 values without an account. Browser targets
must use an HTTPS domain, and their `/attestation` endpoint must permit
cross-origin POST requests. HTTP and raw-IP endpoints require the CLI.

The browser does not authenticate the sibling response manifest, reproduce the
application source, establish a STEVE encrypted session, or automatically
identify the expected deployment. Compare PCRs only with values reviewed through
an independent trusted source.

The verification summary marks authenticated Nitro evidence in green and keeps
the expected deployment neutral until independently reviewed PCRs are supplied.
It turns green when PCR0, PCR1, and PCR2 all match and red for a mismatch.
Attestations with all-zero PCR0, PCR1, and PCR2 are identified as debug enclaves
and cannot be used for workload identity. The page reports when fresh
nonce-bound evidence was verified in the browser, supports explicit
re-verification, and reports each PCR comparison separately.

Expected PCRs can be imported from an `enclave.pcrs` produced by
`caution apps build --no-cache` from a reviewed checkout, or from the
`.caution/trusted_hashes.json` written by a successful CLI verification. Files
are read only in the browser and are not uploaded; both formats remain unsigned
and editable, so importing one does not authenticate its source. Manual entry is
available under the advanced control.

After an exact match, the page saves PCR0, PCR1, and PCR2 for that exact
attestation endpoint and compares them with fresh evidence on later visits. The
page labels saved values as browser continuity and provides explicit replace and
forget controls. This browser storage is not an independent trust root:
same-origin code or the local user can change or clear it.

The default Bootproof pin includes the required attestation CORS policy. An
operator override through `BOOTPROOF_COMMIT` takes precedence. Pin changes apply
only to newly built EIFs; existing applications must be rebuilt and redeployed,
and their expected PCRs reviewed again.

For source reproduction or expected-PCR enforcement, use the CLI:

**Option A: Reproduce and verify (recommended)**

Fetches the attestation from the endpoint, rebuilds the enclave locally, and verifies the PCR hashes match. The attestation endpoint is available at `https://<app-url>/attestation`.

```bash
caution verify --attestation-url <attestation-url>
```

Local source is the default. If the deployment manifest has no app commit, the
CLI uses the current checkout at `HEAD`.

Source-archive preflights use five-second HEAD requests. The Platform framework
archive is checked on Codeberg first, then on the configured GitHub mirror; each
candidate is retried once for transient failures, while missing archives advance
to the next candidate immediately. The canonical Codeberg URL remains in the
measured manifest. If every candidate remains unavailable, verification stops
before starting the expensive reproduction build. Mirrors improve availability
but do not independently prove that an archive matches its claimed Git commit.

**Option B: Verify against known PCR hashes**

PCRs (Platform Configuration Registers) are cryptographic measurements of the enclave's code and configuration. If you already have the expected PCR hashes, you can verify against a file:

```bash
# Create a file with expected PCR hashes
cat pcrs.txt
PCR0: 3c07ec536432532f86b8c735b740f0d67a8b115e4a5e20cc8ecbb4e6a8335fe016bf42693b18e8560e299636afa8dc84
PCR1: 3c07ec536432532f86b8c735b740f0d67a8b115e4a5e20cc8ecbb4e6a8335fe016bf42693b18e8560e299636afa8dc84
PCR2: 21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a

caution verify --pcrs pcrs.txt
```

This is explicitly PCR-only: it does not verify TLS certificate binding, and
the persisted trusted state contains no `tls` object.

### Credit suspension recovery

Resuming a fully managed app starts the same instance and reattaches the
Elastic IP tagged to that app. Redeployment is not required.

## Reference

### Limitations

- AWS Nitro Enclaves only
- Requires x86_64 architecture for enclave builds
- Docker BuildKit required for reproducible builds
- Attestation verification requires network access to the enclave endpoint

### Coming soon

- Other TEE platforms (TDX, SEV)
- Other major cloud platforms and baremetal
- Alternate OCI runtime support (Podman)

## License

Dual-licensed under AGPL-3.0 and a commercial license. See [LICENSE](LICENSE) for details. Contact info@caution.co to obtain a commercial license.
