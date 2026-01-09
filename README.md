**GitHub users:** This repo is mirrored from <a href="https://codeberg.org/caution/platform" target="_blank">Codeberg</a>. Please open issues and PRs there.

**Hosted version:** A hosted deployment is available in closed alpha at <a href="https://alpha.caution.co" target="_blank">alpha.caution.co</a>. To request a registration code, <a href="mailto:info@caution.co?subject=Caution%20Alpha%20Access&body=Hi%2C%0A%0AI%20was%20reviewing%20your%20docs%20at%20https%3A%2F%2Fcodeberg.org%2Fcaution%2Fplatform%20and%20noticed%20that%20you%20are%20also%20offering%20a%20closed%20alpha%20for%20hosted%20deployments.%20Can%20I%20please%20get%20a%20code%20to%20try%20it%20out%3F%0A%0AMy%20details%3A%0AMy%20name%3A%20%0AMy%20company%20name%3A%0A%0AThank%20you">contact info@caution.co</a>.

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
- x86_64 based system (Mac support coming soon)

### 1. Bootstrap AWS infrastructure

Follow the [bootstrapping guide](infra-bootstrap/README.md) to create the required AWS infrastructure (S3 buckets, IAM user, DynamoDB table).

### 2. Run the platform

Set up `.env` file using the credentials from bootstrapping:

```bash
cp env.example .env
# Edit .env with your AWS credentials and bucket names from bootstrapping
```

Install the CLI:

**Option A: Install script**
```bash
curl -fsSL https://codeberg.org/caution/cli/raw/branch/main/install.sh | sh
```

**Option B: Build from source**
```bash
git clone https://codeberg.org/caution/cli
cd cli
make build
make install
```

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

   You may need to adjust the Procfile.

   The <a href="https://codeberg.org/Caution/hello-world-enclave" target="_blank">hello-world-enclave</a> repo is a good test app to deploy.

4. Build and deploy:
   ```bash
   git push caution main
   ```

### 4. Verify a deployed app

You can verify an enclave's attestation in two ways:

**Option A: Reproduce and verify (recommended)**

Fetches the attestation from the endpoint, rebuilds the enclave locally, and verifies the PCR hashes match. The attestation endpoint is available at `https://<app-url>/attestation`.

```bash
caution verify --attestation-url <attestation-url>
```

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
