**GitHub users:** This repo is mirrored from <a href="https://codeberg.org/caution/platform" target="_blank">Codeberg</a>. Please open issues and PRs there.

# Caution Platform

> **Warning: Alpha Software**
>
> This software is in early alpha. It may introduce backwards-incompatible changes, has not undergone security audits, and is not production ready. Use at your own risk.

This software is a cloud hosting management platform that builds and deploys reproducible AWS Nitro Enclaves based on <a href="https://git.distrust.co/public/enclaveos" target="_blank">EnclaveOS</a> with cryptographic attestation.

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

Build the CLI and start services:

```bash
# Build CLI
make build-cli

# Install CLI
./install.sh

# Run services and db
make up
```

### 3. Deploy an app

1. Register using Passkey (via terminal or web browser):

   ```bash
   caution register
   ```

2. Add an SSH key (can be done in browser as well):

   ```bash
   caution keys add ~/.ssh/id_ed25519.pub
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

Fetches the attestation from the endpoint, rebuilds the enclave locally, and verifies the PCR hashes match. The attestation endpoint is available at `http://<app-url>:5000/attestation`.

```bash
caution verify --reproduce <attestation-url>
```

**Option B: Verify against known PCR hashes**

PCRs (Platform Configuration Registers) are cryptographic measurements of the enclave's code and configuration. If you already have the expected PCR hashes, you can verify against a file:

```bash
# Create a file with expected PCR hashes
cat pcrs.txt
PCR0: 3c07ec536432532f86b8c735b740f0d67a8b115e4a5e20cc8ecbb4e6a8335fe016bf42693b18e8560e299636afa8dc84
PCR1: 3c07ec536432532f86b8c735b740f0d67a8b115e4a5e20cc8ecbb4e6a8335fe016bf42693b18e8560e299636afa8dc84
PCR2: 21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a

caution verify --pcrs pcrs.txt <attestation-url>
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
