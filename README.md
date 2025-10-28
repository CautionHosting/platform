# Caution Platform

> **Warning: Alpha Software**
>
> This software is in early alpha. It may introduce backwards-incompatible changes, has not undergone security audits, and is not production ready. Use at your own risk.

This software is a cloud hosting management platform that builds and deploys reproducible AWS Nitro Enclaves based on [EnclaveOS](https://git.distrust.co/public/enclaveos) with cryptographic attestation.

## Getting Started

### Prerequisites

- Docker
  - [containerd](https://docs.docker.com/engine/storage/containerd/#enable-containerd-image-store-on-docker-engine)
- Gnu Make

### Installation

Set up `env` file based on `env.example`

Build the CLI and start services:
```bash
# Build CLI
make build-cli

# Install CLI
./install.sh

# Run services and db
make up
```

### Usage

1. Register using Passkey (via terminal or web browser):
   ```bash
   caution register
   ```

2. Add an SSH key (can be done in browser as well):
   ```bash
   caution keys add ...
   ```

3. Initialize a project within a Dockerized repo:
   ```bash
   caution init
   ```
You may need to adjust the Procfile


4. Build and deploy:
   ```bash
   git push caution main
   ```

5. Verify an enclave's attestation:
   ```bash
   caution verify <url>
   ```

## Limitations

- AWS Nitro Enclaves only 
- Requires x86_64 architecture for enclave builds
- Docker BuildKit required for reproducible builds
- Attestation verification requires network access to the enclave endpoint

## Coming Soon

* Other TEE platforms (TDX, SEV)
* Other major cloud platforms and baremetal
* Alternate OCI runtime support (Podman)

## License

Dual-licensed under AGPL-3.0 and a commercial license. See [LICENSE](LICENSE) for details. Contact info@caution.co to obtain a commercial license.
