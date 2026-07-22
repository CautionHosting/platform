# Caution CLI

Command-line interface for [Caution](https://caution.co) — deploy and verify reproducible secure enclaves.

> **Warning: Alpha Software**
>
> This software is in early alpha. It may introduce backwards-incompatible changes, has not undergone security audits, and is not production ready. Use at your own risk.

## Installation

We offer multiple ways to install the CLI.

Please choose the installation method that's appropriate for your threat model and use-case.

### Prerequisites

Every installation path requires:

- `make`
- `bash`

On Linux/x86_64, the automatic installer selects the StageX build, which
requires Docker with BuildKit and the containerd image store enabled. On
macOS/arm64, it selects the host-toolchain build, which requires the native Rust
and C dependencies listed in the `make install-cli-host` error messages.

### Build Compatibility

The `make build-cli` and `make install-cli` targets use the StageX-based
reproducible build. The automatic `make install` command selects this build on
Linux/x86_64 and the host-toolchain build on macOS/arm64.

The locksmith shard-sending flow, `caution secret send-shard`, currently only
works with the host-toolchain build:

```sh
make install-cli-host
```

The current StageX build is statically linked with musl, and this path can fail
when `pcscdaemon` or the PC/SC stack tries to load
`libpcsclite_real.so.1`, with an error like `Dynamic loading not supported`.
The host build links against the host's native C library (glibc on most Linux
distributions) and PC/SC stack, which avoids this issue. It is not built through
the StageX reproducible pipeline, so bit-for-bit reproducibility is not
guaranteed or verified.

### Blind Trust

> :warning: Before you copy/paste, note that these are *low* security options

If you are on an untrusted machine and are only evaluating our tools, we offer
easy low security install paths common in the industry.

Note that any time you run an unverified binary off the internet you are
giving a third party full permission to execute any code they want on your
system. CDN accounts, git forges, and package repository accounts get
compromised all the time.`curl ... | sh` style installers are a widely spread
anti-pattern when it comes to good security practices.

#### From Source

This is the quickest install path. The installer detects the host platform,
selects the supported build, and installs it to a writable binary directory:

```sh
git clone https://codeberg.org/caution/platform
cd platform
make install
```

If you need to send locksmith shards with `caution secret send-shard`, use the
host-toolchain build instead. That path links against the host PC/SC stack and
requires a one-time acknowledgement that it is not built through StageX:

```sh
make install-cli-host
```

On Linux, the host build needs development packages for clang/libclang,
pkg-config, nettle, GMP, OpenSSL, libudev, and PC/SC. On macOS, it checks for
Homebrew or MacPorts equivalents and prints install hints when packages are
missing.

### CI SSH App Access

`caution apps get` and `caution apps destroy` normally require a logged-in
session. CI jobs can use SSH-signed API access for those two commands after the
public key has been registered with `caution ssh-keys add`.

```sh
export CAUTION_SSH_SIGNING_KEY=/path/to/id_ed25519
caution apps get <app-id> --this-is-a-ci-machine
caution apps destroy <app-id> --force --this-is-a-ci-machine
```

`--this-is-a-ci-machine` is intentionally explicit. Local development should use
the normal login flow. If `CAUTION_SSH_SIGNING_KEY` is unset, the CLI checks
`GIT_SSH_COMMAND`, `git config core.sshCommand`, and then default `~/.ssh/id_*`
keys when a `caution` git remote exists.

### Account PGP Keys

Export an armored OpenPGP public certificate and associate it with your Caution
account:

```sh
gpg --armor --export <fingerprint> > public-key.asc
caution pgp-keys add public-key.asc --name "Work key"
caution pgp-keys list
caution pgp-keys remove <fingerprint>
```

Adding or removing a key requires WebAuthn approval. Pass `--qr` to approve with
a passkey on another device. Removal hides the key from the active list but
retains its public certificate and linked add/remove authorization records for
audit history. The CLI rejects private key material locally, and the gateway
parses, normalizes, and fingerprints the public certificate again before storing
it. Each file must contain exactly one public certificate and be no larger than
64 KiB.

### Encrypt Env Secrets

After generating a quorum bundle with Keymaker, encrypt local `.env` values into
the layout consumed by Caution deployments:

```sh
export KEYMAKER_URL=http://35.163.164.207
caution secret new keyring.asc --threshold 2 --max 4 --no-upload
caution secrets encrypt
```

By default, `caution secrets encrypt` reads `.env`, extracts the recipient
public key from `.caution/quorum-bundle.json`, and writes one armored OpenPGP
message per non-empty env value to `.caution/secrets/<KEY>.asc`.

Encrypt only selected keys:

```sh
caution secrets encrypt PRIVATE_KEY WEB3_RPC_ENDPOINT
```

Override paths when needed:

```sh
caution secrets encrypt \
  --env-file ./prod.env \
  --bundle ./.caution/quorum-bundle.json \
  --secrets-dir ./.caution/secrets
```

### Moderate Trust

These steps allow proving that at least two Caution engineers
signed off on the release manifest, signaling that they reproduced the binary
from source code and got identical results, in addition to the usual two-party
code review processes.

This minimizes single points of trust (and failure) in the release process.

See the [Reproducible Builds](https://reproducible-builds.org/) project for
more information on these practices.

1. Clone repo

   ```sh
   git clone https://codeberg.org/caution/platform
   cd platform
   ```

2. Review and import signing keys

   Before importing, visit each keyoxide profile and verify the identity proofs.
   Check that the key belongs to who it claims via linked social accounts,
   websites, or other attestations. See the [Signers](#signers) table below.

   Once satisfied, import the keys you trust:

   ```sh
   gpg --keyserver hkps://keys.openpgp.org --recv-keys 6B61ECD76088748C70590D55E90A401336C8AAA9
   gpg --keyserver hkps://keys.openpgp.org --recv-keys F4BF5C81EC78A5DD341C91EEDC4B7D1F52E0BA4D
   gpg --keyserver hkps://keys.openpgp.org --recv-keys 88823A75ECAA786B0FF38B148E401478A3FBEF72
   gpg --keyserver hkps://keys.openpgp.org --recv-keys C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD
   ```

3. Verify release metadata

   > [!NOTE]
   > Maintainers create and sign release metadata with `make release-cli` and
   > `make sign-cli` before publishing them. If `dist/cli` is absent in this
   > checkout, no CLI release has been published for this state yet.

   Published release metadata lives in `dist/cli`: `release.env`, which holds
   information about the commit, author, and public key of the Caution software
   being built, `manifest.txt`, which lists the hashsums of the expected binary
   and metadata, and detached signatures over that manifest. The executable
   binary is not committed to this repository.

   Cryptographically verify that the manifest is signed and that the committed
   metadata matches the manifest.
   ```sh
   make verify-cli
   ```

   Note: See Trust section below for expected keys/signers

4. Reproduce binary

   ```sh
   make reproduce-cli
   ```

5. Install reproduced binary

   ```sh
   install -D -m 0755 out/cli/caution-linux-x86_64 "$HOME/.local/bin/caution"
   ```

### Zero Trust

If you intend to use the Caution CLI on a system you need to be able to trust
or for a high risk use case, we strongly recommend taking the time to hold us
accountable to the maximum degree you have resources and time for.

This protects not only you, but also protects our team. If many people are
checking our work for tampering it removes the incentive for someone malicious
to attempt to force one or more of us to tamper with the software.

1. Clone repo

   ```sh
   git clone https://codeberg.org/caution/platform
   cd platform
   ```

2. Review source

   - Ideal: Review the entire supply chain for high risk uses
   - Minimal: Review the build targets in the Makefile and [Containerfile](https://codeberg.org/caution/platform/src/branch/main/containerfiles/Containerfile.cli)

3. Reproduce binary

   This requires published release metadata in `dist/cli`, including
   `release.env` and `manifest.txt`.

   ```sh
   make reproduce-cli
   ```

   Note: See Trust section below for expected keys/signers

4. Install reproduced binary

   ```sh
   install -D -m 0755 out/cli/caution-linux-x86_64 "$HOME/.local/bin/caution"
   ```

5. Upload signature (optional)

   While this step is totally optional, if you took the time to verify our
   binary we would welcome you signing it and submitting your signature so
   we have public evidence third parties are checking our work.

   ```sh
   make sign-cli
   git add dist/cli/manifest.*.asc && git commit -m "Co-sign release"
   # Submit a pull request with your signature
   ```

## Trust

### Process

You should never trust random binaries or code you find on the internet. Even
if it is from a reputable git identity, developers are phished all the time.

Supply chain attacks are becoming increasingly common in our industry and it
takes strong accountability to prevent them from happening.

The only way to be reasonably confident code was actually authored by the
people we think it was, is if that software is cryptographically signed by a
key only those individuals have access to.

Similarly if a company releases binaries, you have no idea if the machine that
compiled it is compromised or not, and no idea if the code in that binary
corresponds to the actual code in the repo that you or someone you trust
authored or reviewed.

To address both problems we take the following steps:

1. All commits are signed with keys that only exist on hardware security
   modules held by each engineer
2. All release manifests are signed by the engineer that compiled the binary
3. Attesting engineers compile the binary and sign the manifest if they get the
   same hashes

### Signature Verification

To learn who signed the current release run:

```sh
make verify-cli
```

Commits will be signed by at least one of the keys under the signers section
below.

Release manifests should be signed by at least two of them signifying successful
reproducible builds.

We encourage you to review the below keyoxide links and any available
web-of-trust for each key to ensure it is really owned by the person it claims
to be owned by.

### Signers

| Name           | PGP Fingerprint |
| -------------- | --------------- |
| Lance Vick     | [6B61 ECD7 6088 748C 7059 0D55 E90A 4013 36C8 AAA9](https://keyoxide.org/6B61ECD76088748C70590D55E90A401336C8AAA9) |
| Anton Livaja   | [F4BF 5C81 EC78 A5DD 341C 91EE DC4B 7D1F 52E0 BA4D](https://keyoxide.org/F4BF5C81EC78A5DD341C91EEDC4B7D1F52E0BA4D) |
| Ryan Heywood   | [8882 3A75 ECAA 786B 0FF3 8B14 8E40 1478 A3FB EF72](https://keyoxide.org/88823A75ECAA786B0FF38B148E401478A3FBEF72) |
| Daniel Grove   | [C92F E5A3 FBD5 8DD3 EC5A A26B B101 16B8 193F 2DBD](https://keyoxide.org/C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD) |
