# Caution CLI

Command-line interface for [Caution](https://caution.co) — deploy and verify reproducible secure enclaves.

> **Warning: Alpha Software**
>
> This software is in early alpha. It may introduce backwards-incompatible changes, has not undergone security audits, and is not production ready. Use at your own risk.

## Installation

We offer multiple ways to install the CLI.

Please choose the installation method that's appropriate for your threat model and use-case.

### Prerequisites

The Makefile assumes the presence of a few basic tools:

- `make`
- `bash`
- `Docker`

### Blind Trust

> :warning: Before you copy/paste, note that these are *low* security options

If you are on an untrusted machine and are only evaluating our tools, we offer
easy low security install paths common in the industry.

Note that any time you run an unverified binary off the internet you are
giving a third party full permission to execute any code they want on your
system. CDN accounts, git forges, and package repository accounts get
compromised all the time.`curl ... | sh` style installers are a widely spread
anti-pattern when it comes to good security practices.

#### Download

| Version | OS    | Architecture | Download |
| ------- | ----- | ------------ | -------- |
| v0.1.0-alpha | Linux | x86_64 | [caution-linux-x86_64](https://codeberg.org/caution/platform/raw/branch/main/dist/cli/caution-linux-x86_64) |

#### From Source

```sh
git clone https://codeberg.org/caution/platform
cd platform
make install-cli
```

### Moderate Trust

These steps allow proving that at least two Caution engineers
signed off on the produced binaries, signaling that they were reproduced from
source code and got identical results, in addition to the usual two-party code
review processes.

This minimizes single points of trust (and failure) in the binary release
process.

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

3. Verify signatures

> [!NOTE]
> The `release-cli` step is meant to be completed by maintainers.

   Create release assets in `dist/cli`: The Caution executable binary,
   `release.env`, which holds information about the commit, author, and public
   key of the Caution software being built, and `manifest.txt` which lists the
   hashsums of the assets.
   ```sh
   make release-cli
   ```

   Cryptographically verify the hashsums correctly match the release
   assets:
   ```sh
   make verify-cli
   ```

   Note: See Trust section below for expected keys/signers

4. Install binary

   ```sh
   make install-cli
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

3. Reproduce binaries

   ```sh
   make reproduce-cli
   ```

   Note: See Trust section below for expected keys/signers

4. Install binaries

   ```sh
   make install-cli
   ```

5. Upload signature (optional)

   While this step is totally optional, if you took the time to verify our
   binaries we would welcome you signing them and submitting your signature so
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
2. All binaries are signed by the engineer that compiled them
3. Attesting engineers compile and sign binaries if they get the same hashes

### Signature Verification

To learn who signed the current release run:

```sh
make verify-cli
```

Commits will be signed by at least one of the keys under the signers section
below.

Released binaries should be signed by at least two of them signifying
successful reproducible builds.

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
