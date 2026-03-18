# Cross-Device QR Code Testing Guide

Manual end-to-end testing for cross-device FIDO2 flows using QR codes. These flows allow users to approve operations on their mobile device (phone/tablet) when they don't have a security key connected to the machine running the CLI.

## Prerequisites

- Platform running locally (`make up`) or against a remote instance
- A registered account with at least one passkey/security key
- A mobile device with a browser that has access to the same passkey (e.g. iCloud Keychain, Google Password Manager, or a roaming authenticator like YubiKey via NFC)
- CLI built: `make install-cli` or `cargo build -p cli`
- A running Keymaker instance (`KEYMAKER_URL` set in `.env` or environment)

## 1. QR Login

Authenticate to the CLI using a passkey on your phone instead of a local security key.

### Steps

```bash
caution login --qr
```

### Expected behavior

1. CLI prints "Starting QR code cross-device login..." (verbose)
2. CLI requests a QR login token from `POST /auth/qr-login/begin`
3. A QR code is rendered in the terminal
4. The URL is also printed below the QR code (for manual entry)
5. CLI shows "Waiting for authentication..." with a spinner
6. **On your phone:** scan the QR code or open the URL in a browser
7. The browser opens the gateway's QR login page
8. Tap "Authenticate" and complete the FIDO2 ceremony (Face ID, fingerprint, PIN, etc.)
9. The phone shows "Authentication successful"
10. CLI detects completion, stores session, prints "Login successful"

### Failure cases to test

| Scenario | Expected result |
|----------|----------------|
| Let the QR code expire (3 min timeout) | CLI prints "QR login timed out. Please try again." |
| Close the phone browser without authenticating | CLI keeps polling until timeout |
| Use an unregistered device | Phone shows FIDO2 error, CLI keeps polling |
| Ctrl+C during polling | CLI exits cleanly |

## 2. QR-Signed Operations

The `--qr` flag enables cross-device FIDO2 signing for any operation that requires a signature (e.g. uploading secrets, modifying SSH keys, changing org settings). The flow is the same regardless of the operation: the CLI requests a signing challenge, renders a QR code, the user approves on their phone, and the CLI sends the signed request.

The example below uses `secret new` as a concrete test case, but any `--qr`-signed operation follows the same pattern.

### Setup

```bash
# Generate a test PGP keyring
gpg --batch --passphrase '' --quick-gen-key "Test <test@test.com>" rsa2048 cert 0
FINGERPRINT=$(gpg --list-keys --with-colons | grep '^fpr' | head -1 | cut -d: -f10)
gpg --batch --passphrase '' --quick-add-key "$FINGERPRINT" rsa2048 encr 0
gpg --armor --export "$FINGERPRINT" > /tmp/test-keyring.asc
```

### Steps

```bash
# Must be in a caution repo (has Procfile or .caution/)
cd your-app-directory

# Generate quorum and upload with QR signing
caution --qr secret new /tmp/test-keyring.asc
```

### Expected behavior

1. CLI connects to Keymaker, generates quorum (threshold=1, max=1 by default)
2. Bundle is saved to `.caution/quorum-bundle.json`
3. CLI prints "Uploading public key material bundle to Caution via QR code signing..."
4. CLI authenticates session (may prompt for login if not already logged in)
5. CLI requests a sign challenge from `POST /auth/qr-sign/begin` including:
   - Method: `POST`
   - Path: `/quorum-bundles`
   - Body hash (SHA-256 of the upload JSON)
6. A QR code is rendered in the terminal
7. CLI shows "Waiting for approval..." with a spinner
8. **On your phone:** scan the QR code or open the URL
9. The browser shows the operation details (method, path, body hash)
10. Tap "Approve" and complete the FIDO2 ceremony
11. The phone shows "Signature submitted"
12. CLI detects completion, sends the signed request with `X-Fido2-Challenge-Id` and `X-Fido2-Response` headers
13. CLI prints "Quorum bundle stored successfully (bundle ID: ...)"

### Verifying the upload

```bash
# List stored bundles (requires local security key or --qr)
caution credential list
```

The uploaded bundle should appear in the list.

### Failure cases to test

| Scenario | Expected result |
|----------|----------------|
| Reject/cancel the FIDO2 prompt on phone | CLI keeps polling until timeout |
| Let the QR code expire (3 min timeout) | CLI prints "QR signing token expired. Please try again." |
| Run without `KEYMAKER_URL` set | CLI prints "KEYMAKER_URL environment variable is required" before any QR interaction |
| Run with `--no-upload` | Quorum generates but no QR code is shown (no upload needed) |
| Run outside a caution repo without `--no-upload` | Warns "not in a Caution repository", outputs JSON to stdout, no upload |

## 3. QR-Signed Secret Generation with Custom Threshold

```bash
caution --qr secret new /tmp/test-keyring.asc --threshold 2 --max 3 --name "prod-signing-key"
```

### Expected behavior

Same as above, but:
- CLI prints "Generating quorum (threshold=2, max=3)..."
- The uploaded bundle includes the name "prod-signing-key"
- Verify with `caution credential list` that the name appears

## 4. QR-Signed Secret with Labels

```bash
caution --qr secret new /tmp/test-keyring.asc --name "staging" env=staging team=infra
```

### Expected behavior

Same flow. Labels `env=staging` and `team=infra` are included in the upload payload and stored with the bundle.

## Flow Diagram

```
CLI                          Gateway                       Phone Browser
 |                              |                              |
 |-- POST /auth/qr-sign/begin ->|                              |
 |<-- { token, url } ----------|                              |
 |                              |                              |
 | [render QR code]             |                              |
 |                              |                              |
 |                              |<---- user scans QR --------- |
 |                              |                              |
 |                              |<- POST /auth/qr-sign/authenticate
 |                              |-> { publicKey challenge }    |
 |                              |                              |
 |                              |  [user taps biometric/PIN]   |
 |                              |                              |
 |                              |<- POST /auth/qr-sign/authenticate/finish
 |                              |-> { success }                |
 |                              |                              |
 |-- GET /auth/qr-sign/status ->|                              |
 |<-- { completed,              |                              |
 |      fido2_response,         |                              |
 |      challenge_id } ---------|                              |
 |                              |                              |
 |-- POST /api/quorum-bundles ->|                              |
 |   (with X-Fido2-* headers)   |                              |
 |<-- { id: "..." } -----------|                              |
```

## Troubleshooting

- **QR code doesn't render properly**: Try a wider terminal (>80 cols). The URL is also printed as text.
- **Phone can't reach the URL**: The phone must be able to reach the gateway. If running locally, the phone needs to be on the same network and you need to use the machine's LAN IP (not localhost).
- **"Challenge expired"**: The FIDO2 challenge has a short TTL. Scan and approve promptly after the QR appears.
- **"Invalid signature"**: The passkey on the phone must be registered to the same account. Re-register if needed.
