# Env Parity Test

A minimal Axum server that exposes environment variables via GET /env.
Used by the e2e env-parity test to verify that environment variables
declared in caution.hcl match those visible inside the running enclave.
