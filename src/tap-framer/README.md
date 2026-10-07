# TAP framer

Preserves Ethernet packet boundaries over the host/enclave vsock connection.

From the repository root, on a disposable host with Docker/BuildKit:

```sh
make build-tap-framer   # export to dist/tap-framer/
make verify-tap-framer  # rebuild and verify host.sha256
```

`host.sha256` pins the binary accepted by host bootstrap. Update it only after
independently rebuilding and reviewing intentional helper changes, never from a
builder-provided checksum alone.

Deploy or roll back the host and enclave together; their framing protocols must
match.
