# Destination attestation fixture

`aws-test.cbor` is the existing AWS-signed Nitro fixture from
`locksmith/crates/locksmith/tests/data/aws-test.cbor` at `cd0f5fd44e252114c3bd160edd84c119b99263d0`.
CLI tests verify it at its recorded time with its recorded nonce, then vary the
expected PCRs and nonce. Production preflight always uses the current clock and
a fresh nonce. This fixture is local regression evidence, not live Nitro acceptance.
