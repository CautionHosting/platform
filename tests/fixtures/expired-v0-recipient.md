# Expired V0 recipient fixture

`expired-v0-recipient.asc` is the unchanged `public_key` string from Locksmith’s
`bundle-single.json` at `a2b7bddc2466b9ff3ce71d12813b1dda7db0c5a5`. It expired in
March 2026. Tests must retain its expiry: ordinary encryption rejects it, whereas
explicitly accepted ImportedV0 encryption can use it without rewriting the bundle.
Revoked recipients remain rejected. The durable V0 round-trip fixture is separate.
