`service-attestation.cbor` is the AWS-signed `aws-test.cbor` fixture from
Bootproof commit `821b5c63e80f082f6d67ba3695c11416933489ec`,
`crates/bootproof-sdk/src/format/data/aws-test.cbor` (AGPL-3.0-only).
Tests use its recorded nonce and historical verification time. It is not a
live service check or a production trust policy.
