# Enclave builder release compatibility

## Verification clients must support standalone recipes

New framework templates compose the canonical component Containerfiles for Init,
Bootproof, STEVE, Locksmith and TAP-framer. Before deploying these templates,
provide verifiers with a CLI whose shared builder supports **all five component
inclusion markers**, selected-revision recipe/source staging, and source-built
component digest verification. An older CLI that only expands the TAP-framer
marker cannot verify these deployments, even when optional features are disabled.
This is a required client upgrade, not a backwards-compatible template change.

Downloading a newer template or manifest cannot update an installed binary's
renderer, and the improved diagnostic exists only in upgraded clients. No numeric
minimum version is claimed here: release qualification must check these builder
capabilities. After upgrading, retry the same `caution verify` invocation with
`--no-cache`, preserving the manifest's framework pin and PCR checks. New clients
retain historical inline recipes and optional-component behavior; do not rewrite
old manifests or substitute current sources to make a verification pass.

## Pair the API image and component selection

TAP-framer's component identity intentionally includes the **whole platform
commit**, not just its source subtree. Every changed platform commit therefore
requires a matching component specification/set and can require a TAP-framer
rebuild even when its source files are unchanged. Startup rejects mismatched API
and component pins; component reuse across such commits is not promised.

Use the normal [`make up` workflow](../../containerfiles/README.md): preparation
builds or verifies the selected components, publishes them, and generates the
paired API-image/component selection automatically before migration/restart.
Operators do not calculate or paste hashes. Do not activate a new API image with
an old set digest. Existing deployments keep their recorded EIF/host-artifact
pairing; changing the active selection does not replace them.
