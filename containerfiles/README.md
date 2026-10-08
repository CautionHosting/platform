# Reusable enclave components

`Containerfile.init`, `Containerfile.bootproof`, `Containerfile.steve`,
`Containerfile.locksmith`, and `Containerfile.tap-framer` are the canonical recipes
used by component publication and source EIF builds. The EIF template only
composes them; historical revisions retain their original inline recipes.

Each recipe exports binaries through its `<component>-export` target. Run builds
on a disposable host with Docker/BuildKit. For example, from the repository root:

```sh
docker buildx build --platform linux/amd64 --provenance=false \
  --build-arg SOURCE_DATE_EPOCH=1 --build-arg BOOTPROOF_COMMIT="$BOOTPROOF_COMMIT" \
  -f containerfiles/Containerfile.bootproof --target bootproof-export \
  --output type=local,dest=dist/bootproof .
```

Use full immutable Git revisions for `BOOTPROOF_COMMIT`, `STEVE_COMMIT`, and
`LOCKSMITH_COMMIT`. Init expects the selected EnclaveOS tree under `enclave/` in
the build context; TAP expects the selected framework's `src/tap-framer/`.
See [TAP build and pin verification](../src/tap-framer/README.md) for its Make targets.

Always pair recipes with their selected framework revision. A recipe change
changes component identity and requires a newly reviewed component set before
activation, even when rebuilt binaries are identical. Publication does not
activate a set or change existing deployments.
