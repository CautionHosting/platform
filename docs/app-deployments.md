# App deployments (blue-green)

An app on the deployments lifecycle keeps one stable Elastic IP and runs several
deployments (one enclave instance each). A push builds a new deployment, you
verify it on its own address, then a passkey-signed switch moves the stable IP
to it. The previous deployment keeps running, so a rollback is another switch.

## Enabling

Set both in `~/.config/caution/.env`, then restart the API (`env.example` lists them):

- `APP_DEPLOYMENTS_ENABLED=true` gives new fully managed apps (`POST /resources`) the
  deployments lifecycle. Default off. The lifecycle is fixed at creation: existing
  apps stay Legacy, and BYOC apps always do.
- `MAX_CANDIDATES_PER_APP` is a positive integer, default `3`. The API refuses to
  start if it is set but invalid.

## Lifecycle

- **Push.** `git push caution main` builds a deployment. Only one build or
  provisioning operation runs per app: another push is refused ("Another build or
  provisioning operation is running"). A push over the candidate cap is refused
  ("Candidate limit reached (N / M)"). Suspended or terminating apps refuse pushes.
- **Auto-live.** A deployment goes live on its own only when nothing is live (the
  first push, or after an app destroy). Otherwise it is a candidate: it runs and is
  billed, the live deployment is unchanged. A push whose ref did not change
  skips the deployment while one is live and rebuilds HEAD when nothing is live.
- **Verify.** `caution verify -d <deployment>` checks it at its current address
  (a candidate's IP changes on stop/start) from a checkout at its commit, and keeps
  its trust in `.caution/deployments/<deployment>/trusted_hashes.json`, apart from
  the app's `.caution/trusted_hashes.json`. `caution apps get [APP] -d <deployment>`
  shows one deployment.
- **Switch.** `caution apps switch -d <deployment>` needs a passkey tap; a session
  or SSH-signed request gets 403 `This operation requires signature verification`
  (no CI form). It names the live deployment it was confirmed against: if that
  changed, or a retry follows a lost response, the answer is 409 (stale), so
  re-read the app and confirm again. The target must be Running and pass the
  platform health check.
- **Destroy.** `caution apps destroy [APP] -d <deployment>` destroys one deployment
  (session, or `--this-is-a-ci-machine` with the app ID). The live deployment is
  never destroyed, whatever the flags. `caution apps destroy` (the app) destroys
  every deployment and clears the live pointer; it returns 409 while a build or
  provisioning is active.

## Recovery

The reconciler runs at startup and every 60 s. It:

- releases reservations no push claimed (they expire after 30 minutes);
- adopts work abandoned by an API restart (building, provisioning, destroying):
  clears its stale state lock, fails the attempt ("abandoned by an API restart") and
  destroys its state, or finishes the interrupted destroy;
- retries the cleanup of failed attempts once they are older than 2x the OpenTofu
  timeout (2 x 600 s);
- repairs the live pointer from the Elastic IP holder (records the holder as live,
  or activates the only Running deployment when nothing is live);
- marks a Running deployment `failed` with `failure_kind = 'runtime_lost'` once EC2
  confirms its instance gone, keeping the live pointer and its state: switch to a
  healthy deployment, then `destroy -d` it;
- only logs two states for an operator: `app Elastic IP is unassociated` (the live
  deployment is unreachable until a switch) and `app Elastic IP is held by an
  instance of no Running deployment` (switches answer 409 until repaired).

App teardown also clears the state locks of dead owners, which would otherwise fail
every retry. Reconciliation relies on the API being one process (work owned by
another process ID counts as abandoned): do not run more than one API replica
before leases exist.

## State keys

In the state bucket: the app state (VPC, Elastic IP) at
`organizations/{org}/resources/{app}/terraform.tfstate`; each deployment at
`organizations/{org}/resources/{app}/deployments/{deployment}/terraform.tfstate`.
Both use S3 lockfiles (`<key>.tflock`).

## Rollout and rollback

Deploy the API (migration 056) before the gateway, whose push check selects
`compute_resources.lifecycle`. Migration 030 no longer creates the one-meter-per-app
index: rolling back to a release with the old 030 fails startup once an app has two
running deployment meters, so treat the migration as one-way once the flag has been on.

## Tests

- `make test-app-deployments-db`: concurrency, reconciliation and metering tests on an
  isolated Postgres (anonymous container, random port; safe on a shared host).
- `make test-e2e-app-deployments-schema`: schema checks against the test stack.
- `make test-e2e-app-deployments`: AWS-backed lifecycle E2E (real enclave builds, three
  deployments). It starts the test stack with the flag and `MAX_CANDIDATES_PER_APP=1`
  (`API_EXTRA_ENV` of `run-api-test`). The switch is signed by
  `tests/e2e/soft-authenticator` (`deployment-switch`). Run it on caution-dev. It
  refuses a non-local target. If its cleanup cannot destroy the app it prints
  `LEAKED app <id> ...` (with the instance IDs) and exits 86. The make target then
  keeps the stack and its database (which record the leak) and skips `down-test`:
  destroy that infrastructure by hand, then run `make down-test`.
