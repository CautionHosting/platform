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
  The slot is reserved before `receive-pack`, so a push while a deployment is live
  can be refused busy or over the limit even when it would change nothing.
- **Auto-live.** A deployment goes live on its own only when nothing is live (the
  first push, or after an app destroy). Otherwise it is a candidate: it runs and is
  billed, the live deployment is unchanged. A push whose ref did not change
  skips the deployment while one is live and rebuilds HEAD when nothing is live.
  If a first deployment is running but cannot be made live, the push says so: for a
  transient error the reconciler retries within about a minute; if another instance
  holds the app address it stays a candidate until the address is repaired.
  While nothing is live, the CLI and dashboard label an attempt that can still go
  live (reserved, building, provisioning, running) Pending, not Candidate.
- **Verify.** `caution verify -d <deployment>` checks it at its current address
  (a candidate's IP changes on stop/start) from a checkout at its commit, and keeps
  its trust in `.caution/deployments/<deployment>/trusted_hashes.json`, apart from
  the app's `.caution/trusted_hashes.json`. With several running deployments, bare
  `caution verify` refuses and asks for `-d`. A `mode = "tls"` build may report TLS
  pending (see [Enclave TLS on candidates](#enclave-tls-on-candidates)); other builds
  fail as before.
- **List and inspect.** `caution apps list` shows the active apps (`-a` adds the
  inactive ones: destroyed or failed) with the columns APP, ID, STATE, LIVE COMMIT,
  CANDIDATES (`used / limit`, or `Legacy`) and HOSTNAME. `caution apps get [APP]` of a
  deployments app prints a summary (app, state, hostname, stable IP, live deployment
  and commit, candidates), the table of retained deployments (live first, then newest;
  DEPLOYMENT, ROLE, COMMIT, PUSHED REF, STATE, SUBJECT) and the five most recent
  [history](#history) lines. The table comes from `GET /resources/{id}/deployments?retained=1`
  (a server without the filter sends every row and the CLI filters by status). History
  is session-only: `--this-is-a-ci-machine` skips it, and a failed history read prints
  "History unavailable" without failing the command. A Legacy app prints
  `Lifecycle: Legacy · single deployment` and its usual details. The tables go to
  stderr, like the rest of the CLI's status output. `caution apps get [APP] -d <deployment>`
  shows one deployment: its instance, its cleanup state (`done` or `pending`, for a
  failed or destroyed deployment) and its address, which is `unavailable` for a
  live deployment lost to `runtime_lost` (AWS has released the stable IP).
- **Short deployment IDs.** Every `-d` takes the full ID or its first 8 or more
  hexadecimal characters, as the tables print them. The prefix must be unique among
  all the app's deployments, destroyed and failed ones included, so IDs printed in
  history resolve; it is resolved once, then every request uses the exact ID. The app
  is the explicit one (`apps get APP -d ...`), else the linked checkout's. So
  `verify -d` and `secret send-shard -d` without `--app` take a short ID only from a
  linked checkout; a full ID works anywhere. Anything shorter than 8 characters is
  refused before any request ("use the full ID or at least its first 8 characters").
- **Dashboard.** The app header is compact, with an App details disclosure for the
  rest. Deployments list the live one first; selecting one opens the inspector with its
  verification command, **Switch live** (a passkey prompt; offered for a running
  non-live deployment) and **Destroy deployment** (not offered for the live one, one
  still building, or for Legacy apps). Settings shows the retained instances and their
  estimated cost. History is a collapsible list below the deployments. A Legacy app
  shows `Legacy · single deployment` and no deployment actions.
- **Known limits.** A candidate is metered only from its health check on, as Legacy
  is. Rolling back keeps the configuration keys the newer deployment added (the
  `project_live` merge): they are not removed again.
- **Switch.** `caution apps switch -d <deployment>` needs a passkey tap; a session
  or SSH-signed request gets 403 `This operation requires signature verification`
  (no CI form). It names the live deployment it was confirmed against: if that
  changed, or a retry follows a lost response, the answer is 409 (stale), so
  re-read the app and confirm again. The target must be Running and pass the
  platform health check. After moving the address, the switch re-reads it up to 3
  times (1 s apart) before reporting a mismatch, as EC2 reads can lag. A target that
  gets its certificate only after the switch
  needs an acknowledgement (see [Enclave TLS on candidates](#enclave-tls-on-candidates)).
  The deployment view carries `bundle_hash` and `tls_after_switch`. The switch answer
  always carries `tls_after_switch` (true when this switch moved the address to a
  deployment that obtains its certificate only now); `/deploy` carries it only when
  true, and the push output says so. The push output also names the deployment right
  after the push is accepted, and if the `/deploy` stream breaks after that (the API
  may have restarted) it says the deployment was abandoned and is cleaned up
  automatically. The CLI prints the signed method and path (without `/api`) above
  the body for every signed POST.
- **Destroy.** `caution apps destroy [APP] -d <deployment>` destroys one deployment
  (session, or `--this-is-a-ci-machine` with the app ID). The live deployment is
  never destroyed, whatever the flags: the CLI refuses it before prompting, and `-d` returns 409 while the app is being
  destroyed. `caution apps destroy` (the app) destroys every deployment and clears
  the live pointer; it returns 409 while a build, provisioning or deployment destroy
  is active.

## History

`deployment_events` records the switch, deployment destroy and app destroy of
deployments-lifecycle apps (Legacy apps get none). Each operation writes a `requested`
row before it executes (who, `auth_method` of `passkey`, `session` or `ssh_signed`,
the target and previous deployment), then one outcome row with the same
`operation_id`: `succeeded`, `rejected` (the request was refused, e.g. a stale switch
409), `failed`, or `observed` (an interrupted operation settled by
[reconciliation](#recovery)). A switch counts as `succeeded` only when the API
confirmed the address association and the live pointer; an HTTP status alone is never
shown as success. No request bodies, shares, secrets, assertions or credential material
are stored, and errors are the API's client messages.

A refused app destroy (for example a 409 while a deployment builds) is recorded as
`rejected`; a refused deployment destroy (live, building or holding the address)
records nothing, because it is refused before the operation starts.

- **Read.** `GET /resources/{id}/history?limit=N` (session only; default 20, at most
  50) returns `{entries, next}`: the operations and the failed push attempts, newest
  first. It is scoped to the caller's organizations (404 otherwise), and a deployment
  is named only through its own app.
- **Signed switches.** A passkey-signed switch links its `signed_request_audit` row:
  `signed_request_id` is the proof, and `signed_request_status` is the response status
  the gateway records after it has answered, so it can lag the switch by a moment. A
  rejected switch keeps the link too.
- **Retention.** The proof follows the audit retention policy: deleting the user
  removes the audit row, and the event keeps its row with the link and actor cleared.

## Releasing shares to a deployment

Release shares to the exact deployment a candidate runs, before switching to it:

```sh
caution verify -d <deployment>
caution secret send-shard -d <deployment>   # once per holder
```

- **Trust.** `verify -d` keeps the PCRs in `.caution/deployments/<deployment>/trusted_hashes.json`;
  `send-shard -d` checks the live attestation against that file only, never the
  app's `.caution/trusted_hashes.json`.
- **Endpoint.** Resolved from the API on every run (a candidate's IP changes on
  stop/start); a destroyed or address-less deployment has none and is refused.
- **Bundle.** The API records the canonical hash of `.caution/quorum-bundle.json`
  committed at the deployment's commit (the documented `COPY` source of the image's
  bundle). `send-shard -d` uses that bundle (the checkout's file or the
  organization's copy with that hash), or an explicit `--bundle` that must match it;
  it never picks another organization bundle. An image that copies its bundle from
  elsewhere records none: pass `--bundle`.
- **Bare commands.** With several running deployments, bare `verify` and
  `send-shard` refuse and require `-d`. Legacy apps, and apps with at most one running
  deployment, keep bare `verify`/`send-shard` and `.caution/trusted_hashes.json`.
- **Approval display.** The CLI names the deployment in the release summary and
  the QR approval page shows it ([share recovery](share-recovery.md)). Roll out the
  gateway before the CLI: an older gateway rejects a display context carrying a
  deployment ID.

## Enclave TLS on candidates

An enclave-TLS app (`mode = "tls"`) obtains its certificate from inside the enclave,
which fails while the deployment does not hold the app's Elastic IP. Deployments-lifecycle
`mode = "tls"` builds therefore start Caddy only once the domain resolves to the
deployment's own public IPv4. Their manifest records `tls_await_app_address: true`
(bound by PCR0). Legacy builds and host-mode builds are unchanged.

- **Address check.** The host publishes the instance's public IPv4 (from EC2 instance
  metadata) as `public-ipv4.caution.internal` through its dnsmasq. Every 15 s the
  enclave resolves that name and the app domain, each with socat, which opens a TCP
  connection to port 80 of the resolved address (5 s timeout) and logs the address
  it reached. Caddy starts once both give the same IPv4, which holds only while this
  deployment holds the app address. The host path is untrusted: a wrong answer can
  only delay issuance.
- **Verify.** While the certificate does not exist yet (a candidate before its
  switch, a live deployment before issuance), `verify -d` reports "PCRs verified;
  application TLS verification pending" and stores the PCR trust. The policy comes
  from the reproduced manifest, never from the API; other builds fail as before.
  Verifying these builds needs an M2 CLI: older CLIs fail closed with a PCR mismatch.
- **Switch.** Switching to a deployment that never held the app address needs a signed
  `acknowledged_tls_pending: true` (else 422). The CLI prints a warning and sends it
  only for such a target, also with `--force`, which skips only the confirmation prompt;
  rolling back to a deployment that was live needs none. Known limit: the
  acknowledgement is required only for a deployment that has never been live. A
  retained previously-live deployment needs none while its instance has not
  restarted; after a suspend/unsuspend it obtains a new certificate only after the
  switch, the switch does not ask for the acknowledgement, and `caution verify -d`
  reports TLS pending until the certificate is issued.
  After the switch, run `caution verify -d <deployment>` again once the certificate
  is issued.
- **Issuance.** Each switch to a fresh deployment issues one certificate (Let's
  Encrypt allows 5 per exact domain set per week).
- **Probe.** `tests/e2e/measure_cutover.sh URL SECONDS` polls a URL and reports the
  longest interruption across a switch.

## Inventory

drift-detector and `caution-admin findings` treat every non-destroyed deployment
instance as tracked, so a candidate is not an orphan. Both stay read-only toward AWS.

## Recovery

At startup the API also releases every unclaimed reservation at once, so a push
whose upload spans an API restart fails at its claim and must be re-pushed.

The reconciler runs at startup and every 60 s. It:

- releases reservations no push claimed (they expire after 30 minutes);
- adopts work abandoned by an API restart (building, provisioning, destroying):
  clears its stale state lock, fails the attempt ("abandoned by an API restart") and
  destroys its state, or finishes the interrupted destroy. A `destroy -d` of this
  process still `destroying` after the grace below (its last write failed) is
  re-run the same way;
- retries the cleanup of failed attempts once they are older than 2x the OpenTofu
  timeout plus 120 s (2 x 600 s + 120 s), first deleting the state lock a timed-out
  (killed) run left. A failed `destroy -d` is owed cleanup too, a `runtime_lost`
  deployment's included, so it is retried the same way;
- repairs the live pointer from the Elastic IP holder (records the holder as live,
  or activates the only Running deployment when nothing is live);
- marks a Running deployment `failed` with `failure_kind = 'runtime_lost'` once EC2
  confirms its instance gone, keeping the live pointer and its state: switch to a
  healthy deployment, then `destroy -d` it;
- settles history requests an API restart left unanswered from what it observes:
  a switch whose Elastic IP holder it finds live (the pointer repair above), or a
  destroy it finds finished, is recorded `observed`, with the request's passkey proof
  still linked;
- only logs two states for an operator: `app Elastic IP is unassociated` (the live
  deployment is unreachable until a switch) and `app Elastic IP is held by an
  instance of no Running deployment` (switches answer 409 until repaired).

An unsuspend that finds the live deployment `runtime_lost` does not re-attach the app
address or restart its meter: the app returns to running, as before the suspension,
with the live deployment unreachable until you switch to a healthy one. Known limit:
an unsuspend within the roughly 60 s window of an interrupted switch (before the
reconciler has repaired the pointer) re-attaches the address to the recorded live
deployment.

Every cleanup (failed attempt, `destroy -d`, app destroy, reconciliation) also
sweeps what the deployment's state may have missed: OpenTofu saves state on an
interval, so a restart during `tofu apply` can leave an instance or security group
that `tofu destroy` cannot see. After the state is destroyed it terminates the
instances not yet terminated that are tagged with both `ResourceId = <app>` and
`DeploymentId = <deployment>`, never the live instance, and deletes security groups
tagged the same way (best effort: one still used by a terminating instance is
retried). The cleanup is recorded, and the meter stopped, only once no such instance
remains in a non-terminated state; until then it stays `failed` and is retried.

App teardown also clears the state locks of dead owners, which would otherwise fail
every retry. Reconciliation relies on the API being one process (work owned by
another process ID counts as abandoned): do not run more than one API replica
before leases exist.

EC2 requests time out after 60 s (all lifecycles), so a hung call fails instead of
holding the app operation lock indefinitely.

## State keys

In the state bucket: the app state (VPC, Elastic IP) at
`organizations/{org}/resources/{app}/terraform.tfstate`; each deployment at
`organizations/{org}/resources/{app}/deployments/{deployment}/terraform.tfstate`.
Only deployment states use S3 lockfiles (`<key>.tflock`; `tofu force-unlock` or
deleting it recovers a stale one). The app state deliberately has none: it relies on
one active operation per app, so there is nothing to unlock.

## Rollout and rollback

On a first install deploy the API (migrations 056 to 058) before the gateway, whose
push check selects `compute_resources.lifecycle`. A host that already runs the M1/M2
migrations deploys the gateway before the API instead: the API refuses switches (403)
until the gateway forwards `X-Caution-Signed-Request-Id`, while an older API ignores
the new headers. The gateway comes before the CLI either way (its display context
accepts `deployment_id`). Migration 030 no longer creates the one-meter-per-app
index: rolling back to a release with the old 030 fails startup once an app has two
running deployment meters, so treat the migration as one-way once the flag has been on.

## Tests

Every other test stack runs with `APP_DEPLOYMENTS_ENABLED=false`
(`API_EXTRA_ENV` defaults to it), whatever `~/.config/caution/.env` says, so Legacy E2Es
test Legacy on a host that enables the flag.

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
  The `caution verify -d` step fails on any `verify -d` failure and requires the
  per-deployment trust file (strict passed on caution-dev, 2026-10-13).
  `E2E_STRICT_VERIFY=0` tolerates the environmental failures `test_happy_path.sh`
  tolerates and prints `ACCEPTANCE OPEN` instead. It also covers `apps list` (and
  `-a`), `apps get` (table, SSH-signed `--this-is-a-ci-machine` read without history),
  the history entries of the switches and destroys (passkey, `ssh_signed`, rejected),
  and short `-d` IDs.
- To run a Legacy target with the flag on, override the default:
  `make test-e2e API_EXTRA_ENV="-e APP_DEPLOYMENTS_ENABLED=true"` (also
  `test-e2e-ssh-units`, `test-e2e-byoc`); Legacy apps must behave the same and get no
  `deployment_events`.
