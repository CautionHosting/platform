// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import test from 'node:test'
import {
  appStateLabel, candidateCountLabel, canDestroy, canSwitch, destroyAppSentence, destroyDeployment, historyEvent, historyRowLabel,
  debugSwitchNotice, deploymentsUrl, isActiveApp, isDebugDeployment, orderDeployments, relativeTime, retainedInstanceRows, retainedMonthlyTotal, roleLabel,
  switchDeployment, switchRequestBody, verifyCommand,
} from '../src/utils/deployments.js'

const app = { id: 'app-1', lifecycle: 'deployments', live_deployment_id: 'a', summary_state: 'running', active: true, candidates: 1, candidate_limit: 3 }
const live = { id: 'a', role: 'live', status: 'running', retained: true, created_at: '2026-10-11T10:00:00Z', instance_id: 'i-a', instance_type: 'm5.xlarge', enclave_cpus: 2, enclave_memory_mb: 4096, estimated_monthly_usd: 140.16 }
const candidate = { id: 'b', role: 'candidate', status: 'running', retained: true, created_at: '2026-10-12T10:00:00Z', instance_id: 'i-b', instance_type: 'm5.xlarge', estimated_monthly_usd: null, tls_after_switch: true }
const lost = { id: 'l', role: 'candidate', status: 'failed', failure_kind: 'runtime_lost', retained: true, created_at: '2026-10-12T09:00:00Z', instance_id: 'i-l', instance_type: 'm5.xlarge', estimated_monthly_usd: null }
const failed = { id: 'c', role: 'candidate', status: 'failed', retained: false, created_at: '2026-10-12T11:00:00Z' }

test('app summaries use server-derived state, activity and candidate usage', () => {
  assert.equal(appStateLabel({ summary_state: 'cleanup_pending', state: 'running' }), 'Cleanup pending')
  assert.equal(candidateCountLabel(app), '1 / 3')
  assert.equal(candidateCountLabel({ lifecycle: 'legacy' }), 'Legacy')
  assert.equal(isActiveApp({ active: false, state: 'running' }), false)
  assert.equal(isActiveApp({ state: 'terminated' }), false) // older API
})

test('the deployment list is live first and omits terminal attempts', () => {
  assert.deepEqual(orderDeployments([candidate, failed, live]).map((d) => d.id), ['a', 'b'])
})

test('an older API without `retained` falls back to the status, like Task 4', () => {
  const old = (id, status, extra = {}) => ({ id, role: 'candidate', status, created_at: '2026-10-12T10:00:00Z', ...extra })
  const rows = [old('r', 'running'), old('d', 'destroyed'), old('f', 'failed'), old('p', 'failed', { cleaned_up_at: null }), old('c', 'failed', { cleaned_up_at: '2026-10-12T12:00:00Z' })]
  assert.deepEqual(orderDeployments(rows).map((d) => d.id), ['r', 'p']) // `failed` counts only with a known pending cleanup
})

test('the deployment list is requested retained-only', () => {
  assert.equal(deploymentsUrl('app-1'), '/api/resources/app-1/deployments?retained=1')
})

test('an attempt is Pending only while nothing is live', () => {
  assert.equal(roleLabel(live, true), 'Live')
  assert.equal(roleLabel(candidate, true), 'Candidate')
  assert.equal(roleLabel(candidate, false), 'Pending') // goes live when ready
  assert.equal(roleLabel(lost, false), 'Candidate') // a failed attempt never goes live
})

test('legacy apps have no deployment actions', () => {
  assert.equal(canSwitch({ lifecycle: 'legacy' }, candidate), false)
  assert.equal(canDestroy({ lifecycle: 'legacy' }, candidate), false)
  assert.equal(canSwitch(app, live), false)
  assert.equal(canDestroy(app, live), false)
  assert.equal(canSwitch(app, candidate), true)
  assert.equal(canDestroy(app, candidate), true)
  assert.equal(verifyCommand(candidate), 'caution verify -d b')
})

test('the signed switch body binds the expected live deployment and pending TLS', () => {
  assert.equal(switchRequestBody('a', candidate), '{"expected_live_deployment_id":"a","acknowledged_verification":true,"acknowledged_tls_pending":true}')
  assert.equal(switchRequestBody(undefined, live), '{"expected_live_deployment_id":null,"acknowledged_verification":true,"acknowledged_tls_pending":false}')
})

test('switch outcome never reports success without confirmation', async () => {
  const sign = async (method, path, body) => { assert.equal(method, 'POST'); assert.equal(path, '/resources/app-1/deployments/b/switch'); assert.ok(body); return { 'X-Fido2-Challenge-Id': 'c' } }
  const respond = (status, body) => async () => ({ ok: status < 300, status, json: async () => body })
  const run = (fetch, signer = sign) => switchDeployment({ sign: signer, fetch, appId: 'app-1', deploymentId: 'b', body: '{}' })
  assert.equal((await run(respond(200, { live_deployment_id: 'b', stable_ip: '198.51.100.42' }))).outcome, 'switched')
  assert.equal((await run(respond(200, { live_deployment_id: 'a' }))).outcome, 'unknown')
  // The exact text of `SwitchRejection::Stale` in src/api/src/app_deployments/switch.rs (pinned there by `the_stale_confirmation_message_is_pinned`).
  assert.equal((await run(respond(409, { error: 'The live deployment changed; review and confirm again.' }))).outcome, 'stale')
  assert.equal((await run(respond(409, { error: 'Only a Running deployment can become live.' }))).outcome, 'rejected')
  assert.equal((await run(respond(502, { error: 'bad gateway' }))).outcome, 'unknown')
  assert.equal((await run(async () => { throw new TypeError('network') })).outcome, 'unknown')
  let fetched = false
  const cancelled = await run(async () => { fetched = true }, async () => { throw new DOMException('cancelled', 'NotAllowedError') })
  assert.equal(cancelled.outcome, 'cancelled'); assert.equal(fetched, false)
  // A request that never answers ends as unknown, not as a hung dialog.
  const hang = (_url, { signal }) => new Promise((_, reject) => signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))))
  const timedOut = await switchDeployment({ sign, fetch: hang, appId: 'app-1', deploymentId: 'b', body: '{}', timeoutMs: 10 })
  assert.equal(timedOut.outcome, 'unknown')
})

test('deployment destroy reports cleanup failures', async () => {
  const run = (status, body) => destroyDeployment({ fetch: async () => ({ ok: status < 300, status, json: async () => body }), appId: 'app-1', deploymentId: 'b' })
  assert.equal((await run(204)).outcome, 'destroyed')
  assert.deepEqual(await run(409, { error: 'The live deployment cannot be destroyed; switch to another deployment first.' }), { outcome: 'rejected', message: 'The live deployment cannot be destroyed; switch to another deployment first.' })
  // A 5xx or a network error may leave the destroy running: unknown, not failed.
  assert.deepEqual(await run(500, { error: 'Deployment destroy failed; retry.' }), { outcome: 'unknown', message: 'The destroy outcome is unknown; refresh to check.' })
  assert.equal((await run(504, null)).outcome, 'unknown')
  const down = await destroyDeployment({ fetch: async () => { throw new Error('offline') }, appId: 'app-1', deploymentId: 'b' })
  assert.equal(down.outcome, 'unknown')
})

test('retained instances list every billed instance and an honest total', () => {
  // A confirmed-lost instance keeps its slot but is no longer billed.
  const rows = retainedInstanceRows([live, candidate, failed, lost])
  assert.deepEqual(rows.map((row) => [row.id, row.role, row.estimate]), [['a', 'Live', 140.16], ['b', 'Candidate', null]])
  assert.deepEqual(retainedMonthlyTotal(rows), { total: 140.16, complete: false })
})

test('history rows name the operation and outcome, with a tone', () => {
  assert.equal(historyRowLabel({ kind: 'operation', operation: 'switch', outcome: 'succeeded', previous_deployment_id: 'a0000000-1', target_deployment_id: 'b0000000-1' }), 'Switch a0000000 → b0000000 · Succeeded')
  assert.equal(historyRowLabel({ kind: 'attempt', outcome: 'failed', target_deployment_id: 'c0000000-1', commit_sha: 'b6e8c92aa' }), 'Deploy c0000000 · Failed')
  assert.equal(historyRowLabel({ kind: 'operation', operation: 'deployment_destroy', outcome: 'requested', target_deployment_id: 'c0000000-1' }), 'Destroy c0000000 · In progress')
  assert.equal(historyRowLabel({ kind: 'operation', operation: 'app_destroy', outcome: 'succeeded', target_deployment_id: null }), 'Destroy app · Succeeded')
  // A stale switch records the target as previous: no "X → X".
  assert.equal(historyEvent({ kind: 'operation', operation: 'switch', outcome: 'rejected', previous_deployment_id: 'b0000000-1', target_deployment_id: 'b0000000-1' }).title, 'Switch to b0000000')
  assert.equal(historyRowLabel({ kind: 'operation', operation: 'switch', outcome: 'rejected', previous_deployment_id: 'b0000000-1', target_deployment_id: 'b0000000-1' }), 'Switch to b0000000 · Rejected')
  assert.equal(historyEvent({ kind: 'operation', operation: 'switch', outcome: 'succeeded', previous_deployment_id: null, target_deployment_id: 'b0000000-1' }).title, 'Switch none → b0000000')
  assert.deepEqual(['succeeded', 'observed', 'requested', 'failed', 'rejected', 'other'].map((outcome) => historyEvent({ kind: 'operation', operation: 'switch', outcome }).tone), ['success', 'success', 'pending', 'danger', 'danger', 'neutral'])
})

test('relative times stay short and fall back to the date', () => {
  const now = Date.parse('2026-10-15T12:00:00Z')
  assert.equal(relativeTime('2026-10-15T11:59:30Z', now), 'just now')
  assert.equal(relativeTime('2026-10-15T11:55:00Z', now), '5 min ago')
  assert.equal(relativeTime('2026-10-15T09:00:00Z', now), '3 h ago')
  assert.equal(relativeTime('2026-10-14T11:00:00Z', now), '1 day ago')
  assert.equal(relativeTime('2026-10-12T12:00:00Z', now), '3 days ago')
  assert.ok(!relativeTime('2026-09-01T12:00:00Z', now).includes('ago'))
  assert.equal(relativeTime(null, now), '—')
})

test('the destroy-app sentence never invents a retained count', () => {
  assert.equal(destroyAppSentence(null), 'Destroys the app and every retained deployment. The service becomes unavailable.')
  assert.equal(destroyAppSentence(1), 'Destroys the app and its 1 retained deployment. The service becomes unavailable.')
  assert.equal(destroyAppSentence(3), 'Destroys the app and its 3 retained deployments. The service becomes unavailable.')
})

test('debug mode shows only when the API recorded it', () => {
  assert.equal(isDebugDeployment({ debug_mode: true }), true)
  for (const deployment of [{ debug_mode: false }, { debug_mode: null }, {}, null]) assert.equal(isDebugDeployment(deployment), false) // an older API sends none
  assert.equal(debugSwitchNotice({ debug_mode: true }), 'This deployment runs in debug mode.')
  assert.equal(debugSwitchNotice({ debug_mode: false }), null)
})
