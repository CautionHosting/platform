// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// Display logic for app deployments. Every value comes from the API; missing
// metadata stays unknown.

import { formatStatusLabel } from './appDetails.js'

const STATUS_LABELS = { reserved: 'Building', building: 'Building', provisioning: 'Starting', running: 'Running', failed: 'Failed', destroying: 'Cleanup pending', destroyed: 'Destroyed' }

export const shortId = (id) => (typeof id === 'string' ? id.slice(0, 8) : '')
export const shortSha = (sha) => (typeof sha === 'string' && sha ? sha.slice(0, 7) : 'unknown')
export const isDeploymentsApp = (app) => app?.lifecycle === 'deployments'
export const isActiveApp = (app) =>
  typeof app?.active === 'boolean' ? app.active : String(app?.state || '').toLowerCase() !== 'terminated'

// Sentence case, like the CLI: "Cleanup pending".
const sentence = (value) => {
  const label = formatStatusLabel(value)
  return label.charAt(0) + label.slice(1).toLowerCase()
}

export const appStateLabel = (app) => sentence(app?.summary_state || app?.state)

export const candidateCountLabel = (app) => {
  if (!isDeploymentsApp(app)) return 'Legacy'
  return Number.isInteger(app.candidates) && Number.isInteger(app.candidate_limit) ? `${app.candidates} / ${app.candidate_limit}` : '—'
}

export const appHostname = (app) =>
  app?.domain || app?.configuration?.domain || (app?.public_ip ? app?.managed_hostname : null) || '—'

// The retained-only list (`?retained=1`); an older API ignores the parameter.
export const deploymentsUrl = (appId) => `/api/resources/${appId}/deployments?retained=1`

// Task 4's `is_retained`, for an API that sends no `retained`. `failed` counts
// only with a known pending cleanup (`cleaned_up_at: null`).
const RETAINED_STATUSES = ['reserved', 'building', 'provisioning', 'running', 'destroying']
const isRetained = (deployment) =>
  deployment.retained ?? (RETAINED_STATUSES.includes(deployment.status) || (deployment.status === 'failed' && deployment.cleaned_up_at === null))

export const orderDeployments = (deployments) =>
  (deployments || [])
    .filter(isRetained)
    .sort((a, b) => (b.role === 'live') - (a.role === 'live') || String(b.created_at).localeCompare(String(a.created_at)))

// While nothing is live, an attempt that can still become live is Pending
// (it goes live when ready), not a Candidate. `hasLive`: some row has role live.
export const roleLabel = (deployment, hasLive) => {
  if (deployment?.role === 'live') return 'Live'
  return !hasLive && ['reserved', 'building', 'provisioning', 'running'].includes(deployment?.status) ? 'Pending' : 'Candidate'
}

export const deploymentStateLabel = (deployment) =>
  deployment?.status === 'failed' && deployment?.failure_kind === 'runtime_lost'
    ? 'Unavailable'
    : STATUS_LABELS[deployment?.status] || 'Unknown'

// `debug_mode` is null until the API records it, and absent from an older API.
export const isDebugDeployment = (deployment) => deployment?.debug_mode === true
export const debugSwitchNotice = (deployment) => (isDebugDeployment(deployment) ? 'This deployment runs in debug mode.' : null)

export const verifyCommand = (deployment) => `caution verify -d ${deployment.id}`
export const switchCommand = (deployment) => `caution apps switch -d ${deployment.id}`
export const destroyCommand = (deployment) => `caution apps destroy -d ${deployment.id}`

export const canSwitch = (app, deployment) =>
  isDeploymentsApp(app) && deployment?.role !== 'live' && deployment?.status === 'running'
export const canDestroy = (app, deployment) =>
  isDeploymentsApp(app) && deployment?.role !== 'live' &&
  !['reserved', 'building', 'provisioning', 'destroying', 'destroyed'].includes(deployment?.status)

// The exact bytes that are signed and sent. `liveId` is the app's
// `live_deployment_id` (the CLI sends the same), so a stale view gets a 409
// instead of switching away from a deployment the operator never saw.
export const switchRequestBody = (liveId, deployment) => JSON.stringify({
  expected_live_deployment_id: liveId ?? null,
  acknowledged_verification: true,
  acknowledged_tls_pending: Boolean(deployment?.tls_after_switch),
})

const UNKNOWN = 'The switch outcome is unknown. Refresh to see the live deployment before trying again.'

// Must match `SwitchRejection::Stale` in src/api/src/app_deployments/switch.rs;
// Task 3's API test `the_stale_confirmation_message_is_pinned` pins that text, and the frontend test pins it here.
const STALE_LIVE = 'The live deployment changed; review and confirm again.'

// Never reports success without the API's confirmation, and never retries. A
// request that never answers ends as `unknown` after `timeoutMs`.
export async function switchDeployment({ sign, fetch, appId, deploymentId, body, timeoutMs = 180000 }) {
  const path = `/resources/${appId}/deployments/${deploymentId}/switch`
  let headers
  try {
    headers = await sign('POST', path, body)
  } catch (error) {
    if (error?.name === 'NotAllowedError') return { outcome: 'cancelled', message: 'Passkey approval was cancelled. Nothing was switched.' }
    return { outcome: 'rejected', message: error?.message || 'Could not request passkey approval.' }
  }
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  let response, data
  try {
    response = await fetch(`/api${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body, signal: controller.signal })
    data = await response.json().catch(() => null)
  } catch {
    return { outcome: 'unknown', message: UNKNOWN }
  } finally {
    clearTimeout(timer)
  }
  if (response.ok) return data?.live_deployment_id === deploymentId ? { outcome: 'switched', data } : { outcome: 'unknown', message: UNKNOWN }
  if (response.status >= 500) return { outcome: 'unknown', message: UNKNOWN }
  if (response.status === 409 && data?.error === STALE_LIVE) {
    return { outcome: 'stale', message: 'The live deployment changed. Review the refreshed deployments and confirm again.' }
  }
  return { outcome: 'rejected', message: data?.error || `Switch failed (HTTP ${response.status}).` }
}

const DESTROY_UNKNOWN = 'The destroy outcome is unknown; refresh to check.'

export async function destroyDeployment({ fetch, appId, deploymentId }) {
  let response
  try {
    response = await fetch(`/api/resources/${appId}/deployments/${deploymentId}`, { method: 'DELETE' })
  } catch {
    return { outcome: 'unknown', message: DESTROY_UNKNOWN }
  }
  if (response.ok) return { outcome: 'destroyed' }
  // A 5xx (or a proxy 504) can leave the spawned destroy running: never call it failed.
  if (response.status >= 500) return { outcome: 'unknown', message: DESTROY_UNKNOWN }
  const data = await response.json().catch(() => null)
  return { outcome: 'rejected', message: data?.error || `Destroy failed (HTTP ${response.status}).` }
}

// One row per retained instance, including cleanup pending; unknown estimates stay null.
export const retainedInstanceRows = (deployments) => {
  const hasLive = (deployments || []).some((deployment) => deployment.role === 'live')
  return orderDeployments(deployments)
    // A confirmed-lost instance is gone: its slot stays, its cost does not.
    .filter((deployment) => deployment.instance_id && deployment.failure_kind !== 'runtime_lost')
    .map((deployment) => ({
      id: deployment.id,
      role: roleLabel(deployment, hasLive),
      instanceType: deployment.instance_type || 'unknown',
      cpus: deployment.enclave_cpus ?? null,
      memoryMb: deployment.enclave_memory_mb ?? null,
      state: deploymentStateLabel(deployment),
      estimate: typeof deployment.estimated_monthly_usd === 'number' ? deployment.estimated_monthly_usd : null,
    }))
}

export const retainedMonthlyTotal = (rows) => ({
  total: Math.round(rows.reduce((sum, row) => sum + (row.estimate ?? 0), 0) * 100) / 100,
  complete: rows.every((row) => row.estimate !== null),
})

const OUTCOME_LABELS = { requested: 'In progress', observed: 'Succeeded (observed after restart)' }
const outcomeLabel = (outcome) => OUTCOME_LABELS[outcome] || sentence(outcome)

export const historyRowLabel = (entry) => {
  const target = shortId(entry?.target_deployment_id)
  if (entry?.kind === 'attempt') return `Attempt ${target} · ${shortSha(entry.commit_sha)} · ${outcomeLabel(entry.outcome)}`
  if (entry?.operation === 'switch') return `Switch ${shortId(entry.previous_deployment_id) || 'none'} → ${target} · ${outcomeLabel(entry.outcome)}`
  return `${sentence(entry?.operation)}${target ? ` ${target}` : ''} · ${outcomeLabel(entry?.outcome)}`
}

// `count` is null until the deployments list has loaded: never state a number then.
export const destroyAppSentence = (count) =>
  `Destroys the app and ${count === null || count === undefined ? 'every retained deployment' : `its ${count} retained deployment${count === 1 ? '' : 's'}`}. The service becomes unavailable.`
