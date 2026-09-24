// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
import { resolveAttestationTarget, quotePosixShellArgument } from './publicAttestation.js'

export function safeUrl(raw) {
  try {
    const url = new URL(raw)
    return url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash ? url.href : null
  } catch { return null }
}

export function verificationTarget(raw, serviceId, platformOrigin) {
  const url = safeUrl(raw)
  if (!url) return null
  const endpoint = url.replace(/\/$/, '') + '/attestation'
  try {
    resolveAttestationTarget('?url=' + encodeURIComponent(endpoint))
    let command = `caution verify --attestation-url ${quotePosixShellArgument(endpoint)}`
    if (['keymaker', 'key-service'].includes(serviceId) && platformOrigin) {
      const platform = new URL(platformOrigin)
      if (!['https:', 'http:'].includes(platform.protocol) || platform.username || platform.password || platform.search || platform.hash || platform.pathname !== '/') return null
      command = `caution --url ${quotePosixShellArgument(platform.origin)} verify --service ${serviceId}`
    }
    return { href: '/verify?url=' + encodeURIComponent(endpoint), command }
  } catch { return null }
}

export function repositoryLabel(raw) {
  const url = safeUrl(raw)
  return url ? new URL(url).pathname.replace(/^\//, '').replace(/\.git\/?$/, '') || new URL(url).hostname : 'Unavailable'
}

const transportReasons = new Set(['Request failed', 'Request timed out', 'Response read failed'])
const transportFailure = check => check?.status === 'failed' && transportReasons.has(check.reason)

export function servicePresentation(service) {
  const checks = [
    { label: 'Readiness', result: service.readiness, success: 'Ready' },
    { label: 'Attestation', result: service.attestation, success: 'Authenticated' },
    ...(service.policies || []).map(policy => ({ label: policy.purpose + ' policy', result: policy.result, success: 'Matches' })),
  ].map(check => ({ ...check, presentation: checkPresentation(check.result, check.success),
    reason: transportFailure(check.result) || check.result?.reason === 'No authenticated measurements' ? null : check.result?.reason }))
  return {
    checks,
    transportDetails: checks.filter(check => transportFailure(check.result)),
    unreachable: transportFailure(service.readiness) && transportFailure(service.attestation),
    hasMeasurements: service.attestation?.status === 'passed' && Object.keys(service.measurements || {}).length > 0,
  }
}

export function checkPresentation(check, success) {
  if (check?.status === 'passed') return { tone: 'passed', icon: '✓', label: success }
  if (transportFailure(check)) return { tone: 'unavailable', icon: '—', label: 'Unavailable' }
  if (check?.status === 'failed' && success === 'Matches' && check.reason === 'No authenticated measurements') return { tone: 'unavailable', icon: '—', label: 'Not evaluated' }
  if (check?.status === 'failed' && success === 'Ready' && check.reason === 'Service is not ready') return { tone: 'pending', icon: '◌', label: 'Not ready' }
  if (check?.status === 'failed') return { tone: 'failed', icon: '×', label: 'Failed' }
  if (check?.status === 'pending') return { tone: 'pending', icon: '◌', label: 'Pending' }
  return { tone: 'unavailable', icon: '—', label: 'Unavailable' }
}

const validPcr = value => typeof value === 'string' && /^[a-f\d]{96}$/i.test(value)
const sortPcrs = keys => [...keys].sort((a, b) => Number(a) - Number(b))

export function measurementRows(service) {
  const pinned = new Set((service.policies || []).flatMap(policy => (policy.sets || []).flatMap(set => Object.keys(set.pcrs || {}))))
  const measurements = service.measurements || {}
  const keys = new Set(['0', '1', '2', ...Object.keys(measurements), ...pinned])
  return sortPcrs(keys).map(index => {
    const value = measurements[index]
    return { index, value, pinned: pinned.has(index), valid: validPcr(value), hidden: Number(index) > 2 && !pinned.has(index) && typeof value === 'string' && /^0{96}$/.test(value) }
  })
}

export function policyRows(set, measurements = {}) {
  const expected = set.pcrs || {}
  return sortPcrs(new Set(['0', '1', '2', ...Object.keys(expected)])).map(index => {
    const observed = measurements?.[index]
    const allowed = expected[index]
    let comparison = 'Observed only'
    if (Object.hasOwn(expected, index)) {
      comparison = !validPcr(observed) || !validPcr(allowed) ? 'Missing or invalid' : observed.toLowerCase() === allowed.toLowerCase() ? 'Same value' : 'Different value'
    } else if (!validPcr(observed)) comparison = 'Missing or invalid'
    return { index, observed, allowed, comparison }
  })
}

export function relativeCheckTime(timestamp, now) {
  const parsed = Date.parse(timestamp)
  if (!Number.isFinite(parsed)) return 'Check time unavailable'
  if (Math.abs(parsed - now) <= 5000) return 'Checked just now'
  const seconds = Math.round((parsed - now) / 1000)
  if (seconds > 0) return 'Check timestamp is ahead of this device’s clock'
  const [amount, unit] = Math.abs(seconds) < 60 ? [seconds, 'second'] : Math.abs(seconds) < 3600 ? [Math.round(seconds / 60), 'minute'] : Math.abs(seconds) < 86400 ? [Math.round(seconds / 3600), 'hour'] : [Math.round(seconds / 86400), 'day']
  return 'Checked ' + new Intl.RelativeTimeFormat('en', { numeric: 'auto' }).format(amount, unit)
}
