// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
import { resolveAttestationTarget, quotePosixShellArgument } from './publicAttestation.js'

export function safeUrl(raw) {
  try {
    const url = new URL(raw)
    return url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash ? url.href : null
  } catch { return null }
}

export function verificationTarget(raw) {
  const url = safeUrl(raw)
  if (!url) return null
  const endpoint = url.replace(/\/$/, '') + '/attestation'
  try {
    resolveAttestationTarget('?url=' + encodeURIComponent(endpoint))
    return { href: '/verify?url=' + encodeURIComponent(endpoint), command: `caution verify --attestation-url ${quotePosixShellArgument(endpoint)}` }
  } catch { return null }
}

export function repositoryLabel(raw) {
  const url = safeUrl(raw)
  return url ? new URL(url).pathname.replace(/^\//, '').replace(/\.git\/?$/, '') || new URL(url).hostname : 'Unavailable'
}

export function checkPresentation(check, success) {
  if (check?.status === 'passed') return { tone: 'passed', icon: '✓', label: success }
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
  const seconds = Math.round((parsed - now) / 1000)
  if (seconds > 0) return 'Check timestamp is ahead of this device’s clock'
  const [amount, unit] = Math.abs(seconds) < 60 ? [seconds, 'second'] : Math.abs(seconds) < 3600 ? [Math.round(seconds / 60), 'minute'] : Math.abs(seconds) < 86400 ? [Math.round(seconds / 3600), 'hour'] : [Math.round(seconds / 86400), 'day']
  return 'Checked ' + new Intl.RelativeTimeFormat('en', { numeric: 'auto' }).format(amount, unit)
}
