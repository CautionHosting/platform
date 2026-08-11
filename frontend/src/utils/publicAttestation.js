// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

export function ensureUint8ArrayBase64(Uint8ArrayType = Uint8Array) {
  if (typeof Uint8ArrayType.prototype.toBase64 === 'function') return

  Object.defineProperty(Uint8ArrayType.prototype, 'toBase64', {
    configurable: true,
    writable: true,
    value() {
      let binary = ''
      for (const byte of this) binary += String.fromCharCode(byte)
      return btoa(binary)
    },
  })
}

export function describeAttestationError(error, attestationUrl, currentOrigin) {
  const message = error?.message || 'The attestation evidence could not be verified.'
  if (message !== 'Failed to fetch') return message

  try {
    if (new URL(attestationUrl).origin !== new URL(currentOrigin).origin) {
      return 'Could not fetch the cross-origin attestation endpoint. It must allow browser POST requests with CORS.'
    }
  } catch {
    // URL validation reports malformed targets before the widget is rendered.
  }

  return message
}

function parseHttpUrl(value) {
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    throw new Error('The url query parameter must be a valid absolute URL.')
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('The url query parameter must use HTTP or HTTPS.')
  }
  if (parsed.username || parsed.password) {
    throw new Error('The url query parameter must not contain credentials.')
  }

  parsed.hash = ''
  return parsed
}

export function resolveAttestationTarget(search, currentOrigin = null) {
  const rawUrl = new URLSearchParams(search).get('url')?.trim()
  const fallbackOrigin = currentOrigin || (typeof window !== 'undefined' ? window.location.origin : '')

  const appUrl = parseHttpUrl(rawUrl || fallbackOrigin)
  const attestationUrl = new URL(appUrl)

  if (attestationUrl.pathname === '/') {
    attestationUrl.pathname = '/attestation'
    attestationUrl.search = ''
  }

  return {
    appUrl: appUrl.href,
    attestationUrl: attestationUrl.href,
  }
}

function sourceRepositoryUrl(source) {
  const candidate = source?.urls?.[0] || source?.url
  if (typeof candidate !== 'string') return null

  const scpStyle = candidate.trim().match(/^git@([a-z0-9.-]+):(.+)$/i)
  if (scpStyle) {
    const repositoryPath = scpStyle[2].replace(/\.git\/?$/, '')
    return `https://${scpStyle[1]}/${repositoryPath}`
  }

  try {
    const sshUrl = new URL(candidate)
    if (sshUrl.protocol === 'ssh:' && sshUrl.hostname) {
      return `https://${sshUrl.hostname}${sshUrl.pathname.replace(/\.git\/?$/, '')}`
    }

    const parsed = parseHttpUrl(candidate.replace(/\.git\/?$/, ''))
    return parsed.href
  } catch {
    return null
  }
}

export function extractVerifiedAppSource(result) {
  if (!result?.verified) return null

  const appSource = result.manifest?.app_source
  const commit = typeof appSource?.commit === 'string' ? appSource.commit.trim() : ''
  if (!commit) return null

  const url = sourceRepositoryUrl(appSource)
  return {
    commit,
    url,
    commitUrl: url ? `${url.replace(/\/$/, '')}/commit/${encodeURIComponent(commit)}` : null,
    branch: typeof appSource.branch === 'string' ? appSource.branch : null,
  }
}

function normalizePcrHash(value) {
  const normalized = value.trim().replace(/^0x/i, '').toLowerCase()
  if (!/^[0-9a-f]{96}$/.test(normalized)) {
    throw new Error('Each PCR value must be a 96 hexadecimal character SHA-384 hash.')
  }
  return normalized
}

export function parseExpectedPcrs(input) {
  const entries = input
    .split(/[\n,;]+/)
    .map((entry) => entry.trim())
    .filter(Boolean)

  if (entries.length !== 3) {
    throw new Error('Provide PCR0, PCR1, and PCR2.')
  }

  const labeled = entries.map((entry) => entry.match(/^PCR([012])\s*(?:=|:|\s)\s*(.+)$/i))
  if (labeled.some(Boolean) && !labeled.every(Boolean)) {
    throw new Error('Use labels for all three values or paste PCR0, PCR1, and PCR2 in order.')
  }

  if (labeled.every(Boolean)) {
    const result = {}
    for (const match of labeled) {
      const name = `PCR${match[1]}`
      if (result[name]) throw new Error(`${name} was provided more than once.`)
      result[name] = normalizePcrHash(match[2])
    }
    if (!result.PCR0 || !result.PCR1 || !result.PCR2) {
      throw new Error('Provide PCR0, PCR1, and PCR2.')
    }
    return result
  }

  return {
    PCR0: normalizePcrHash(entries[0]),
    PCR1: normalizePcrHash(entries[1]),
    PCR2: normalizePcrHash(entries[2]),
  }
}

export function compareVerifiedPcrs(result, expectedPcrs) {
  const mismatches = Object.keys(expectedPcrs).filter((name) => {
    const actual = result?.verified ? result.pcrs?.[name] : null
    return typeof actual !== 'string' || actual.toLowerCase() !== expectedPcrs[name]
  })

  return {
    matches: mismatches.length === 0,
    mismatches,
  }
}

export function compareOptionalExpectedPcrs(result, input) {
  if (!input.trim()) {
    return {
      checked: false,
      matches: true,
      mismatches: [],
    }
  }

  return {
    checked: true,
    ...compareVerifiedPcrs(result, parseExpectedPcrs(input)),
  }
}
