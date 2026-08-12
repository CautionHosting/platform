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

const BROWSER_TARGET_ERROR =
  'Browser verification requires an HTTPS domain. Use the Caution CLI for HTTP or raw-IP attestation endpoints.'

function isIpAddress(hostname) {
  const unwrapped = hostname.replace(/^\[|\]$/g, '')
  return unwrapped.includes(':') || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(unwrapped)
}

function parseBrowserAttestationUrl(value) {
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    throw new Error('The url query parameter must be a valid absolute URL.')
  }

  if (parsed.username || parsed.password) {
    throw new Error('The url query parameter must not contain credentials.')
  }
  if (parsed.protocol !== 'https:' || isIpAddress(parsed.hostname)) {
    throw new Error(BROWSER_TARGET_ERROR)
  }

  parsed.hash = ''
  return parsed
}

export function resolveAttestationTarget(search) {
  const rawUrl = new URLSearchParams(search).get('url')?.trim()
  if (!rawUrl) return null

  const appUrl = parseBrowserAttestationUrl(rawUrl)
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

export function normalizeAttestationInput(value) {
  const trimmed = value.trim()
  if (!trimmed) throw new Error('Enter an HTTPS application domain or attestation URL.')

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  return parseBrowserAttestationUrl(withScheme).href
}

export function quotePosixShellArgument(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`
}

function normalizePcrHash(value) {
  if (typeof value !== 'string') {
    throw new Error('Each PCR value must be a 96 hexadecimal character SHA-384 hash.')
  }
  const normalized = value.trim().replace(/^0x/i, '').toLowerCase()
  if (!/^[0-9a-f]{96}$/.test(normalized)) {
    throw new Error('Each PCR value must be a 96 hexadecimal character SHA-384 hash.')
  }
  return normalized
}

const REQUIRED_PCR_NAMES = ['PCR0', 'PCR1', 'PCR2']
export const MAX_EXPECTED_PCR_FILE_SIZE = 64 * 1024
const REMEMBERED_PCR_PREFIX = 'caution.verify.expected-pcrs.v1:'

export function hasDebugPcrs(result) {
  return (
    result?.verified === true &&
    REQUIRED_PCR_NAMES.every((name) => result.pcrs?.[name] === '0'.repeat(96))
  )
}

export function parseExpectedPcrs(input) {
  const trimmed = input.trim()
  if (trimmed.startsWith('{')) {
    let parsed
    try {
      parsed = JSON.parse(trimmed)
    } catch {
      throw new Error('Expected PCR JSON is invalid.')
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Expected PCR JSON must contain pcr0, pcr1, and pcr2.')
    }

    return Object.fromEntries(
      REQUIRED_PCR_NAMES.map((name) => [
        name,
        normalizePcrHash(parsed[name] ?? parsed[name.toLowerCase()]),
      ]),
    )
  }

  const entries = input
    .split(/[\n,;]+/)
    .map((entry) => entry.trim())
    .filter(Boolean)

  if (entries.length !== 3) {
    throw new Error('Provide PCR0, PCR1, and PCR2.')
  }

  const digestFirst = entries.map((entry) => entry.match(/^(\S+)\s+PCR([012])$/i))
  if (digestFirst.every(Boolean)) {
    const result = {}
    for (const match of digestFirst) {
      const name = `PCR${match[2]}`
      if (result[name]) throw new Error(`${name} was provided more than once.`)
      result[name] = normalizePcrHash(match[1])
    }
    if (!REQUIRED_PCR_NAMES.every((name) => result[name])) {
      throw new Error('Provide PCR0, PCR1, and PCR2.')
    }
    return result
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
  const comparisons = Object.keys(expectedPcrs).map((name) => {
    const actual = result?.verified ? result.pcrs?.[name] : null
    const authenticated = typeof actual === 'string' ? actual.toLowerCase() : null

    return {
      name,
      expected: expectedPcrs[name],
      authenticated,
      matches: authenticated === expectedPcrs[name],
    }
  })
  const mismatches = comparisons.filter((comparison) => !comparison.matches).map(({ name }) => name)

  return {
    matches: mismatches.length === 0,
    mismatches,
    comparisons,
  }
}

export function compareOptionalExpectedPcrs(result, input) {
  if (!input.trim()) {
    return {
      checked: false,
      matches: true,
      mismatches: [],
      comparisons: [],
    }
  }

  return {
    checked: true,
    ...compareVerifiedPcrs(result, parseExpectedPcrs(input)),
  }
}

export function parseExpectedPcrFile(input) {
  const trimmed = input.trim()
  if (trimmed.startsWith('{')) {
    let parsed
    try {
      parsed = JSON.parse(trimmed)
    } catch {
      throw new Error('Expected PCR JSON is invalid.')
    }
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      Array.isArray(parsed) ||
      !REQUIRED_PCR_NAMES.every((name) => parsed[name.toLowerCase()] !== undefined)
    ) {
      throw new Error('Choose an enclave.pcrs or .caution/trusted_hashes.json file.')
    }
    return { pcrs: parseExpectedPcrs(input), source: 'cli' }
  }

  const entries = trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
  if (!entries.every((entry) => /^(\S+)\s+PCR[012]$/i.test(entry))) {
    throw new Error('Choose an enclave.pcrs or .caution/trusted_hashes.json file.')
  }
  return { pcrs: parseExpectedPcrs(input), source: 'build' }
}

export async function readExpectedPcrFile(file) {
  if (!file || typeof file.text !== 'function') throw new Error('Choose a PCR file.')
  if (file.size > MAX_EXPECTED_PCR_FILE_SIZE) {
    throw new Error('Expected PCR files must be 64 KiB or smaller.')
  }
  return parseExpectedPcrFile(await file.text())
}

function rememberedPcrKey(attestationUrl) {
  return `${REMEMBERED_PCR_PREFIX}${attestationUrl}`
}

export function loadRememberedPcrs(storage, attestationUrl) {
  const value = storage.getItem(rememberedPcrKey(attestationUrl))
  if (!value) return null

  try {
    const record = JSON.parse(value)
    if (record.version !== 1 || typeof record.savedAt !== 'string') return null
    if (Number.isNaN(Date.parse(record.savedAt))) return null
    return {
      pcrs: parseExpectedPcrs(JSON.stringify(record.pcrs)),
      savedAt: record.savedAt,
    }
  } catch {
    return null
  }
}

export function saveRememberedPcrs(storage, attestationUrl, pcrs, savedAt = new Date().toISOString()) {
  const record = {
    version: 1,
    pcrs: parseExpectedPcrs(JSON.stringify(pcrs)),
    savedAt,
  }
  storage.setItem(rememberedPcrKey(attestationUrl), JSON.stringify(record))
  return record
}

export function forgetRememberedPcrs(storage, attestationUrl) {
  storage.removeItem(rememberedPcrKey(attestationUrl))
}
