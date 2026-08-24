// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import {
  compareVerifiedPcrs,
  parseExpectedPcrs,
} from './publicAttestation.js'

export const STEVE_CLIENT_COMMIT = '2ee4760186df3022931aecc9145bd6bee8fc6137'
export const STEVE_CLIENT_ROOT = `/verify-e2ee/client/${STEVE_CLIENT_COMMIT}`
export const STEVE_REGISTER_PATH = `${STEVE_CLIENT_ROOT}/register.js`
export const STEVE_WORKER_PATH = `${STEVE_CLIENT_ROOT}/enclave-sw.js`
export const STEVE_TARGETS_ROOT = `${STEVE_CLIENT_ROOT}/targets`
export const STEVE_SUITES = ['X25519', 'XWING-DRAFT10']
export const MAX_REQUEST_BODY_BYTES = 64 * 1024
export const MAX_RESPONSE_PREVIEW_BYTES = 32 * 1024

export const REQUIRED_PCRS = ['PCR0', 'PCR1', 'PCR2']
export const E2EE_TRUST_MODES = ['none', 'pinned', 'tofu']
const ZERO_PCR = '0'.repeat(96)
const PROFILE_STORAGE_PREFIX = 'caution.verify-e2ee.pcr-profiles.v2:'
const LEGACY_PROFILE_STORAGE_PREFIX = 'caution.verify-e2ee.expected-pcrs.v1:'

function requireSuite(value) {
  if (!STEVE_SUITES.includes(value)) {
    throw new Error('Choose X25519 or XWING-DRAFT10.')
  }
  return value
}

function requireTrustMode(value) {
  if (!E2EE_TRUST_MODES.includes(value)) {
    throw new Error('Choose None, Pinned, or TOFU browser trust.')
  }
  return value
}

export function normalizeSteveOrigin(value) {
  const trimmed = String(value || '').trim()
  if (!trimmed) throw new Error('Enter an HTTPS STEVE origin.')

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`
  let parsed
  try {
    parsed = new URL(withScheme)
  } catch {
    throw new Error('Enter a valid HTTPS STEVE origin.')
  }

  if (parsed.protocol !== 'https:') throw new Error('The STEVE origin must use HTTPS.')
  if (parsed.username || parsed.password) throw new Error('The STEVE origin must not contain credentials.')
  if (parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error('Enter only the STEVE origin, without a path, query, or fragment.')
  }
  return parsed.origin
}

export function externalSteveOrigin(value, testerOrigin) {
  const targetOrigin = normalizeSteveOrigin(value)
  if (targetOrigin === new URL(testerOrigin).origin) {
    throw new Error('The STEVE target must differ from this verifier origin.')
  }
  return targetOrigin
}

export async function sha256Hex(value, cryptoObject = globalThis.crypto) {
  if (!cryptoObject?.subtle) throw new Error('This browser does not provide Web Crypto.')
  const digest = await cryptoObject.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

export async function steveTargetHash(origin, suite, cryptoObject = globalThis.crypto) {
  return sha256Hex(`${normalizeSteveOrigin(origin)}\n${requireSuite(suite)}`, cryptoObject)
}

export async function buildControlledTesterTarget(origin, suite, cryptoObject = globalThis.crypto) {
  const normalizedOrigin = normalizeSteveOrigin(origin)
  const normalizedSuite = requireSuite(suite)
  const hash = await sha256Hex(`${normalizedOrigin}\n${normalizedSuite}`, cryptoObject)
  const scope = `${STEVE_TARGETS_ROOT}/${hash}/`
  const query = new URLSearchParams({ origin: normalizedOrigin, suite: normalizedSuite })
  return {
    origin: normalizedOrigin,
    suite: normalizedSuite,
    hash,
    scope,
    url: `${scope}?${query}`,
  }
}

export function buildE2eeChooserUrl(origin, suite, trust) {
  const query = new URLSearchParams({
    origin: normalizeSteveOrigin(origin),
    suite: requireSuite(suite),
    trust: requireTrustMode(trust),
  })
  return `/verify-e2ee/?${query}`
}

export function parseE2eeChooserDefaults(search, testerOrigin) {
  const params = new URLSearchParams(search)
  if (!params.has('origin') && !params.has('suite') && !params.has('trust')) return null
  return {
    origin: externalSteveOrigin(params.get('origin'), testerOrigin),
    suite: requireSuite(params.get('suite')),
    trust: requireTrustMode(params.get('trust')),
  }
}

export function buildSteveCorsExample(pageOrigin, suite) {
  const origin = new URL(pageOrigin)
  if (origin.origin !== pageOrigin || !['http:', 'https:'].includes(origin.protocol)) {
    throw new Error('The tester origin must be an HTTP(S) origin.')
  }
  const keyExchange = requireSuite(suite) === 'XWING-DRAFT10'
    ? 'xwing-draft10'
    : 'x25519'
  return `e2e_encryption {\n    mode = "steve"\n    key_exchange = "${keyExchange}"\n    cors_origins = ["${origin.origin}"]\n  }`
}

export async function resolveControlledTesterTarget(
  pathname,
  search,
  cryptoObject = globalThis.crypto,
) {
  if (pathname === '/verify-e2ee' || pathname === '/verify-e2ee/') return null

  const match = pathname.match(
    new RegExp(`^${STEVE_TARGETS_ROOT}/([0-9a-f]{64})/$`),
  )
  if (!match) throw new Error('This is not a valid STEVE tester URL.')

  const params = new URLSearchParams(search)
  const origin = params.get('origin')
  const suite = params.get('suite')
  if (!origin || !suite) throw new Error('The tester URL is missing its origin or suite.')
  const target = await buildControlledTesterTarget(origin, suite, cryptoObject)
  if (match[1] !== target.hash) {
    throw new Error('The tester URL does not match its origin and suite.')
  }
  return target
}

function decodePath(pathname) {
  let decoded = pathname
  for (let index = 0; index < 2; index += 1) {
    try {
      const next = decodeURIComponent(decoded)
      if (next === decoded) break
      decoded = next
    } catch {
      throw new Error('The request path contains invalid percent encoding.')
    }
  }
  return decoded.replaceAll('\\', '/')
}

function isReservedPath(pathname) {
  const decoded = decodePath(pathname).toLowerCase()
  const segments = []
  for (const segment of decoded.split('/')) {
    if (!segment || segment === '.') continue
    if (segment === '..') segments.pop()
    else segments.push(segment)
  }
  const normalized = `/${segments.join('/')}`
  return (
    normalized === '/e2p' ||
    normalized.startsWith('/e2p/') ||
    normalized === '/attestation' ||
    normalized.startsWith('/attestation/')
  )
}

export function normalizeProtectedPath(value, origin) {
  const input = String(value || '').trim()
  if (!input) throw new Error('Enter an origin-relative request path.')
  if (!input.startsWith('/') || input.startsWith('//')) {
    throw new Error('Use an origin-relative path beginning with one slash.')
  }
  if (input.includes('\\') || input.includes('#') || /[\u0000-\u001f\u007f]/u.test(input)) {
    throw new Error('The request path contains unsafe characters.')
  }

  const targetOrigin = normalizeSteveOrigin(origin)
  const parsed = new URL(input, `${targetOrigin}/`)
  if (parsed.origin !== targetOrigin || parsed.username || parsed.password || parsed.hash) {
    throw new Error('The request must stay on the selected STEVE origin.')
  }
  if (isReservedPath(parsed.pathname)) {
    throw new Error('STEVE protocol and attestation endpoints cannot be tested as application paths.')
  }
  return `${parsed.pathname}${parsed.search}`
}

export function prepareProtectedRequest(origin, input) {
  const method = String(input?.method || '').toUpperCase()
  if (method !== 'GET' && method !== 'POST') throw new Error('Only GET and POST are supported.')
  const path = normalizeProtectedPath(input?.path, origin)
  const request = {
    path,
    options: {
      method,
    },
  }

  if (method === 'POST') {
    const body = String(input?.body ?? '')
    const bodyType = input?.bodyType
    if (bodyType !== 'json' && bodyType !== 'text') {
      throw new Error('Choose a JSON or text request body.')
    }
    if (new TextEncoder().encode(body).byteLength > MAX_REQUEST_BODY_BYTES) {
      throw new Error('Request bodies must be 64 KiB or smaller.')
    }
    if (bodyType === 'json') {
      try {
        JSON.parse(body)
      } catch {
        throw new Error('The JSON request body is invalid.')
      }
    }
    request.options.headers = {
      'Content-Type': bodyType === 'json' ? 'application/json' : 'text/plain;charset=UTF-8',
    }
    request.options.body = body
  }

  return request
}

async function readPreview(response, limit = MAX_RESPONSE_PREVIEW_BYTES) {
  if (!response.body?.getReader) {
    const text = await response.text()
    const bytes = new TextEncoder().encode(text)
    if (bytes.byteLength <= limit) {
      return { preview: text, truncated: false, bodyBytes: bytes.byteLength }
    }
    return {
      preview: new TextDecoder().decode(bytes.slice(0, limit)),
      truncated: true,
      bodyBytes: bytes.byteLength,
    }
  }

  const reader = response.body.getReader()
  const chunks = []
  let previewBytes = 0
  let bodyBytes = 0
  let truncated = false
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      bodyBytes += value.byteLength
      const remaining = limit - previewBytes
      if (value.byteLength > remaining) {
        if (remaining > 0) chunks.push(value.slice(0, remaining))
        previewBytes = limit
        truncated = true
      } else if (remaining > 0) {
        chunks.push(value)
        previewBytes += value.byteLength
      }
    }
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(previewBytes)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return { preview: new TextDecoder().decode(bytes), truncated, bodyBytes }
}

async function summarizeProtectedResponse(
  response,
  sessionId,
  exchange,
  request,
  startedAt,
  now,
) {
  const durationMs = Math.max(0, now() - startedAt)
  const responseHeaders = [...response.headers.entries()]
  const contentType = response.headers.get('content-type') || 'Not provided'
  const { preview, truncated, bodyBytes: responseBodyBytes } = await readPreview(response)
  return {
    protected: true,
    sessionId,
    exchange,
    method: request.options.method,
    path: request.path,
    requestBodyBytes: request.options.body
      ? new TextEncoder().encode(request.options.body).byteLength
      : 0,
    responseBodyBytes,
    responseHeaders,
    ok: response.ok,
    status: response.status,
    contentType,
    durationMs,
    preview,
    truncated,
  }
}

export function isAuthenticatedSteveStatus(status) {
  const checks = status?.attestation?.checks
  return Boolean(
    status?.initialized &&
      status?.state === 'ready' &&
      status?.session?.confirmation === 'verified' &&
      status?.attestation?.verified === true &&
      status?.attestation?.synthetic === false &&
      status?.attestationVerifier?.id === 'aws-nitro' &&
      status?.attestationVerifier?.synthetic === false &&
      REQUIRED_PCRS.every((name) => /^[0-9a-f]{96}$/iu.test(status?.attestation?.pcrs?.[name])) &&
      checks?.certificateChain === 'verified' &&
      checks?.nonceBinding === 'verified' &&
      checks?.sessionBinding === 'verified' &&
      checks?.keyConfirmation === 'verified',
  )
}

export function hasDebugPcrs(pcrs) {
  return REQUIRED_PCRS.some((name) => String(pcrs?.[name] || '').toLowerCase() === ZERO_PCR)
}

function pcrIndex(name) {
  const match = String(name).match(/^PCR(\d{1,3})$/iu)
  if (!match || Number(match[1]) > 255) return null
  return Number(match[1])
}

export function classifyE2eePcrs(pcrs) {
  const classified = { required: [], optional: [], zero: [], malformed: [] }
  for (const [rawName, rawValue] of Object.entries(pcrs || {})) {
    const index = pcrIndex(rawName)
    const name = index === null ? String(rawName) : `PCR${index}`
    const value = String(rawValue || '').trim().replace(/^0x/iu, '').toLowerCase()
    if (index === null || !/^[0-9a-f]{96}$/u.test(value)) {
      classified.malformed.push({ name, value })
    } else if (value === ZERO_PCR) {
      classified.zero.push({ name, value })
    } else {
      classified[REQUIRED_PCRS.includes(name) ? 'required' : 'optional'].push({ name, value })
    }
  }
  const sort = (left, right) => {
    const leftIndex = pcrIndex(left.name)
    const rightIndex = pcrIndex(right.name)
    if (leftIndex === null || rightIndex === null) return left.name.localeCompare(right.name)
    return leftIndex - rightIndex
  }
  for (const entries of Object.values(classified)) entries.sort(sort)
  return classified
}

export function isPcrPolicyMismatch(error) {
  return ['PCR_POLICY_MISMATCH', 'PCR_TRUST_MISMATCH'].includes(error?.code)
}

export function normalizeE2eePcrs(pcrs) {
  if (!pcrs || typeof pcrs !== 'object' || Array.isArray(pcrs)) {
    throw new Error('A PCR profile must be an object.')
  }
  const entries = []
  const seen = new Set()
  for (const [rawName, rawValue] of Object.entries(pcrs)) {
    const index = pcrIndex(rawName)
    if (index === null) throw new Error('PCR profile keys must be PCR0 through PCR255.')
    const name = `PCR${index}`
    if (seen.has(name)) throw new Error(`${name} was provided more than once.`)
    const value = String(rawValue || '').trim().replace(/^0x/iu, '').toLowerCase()
    if (!/^[0-9a-f]{96}$/u.test(value)) {
      throw new Error('Each PCR value must be a 96 hexadecimal character SHA-384 hash.')
    }
    if (value === ZERO_PCR) throw new Error(`${name} must be a non-zero release measurement.`)
    entries.push([name, value, index])
    seen.add(name)
  }
  if (!REQUIRED_PCRS.every((name) => seen.has(name))) {
    throw new Error('Provide PCR0, PCR1, and PCR2.')
  }
  return Object.fromEntries(entries.sort((left, right) => left[2] - right[2]).map(([name, value]) => [name, value]))
}

export function parseE2eePcrProfile(input) {
  const trimmed = String(input || '').trim()
  if (trimmed.startsWith('{')) {
    let parsed
    try {
      parsed = JSON.parse(trimmed)
    } catch {
      throw new Error('Expected PCR JSON is invalid.')
    }
    return normalizeE2eePcrs(parsed)
  }
  return normalizeE2eePcrs(parseExpectedPcrs(trimmed))
}

function canonicalPcrProfile(pcrs) {
  return Object.entries(normalizeE2eePcrs(pcrs))
    .map(([name, value]) => `${name}=${value}`)
    .join('\n')
}

export async function createE2eePcrProfile(
  pcrs,
  source = 'manual',
  addedAt = new Date().toISOString(),
  cryptoObject = globalThis.crypto,
) {
  if (typeof addedAt !== 'string' || Number.isNaN(Date.parse(addedAt))) {
    throw new Error('PCR profile timestamp is invalid.')
  }
  const normalized = normalizeE2eePcrs(pcrs)
  return {
    fingerprint: await sha256Hex(canonicalPcrProfile(normalized), cryptoObject),
    pcrs: normalized,
    source: String(source || 'manual'),
    addedAt,
  }
}

export async function normalizeE2eePcrProfiles(profiles, cryptoObject = globalThis.crypto) {
  if (!Array.isArray(profiles)) throw new Error('PCR profiles must be an array.')
  const normalized = []
  const seen = new Set()
  for (const profile of profiles) {
    const next = await createE2eePcrProfile(
      profile?.pcrs,
      profile?.source,
      profile?.addedAt,
      cryptoObject,
    )
    if (seen.has(next.fingerprint)) continue
    seen.add(next.fingerprint)
    normalized.push(next)
  }
  return normalized
}

function profileStorageKey(prefix, origin, suite) {
  return `${prefix}${requireSuite(suite)}:${normalizeSteveOrigin(origin)}`
}

export async function loadE2eePcrProfiles(storage, origin, suite, cryptoObject = globalThis.crypto) {
  const normalizedOrigin = normalizeSteveOrigin(origin)
  const normalizedSuite = requireSuite(suite)
  const currentKey = profileStorageKey(PROFILE_STORAGE_PREFIX, normalizedOrigin, normalizedSuite)
  const currentValue = storage.getItem(currentKey)
  if (currentValue) {
    try {
      const record = JSON.parse(currentValue)
      if (record.version !== 2 || record.origin !== normalizedOrigin || record.suite !== normalizedSuite) return []
      return normalizeE2eePcrProfiles(record.profiles, cryptoObject)
    } catch {
      return []
    }
  }

  const legacyKey = profileStorageKey(LEGACY_PROFILE_STORAGE_PREFIX, normalizedOrigin, normalizedSuite)
  const legacyValue = storage.getItem(legacyKey)
  if (!legacyValue) return []
  try {
    const record = JSON.parse(legacyValue)
    if (record.version !== 1 || record.origin !== normalizedOrigin || record.suite !== normalizedSuite) return []
    const profiles = [await createE2eePcrProfile(record.pcrs, 'remembered', record.savedAt, cryptoObject)]
    await saveE2eePcrProfiles(storage, normalizedOrigin, normalizedSuite, profiles, cryptoObject)
    storage.removeItem(legacyKey)
    return profiles
  } catch {
    return []
  }
}

export async function saveE2eePcrProfiles(
  storage,
  origin,
  suite,
  profiles,
  cryptoObject = globalThis.crypto,
) {
  const normalizedOrigin = normalizeSteveOrigin(origin)
  const normalizedSuite = requireSuite(suite)
  const normalizedProfiles = await normalizeE2eePcrProfiles(profiles, cryptoObject)
  storage.setItem(
    profileStorageKey(PROFILE_STORAGE_PREFIX, normalizedOrigin, normalizedSuite),
    JSON.stringify({
      version: 2,
      origin: normalizedOrigin,
      suite: normalizedSuite,
      profiles: normalizedProfiles,
    }),
  )
  return normalizedProfiles
}

export function e2eePcrPolicy(profiles) {
  if (!profiles.length) return null
  return {
    mode: 'pinned',
    profiles: profiles.map(({ pcrs }) =>
      Object.fromEntries(Object.entries(pcrs).map(([name, value]) => [name, value])),
    ),
  }
}

export async function reconcileE2eePcrProfiles(
  workerPolicy,
  storedProfiles,
  cryptoObject = globalThis.crypto,
  now = () => new Date().toISOString(),
) {
  const stored = await normalizeE2eePcrProfiles(storedProfiles, cryptoObject)
  if (!workerPolicy) {
    return { profiles: stored, replaceWorkerPolicy: stored.length > 0 }
  }
  if (workerPolicy.mode !== 'pinned' || !Array.isArray(workerPolicy.profiles)) {
    throw new Error('This tester supports only pinned browser PCR policies.')
  }
  const metadata = new Map(stored.map((profile) => [profile.fingerprint, profile]))
  const profiles = []
  for (const pcrs of workerPolicy.profiles) {
    const candidate = await createE2eePcrProfile(pcrs, 'worker', now(), cryptoObject)
    profiles.push(metadata.get(candidate.fingerprint) || candidate)
  }
  return {
    profiles: await normalizeE2eePcrProfiles(profiles, cryptoObject),
    replaceWorkerPolicy: false,
  }
}

export function compareSessionPcrProfiles(status, profiles) {
  if (!isAuthenticatedSteveStatus(status)) return null
  if (hasDebugPcrs(status.attestation.pcrs)) return { state: 'debug', comparisons: [] }
  if (!profiles.length) return { state: 'not-checked', comparisons: [] }
  for (const profile of profiles) {
    const comparison = compareVerifiedPcrs(
      { verified: true, pcrs: status.attestation.pcrs },
      profile.pcrs,
    )
    if (comparison.matches) {
      return { state: 'matched', profileFingerprint: profile.fingerprint, ...comparison }
    }
  }
  return { state: 'mismatch', comparisons: [] }
}

export function describeSteveTrustState(
  status,
  profileCount,
  { busy = false, error = null, sdkReady = false } = {},
) {
  const authenticated = isAuthenticatedSteveStatus(status)
  if (busy) {
    return {
      badge: 'Working',
      tone: 'neutral',
      title: authenticated ? 'Refreshing the STEVE session' : 'Authenticating the STEVE session',
      message: 'Protected requests are paused until this session operation finishes.',
    }
  }
  if (error || status?.state === 'error') {
    const mismatch = isPcrPolicyMismatch(error)
    return {
      badge: 'Blocked',
      tone: 'danger',
      title: mismatch ? 'Pinned PCR policy mismatch' : 'Session authentication failed',
      message: mismatch
        ? 'Nitro evidence authenticated, but no complete pinned profile matched. Add an independently approved profile before sending a request.'
        : 'No authenticated STEVE channel is available.',
    }
  }
  if (authenticated && hasDebugPcrs(status.attestation.pcrs)) {
    return {
      badge: 'Blocked',
      tone: 'danger',
      title: 'Zero PCR measurements detected',
      message: 'At least one required PCR is zero. Protected requests are blocked.',
    }
  }
  if (
    authenticated &&
    profileCount > 0 &&
    status?.attestation?.pcrTrust === 'pinned' &&
    status?.attestation?.checks?.expectedPcrPolicy === 'verified'
  ) {
    return {
      badge: 'Matched',
      tone: 'success',
      title: 'Browser PCR policy matched',
      message: `This session matched one of ${profileCount} complete pinned ${profileCount === 1 ? 'profile' : 'profiles'}.`,
    }
  }
  if (authenticated) {
    return {
      badge: 'Not checked',
      tone: 'warning',
      title: 'Session authenticated; deployment not checked',
      message: 'Nitro evidence and STEVE protocol bindings are verified, but no browser PCR policy is active.',
    }
  }
  if (!sdkReady) {
    return {
      badge: 'Loading',
      tone: 'neutral',
      title: 'Loading the pinned STEVE client',
      message: 'Session controls will appear when the client is ready.',
    }
  }
  return {
    badge: 'Ready',
    tone: 'neutral',
    title: 'Ready to establish a STEVE session',
    message: 'No application request is sent until the Nitro-backed session is authenticated.',
  }
}

export function protectedRequestGate(status, profileCount, acknowledged, error = null) {
  if (isPcrPolicyMismatch(error)) {
    return {
      allowed: false,
      reason: 'Pinned PCR policy mismatch. Add an independently approved profile before sending a request.',
    }
  }
  if (!isAuthenticatedSteveStatus(status)) {
    return { allowed: false, reason: 'Establish an authenticated STEVE session first.' }
  }
  if (hasDebugPcrs(status.attestation.pcrs)) {
    return { allowed: false, reason: 'Zero PCR measurements block protected requests.' }
  }
  if (profileCount > 0) {
    const enforced =
      status?.attestation?.pcrTrust === 'pinned' &&
      status?.attestation?.checks?.expectedPcrPolicy === 'verified'
    return enforced
      ? { allowed: true, reason: '' }
      : { allowed: false, reason: 'The worker has not verified the pinned PCR policy.' }
  }
  if (!acknowledged) {
    return { allowed: false, reason: 'Enable non-sensitive test-data mode first.' }
  }
  return { allowed: true, reason: '' }
}

async function runtimeImport(path) {
  return import(/* @vite-ignore */ path)
}

export class SteveSessionAdapter {
  constructor(client, origin) {
    this.client = client
    this.origin = normalizeSteveOrigin(origin)
  }

  status() {
    return this.client.getStatus()
  }

  establish() {
    return this.client.initialize()
  }

  async reconnect() {
    await this.client.reset()
    return this.client.initialize()
  }

  rotate() {
    return this.client.rotateSession()
  }

  reset() {
    return this.client.reset()
  }

  getPcrPolicy() {
    return this.client.getPcrPolicy()
  }

  replacePcrProfiles(profiles) {
    return this.client.replacePcrPolicy(e2eePcrPolicy(profiles))
  }

  onChange(callback, onError = () => {}) {
    let active = true
    let refreshPending = false
    const refresh = () => {
      if (!active || refreshPending) return
      refreshPending = true
      Promise.resolve()
        .then(() => this.status())
        .then((status) => active && callback(status))
        .catch((error) => active && onError(error))
        .finally(() => {
          refreshPending = false
        })
    }
    const removers = ['status', 'initialized', 'key-rotated', 'reset'].map((event) =>
      this.client.on(event, refresh),
    )
    const removeError = this.client.on('error', (event) => {
      if (event?.stage === 'initialization') onError(event)
      else refresh()
    })
    return () => {
      active = false
      for (const remove of [...removers, removeError]) {
        if (typeof remove === 'function') remove()
      }
    }
  }

  async request(input, now = () => performance.now()) {
    const request = prepareProtectedRequest(this.origin, input)
    const startedAt = now()
    const { response, sessionId, exchange } = await this.client.send(
      request.path,
      request.options,
    )
    return summarizeProtectedResponse(response, sessionId, exchange, request, startedAt, now)
  }
}

export async function sendProtectedRequest(adapter, status, profileCount, acknowledged, input) {
  const gate = protectedRequestGate(status, profileCount, acknowledged)
  if (!gate.allowed) throw new Error(gate.reason)
  const result = await adapter.request(input)
  return { status: await adapter.status(), result }
}

export async function connectSteveSession(
  target,
  { importer = runtimeImport } = {},
) {
  const module = await importer(STEVE_REGISTER_PATH)
  if (typeof module.registerEnclaveServiceWorker !== 'function') {
    throw new Error('The pinned STEVE browser client could not be loaded.')
  }
  const client = await module.registerEnclaveServiceWorker({
    swPath: STEVE_WORKER_PATH,
    scope: target.scope,
    config: {
      enclaveOrigin: target.origin,
      expectedKeyExchange: target.suite,
      emitEncryptedPayloads: false,
      passthroughPaths: [],
      excludePrefixes: [],
      requestTimeoutMs: 30_000,
    },
  })
  return new SteveSessionAdapter(client, target.origin)
}

export function describeSteveError(error, pageOrigin) {
  switch (error?.code) {
    case 'TRANSPORT':
    case 'TIMEOUT':
      return `Could not reach STEVE. Its /e2p/v2 endpoints must allow POST and OPTIONS from ${pageOrigin}.`
    case 'HTTP_STATUS':
      return Number.isInteger(error.httpStatus)
        ? `STEVE rejected the protocol request with HTTP ${error.httpStatus}. Check target availability and exact-origin CORS for ${pageOrigin}.`
        : `STEVE rejected the protocol request. Check target availability and exact-origin CORS for ${pageOrigin}.`
    case 'PCR_POLICY_MISMATCH':
    case 'PCR_TRUST_MISMATCH':
      return 'Authenticated evidence did not match any complete pinned PCR profile.'
    case 'ATTESTED_PCR_INVALID':
      return 'STEVE returned missing, malformed, or zero PCR measurements.'
    case 'PCR_POLICY_INVALID':
      return 'The browser PCR policy is invalid.'
    case 'ATTESTATION_INVALID':
      return 'AWS Nitro attestation verification failed.'
    case 'CONFIRMATION_INVALID':
      return 'STEVE session key confirmation failed.'
    default:
      return error?.message || 'The STEVE operation failed.'
  }
}

export function describeSteveSessionError(error, pageOrigin) {
  return describeSteveError(error, pageOrigin)
}
