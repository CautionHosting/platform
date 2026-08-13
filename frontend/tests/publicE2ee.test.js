// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'

import {
  MAX_REQUEST_BODY_BYTES,
  MAX_RESPONSE_PREVIEW_BYTES,
  STEVE_CLIENT_COMMIT,
  STEVE_REGISTER_PATH,
  STEVE_WORKER_PATH,
  SteveSessionAdapter,
  buildControlledTesterTarget,
  buildSteveCorsExample,
  compareSessionPcrProfiles,
  connectSteveSession,
  createE2eePcrProfile,
  describeSteveError,
  describeSteveTrustState,
  e2eePcrPolicy,
  externalSteveOrigin,
  hasDebugPcrs,
  loadE2eePcrProfiles,
  normalizeE2eePcrProfiles,
  normalizeE2eePcrs,
  normalizeProtectedPath,
  normalizeSteveOrigin,
  parseE2eePcrProfile,
  prepareProtectedRequest,
  protectedRequestGate,
  reconcileE2eePcrProfiles,
  resolveControlledTesterTarget,
  saveE2eePcrProfiles,
  sendProtectedRequest,
} from '../src/utils/publicE2ee.js'

const PCRS = {
  PCR0: 'a'.repeat(96),
  PCR1: 'b'.repeat(96),
  PCR2: 'c'.repeat(96),
}

const EXCHANGE = {
  protocolName: 'STEVE-E2P-V2',
  protection: 'AES-256-GCM',
  sessionId: 'protected-session',
  sequence: '1',
  keyExchange: 'X25519',
  pcrTrust: 'pinned',
  outerStatus: 200,
  requestPlaintextBytes: 57,
  requestCiphertextBytes: 73,
  requestEnvelopeBytes: 116,
  responseEnvelopeBytes: 111,
  responseCiphertextBytes: 68,
  responsePlaintextBytes: 52,
}

function readyStatus(pcrs = PCRS, pcrTrust = 'not-checked') {
  return {
    state: 'ready',
    initialized: true,
    protocol: { keyEstablishment: 'X25519' },
    session: { confirmation: 'verified', id: 'session' },
    attestationVerifier: { id: 'aws-nitro', synthetic: false },
    attestation: {
      verified: true,
      synthetic: false,
      pcrs,
      pcrTrust,
      checks: {
        certificateChain: 'verified',
        nonceBinding: 'verified',
        sessionBinding: 'verified',
        keyConfirmation: 'verified',
        expectedPcrPolicy: pcrTrust === 'pinned' ? 'verified' : 'not-checked',
      },
    },
  }
}

function memoryStorage() {
  const values = new Map()
  return {
    values,
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  }
}

test('accepts only bare external HTTPS STEVE origins and exact suites', async () => {
  assert.equal(normalizeSteveOrigin('Example.COM'), 'https://example.com')
  assert.equal(normalizeSteveOrigin('https://example.com:8443'), 'https://example.com:8443')
  for (const input of [
    'http://example.com',
    'https://user:secret@example.com',
    'https://example.com/path',
    'https://example.com?query=1',
    'https://example.com/#fragment',
  ]) assert.throws(() => normalizeSteveOrigin(input))
  await assert.rejects(buildControlledTesterTarget('https://example.com', 'x25519'), /X25519/)
  assert.equal(externalSteveOrigin('https://example.com', 'https://dashboard.caution.co'), 'https://example.com')
  assert.throws(
    () => externalSteveOrigin('https://dashboard.caution.co', 'https://dashboard.caution.co'),
    /must differ/u,
  )
})

test('builds and verifies a deterministic isolated tester URL', async () => {
  const target = await buildControlledTesterTarget('https://example.com', 'X25519')
  assert.match(target.hash, /^[0-9a-f]{64}$/u)
  assert.equal(target.scope, target.url.split('?')[0])
  assert.deepEqual(
    await resolveControlledTesterTarget(target.scope, target.url.slice(target.url.indexOf('?'))),
    target,
  )
  assert.equal(await resolveControlledTesterTarget('/verify-e2ee/', ''), null)
  await assert.rejects(
    resolveControlledTesterTarget(target.scope.replace(target.hash, '0'.repeat(64)), target.url.slice(target.url.indexOf('?'))),
    /does not match/u,
  )
})

test('renders the exact-origin caution.hcl CORS configuration', () => {
  assert.match(buildSteveCorsExample('https://dashboard.caution.co', 'X25519'), /key_exchange = "x25519"/u)
  assert.match(buildSteveCorsExample('http://127.0.0.1:3000', 'XWING-DRAFT10'), /cors_origins = \["http:\/\/127\.0\.0\.1:3000"\]/u)
})

test('accepts only safe application paths and GET or POST request shapes', () => {
  assert.equal(normalizeProtectedPath('/v1/hello?name=test', 'https://example.com'), '/v1/hello?name=test')
  for (const path of [
    'https://attacker.example/',
    '//attacker.example/',
    '/e2p/v2/session',
    '/%65%32%70/v2/session',
    '/attestation',
    '/safe/../attestation',
    '/hello#fragment',
    '/hello\\world',
  ]) assert.throws(() => normalizeProtectedPath(path, 'https://example.com'))

  assert.deepEqual(prepareProtectedRequest('https://example.com', { method: 'GET', path: '/health' }), {
    path: '/health',
    options: { method: 'GET' },
  })
  assert.deepEqual(prepareProtectedRequest('https://example.com', {
    method: 'POST',
    path: '/echo',
    bodyType: 'json',
    body: '{"ok":true}',
  }), {
    path: '/echo',
    options: {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"ok":true}',
    },
  })
  assert.throws(() => prepareProtectedRequest('https://example.com', {
    method: 'POST', path: '/', bodyType: 'text', body: 'x'.repeat(MAX_REQUEST_BODY_BYTES + 1),
  }), /64 KiB/u)
})

test('normalizes complete profiles with optional PCRs and rejects every zero value', () => {
  assert.deepEqual(normalizeE2eePcrs({ pcr3: 'D'.repeat(96), ...PCRS }), {
    ...PCRS,
    PCR3: 'd'.repeat(96),
  })
  assert.deepEqual(parseE2eePcrProfile(JSON.stringify({ ...PCRS, PCR8: 'e'.repeat(96) })), {
    ...PCRS,
    PCR8: 'e'.repeat(96),
  })
  assert.deepEqual(parseE2eePcrProfile(`PCR0=${PCRS.PCR0}\nPCR1=${PCRS.PCR1}\nPCR2=${PCRS.PCR2}`), PCRS)
  assert.throws(() => normalizeE2eePcrs({ PCR0: '0'.repeat(96), PCR1: PCRS.PCR1, PCR2: PCRS.PCR2 }), /PCR0/u)
  assert.throws(() => normalizeE2eePcrs({ ...PCRS, PCR3: '0'.repeat(96) }), /PCR3/u)
  assert.throws(() => normalizeE2eePcrs({ PCR0: PCRS.PCR0, PCR1: PCRS.PCR1 }), /PCR2/u)
})

test('fingerprints and de-duplicates whole profiles without mixing values', async () => {
  const first = await createE2eePcrProfile(PCRS, 'file', '2026-01-01T00:00:00.000Z')
  const duplicate = await createE2eePcrProfile({ PCR2: PCRS.PCR2, PCR0: PCRS.PCR0, PCR1: PCRS.PCR1 })
  const second = await createE2eePcrProfile({ ...PCRS, PCR2: 'd'.repeat(96) })
  assert.equal(first.fingerprint, duplicate.fingerprint)
  assert.equal((await normalizeE2eePcrProfiles([first, duplicate, second])).length, 2)

  const mixed = readyStatus({ PCR0: PCRS.PCR0, PCR1: 'e'.repeat(96), PCR2: 'd'.repeat(96) }, 'pinned')
  assert.equal(compareSessionPcrProfiles(mixed, [first, second]).state, 'mismatch')
  assert.equal(compareSessionPcrProfiles(readyStatus(PCRS, 'pinned'), [first, second]).profileFingerprint, first.fingerprint)

  const optional = await createE2eePcrProfile({ ...PCRS, PCR3: 'e'.repeat(96) })
  assert.equal(compareSessionPcrProfiles(readyStatus({ ...PCRS, PCR3: 'f'.repeat(96) }, 'pinned'), [optional]).state, 'mismatch')
})

test('stores multiple profiles and migrates the legacy single profile', async () => {
  const storage = memoryStorage()
  const origin = 'https://example.com'
  const suite = 'X25519'
  const first = await createE2eePcrProfile(PCRS, 'file', '2026-01-01T00:00:00.000Z')
  const second = await createE2eePcrProfile({ ...PCRS, PCR2: 'd'.repeat(96) }, 'manual')
  assert.equal((await saveE2eePcrProfiles(storage, origin, suite, [first, second])).length, 2)
  assert.deepEqual(await loadE2eePcrProfiles(storage, origin, suite), [first, second])

  const legacy = memoryStorage()
  legacy.setItem(`caution.verify-e2ee.expected-pcrs.v1:${suite}:${origin}`, JSON.stringify({
    version: 1,
    origin,
    suite,
    pcrs: PCRS,
    savedAt: '2026-01-02T00:00:00.000Z',
  }))
  const migrated = await loadE2eePcrProfiles(legacy, origin, suite)
  assert.equal(migrated.length, 1)
  assert.equal(migrated[0].source, 'remembered')
  assert.equal([...legacy.values.keys()].some((key) => key.includes('.v2:')), true)
})

test('surfaces browser metadata storage failure without weakening the worker policy', async () => {
  const profile = await createE2eePcrProfile(PCRS)
  const unavailable = {
    getItem: () => null,
    setItem: () => { throw new Error('unavailable') },
  }
  await assert.rejects(
    saveE2eePcrProfiles(unavailable, 'https://example.com', 'X25519', [profile]),
    /unavailable/u,
  )
  const workerPolicy = e2eePcrPolicy([profile])
  assert.deepEqual(workerPolicy, { mode: 'pinned', profiles: [PCRS] })
  assert.notEqual(workerPolicy.profiles[0], profile.pcrs)
  assert.equal(e2eePcrPolicy([]), null)
})

test('reconciles browser metadata to the worker-authoritative pinned policy', async () => {
  const stored = [await createE2eePcrProfile(PCRS, 'first-use', '2026-01-01T00:00:00.000Z')]
  assert.deepEqual(await reconcileE2eePcrProfiles(null, stored), {
    profiles: stored,
    replaceWorkerPolicy: true,
  })
  const fromWorker = await reconcileE2eePcrProfiles(e2eePcrPolicy(stored), stored)
  assert.equal(fromWorker.replaceWorkerPolicy, false)
  assert.equal(fromWorker.profiles[0].source, 'first-use')
  await assert.rejects(reconcileE2eePcrProfiles({ mode: 'tofu' }, stored), /only pinned/u)
})

test('uses worker PCR trust as the protected-request authority', async () => {
  const profile = await createE2eePcrProfile(PCRS)
  assert.deepEqual(protectedRequestGate(readyStatus(PCRS, 'pinned'), 1, false), { allowed: true, reason: '' })
  assert.equal(protectedRequestGate(readyStatus(PCRS), 1, true).allowed, false)
  assert.equal(protectedRequestGate(readyStatus(PCRS), 0, false).allowed, false)
  assert.equal(protectedRequestGate(readyStatus(PCRS), 0, true).allowed, true)
  assert.equal(protectedRequestGate(readyStatus({ ...PCRS, PCR1: '0'.repeat(96) }), 0, true).allowed, false)
  assert.equal(hasDebugPcrs({ ...PCRS, PCR2: '0'.repeat(96) }), true)
  assert.equal(compareSessionPcrProfiles(readyStatus(PCRS), [profile]).state, 'matched')
})

test('describes SDK-authoritative trust states without claiming independent identity', () => {
  assert.equal(describeSteveTrustState(readyStatus(PCRS, 'pinned'), 2).title, 'Browser PCR policy matched')
  assert.equal(describeSteveTrustState(readyStatus(PCRS), 0).badge, 'Not checked')
  assert.equal(describeSteveTrustState(null, 0, { sdkReady: true }).badge, 'Ready')
  assert.equal(describeSteveTrustState(null, 1, { error: { code: 'PCR_POLICY_MISMATCH' } }).title, 'Browser PCR policy did not match')
})

test('adapter delegates lifecycle, policy, and protected requests to the SDK', async () => {
  const calls = []
  const status = readyStatus(PCRS, 'pinned')
  const client = {
    getStatus: async () => status,
    initialize: async () => (calls.push('initialize'), status),
    reset: async () => (calls.push('reset'), { state: 'idle' }),
    rotateSession: async () => (calls.push('rotate'), status),
    getPcrPolicy: async () => ({ mode: 'pinned', profiles: [PCRS] }),
    replacePcrPolicy: async (policy) => ({ policy, status: { state: 'idle' } }),
    send: async (path, options) => {
      calls.push({ path, options })
      return {
        response: new Response('hello', { status: 200, headers: { 'content-type': 'text/plain' } }),
        sessionId: 'protected-session',
        exchange: EXCHANGE,
      }
    },
    on: () => () => {},
  }
  const adapter = new SteveSessionAdapter(client, 'https://example.com')
  assert.equal((await adapter.establish()).state, 'ready')
  assert.equal((await adapter.rotate()).state, 'ready')
  assert.equal((await adapter.reconnect()).state, 'ready')
  assert.equal((await adapter.replacePcrProfiles([await createE2eePcrProfile(PCRS)])).policy.mode, 'pinned')
  const result = await adapter.request({ method: 'GET', path: '/hello' }, (() => {
    let tick = 0
    return () => (tick += 5)
  })())
  assert.equal(result.sessionId, 'protected-session')
  assert.equal(result.exchange, EXCHANGE)
  assert.equal(result.requestBodyBytes, 0)
  assert.equal(result.responseBodyBytes, 5)
  assert.equal(result.preview, 'hello')
  assert.equal(result.durationMs, 5)
  assert.deepEqual(calls.at(-1), { path: '/hello', options: { method: 'GET' } })
})

test('adapter reports authenticated application HTTP errors as responses', async () => {
  const exchange = { ...EXCHANGE, sessionId: 'session-404', sequence: '2' }
  const client = {
    send: async () => ({
      response: new Response('missing', {
        status: 404,
        headers: { 'content-type': 'text/plain', 'x-display-test': '<script>alert(1)</script>' },
      }),
      sessionId: 'session-404',
      exchange,
    }),
  }
  const result = await new SteveSessionAdapter(client, 'https://example.com').request(
    { method: 'POST', path: '/missing', bodyType: 'text', body: 'é' },
    (() => {
      let tick = 0
      return () => (tick += 1)
    })(),
  )
  assert.equal(result.ok, false)
  assert.equal(result.status, 404)
  assert.equal(result.preview, 'missing')
  assert.equal(result.sessionId, 'session-404')
  assert.equal(result.exchange, exchange)
  assert.equal(result.requestBodyBytes, 2)
  assert.equal(result.responseBodyBytes, 7)
  assert.deepEqual(result.responseHeaders, [
    ['content-type', 'text/plain'],
    ['x-display-test', '<script>alert(1)</script>'],
  ])
})

test('adapter truncates only the preview while counting the complete response body', async () => {
  const body = 'x'.repeat(MAX_RESPONSE_PREVIEW_BYTES + 7)
  const client = {
    send: async () => ({
      response: new Response(body),
      sessionId: EXCHANGE.sessionId,
      exchange: EXCHANGE,
    }),
  }
  const result = await new SteveSessionAdapter(client, 'https://example.com').request(
    { method: 'GET', path: '/large' },
  )
  assert.equal(result.truncated, true)
  assert.equal(result.preview.length, MAX_RESPONSE_PREVIEW_BYTES)
  assert.equal(result.responseBodyBytes, MAX_RESPONSE_PREVIEW_BYTES + 7)
})

test('guarded sends use SDK routing and refresh display status afterward', async () => {
  const status = readyStatus(PCRS, 'pinned')
  const adapter = {
    request: async () => ({ protected: true, sessionId: 'new-session' }),
    status: async () => ({ ...status, session: { ...status.session, id: 'new-session' } }),
  }
  const sent = await sendProtectedRequest(adapter, status, 1, false, { method: 'GET', path: '/' })
  assert.equal(sent.result.sessionId, 'new-session')
  assert.equal(sent.status.session.id, 'new-session')
})

test('connects the isolated worker without installing a page-side PCR policy', async () => {
  let registration
  const client = { getStatus: async () => null }
  const target = await buildControlledTesterTarget('https://example.com', 'X25519')
  const adapter = await connectSteveSession(target, {
    importer: async (path) => ({
      registerEnclaveServiceWorker: async (options) => {
        registration = { path, options }
        return client
      },
    }),
  })
  assert.equal(adapter.client, client)
  assert.equal(registration.path, STEVE_REGISTER_PATH)
  assert.equal(registration.options.swPath, STEVE_WORKER_PATH)
  assert.equal(registration.options.scope, target.scope)
  assert.equal('pcrPolicy' in registration.options.config, false)
})

test('maps structured SDK errors without parsing diagnostic messages', () => {
  assert.match(describeSteveError({ code: 'TRANSPORT', message: 'opaque' }, 'https://dashboard.example'), /POST and OPTIONS/u)
  assert.match(describeSteveError({ code: 'PCR_POLICY_MISMATCH', message: 'opaque' }, 'https://dashboard.example'), /complete pinned/u)
  assert.equal(describeSteveError({ code: 'FUTURE_CODE', message: 'future detail' }, 'https://dashboard.example'), 'future detail')
})

test('pins the reviewed STEVE browser artifacts by commit and digest', async () => {
  assert.equal(STEVE_CLIENT_COMMIT, '2ee4760186df3022931aecc9145bd6bee8fc6137')
  const assets = {
    '../public/verify-e2ee/client/2ee4760186df3022931aecc9145bd6bee8fc6137/register.js':
      '3b271cdf4787c5374a2404616ddc226e95032c95f3cdd7db087c4e22dd45c623',
    '../public/verify-e2ee/client/2ee4760186df3022931aecc9145bd6bee8fc6137/enclave-sw.js':
      'b6df58f2de1197cb96a9621d9b2d8bc67a8200f3ad3c41e07b243d8ae9c1515f',
    '../public/verify-e2ee/client/2ee4760186df3022931aecc9145bd6bee8fc6137/xwing/steve_xwing_wasm_bg.wasm':
      '802131b0e84424760f3e2e37bcee0c76fb029aa3480d7742b839f60508cc0912',
  }
  for (const [path, expected] of Object.entries(assets)) {
    const bytes = await readFile(new URL(path, import.meta.url))
    assert.equal(createHash('sha256').update(bytes).digest('hex'), expected)
  }
})
