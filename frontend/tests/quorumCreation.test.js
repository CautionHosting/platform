import assert from 'node:assert/strict'
import test from 'node:test'
import * as pgp from 'openpgp'
import { recoveryMethods, initialSelection, creationRequest, parsePublicKeyring, parsePublicHolder, validateHolderFingerprints, MAX_DASHBOARD_HOLDERS, createBundleSubmitter, MAX_KEYRING_BYTES, MAX_CREATION_BYTES, GENERATION_PATH } from '../src/utils/quorumCreation.js'

const members = [
  { user_id: 'alice', username: 'Alice', pgp_keys: [{ id: 'key-a', fingerprint: 'AA' }], webauthn_credentials: 0, webauthn_uv_credentials: 0 },
  { user_id: 'bob', username: 'Bob', pgp_keys: [], webauthn_credentials: 3, webauthn_uv_credentials: 1 },
  { user_id: 'chloe', username: 'Chloe', pgp_keys: [{ id: 'key-c1', fingerprint: 'CC' }, { id: 'key-c2', fingerprint: 'DD' }], webauthn_credentials: 1, webauthn_uv_credentials: 1 },
  { user_id: 'dan', username: 'Dan', pgp_keys: [], webauthn_credentials: 0, webauthn_uv_credentials: 0 },
]
const base = () => ({ name: ' Demo ', threshold: 2, members, selections: members.slice(0, 2).map(initialSelection), certificates: [] })
test('eligibility, explicit method choice, and exact registered key selection', () => {
  assert.deepEqual(recoveryMethods(members[3]), [])
  assert.equal(initialSelection(members[2]).key_source, '')
  assert.equal(initialSelection(members[2]).pgp_key_id, '')
  const args = base()
  const mixed = creationRequest(args)
  assert.equal(mixed.name, 'Demo')
  assert.equal(mixed.allow_caution_backed_keys, true)
  assert.equal(mixed.participants.length, 2) // three passkeys still one share
  assert.equal(mixed.participants[1].pgp_key_id, null)
  args.selections = [initialSelection(members[2])]; args.threshold = 1
  assert.throws(() => creationRequest(args), /approval method/)
  args.selections[0].key_source = 'existing_pgp'
  assert.throws(() => creationRequest(args), /registered PGP key/)
  args.selections[0].pgp_key_id = 'key-c2'
  assert.equal(creationRequest(args).allow_caution_backed_keys, false)
  args.selections = [initialSelection(members[1])]
  assert.equal(creationRequest(args).participants[0].key_source, 'caution_backed_pgp')
})
test('threshold, unavailable members, duplicate users, holder and request bounds', () => {
  for (const threshold of [0, 3, 1.5, '', NaN]) assert.throws(() => creationRequest({ ...base(), threshold }), /threshold/)
  assert.equal(creationRequest({ ...base(), threshold: 1 }).threshold, 1)
  assert.throws(() => creationRequest({ ...base(), selections: [initialSelection(members[3])] }), /approval method/)
  assert.throws(() => creationRequest({ ...base(), selections: [initialSelection(members[0]), initialSelection(members[0])] }), /only once/)
  assert.throws(() => creationRequest({ ...base(), name: 'x'.repeat(MAX_CREATION_BYTES) }), /1 MiB/)
  assert.equal(MAX_DASHBOARD_HOLDERS, 10)
  for (const count of [9, 10, 11]) {
    const args = { ...base(), certificates: Array.from({ length: count - 2 }, (_, i) => ({ armor: 'public', fingerprint: `F${i}` })) }
    if (count <= 10) assert.equal(creationRequest(args).participants.length + creationRequest(args).pgp_certificates.length, count)
    else assert.throws(() => creationRequest(args), /at most 10/)
  }
})
test('combines both holder types and detects duplicate fingerprints in either selection order', () => {
  const certificates = [{ armor: 'public', fingerprint: 'FF' }]
  const request = creationRequest({ ...base(), certificates })
  assert.equal(request.participants.length, 2)
  assert.deepEqual(request.pgp_certificates, ['public'])
  assert.equal(request.allow_caution_backed_keys, true)
  assert.equal(creationRequest({ ...base(), selections: [], threshold: 1, certificates }).allow_caution_backed_keys, false)
  assert.throws(() => creationRequest({ ...base(), selections: [], certificates: [] }), /at least one/)
  const duplicate = [{ armor: 'public', fingerprint: 'a a' }]
  assert.throws(() => validateHolderFingerprints(base().selections, members, duplicate), /Duplicate PGP holder/)
  assert.throws(() => creationRequest({ ...base(), certificates: duplicate }), /Duplicate PGP holder/)
  assert.throws(() => creationRequest({ ...base(), certificates: [...certificates, ...certificates] }), /Duplicate PGP holder/)
})
const keys = Promise.all(['Alice', 'Bob'].map(name => pgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })))
const armorPackets = packets => pgp.armor(pgp.enums.armor.publicKey, packets.write())
test('imports separate armor blocks and multiple certificates in a single armor block', async () => {
  const [a, b] = await keys
  for (const text of [a.publicKey.armor() + '\n' + b.publicKey.armor(), armorPackets(new pgp.PacketList(...a.publicKey.toPacketList(), ...b.publicKey.toPacketList()))]) {
    const result = await parsePublicKeyring(text)
    assert.deepEqual(result.map(cert => cert.userId), ['Alice', 'Bob'])
    assert.equal(result[0].fingerprint, a.publicKey.getFingerprint().toUpperCase())
    assert.equal((await pgp.readKeys({ armoredKeys: result[0].armor })).length, 1)
  }
})
test('manual holder addition accepts exactly one certificate', async () => {
  const [a, b] = await keys
  assert.equal((await parsePublicHolder(a.publicKey.armor())).fingerprint, a.publicKey.getFingerprint().toUpperCase())
  for (const input of [a.publicKey.armor() + b.publicKey.armor(), armorPackets(new pgp.PacketList(...a.publicKey.toPacketList(), ...b.publicKey.toPacketList()))]) {
    await assert.rejects(parsePublicHolder(input), /one public certificate/)
  }
})
test('rejects private material even inside public armor or attached to a public primary key', async () => {
  const [a, b] = await keys
  const hiddenSecret = armorPackets(new pgp.PacketList(...a.publicKey.toPacketList(), ...b.privateKey.toPacketList()))
  const hiddenSubkey = armorPackets(new pgp.PacketList(...a.publicKey.toPacketList(), b.privateKey.subkeys[0].keyPacket))
  for (const text of [a.privateKey.armor(), a.publicKey.armor() + b.privateKey.armor(), hiddenSecret, hiddenSubkey]) {
    await assert.rejects(parsePublicKeyring(text), /Private keys/)
  }
})
test('rejects malformed, trailing, duplicate, oversized and non-key packets', async () => {
  const [a] = await keys
  await assert.rejects(parsePublicKeyring('not armor'))
  await assert.rejects(parsePublicKeyring(a.publicKey.armor() + 'unconsumed data'))
  await assert.rejects(parsePublicKeyring(a.publicKey.armor().replace('END PGP', 'BROKEN PGP')))
  await assert.rejects(parsePublicKeyring(a.publicKey.armor() + a.publicKey.armor()), /Duplicate/)
  await assert.rejects(parsePublicKeyring('x'.repeat(MAX_KEYRING_BYTES + 1)), /512 KiB/)
  const packets = new pgp.PacketList(...a.publicKey.toPacketList())
  packets.push(new pgp.LiteralDataPacket())
  packets.at(-1).setText('not a key')
  await assert.rejects(parsePublicKeyring(armorPackets(packets)))
})
test('signs exactly the body sent, using the canonical path, and guards double submission', async () => {
  const calls = []
  let release
  const waiting = new Promise(resolve => { release = resolve })
  const submit = createBundleSubmitter({
    sign: async (...args) => { calls.push(['sign', ...args]); await waiting; return { 'X-Fido2-Response': 'assertion' } },
    fetch: async (url, options) => { calls.push(['fetch', url, options]); return Response.json({ id: 'created', data: {} }) },
  })
  const payload = creationRequest(base())
  const pending = submit(payload)
  await assert.rejects(submit(payload), /already in progress/)
  release()
  assert.equal((await pending).id, 'created')
  assert.equal(calls.length, 2)
  assert.deepEqual(calls[0], ['sign', 'POST', GENERATION_PATH, JSON.stringify(payload)])
  assert.equal(calls[1][1], `/api${GENERATION_PATH}`)
  assert.equal(calls[1][2].body, calls[0][3])
  assert.equal(calls[1][2].headers['X-Fido2-Response'], 'assertion')
})
test('cancelled signing never sends a creation request', async () => {
  let calls = 0
  const submit = createBundleSubmitter({ sign: async () => { throw new DOMException('Cancelled', 'NotAllowedError') }, fetch: async () => { calls++ } })
  await assert.rejects(submit({}), error => error.name === 'NotAllowedError' && !error.uncertain)
  assert.equal(calls, 0)
})
test('preserves text/JSON errors and marks uncertain outcomes without retrying', async () => {
  for (const [reply, uncertain, message] of [
    [() => new Response('Invalid certificate', { status: 400 }), false, 'Invalid certificate'],
    [() => Response.json({ error: 'Unavailable' }, { status: 503 }), true, 'Unavailable'],
    [() => new Response('{broken', { status: 200 }), true, null],
    [() => Response.json({ id: 'missing-data' }), true, null],
    [() => { throw new TypeError('Network lost') }, true, 'Network lost'],
  ]) {
    let calls = 0
    const submit = createBundleSubmitter({ sign: async () => ({}), fetch: async () => { calls++; return reply() } })
    await assert.rejects(submit({}), error => error.uncertain === uncertain && (!message || error.message === message))
    assert.equal(calls, 1)
  }
})
test('generation timeout is uncertain and never retried', async () => {
  let calls = 0
  const submit = createBundleSubmitter({ timeoutMs: 5, sign: async () => ({}), fetch: async (_, { signal }) => {
    calls++
    return new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(new DOMException('Timeout', 'AbortError'))))
  } })
  await assert.rejects(submit({}), error => error.uncertain)
  assert.equal(calls, 1)
})
