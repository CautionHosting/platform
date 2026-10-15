import test from 'node:test'
import assert from 'node:assert/strict'
import { verifyPasskeyRecovery } from '../src/composables/passkeyRecovery.js'
import { cautionCustodyUnavailable, recoveryMethods } from '../src/utils/quorumCreation.js'

const credential = () => {
  const bytes = Uint8Array.of(1).buffer
  return { id: 'AQ', rawId: bytes, type: 'public-key', response: {
    authenticatorData: bytes, clientDataJSON: bytes, signature: bytes, userHandle: null,
  }, getClientExtensionResults: () => ({}) }
}
const begin = () => Response.json({ session: 'once', publicKey: {
  challenge: 'AQ', allowCredentials: [{ type: 'public-key', id: 'AQ' }], userVerification: 'preferred',
} })

test('verify existing credential requires UV and waits for server confirmation', async () => {
  const calls = []
  await verifyPasskeyRecovery('row', async (path, options) => {
    calls.push([path, options])
    return calls.length === 1 ? begin() : Response.json({ uv_verified: true })
  }, async ({ publicKey }) => {
    assert.equal(publicKey.userVerification, 'required')
    assert.deepEqual([...publicKey.allowCredentials[0].id], [1])
    return credential()
  })
  assert.equal(calls[0][0], '/passkeys/row/recovery-verification/begin')
  assert.equal(calls[1][0], '/passkeys/row/recovery-verification/finish')
  assert.equal(JSON.parse(calls[1][1].body).session, 'once')
  assert.equal(JSON.parse(calls[1][1].body).response.signature, 'AQ')
})

test('cancelled verification sends no finish and false server confirmation fails', async () => {
  let calls = 0
  await assert.rejects(verifyPasskeyRecovery('row', async () => { calls++; return begin() }, async () => {
    throw new DOMException('cancelled', 'NotAllowedError')
  }), { name: 'NotAllowedError' })
  assert.equal(calls, 1)
  calls = 0
  await assert.rejects(verifyPasskeyRecovery('row', async () => ++calls === 1 ? begin() : Response.json({ uv_verified: false }), async () => credential()), /not confirmed/)
})

test('quorum UI requires evidence and a complete snapshot within the recovery bound', () => {
  const member = { pgp_keys: [], webauthn_credentials: 1 }
  assert.match(cautionCustodyUnavailable(member), /Verify/)
  assert.deepEqual(recoveryMethods(member), [])
  member.webauthn_uv_credentials = 1
  for (const count of [0, 1, 64, 65]) {
    member.webauthn_credentials = count
    assert.equal(recoveryMethods(member).includes('caution_backed_pgp'), count >= 1 && count <= 64)
  }
})
