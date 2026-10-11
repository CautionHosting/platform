import test from 'node:test'
import assert from 'node:assert/strict'
import { reactive } from 'vue'
import { releaseOptions, releaseAssertion } from '../src/composables/releaseApproval.js'

test('release approval requires UV and permits platform/phone authenticators without changing attested options', () => {
  const options = { publicKey: { challenge: 'AQID', userVerification: 'preferred', hints: ['security-key'], allowCredentials: [{ type: 'public-key', id: 'BAUG' }] } }
  const result = releaseOptions(reactive(options))
  assert.equal(result.userVerification, 'required')
  assert.equal(result.hints, undefined)
  assert.deepEqual([...result.challenge], [1, 2, 3])
  assert.deepEqual([...result.allowCredentials[0].id], [4, 5, 6])
  assert.equal(options.publicKey.challenge, 'AQID')
})
test('raw assertion is preserved for enclave verification; cancellation produces no assertion', () => {
  assert.throws(() => releaseAssertion(null))
  const value = Uint8Array.of(1, 2, 3).buffer
  const result = releaseAssertion({ id: 'AQID', rawId: value, type: 'public-key', response: { authenticatorData: value, clientDataJSON: value, signature: value, userHandle: null }, getClientExtensionResults: () => ({}) })
  assert.equal(result.response.signature, 'AQID')
  assert.equal(result.response.userHandle, null)
  assert.equal(result.rawId, 'AQID')
})
