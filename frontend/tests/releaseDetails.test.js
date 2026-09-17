import test from 'node:test'
import assert from 'node:assert/strict'
import { comparisonCode, secondsRemaining, displayValue, uuid } from '../src/composables/releaseDetails.js'
test('comparison uses exactly the same uppercase grouped prefix as the CLI', () => {
  assert.equal(comparisonCode('edcd12bf40e1c288' + '0'.repeat(48)), 'EDCD 12BF 40E1 C288')
  assert.equal(comparisonCode('invalid'), 'Unavailable')
})
test('expiry fails closed at the cutoff or if missing', () => {
  assert.equal(secondsRemaining(100, 99000), 1)
  assert.equal(secondsRemaining(100, 100000), 0)
  assert.equal(secondsRemaining(100, 101000), 0)
  assert.equal(secondsRemaining(undefined), 0)
})
test('display preserves full values and reports missing metadata', () => {
  assert.equal(displayValue(null), 'Unavailable')
  assert.equal(displayValue(0), '0')
  assert.equal(displayValue('<script>'), '<script>')
  assert.equal(uuid(Array(16).fill(1)), '01010101-0101-0101-0101-010101010101')
})
