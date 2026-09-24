import test from 'node:test'
import assert from 'node:assert/strict'
import { safeUrl, verificationTarget, checkPresentation, servicePresentation, measurementRows, policyRows, relativeCheckTime, repositoryLabel } from '../src/utils/components.js'

const hash = 'a'.repeat(96)
const zero = '0'.repeat(96)
test('verification links carry only a safe endpoint, never observed PCRs', () => {
  const target = verificationTarget('https://keymaker.example.com/')
  const url = new URL(target.href, 'https://platform.example.com')
  assert.equal(url.pathname, '/verify')
  assert.deepEqual([...url.searchParams], [['url', 'https://keymaker.example.com/attestation']])
  assert.equal(target.command, "caution verify --attestation-url 'https://keymaker.example.com/attestation'")
  for (const bad of ['javascript:alert(1)', 'http://host.example', 'https://user:secret@host.example', 'https://host.example/?x=1', 'https://host.example/#x', 'invalid', null, 'https://127.0.0.1']) assert.equal(verificationTarget(bad), null)
  assert.equal(safeUrl('https://codeberg.org/caution/platform.git'), 'https://codeberg.org/caution/platform.git')
  assert.equal(repositoryLabel('https://codeberg.org/caution/platform.git'), 'caution/platform')
})
test('only valid zero unpinned optional PCRs are hidden', () => {
  const rows = measurementRows({ measurements: { 0: zero, 2: hash, 3: zero, 4: zero, 5: '0', 6: 'garbage', 7: hash }, policies: [{ sets: [{ pcrs: { 0: hash, 4: zero, 8: hash } }] }] })
  assert.deepEqual(rows.filter(row => row.hidden).map(row => row.index), ['3'])
  assert.equal(rows.find(row => row.index === '0').hidden, false)
  assert.equal(rows.find(row => row.index === '1').value, undefined)
  assert.equal(rows.find(row => row.index === '8').pinned, true)
  assert.equal(rows.find(row => row.index === '5').valid, false)
  assert.equal(rows.find(row => row.index === '7').pinned, false)
  assert.deepEqual(measurementRows({}).map(row => row.index), ['0', '1', '2'])
})
test('policy comparisons keep alternate sets and missing values distinct from acceptance', () => {
  const observations = { 0: hash, 1: zero, 2: hash }
  const set = { pcrs: { 0: hash.toUpperCase(), 1: hash, 2: hash, 8: 'invalid' }, expires_at_unix_seconds: 1 }
  assert.deepEqual(policyRows(set, observations).map(row => row.comparison), ['Same value', 'Different value', 'Same value', 'Missing or invalid'])
  assert.equal(policyRows({ pcrs: { 0: zero } }, observations)[2].comparison, 'Observed only')
  assert.equal(checkPresentation({ status: 'failed' }, 'Matches').label, 'Failed')
  assert.equal(checkPresentation(undefined, 'Ready').label, 'Unavailable')
  assert.equal(checkPresentation({ status: 'pending' }, 'Ready').label, 'Pending')
  assert.equal(checkPresentation({ status: 'passed' }, 'Ready').label, 'Ready')
})
test('check age uses the snapshot timestamp and handles bad clocks', () => {
  const now = Date.parse('2026-09-24T12:00:30Z')
  assert.equal(relativeCheckTime('2026-09-24T12:00:00Z', now), 'Checked 30 seconds ago')
  assert.equal(relativeCheckTime('2026-09-24T11:58:30Z', now), 'Checked 2 minutes ago')
  assert.match(relativeCheckTime('bad', now), /unavailable/)
  assert.match(relativeCheckTime('2026-09-24T13:00:00Z', now), /ahead/)
})

test('transport outages are compact without hiding security or configuration failures', () => {
  const failed = reason => ({ status: 'failed', reason })
  const policies = [{ purpose: 'Share release', result: failed('No authenticated measurements') }]
  for (const reason of ['Request failed', 'Request timed out', 'Response read failed']) {
    const view = servicePresentation({ readiness: failed(reason), attestation: failed(reason), policies })
    assert.equal(view.unreachable, true)
    assert.equal(view.transportDetails.length, 2)
    assert.deepEqual(view.checks.map(c => c.presentation.label), ['Unavailable', 'Unavailable', 'Not evaluated'])
    assert.ok(view.checks.every(c => !c.reason))
    assert.equal(view.hasMeasurements, false)
  }
  const partial = servicePresentation({ readiness: failed('Service is not ready'), attestation: { status: 'passed' }, measurements: { 0: hash }, policies: [{ purpose: 'Share release', result: { status: 'passed' } }] })
  assert.equal(partial.unreachable, false)
  assert.equal(partial.hasMeasurements, true)
  assert.deepEqual(partial.checks.map(c => c.presentation.label), ['Not ready', 'Authenticated', 'Matches'])
  const unavailableQuote = servicePresentation({ readiness: { status: 'passed' }, attestation: failed('Request failed'), policies })
  assert.equal(unavailableQuote.unreachable, false)
  assert.equal(unavailableQuote.transportDetails.length, 1)
  assert.equal(unavailableQuote.checks[0].presentation.label, 'Ready')
  for (const reason of ['Attestation authentication failed', 'Debug measurements are not accepted', 'Invalid JSON response', 'Response too large', 'Endpoint returned an unsuccessful status', 'Service URL is missing or invalid', 'Policy missing or invalid', 'Authenticated measurements do not match an active policy set', 'Unknown future error']) {
    const view = servicePresentation({ attestation: failed(reason), policies: [{ purpose: 'Share release', result: failed(reason) }] })
    assert.equal(view.transportDetails.length, 0)
    for (const check of view.checks.slice(1)) {
      assert.equal(check.presentation.tone, 'failed')
      assert.equal(check.reason, reason)
    }
  }
  assert.equal(servicePresentation({ attestation: failed('Attestation authentication failed'), measurements: { 0: hash } }).hasMeasurements, false)
})

test('check timestamps tolerate only five seconds around the current time', () => {
  const now = Date.parse('2026-09-28T12:00:00Z')
  for (const offset of [-5000, -1, 0, 1, 5000]) assert.equal(relativeCheckTime(new Date(now + offset).toISOString(), now), 'Checked just now')
  assert.match(relativeCheckTime(new Date(now + 5001).toISOString(), now), /ahead/)
  assert.notEqual(relativeCheckTime(new Date(now - 5001).toISOString(), now), 'Checked just now')
})


test('hosted CLI commands use stable service IDs and the displayed Platform', () => {
  for (const id of ['keymaker', 'key-service']) {
    const target = verificationTarget('https://service.example.com', id, 'https://alpha.example.com')
    assert.equal(target.command, `caution --url 'https://alpha.example.com' verify --service ${id}`)
    assert.deepEqual([...new URL(target.href, 'https://alpha.example.com').searchParams], [['url', 'https://service.example.com/attestation']])
  }
  assert.match(verificationTarget('https://service.example.com', undefined, 'https://alpha.example.com').command, /--attestation-url/)
  assert.match(verificationTarget('https://service.example.com', 'unrecognized; command', 'https://alpha.example.com').command, /--attestation-url/)
  for (const origin of ['javascript:alert(1)', 'https://user:secret@platform.example.com', 'https://platform.example.com/?x=1']) assert.equal(verificationTarget('https://service.example.com', 'keymaker', origin), null)
})
