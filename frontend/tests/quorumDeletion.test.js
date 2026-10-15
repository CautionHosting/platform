import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'

// Exercise the actual Dashboard handler with controlled browser/API dependencies.
const dashboard = readFileSync(new URL('../src/views/Dashboard.vue', import.meta.url), 'utf8')
const handler = dashboard.slice(dashboard.indexOf('    const deleteBundle ='), dashboard.indexOf('    const computeBundleHashes'))
function setup({ confirmed = true, cancelled = false } = {}) {
  const calls = []
  const busy = { value: null }
  const headers = { 'X-Fido2-Challenge-Id': 'fresh-challenge', 'X-Fido2-Response': 'assertion' }
  const run = new Function('confirm', 'deletingBundle', 'buildSignedHeaders', 'authFetch', 'showToast', 'loadBundles', `${handler}; return deleteBundle`)(
    () => confirmed, busy,
    async (...args) => { calls.push(['sign', ...args]); if (cancelled) throw new Error('Passkey cancelled'); return headers },
    async (...args) => { calls.push(['fetch', ...args]); return { ok: true, status: 204 } },
    () => {}, async () => { calls.push(['reload']) },
  )
  return { run, calls, busy, headers }
}

test('deletion signs the canonical path and empty body before sending', async () => {
  const { run, calls, busy, headers } = setup()
  await run('bundle-id')
  assert.deepEqual(calls, [
    ['sign', 'DELETE', '/quorum-bundles/bundle-id', ''],
    ['fetch', '/api/quorum-bundles/bundle-id', { method: 'DELETE', headers }],
    ['reload'],
  ])
  assert.equal(busy.value, null)
})

test('confirmation or passkey cancellation never sends deletion', async () => {
  for (const options of [{ confirmed: false }, { cancelled: true }]) {
    const { run, calls, busy } = setup(options)
    await run('bundle-id')
    assert.equal(calls.some(([operation]) => operation === 'fetch'), false)
    assert.equal(busy.value, null)
  }
})
