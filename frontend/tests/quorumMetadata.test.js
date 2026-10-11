import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'

const dashboard = readFileSync(new URL('../src/views/Dashboard.vue', import.meta.url), 'utf8')
for (const [name, next] of [['saveBundleName', 'cancelEditBundleName'], ['saveLabel', 'removeLabel'], ['removeLabel', 'downloadFile']]) {
  test(`${name} preserves passkey cancellation without sending an update`, async () => {
    const handler = dashboard.slice(dashboard.indexOf(`    const ${name} =`), dashboard.indexOf(`    const ${next} =`))
    const toasts = []
    let sent = false
    const deps = {
      editBundleNameValue: { value: 'prod' },
      newLabelKey: { value: 'env' }, newLabelValue: { value: 'prod' },
      quorumBundles: { value: [{ id: 'bundle', labels: { env: 'old' } }] },
      buildSignedHeaders: async () => { throw new Error('Passkey cancelled') },
      authFetch: async () => { sent = true },
      showToast: (...args) => toasts.push(args),
    }
    const run = new Function(...Object.keys(deps), `${handler}; return ${name}`)(...Object.values(deps))
    await run('bundle', 'env')
    assert.equal(sent, false)
    assert.deepEqual(toasts, [['Passkey cancelled', 'error']])
  })
}

for (const [name, next, expected] of [
  ['saveBundleName', 'cancelEditBundleName', { name: 'prod' }],
  ['saveLabel', 'removeLabel', { labels: { env: 'prod' } }],
  ['removeLabel', 'downloadFile', { labels: {} }],
]) {
  test(`${name} signs and sends the identical metadata body then refreshes`, async () => {
    const source = dashboard.slice(dashboard.indexOf(`    const ${name} =`), dashboard.indexOf(`    const ${next} =`))
    const calls = []
    const deps = {
      editBundleNameValue: { value: 'prod' }, editingBundleName: { value: 'bundle' },
      newLabelKey: { value: 'env' }, newLabelValue: { value: 'prod' },
      quorumBundles: { value: [{ id: 'bundle', labels: { env: 'old' } }] },
      buildSignedHeaders: async (...args) => { calls.push(['sign', ...args]); return { 'X-Signature': 'signature' } },
      authFetch: async (...args) => { calls.push(['fetch', ...args]); return { ok: true } },
      loadBundles: async () => { calls.push(['refresh']) }, cancelAddLabel() {}, showToast() {},
    }
    const run = new Function(...Object.keys(deps), `${source}; return ${name}`)(...Object.values(deps))
    await run('bundle', 'env')
    const body = JSON.stringify(expected)
    assert.deepEqual(calls, [
      ['sign', 'PATCH', '/quorum-bundles/bundle', body],
      ['fetch', '/api/quorum-bundles/bundle', { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-Signature': 'signature' }, body }],
      ['refresh'],
    ])
  })
}
