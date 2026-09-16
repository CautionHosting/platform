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
