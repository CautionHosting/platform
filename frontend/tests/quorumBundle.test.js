// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { compile } from 'vue'
import { parse } from 'vue/compiler-sfc'
import { getQuorumBundleFiles } from '../src/utils/quorumBundle.js'

const dashboard = readFileSync(new URL('../src/views/Dashboard.vue', import.meta.url), 'utf8')
const { descriptor } = parse(dashboard)
function findDetails(node) {
  if (node.type === 1 && node.props.some(p => p.name === 'class' && p.value?.content === 'bundle-details')) return node
  for (const child of node.children ?? []) {
    const found = findDetails(child)
    if (found) return found
  }
}
const renderDetails = compile(findDetails(descriptor.template.ast).loc.source, { hoistStatic: false })
function buttons(node) {
  if (node?.type === 'button') return [node]
  return Array.isArray(node?.children) ? node.children.flatMap(buttons) : []
}
const handler = (name, next) => dashboard.slice(dashboard.indexOf(`    const ${name} =`), dashboard.indexOf(`    const ${next} =`))

const publicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----\npublic\n-----END PGP PUBLIC KEY BLOCK-----'
const shardfile = '-----BEGIN PGP MESSAGE-----\nshards\n-----END PGP MESSAGE-----'
for (const [name, data] of [
  ['V1 envelope', { data: { version: 'V1', public_key: publicKey, shardfile }, necroproof: [1, 2, 3] }],
  ['legacy payload', { secret_recipient_public_key: publicKey, shardfile }],
  ['legacy public_key payload', { public_key: publicKey, shardfile }],
]) {
  test(`${name} renders downloads with the original contents and public-key hash`, async () => {
    const bundle = { id: 'bundle-id', data: structuredClone(data) }
    const original = structuredClone(bundle)
    const blobs = []
    const downloads = []
    const revoked = []
    const downloadFile = new Function('URL', 'document', `${handler('downloadFile', 'resetCredentialForm')}; return downloadFile`)(
      {
        createObjectURL: blob => { blobs.push(blob); return `blob:${blobs.length}` },
        revokeObjectURL: url => revoked.push(url),
      },
      { createElement: () => ({ click() { downloads.push([this.href, this.download]) } }) },
    )
    const bundleKeyHashes = { value: {} }
    const computeHashes = new Function('quorumBundles', 'bundleKeyHashes', 'getQuorumBundleFiles',
      `${handler('computeBundleHashes', 'startEditBundleName')}; return computeBundleHashes`)(
      { value: [bundle] }, bundleKeyHashes, getQuorumBundleFiles,
    )
    await computeHashes()
    assert.equal(bundleKeyHashes.value[bundle.id], createHash('sha256').update(publicKey).digest('hex').slice(0, 16))

    const rendered = renderDetails({ bundle, bundleKeyHashes: bundleKeyHashes.value, getQuorumBundleFiles, downloadFile, truncateId: id => id }, [])
    const actions = buttons(rendered)
    assert.equal(actions.length, 2)
    for (const action of actions) action.props.onClick()
    assert.deepEqual(downloads, [
      ['blob:1', 'bundle-id_public_key.asc'],
      ['blob:2', 'bundle-id_shardfile.asc'],
    ])
    assert.deepEqual(await Promise.all(blobs.map(blob => blob.text())), [publicKey, shardfile])
    assert.deepEqual(revoked, ['blob:1', 'blob:2'])
    assert.deepEqual(bundle, original)
  })
}

test('missing or non-string files do not render download buttons', () => {
  for (const data of [undefined, null, {}, { data: { version: 'V1' }, necroproof: [] }, { shardfile: {}, public_key: [] }]) {
    const bundle = { id: 'empty', data }
    assert.deepEqual(getQuorumBundleFiles(bundle), { publicKey: '', shardfile: '' })
    assert.equal(buttons(renderDetails({ bundle, bundleKeyHashes: {}, getQuorumBundleFiles }, [])).length, 0)
  }
  assert.deepEqual(getQuorumBundleFiles(undefined), { publicKey: '', shardfile: '' })
})

test('a shard-only bundle keeps its shard download', () => {
  const bundle = { id: 'shards', data: { data: { version: 'V1', shardfile }, necroproof: [] } }
  const downloads = []
  const actions = buttons(renderDetails({ bundle, bundleKeyHashes: {}, getQuorumBundleFiles, downloadFile: (...args) => downloads.push(args), truncateId: id => id }, []))
  assert.equal(actions.length, 1)
  actions[0].props.onClick()
  assert.deepEqual(downloads, [[shardfile, 'shards_shardfile.asc']])
})
