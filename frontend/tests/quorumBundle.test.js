// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { compile } from 'vue'
import { parse } from 'vue/compiler-sfc'
import { getQuorumBundleFiles, getQuorumBundleSummary, serializeQuorumBundle, getEmbeddedBundleId, bundleTitle, bundleIdentifiers, abbreviateBundleValue, selectBundles } from '../src/utils/quorumBundle.js'

const dashboard = readFileSync(new URL('../src/views/Dashboard.vue', import.meta.url), 'utf8')
const { descriptor } = parse(dashboard)
function findDetails(node, className) {
  if (node.type === 1 && node.props.some(p => p.name === 'class' && p.value?.content === className)) return node
  for (const child of node.children ?? []) {
    const found = findDetails(child, className)
    if (found) return found
  }
}
const compileSection = name => compile(findDetails(descriptor.template.ast, name).loc.source, { hoistStatic: false })
const compiledDetails = compileSection('bundle-details')
const compiledActions = compileSection('bundle-actions')
const defaults = {
  getQuorumBundleSummary, getQuorumBundleFiles, serializeQuorumBundle, bundleTitle, bundleIdentifiers, abbreviateBundleValue,
  expandedBundles: new Proxy({}, { get: () => true }), bundleGuidance: {}, bundleEncryptCommand: "caution secret encrypt DATABASE_URL --env-file /private/path/app.env",
   truncateId: id => id, addingLabelTo: null, bundleKeyHashes: {}, handleBundleMenuSelection() {}, toggleBundleMenu() {},
  deletingBundle: null, startAddLabel() {}, copyToClipboard() {},
}
const renderDetails = context => compiledDetails({ ...defaults, ...context }, [])
const renderActions = context => compiledActions({ ...defaults, bundleMenu: context.bundle.id + ':actions', ...context }, [])
const downloadButtons = node => buttons(node).filter(b => ['bundle-download', 'bundle-file-download'].includes(b.props?.class))
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
    assert.equal(bundleKeyHashes.value[bundle.id], createHash('sha256').update(publicKey).digest('hex'))

    const rendered = renderActions({ bundle, bundleKeyHashes: bundleKeyHashes.value, getQuorumBundleFiles, downloadFile, truncateId: id => id }, [])
    const actions = downloadButtons(rendered)
    assert.equal(actions.length, 3)
    for (const action of actions) action.props.onClick()
    assert.deepEqual(downloads, [
      ['blob:1', 'bundle-id_quorum-bundle.json'],
      ['blob:2', 'bundle-id_public_key.asc'],
      ['blob:3', 'bundle-id_shardfile.asc'],
    ])
    assert.deepEqual(await Promise.all(blobs.map(blob => blob.text())), [JSON.stringify(data, null, 2), publicKey, shardfile])
    assert.equal(blobs[0].type, 'application/json')
    assert.deepEqual(JSON.parse(await blobs[0].text()), data)
    assert.deepEqual(revoked, ['blob:1', 'blob:2', 'blob:3'])
    assert.deepEqual(bundle, original)
  })
}

test('missing or non-string files do not render download buttons', () => {
  for (const data of [undefined, null, {}, { data: { version: 'V1' }, necroproof: [] }, { shardfile: {}, public_key: [] }]) {
    const bundle = { id: 'empty', data }
    assert.deepEqual(getQuorumBundleFiles(bundle), { publicKey: '', shardfile: '' })
    assert.equal(downloadButtons(renderActions({ bundle, bundleKeyHashes: {}, getQuorumBundleFiles })).length, serializeQuorumBundle(bundle) ? 1 : 0)
  }
  assert.deepEqual(getQuorumBundleFiles(undefined), { publicKey: '', shardfile: '' })
})

test('a shard-only bundle keeps its shard download', () => {
  const bundle = { id: 'shards', data: { data: { version: 'V1', shardfile }, necroproof: [] } }
  const downloads = []
  const actions = downloadButtons(renderActions({ bundle, bundleKeyHashes: {}, getQuorumBundleFiles, downloadFile: (...args) => downloads.push(args), truncateId: id => id }, []))
  assert.equal(actions.length, 2)
  actions[1].props.onClick()
  assert.deepEqual(downloads, [[shardfile, 'shards_shardfile.asc']])
})

 test('summary counts holders, not credentials, and leaves unknown legacy metadata absent', () => {
  const keyring = [{ OpenPGP: { cert: publicKey } }, { WebAuthn: { cert: publicKey, credential: ['one', 'two'] } }]
  const bundle = { data: { data: { version: 'V1', threshold: 2, max: 2, keyring }, necroproof: [1] } }
  assert.deepEqual(getQuorumBundleSummary(bundle), { threshold: '2 of 2 holders', custody: '1 external PGP · 1 passkey' })
  bundle.data.data.keyring = [keyring[1], keyring[1]]
  assert.equal(getQuorumBundleSummary(bundle).custody, '2 passkey')
  assert.deepEqual(getQuorumBundleSummary({ data: { shardfile } }), { threshold: '', custody: '' })
  bundle.data.data.threshold = 3
  assert.equal(getQuorumBundleSummary(bundle).threshold, '')
})

test('download preserves proof and bindings but excludes database and display metadata', () => {
  const data = { data: { version: 'V1', keyring: [{ WebAuthn: { credential: ['private-display-id'], cert: publicKey } }] }, necroproof: [0, 127, 255] }
  const bundle = { id: 'id', organization_id: 'org', holders: [{ username: 'alice' }], data }
  assert.deepEqual(JSON.parse(serializeQuorumBundle(bundle)), data)
  assert.equal(serializeQuorumBundle({ data: null }), null)
})

test('holder display uses metadata in bundle order without rendering credential identifiers', () => {
  const bundle = { id: 'id', data: { data: { keyring: [{ WebAuthn: { credential: ['HIDDEN-CREDENTIAL'], cert: publicKey } }] } },
    holders: [{ custody: 'caution_backed', username: '<alice>', fingerprint: 'ABC123' }, { custody: 'pgp', username: null, fingerprint: 'DEF456' }] }
  const rendered = renderDetails({ bundle, bundleKeyHashes: {}, getQuorumBundleFiles, downloadFile() {}, truncateId: id => id })
  const text = node => typeof node === 'string' ? node : typeof node?.children === 'string' ? node.children : Array.isArray(node?.children) ? node.children.map(text).join(' ') : ''
  const display = text(rendered)
  assert.ok(display.includes('<alice>'))
  assert.ok(display.includes('Holder 2'))
  assert.ok(display.includes('ABC123'))
  assert.ok(display.indexOf('ABC123') < display.indexOf('DEF456'))
  assert.ok(!display.includes('HIDDEN-CREDENTIAL'))
})

test('expanded values display and copy full fingerprints and hashes without changing data', () => {
  const fingerprint = '0123456789ABCDEF'.repeat(3)
  const hash = 'abcdef0123456789'.repeat(4)
  const bundle = { id: 'id', holders: [{ fingerprint, custody: 'pgp' }] }
  const copies = []
  const revealedBundleValues = {}
  const context = { bundle, revealedBundleValues, bundleKeyHashes: { id: hash }, copyToClipboard: (...args) => copies.push(args) }
  const actions = buttons(renderDetails(context))
  actions.find(b => b.props?.['aria-label'] === 'Copy certificate fingerprint for holder 1').props.onClick()
  actions.find(b => b.props?.['aria-label'] === 'Copy Public key SHA-256').props.onClick()
  assert.deepEqual(copies, [[fingerprint, 'Certificate fingerprint'], [hash, 'Public key SHA-256']])
  assert.ok(!actions.some(b => b.props?.['aria-label']?.startsWith('Toggle full')))
  assert.deepEqual(revealedBundleValues, {})
  assert.equal(renderDetails({ ...context, expandedBundles: {} }).type.toString(), 'Symbol(v-cmt)')
})

test('action menus toggle exclusively, dismiss outside/on selection/Escape and restore focus', () => {
  let watched
  const controls = new Function('ref', 'watch', 'activeTab', `${handler('expandedBundles', 'quorumBundles')}; return { bundleMenu, toggleBundleMenu, handleBundleMenuSelection, handleBundleMenuOutsideClick, handleBundleMenuKeydown }`)(
    value => ({ value }), (source, callback) => { watched = callback }, {},
  )
  let focused = 0
  const event = { currentTarget: { focus() { focused++ } } }
  controls.toggleBundleMenu('a:downloads', event)
  controls.toggleBundleMenu('b:actions', event)
  assert.equal(controls.bundleMenu.value, 'b:actions')
  controls.handleBundleMenuKeydown({ key: 'Escape' })
  assert.equal(controls.bundleMenu.value, null)
  assert.equal(focused, 1)
  controls.toggleBundleMenu('a:downloads', event)
  controls.handleBundleMenuOutsideClick({ target: { closest: () => null } })
  assert.equal(controls.bundleMenu.value, null)
  controls.toggleBundleMenu('a:downloads', event)
  controls.handleBundleMenuSelection({ target: { closest: () => ({}) } })
  assert.equal(controls.bundleMenu.value, null)
  controls.toggleBundleMenu('a:downloads', event)
  watched()
  assert.equal(controls.bundleMenu.value, null)
})

test('embedded identity is shared with CLI and record IDs remain distinct', () => {
  const id = '9fd6da23b21b4ebc8544442414e7d1c1';
  const bundle = { id: 'bae317a1-record', data: { data: { bundle_id: [...Buffer.from(id, 'hex')] } }, bundle_hash: 'e8'.repeat(32) };
  assert.equal(getEmbeddedBundleId(bundle), '9fd6da23-b21b-4ebc-8544-442414e7d1c1');
  assert.equal(bundleTitle(bundle), 'Bundle 9fd6da23');
  assert.equal(bundleTitle({ ...bundle, name: 'root' }), 'root · 9fd6da23');
  assert.equal(bundleTitle({ id: bundle.id }), 'Platform record bae317a1');
  assert.equal(getEmbeddedBundleId({ data: { data: { bundle_id: Array(16).fill(256) } } }), null);
  assert.equal(abbreviateBundleValue('0123456789abcdef'.repeat(3)), '01234567…89abcdef');
  const copies = [];
  const actions = buttons(renderDetails({ bundle, bundleKeyHashes: {}, copyToClipboard: (...args) => copies.push(args) }));
  for (const label of ['Bundle ID', 'Bundle hash', 'Platform record ID']) actions.find(b => b.props?.['aria-label'] === `Copy ${label}`).props.onClick();
  assert.deepEqual(copies, [[getEmbeddedBundleId(bundle), 'Bundle ID'], [bundle.bundle_hash, 'Bundle hash'], [bundle.id, 'Platform record ID']]);
  assert.equal(bundleIdentifiers({ id: 'legacy' }).length, 1);
});

test('bundle search and newest-first ordering preserve source order and retain the new record first', () => {
  const bundles = [{ id: 'old', name: 'Root', created_at: '2025-01-01' }, { id: 'new', name: 'App', created_at: '2026-01-01' }, { id: 'legacy' }]
  assert.deepEqual(selectBundles(bundles).map(b => b.id), ['new', 'old', 'legacy'])
  assert.deepEqual(bundles.map(b => b.id), ['old', 'new', 'legacy'])
  assert.deepEqual(selectBundles(bundles, ' ROOT ').map(b => b.id), ['old'])
  assert.deepEqual(selectBundles(bundles, 'legacy').map(b => b.id), ['legacy'])
  assert.deepEqual(selectBundles(bundles, 'missing'), [])
  assert.equal(selectBundles(bundles, '', 'old')[0].id, 'old')
  const embedded = { id: 'record', data: { data: { bundle_id: Array(16).fill(17) } } }
  assert.deepEqual(selectBundles([embedded], '11111111-1111'), [embedded])
})

test('usage instructions copy a fixed command without incorporating bundle metadata', () => {
  const copies = []
  const bundle = { id: 'id', name: '$(unsafe)', holders: [] }
  const actions = buttons(renderDetails({ bundle, copyToClipboard: (...args) => copies.push(args) }))
  actions.find(b => b.props?.['aria-label'] === 'Copy encryption command').props.onClick()
  assert.deepEqual(copies, [[defaults.bundleEncryptCommand, 'Encryption command']])
})
