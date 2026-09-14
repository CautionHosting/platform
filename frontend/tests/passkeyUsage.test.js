// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { compile, createSSRApp } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { parse } from '@vue/compiler-sfc'

const source = readFileSync(new URL('../src/views/Dashboard.vue', import.meta.url), 'utf8')
const { descriptor } = parse(source)
function findClass(node, className, contains = '') {
  if (node.loc?.source.includes(contains) && node.props?.some(p => p.name === 'class' && p.value?.content.split(' ').includes(className))) return node
  for (const child of node.children ?? []) {
    const found = findClass(child, className, contains)
    if (found) return found
  }
}
const card = findClass(descriptor.template.ast, 'passkey-info', 'formatLastUsed').loc.source
const sshUsage = findClass(descriptor.template.ast, 'ssh-key-usage').loc.source
// Exercise the existing shared formatter without mounting the dashboard's API calls.
const formatter = source.match(/const formatLastUsed = \(dateValue\) => \{([\s\S]*?)\n    \};/)[1]
const formatLastUsed = new Function('parseDate', `return (dateValue) => {${formatter}}`)(value => new Date(value))

async function render(template, context) {
  return renderToString(createSSRApp({ render: compile(template), setup: () => context }))
}

for (const current of [true, false]) {
  test(`passkey usage has exactly one prefix (current session: ${current})`, async () => {
    const html = await render(card, {
      passkey: { last_used_at: new Date().toISOString(), is_current_session: current },
      formatLastUsed, formatPasskeyTitle: () => 'Key', formatDate: () => 'Today', formatPasskeyTransports: () => '',
    })
    assert.equal(html.match(/Last used/g)?.length, 1)
    assert.match(html, /Last used just now/)
    assert.equal(html.includes('Current session'), current)
  })
}

test('unknown passkey history does not claim the key is unused', async () => {
  const html = await render(card, {
    passkey: { last_used_at: null }, formatLastUsed,
    formatPasskeyTitle: () => 'Key', formatDate: () => 'Today', formatPasskeyTransports: () => '',
  })
  assert.match(html, /Usage unknown/)
  assert.doesNotMatch(html, /Never used|Not used recently|Last used/)
})

test('shared SSH usage formatter retains its wording', async () => {
  assert.match(await render(sshUsage, { key: { last_used_at: new Date().toISOString() }, formatLastUsed }), /Last used just now/)
  assert.match(await render(sshUsage, { key: { last_used_at: null }, formatLastUsed }), /Never used/)
})
