// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
// Actual dashboard + virtual WebAuthn; mocked API/Keymaker, no Nitro acceptance.
import puppeteer from 'puppeteer'
import { createServer } from 'node:http'
import { readFile, writeFile, mkdir, mkdtemp, rm } from 'node:fs/promises'
import { resolve, extname, join } from 'node:path'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto'
import assert from 'node:assert/strict'
import { resolveDashboardPreviewRequest } from '../../../frontend/dev/dashboardPreview.js'
const pgp = createRequire(new URL('../../../frontend/package.json', import.meta.url))('openpgp')
const root = resolve(import.meta.dirname, '../../../frontend/dist')
const fixtureDir = await mkdtemp(join(tmpdir(), 'caution-quorum-ui-'))
const keys = await Promise.all(['Alice', 'Uploaded Bob'].map(name => pgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })))
const members = [
  { user_id: '11111111-1111-4111-8111-111111111111', username: 'Alice', pgp_keys: [{ id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', fingerprint: keys[0].publicKey.getFingerprint().toUpperCase(), public_key: keys[0].publicKey.armor() }], webauthn_credentials: 0, webauthn_uv_credentials: 0 },
  { user_id: '22222222-2222-4222-8222-222222222222', username: 'Bob', pgp_keys: [], webauthn_credentials: 2, webauthn_uv_credentials: 1 },
  { user_id: '33333333-3333-4333-8333-333333333333', username: 'Chloe', pgp_keys: [{ id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', fingerprint: 'AB'.repeat(20) }, { id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', fingerprint: 'CD'.repeat(20) }], webauthn_credentials: 1, webauthn_uv_credentials: 1 },
  { user_id: '44444444-4444-4444-8444-444444444444', username: 'Dan', pgp_keys: [], webauthn_credentials: 0, webauthn_uv_credentials: 0 },
]
const challenges = new Map(), bundles = [], requests = [], serverErrors = [], browserErrors = []
bundles.push(
  { id: 'older-record', name: 'Existing application secrets', created_at: '2025-01-01', data: { data: { bundle_id: Array(16).fill(5), threshold: 2, max: 2, keyring: [{ OpenPGP: {} }, { OpenPGP: {} }], public_key: keys[0].publicKey.armor(), shardfile: 'fixture' }, necroproof: [] } },
  { id: 'legacy-record', name: 'Legacy metadata unavailable', data: { public_key: keys[0].publicKey.armor() } },
)
let registration, responseMode = 'ok', participantsFail = false, signCount = 0
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://localhost').pathname
  const json = (status, data) => { response.writeHead(status, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(data)) }
  try {
    if (path === '/api/quorum-bundles/participants') return participantsFail ? json(503, { error: 'Members temporarily unavailable' }) : json(200, members)
    if (path === '/api/quorum-bundles') return json(200, [...bundles].reverse())
    if (path === '/auth/sign-request') {
      let body = ''; for await (const chunk of request) body += chunk
      const input = JSON.parse(body), id = randomBytes(16).toString('hex'), challenge = randomBytes(32).toString('base64url')
      signCount++; challenges.set(id, { ...input, challenge })
      return json(200, { challenge_id: id, publicKey: { challenge, rpId: 'localhost', timeout: 30000, userVerification: 'required', allowCredentials: [{ type: 'public-key', id: registration.id }] } })
    }
    if (path === '/api/quorum-bundles/from-org-users') {
      let body = ''; for await (const chunk of request) body += chunk
      const challenge = challenges.get(request.headers['x-fido2-challenge-id'])
      assert.ok(challenge, 'fresh signed creation challenge')
      challenges.delete(request.headers['x-fido2-challenge-id'])
      assert.equal(challenge.path, '/quorum-bundles/from-org-users')
      assert.equal(challenge.method, 'POST')
      assert.equal(challenge.body_hash, createHash('sha256').update(body).digest('hex'))
      const assertion = JSON.parse(Buffer.from(request.headers['x-fido2-response'], 'base64url'))
      const client = Buffer.from(assertion.response.clientDataJSON, 'base64url'), auth = Buffer.from(assertion.response.authenticatorData, 'base64url')
      assert.equal(JSON.parse(client).challenge, challenge.challenge)
      assert.equal(JSON.parse(client).origin, origin)
      assert.ok(auth[32] & 4, 'user verification')
      assert.ok(verify('sha256', Buffer.concat([auth, createHash('sha256').update(client).digest()]), createPublicKey({ key: Buffer.from(registration.publicKey), format: 'der', type: 'spki' }), Buffer.from(assertion.response.signature, 'base64url')))
      const input = JSON.parse(body); requests.push(input)
      if (responseMode === 'bad') { response.writeHead(400, { 'Content-Type': 'text/plain' }); return response.end('Selected certificate is no longer eligible') }
      if (responseMode === 'uncertain') { response.writeHead(200, { 'Content-Type': 'application/json' }); response.write('{'); setTimeout(() => response.destroy(), 10); return }
      if (responseMode === 'slow') await new Promise(resolve => setTimeout(resolve, 250))
      const holders = input.participants.map(holder => holder.key_source === 'existing_pgp' ? { OpenPGP: { cert: keys[0].publicKey.armor() } } : { WebAuthn: { cert: keys[1].publicKey.armor(), credential: [] } }).concat(input.pgp_certificates.map(cert => ({ OpenPGP: { cert } })))
      const bundle = { id: `bundle-${requests.length}`, name: input.name, created_at: new Date().toISOString(), data: { data: { version: 'V1', bundle_id: Array(16).fill(requests.length), threshold: input.threshold, max: holders.length, keyring: holders, public_key: keys[0].publicKey.armor(), shardfile: 'synthetic shardfile' }, necroproof: [] }, holders: holders.map((holder, index) => ({ username: index === 0 ? 'Long-holder-name-with-an-unbroken-organization-suffix-12345678901234567890' : `Holder ${index + 1}`, custody: holder.OpenPGP ? 'pgp' : 'caution_backed', fingerprint: (index ? 'BC' : 'AD').repeat(32) })) }
      bundles.unshift(bundle); return json(200, bundle)
    }
    const fixture = resolveDashboardPreviewRequest(request.method, request.url)
    if (fixture) { response.writeHead(fixture.status, fixture.headers); return response.end(fixture.body) }
    if (path === '/enroll') return response.end('<!doctype html><title>Enroll</title>')
    const file = path.startsWith('/assets/') ? resolve(root, `.${path}`) : resolve(root, 'index.html')
    if (!file.startsWith(root + '/')) { response.writeHead(404); return response.end() }
    response.setHeader('Content-Type', { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' }[extname(file)] || 'application/octet-stream')
    response.end(await readFile(file))
  } catch (error) { serverErrors.push(error); if (!response.headersSent) json(500, { error: error.message }); else response.destroy() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://localhost:${server.address().port}`
let browser
try {
  browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'], ...(process.env.PUPPETEER_EXECUTABLE_PATH ? { executablePath: process.env.PUPPETEER_EXECUTABLE_PATH } : {}) })
  const page = await browser.newPage(); await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: 'light' }]); await page.setViewport({ width: 1580, height: 1100 })
  page.on('pageerror', error => browserErrors.push(error))
  const cdp = await page.createCDPSession(); await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })
  await page.goto(`${origin}/enroll`)
  registration = await page.evaluate(async () => {
    const cred = await navigator.credentials.create({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { id: 'localhost', name: 'Quorum test' }, user: { id: new Uint8Array([1]), name: 'operator', displayName: 'Operator' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { residentKey: 'required', userVerification: 'required' }, attestation: 'none' } })
    return { id: cred.id, publicKey: Array.from(new Uint8Array(cred.response.getPublicKey())) }
  })
  const button = async text => {
    const handle = await page.evaluateHandle(text => [...document.querySelectorAll('button')].find(button => button.textContent.trim() === text), text)
    assert.ok(handle.asElement(), `button ${text}`); await handle.asElement().click(); await handle.dispose()
  }
  const textIncludes = text => page.waitForFunction(text => document.body.innerText.includes(text), {}, text)
  const open = async () => { await page.goto(`${origin}/#keys`); await page.reload(); await textIncludes('Create quorum bundle'); await button('Create quorum bundle'); await page.waitForSelector('#quorum-name'); await page.waitForSelector('.member-row'); }
  const selectMember = async name => { await page.evaluate(name => { const row = [...document.querySelectorAll('.member-row')].find(row => row.querySelector('.member-name strong').textContent.trim() === name); row.querySelector('input').click() }, name) }
  const paste = async armor => { await page.$eval('#quorum-armor', (input, value) => { input.value = value; input.dispatchEvent(new Event('input', { bubbles: true })) }, armor); await button('Add holder') }
  const add = async armor => { await button('Add PGP holder'); await paste(armor); await page.waitForFunction(() => !document.querySelector('#quorum-armor')) }
  await page.goto(`${origin}/#keys`); await page.reload(); await page.waitForSelector('#bundle-search'); await page.type('#bundle-search', 'older-record'); await button('Create quorum bundle'); await page.waitForSelector('.member-row')
  assert.ok((await page.$eval('.holder-count', el => el.textContent)).includes('No holders selected'))
  assert.equal(await page.$eval('#quorum-threshold', input => input.disabled), true)
  assert.equal(await page.$('.summary'), null)
  assert.equal(await page.$$eval('.creation-panel', panels => panels.length), 1)
  assert.ok(await page.$('.creation-panel footer'))
  assert.equal(await page.$('.custody-help'), null)
  assert.equal(await page.$('#quorum-source'), null)
  assert.equal(await page.$eval('#quorum-threshold', input => input.value), '2')
  assert.ok((await page.$$eval('.member-row', rows => rows.map(row => row.textContent).join(' '))).includes('1 of 2 passkeys verified for quorum approval'))
  assert.equal(await page.$eval('.member-row:last-child input', input => input.disabled), true)
  await selectMember('Alice'); assert.equal(await page.$('[aria-label="PGP key for Alice"]'), null); assert.ok((await page.$eval('.member-row code', el => el.textContent)).includes(keys[0].publicKey.getFingerprint().toUpperCase())); assert.ok(!(await page.$eval('.threshold', el => el.textContent)).includes('of 1 holders required')); await selectMember('Bob')
  await add(keys[1].publicKey.armor())
  await page.type('#quorum-name', 'Mixed demo')
  assert.ok((await page.$eval('.holder-count', el => el.textContent)).includes('3 selected · Max 10'))
  if (process.env.QUORUM_SCREENSHOT_DIR) { await mkdir(process.env.QUORUM_SCREENSHOT_DIR, { recursive: true }); await page.screenshot({ path: join(process.env.QUORUM_SCREENSHOT_DIR, 'quorum-configure.png'), fullPage: true }) }
  assert.equal(await page.$eval('.custody-help', el => el.open), false)
  await page.click('.custody-help summary'); assert.equal(await page.$eval('.custody-help', el => el.open), true)
  await page.keyboard.press('Enter'); assert.equal(await page.$eval('.custody-help', el => el.open), false)
  await button('Review bundle →')
  assert.equal(signCount, 0)
  assert.equal(await page.$$eval('.review-list li', rows => rows.length), 3)
  assert.ok((await page.$eval('.review-list', el => el.textContent)).includes('1 of 2 passkeys verified for quorum approval'))
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Mixed demo')
  assert.ok((await page.$eval('.review-list', el => el.textContent)).includes(keys[0].publicKey.getFingerprint().toUpperCase()))
  if (process.env.QUORUM_SCREENSHOT_DIR) await page.screenshot({ path: join(process.env.QUORUM_SCREENSHOT_DIR, 'quorum-review.png'), fullPage: true })
  assert.ok((await page.$eval('.review-heading', el => el.textContent)).includes('2 external PGP · 1 Caution custody'))
  assert.equal(await page.$$eval('.review-quorum', rows => rows.length), 1)
  responseMode = 'slow'
  await button('Create bundle')
  await page.evaluate(() => document.querySelector('.quorum-create footer .primary')?.click())
  await textIncludes('Quorum bundle created')
  await page.waitForSelector('.bundle-card--created .bundle-details')
  assert.equal(requests.length, 1); assert.equal(requests[0].participants.length, 2); assert.equal(requests[0].pgp_certificates.length, 1); assert.equal(requests[0].allow_caution_backed_keys, true)
  assert.ok(await page.$('.bundle-card--created .bundle-download'))
  assert.equal(await page.$eval('.bundle-card', el => el.id), 'bundle-bundle-1')
  assert.equal(await page.$eval('.bundle-guide', el => el.open), true)
  assert.equal(await page.$eval('#bundle-search', el => el.value), '')
  await page.waitForFunction(() => document.activeElement.classList.contains('bundle-card'))
  await page.evaluate(() => { window.copiedCommands = []; Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async text => window.copiedCommands.push(text) } }) })
  await page.click('[aria-label="Copy encryption command"]')
  assert.deepEqual(await page.evaluate(() => window.copiedCommands), ['caution secret encrypt DATABASE_URL --env-file /private/path/app.env'])
  assert.deepEqual(await page.$$eval('.bundle-guide a', links => links.map(a => a.href)), ['https://docs.caution.co/concepts/key-services/#2-add-encrypted-secrets', 'https://docs.caution.co/concepts/key-services/#7-send-shards'])
  await page.focus('.bundle-guide summary'); await page.keyboard.press('Enter')
  await page.waitForFunction(() => !document.querySelector('.bundle-guide').open)
  await page.click('.bundle-toggle'); await page.click('.bundle-toggle')
  assert.equal(await page.$eval('.bundle-guide', el => el.open), false)
  await page.click('.bundle-guide summary')
  await page.click('.bundle-overflow'); await page.keyboard.press('Escape')
  assert.equal(await page.$('.bundle-menu'), null)
  assert.equal(await page.evaluate(() => document.activeElement.className), 'bundle-overflow')
  await page.type('#bundle-search', 'no-such-bundle'); await textIncludes('No matching bundles.')
  await page.$eval('#bundle-search', el => { el.value = ''; el.dispatchEvent(new Event('input', { bubbles: true })) })
  await page.waitForSelector('.bundle-card')
  await page.click('.bundle-technical summary')
  for (const theme of ['light', 'dark']) {
    await page.evaluate(theme => document.documentElement.dataset.theme = theme, theme)
    for (const width of [1580, 1000]) {
      await page.setViewport({ width, height: 1300 })
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'bundle list has no horizontal overflow')
      assert.equal(await page.$$eval('.bundle-details code', nodes => nodes.some(n => n.scrollWidth > n.clientWidth)), false, 'fingerprints and commands wrap')
      if (process.env.QUORUM_SCREENSHOT_DIR) await page.screenshot({ path: join(process.env.QUORUM_SCREENSHOT_DIR, `bundles-expanded-${theme}-${width}.png`), fullPage: true })
      await page.click('.bundle-toggle')
      if (process.env.QUORUM_SCREENSHOT_DIR) await page.screenshot({ path: join(process.env.QUORUM_SCREENSHOT_DIR, `bundles-collapsed-${theme}-${width}.png`), fullPage: true })
      await page.click('.bundle-toggle')
    }
  }
  await page.setViewport({ width: 1580, height: 1100 })
  await page.reload(); await page.waitForSelector('.bundle-toggle'); await page.click('.bundle-toggle'); assert.equal(await page.$eval('.bundle-guide', el => el.open), false, 'existing guidance starts collapsed');
  responseMode = 'ok'

  await open(); await selectMember('Chloe')
  await page.select('[aria-label="Approval method for Chloe"]', 'existing_pgp')
  assert.equal(await page.$eval('footer .primary', button => button.disabled), true)
  await page.select('[aria-label="PGP key for Chloe"]', members[2].pgp_keys[1].id)
  await selectMember('Bob')
  await button('Add PGP holder')
  assert.equal(await page.evaluate(() => document.activeElement.id), 'quorum-armor')
  assert.equal(await page.$eval('footer .primary', button => button.disabled), true)
  await paste(keys[0].privateKey.armor()); await textIncludes('Private keys cannot be uploaded')
  assert.equal(requests.length, 1)
  const keyring = pgp.armor(pgp.enums.armor.publicKey, new pgp.PacketList(...keys[0].publicKey.toPacketList(), ...keys[1].publicKey.toPacketList()).write())
  await paste(keyring); await textIncludes('Add one public certificate at a time')
  assert.equal(await page.$$eval('.certificate-list li', rows => rows.length), 0)
  await page.click('.holder-import .text-button')
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Add PGP holder')
  assert.equal(await page.$$eval('.member-row input:checked', rows => rows.length), 2)
  await selectMember('Chloe'); await selectMember('Bob')
  await add(keys[0].publicKey.armor())
  await selectMember('Alice'); await textIncludes('Duplicate PGP holder')
  assert.equal(await page.$eval('footer .primary', button => button.disabled), true)
  await selectMember('Alice')
  await button('Add PGP holder'); await paste(keys[0].publicKey.armor()); await textIncludes('Duplicate PGP holder')
  await page.click('.holder-import .text-button')
  await page.click('.certificate-list button')
  assert.equal(await page.$eval('#quorum-threshold', input => input.value), '2')
  await selectMember('Alice'); await button('Add PGP holder'); await paste(keys[0].publicKey.armor()); await textIncludes('Duplicate PGP holder')
  await page.click('.holder-import .text-button'); await selectMember('Alice')
  await add(keys[0].publicKey.armor())
  assert.equal(await page.$eval('footer .primary', button => button.disabled), true)
  await button('Add PGP holder')
  assert.equal(await page.$eval('#quorum-armor', el => el.value), '')
  const file = join(fixtureDir, 'public.asc'); await writeFile(file, keys[1].publicKey.armor())
  await (await page.$('#quorum-file')).uploadFile(file)
  await page.waitForFunction(() => document.querySelector('#quorum-armor').value.length > 0)
  await button('Add holder'); await page.waitForFunction(() => document.querySelectorAll('.certificate-list li').length === 2 && !document.querySelector('#quorum-armor'))
  await page.setViewport({ width: 1000, height: 1100 })
  await page.evaluate(() => document.documentElement.dataset.theme = 'dark')
  const layout = await page.evaluate(() => ({ cardWidth: document.querySelector('.creation-panel').getBoundingClientRect().width, inside: !!document.querySelector('.creation-panel footer'), columns: getComputedStyle(document.querySelector('.certificate-list li')).gridTemplateColumns.split(' ').length, overflow: document.documentElement.scrollWidth > innerWidth }))
  assert.ok(layout.cardWidth <= 860); assert.equal(layout.inside, true); assert.equal(layout.columns, 1, 'narrow holder rows stack'); assert.equal(layout.overflow, false)
  assert.equal(await page.$('.custody-help'), null)
  if (process.env.QUORUM_SCREENSHOT_DIR) await page.screenshot({ path: join(process.env.QUORUM_SCREENSHOT_DIR, 'quorum-keyring-dark.png'), fullPage: true })
  await page.setViewport({ width: 1580, height: 1100 }); await page.evaluate(() => document.documentElement.dataset.theme = 'light')
  await button('Review bundle →'); assert.equal(await page.$eval('.review-quorum .hint', el => el.textContent), '2 external PGP'); await button('Create bundle'); await page.waitForSelector('#bundle-bundle-2')
  assert.equal(requests[1].participants.length, 0); assert.equal(requests[1].pgp_certificates.length, 2); assert.equal(requests[1].allow_caution_backed_keys, false)

  // Cancel the real signing boundary before the mutation request.
  await open(); await selectMember('Alice'); await selectMember('Bob'); await button('Review bundle →')
  await page.evaluate(() => { navigator.credentials.get = async () => { throw new DOMException('Cancelled', 'NotAllowedError') } })
  await button('Create bundle'); await textIncludes('No creation request was sent'); assert.equal(requests.length, 2)
  assert.equal(await page.$eval('footer .primary', button => button.disabled), true)
  await button('Back'); await button('Add PGP holder'); assert.equal(await page.$eval('#quorum-armor', el => el.value), '')

  for (const mode of ['bad', 'uncertain']) {
    responseMode = mode
    await open(); await selectMember('Alice'); await selectMember('Bob'); await button('Review bundle →'); await button('Create bundle')
    await textIncludes(mode === 'bad' ? 'Selected certificate is no longer eligible' : 'Creation outcome unknown')
    const count = requests.length
    assert.equal(await page.$eval('footer .primary', button => button.disabled), true)
    await page.keyboard.press('Enter')
    await new Promise(resolve => setTimeout(resolve, 150))
    assert.equal(requests.length, count)
    if (mode === 'uncertain') { await button('Check bundles'); await page.waitForSelector('.bundle-list'); assert.equal(await page.$('.bundle-card--created'), null); assert.equal(await page.$('.bundle-guide[open]'), null); assert.equal(await page.$eval('.bundle-card', el => el.id), 'bundle-bundle-2') }
  }
  // The dashboard cap combines manual holders and members, without changing API limits.
  members.push(...Array.from({ length: 8 }, (_, index) => ({ user_id: `extra-${index}`, username: `Extra ${index}`, pgp_keys: [], webauthn_credentials: 1, webauthn_uv_credentials: 1 })))
  await open(); await selectMember('Bob')
  for (let index = 0; index < 8; index++) await selectMember(`Extra ${index}`)
  assert.ok((await page.$eval('.holder-count', el => el.textContent)).includes('9 selected · Max 10'))
  await add(keys[1].publicKey.armor())
  assert.ok((await page.$eval('.holder-count', el => el.textContent)).includes('10 selected · Max 10'))
  assert.equal(await page.evaluate(() => [...document.querySelectorAll('button')].find(el => el.textContent === 'Add PGP holder').disabled), true)
  await selectMember('Alice') // disabled at the cap
  assert.equal(await page.$$eval('.member-row input:checked', rows => rows.length), 9)
  await page.click('.certificate-list button')
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Add PGP holder')
  await page.keyboard.press('Enter')
  await page.waitForSelector('#quorum-armor')
  assert.equal(await page.evaluate(() => document.activeElement.id), 'quorum-armor')
  await page.keyboard.press('Tab'); await page.keyboard.press('Enter') // empty Add is disabled; Cancel receives focus
  await page.waitForFunction(() => !document.querySelector('#quorum-armor'))
  await selectMember('Alice'); await button('Review bundle →')
  assert.equal(await page.$$eval('.review-list li', rows => rows.length), 10)
  await button('Back'); await selectMember('Alice')
  for (let index = 0; index < 8; index++) await selectMember(`Extra ${index}`)
  assert.equal(await page.$eval('#quorum-threshold', el => el.value), '2')
  assert.ok((await page.$eval('.holder-count', el => el.textContent)).includes('1 selected · Max 10'))
  assert.equal(await page.$eval('footer .primary', el => el.disabled), true)
  assert.equal(requests.length, 4, 'cap and validation checks did not submit')
  members.splice(4)
  const originalName = members[0].username
  members[0].username = 'Long-holder-name-with-a-full-organization-identifier-and-unbroken-suffix-12345678901234567890'
  await open(); await selectMember(members[0].username); await selectMember('Bob')
  for (const theme of ['light', 'dark']) {
    await page.evaluate(theme => document.documentElement.dataset.theme = theme, theme)
    for (const width of [1580, 1000]) {
      await page.setViewport({ width, height: 1100 })
      for (const stage of ['configure', 'import', 'review']) {
        if (stage === 'import') await button('Add PGP holder')
        if (stage === 'review') { await page.click('.holder-import .text-button'); await button('Review bundle →') }
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `${theme} ${width} ${stage}: no page overflow`)
        assert.equal(await page.$$eval('.creation-panel code', nodes => nodes.some(node => node.scrollWidth > node.clientWidth)), false, 'full fingerprints fit')
        assert.ok(await page.$('.creation-panel footer'))
        if (process.env.QUORUM_SCREENSHOT_DIR) await page.screenshot({ path: join(process.env.QUORUM_SCREENSHOT_DIR, `compact-${stage}-${theme}-${width}.png`), fullPage: true })
        if (stage === 'review') await button('Back')
      }
    }
  }
  members[0].username = originalName
  participantsFail = true
  await page.goto(`${origin}/#keys`); await page.reload(); await textIncludes('Create quorum bundle'); await button('Create quorum bundle'); await textIncludes('Members temporarily unavailable')
  participantsFail = false; await button('Reload members'); await page.waitForSelector('.member-row')
  assert.deepEqual(serverErrors, []); assert.deepEqual(browserErrors, [])
  console.log('PASS: dashboard member/manual/mixed holder creation, real virtual-passkey signatures, selection/review, private-key rejection, cancellation, no retries, errors, downloads, focus, custody disclosure and compact light/dark layout. Mock API only; no Nitro acceptance.')
} finally { if (browser) await browser.close(); await new Promise(resolve => server.close(resolve)); await rm(fixtureDir, { recursive: true, force: true }) }
