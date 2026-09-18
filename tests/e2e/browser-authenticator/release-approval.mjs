// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
// Real Vue approval page + Chromium's virtual platform passkey. No Nitro evidence.
import puppeteer from 'puppeteer'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { resolve, extname } from 'node:path'
import { randomBytes, createHash, createPublicKey, verify } from 'node:crypto'
import assert from 'node:assert/strict'

const root = resolve(import.meta.dirname, '../../../frontend/dist')
let options, finish
let expires = Math.floor(Date.now()/1000) + 120
let includeMetadata = true
let appName = '<img src=x onerror=alert(1)>', recordedAddress = '203.0.113.43'
let readStatus = 200, finishStatus = 200, dropFinish = false, finishCount = 0
let cancellationDelay = 0
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://localhost').pathname
  if (path.startsWith('/auth/qr-release/')) {
    let body = ''; for await (const chunk of request) body += chunk
    const input = JSON.parse(body)
    response.setHeader('content-type', 'application/json')
    if (path.endsWith('/read') && readStatus !== 200) { response.writeHead(readStatus); return response.end('{}') }
    if (path.endsWith('/read')) return response.end(JSON.stringify({ options, context: { bundle_id: Array(16).fill(1), holder: 'cd'.repeat(20), bundle_hash: 'ef'.repeat(32), holder_position: 1, certificate_index: 0, expires_at_unix_seconds: expires, organization_id: Array(16).fill(3), version: 'V1', destination_policy: { 0: 'ab'.repeat(48), 1: 'ab'.repeat(48), 2: 'ab'.repeat(48) } }, custody_policy: { 0: 'bc'.repeat(48), 1: 'bc'.repeat(48), 2: 'bc'.repeat(48) }, approval_origin: origin, destination_attestation_hash: 'de'.repeat(32), destination_key: Array(32).fill(2), context_hash: 'edcd12bf40e1c288' + '0'.repeat(48), metadata: includeMetadata ? { application: { name: appName, id: 'test-app', public_ip: recordedAddress, domain: 'app.example.test', state: 'running' }, organization: { name: 'My organization' }, bundle: { username: 'alice', threshold: 2, holders: 3, eligible_passkeys: 2 } } : null, reported: { destination_address: '203.0.113.42:49504', custody_url: 'https://custody.example.test' } }))
    if (input.assertion === null && cancellationDelay) await new Promise(resolve => setTimeout(resolve, cancellationDelay))
    finish = input
    finishCount++
    if (dropFinish) {
      // Deliver headers before losing the body: avoids Chromium's transport-level
      // retry of a connection closed before any response bytes were received.
      response.writeHead(200); response.write('{')
      setTimeout(() => response.destroy(), 20)
      return
    }
    response.writeHead(finishStatus)
    return response.end('{}')
  }
  if (path === '/enroll') return response.end('<!doctype html><title>Test enrollment</title>')
  const file = path.startsWith('/assets/') ? resolve(root, `.${path}`) : resolve(root, 'index.html')
  if (!file.startsWith(root + '/')) { response.writeHead(404); return response.end() }
  response.setHeader('content-type', { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html' }[extname(file)] || 'application/octet-stream')
  try { response.end(await readFile(file)) } catch { response.writeHead(404); response.end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://localhost:${server.address().port}`
let browser
try {
  browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] })
  const page = await browser.newPage()
  page.on('pageerror', error => console.error('Browser error:', error.message))
  page.on('console', message => { if (message.type() === 'error') console.error('Browser:', message.text()) })
  const cdp = await page.createCDPSession()
  await cdp.send('WebAuthn.enable')
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })
  await page.goto(`${origin}/enroll`)
  const registration = await page.evaluate(async () => {
    const credential = await navigator.credentials.create({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { id: 'localhost', name: 'Release test' },
      user: { id: new Uint8Array([1, 2, 3]), name: 'test', displayName: 'Test holder' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' }, attestation: 'none',
    } })
    return { id: credential.id, publicKey: Array.from(new Uint8Array(credential.response.getPublicKey())) }
  })
  const challenge = randomBytes(32).toString('base64url')
  options = { publicKey: { challenge, rpId: 'localhost', timeout: 30000, userVerification: 'required', allowCredentials: [{ type: 'public-key', id: registration.id }] } }
  await page.goto(`${origin}/qr-release#approval-test`)
  await page.waitForFunction(() => [...document.querySelectorAll('button')].some(b => b.textContent.includes('Approve with passkey')), { timeout: 10000 }).catch(async error => { console.error(await page.evaluate(() => document.body.innerText)); throw error })
  assert.ok((await page.content()).includes('EDCD 12BF 40E1 C288'))
  assert.equal(await page.$eval('dialog', e => e.open), false)
  assert.ok((await page.evaluate(() => document.body.innerText)).includes('<img src=x onerror=alert(1)>'))
  assert.equal(await page.$('main img'), null)
  await page.setViewport({ width: 1360, height: 900 })
  assert.ok(await page.$eval('button.primary', e => e.getBoundingClientRect().bottom <= window.innerHeight), 'desktop action fits without scrolling')
  if (process.env.RELEASE_SCREENSHOT_PATH) await page.screenshot({ path: process.env.RELEASE_SCREENSHOT_PATH, fullPage: true })
  await page.evaluate(() => { window.copiedValue = null; Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async text => { window.copiedValue = text } } }) })
  await page.click('.details-trigger')
  assert.equal(await page.$eval('dialog', e => e.open), true)
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), 'Close verification details')
  async function assertPlainFields(labels) {
    for (const label of labels) {
      const field = await page.evaluate(label => {
        const term = [...document.querySelectorAll('dialog dt')].find(e => e.textContent === label)
        const value = term?.nextElementSibling
        return value && { text: value.textContent.trim(), buttons: value.querySelectorAll('button').length, technical: !!value.querySelector('.technical') }
      }, label)
      assert.ok(field?.text, `${label} remains visible`)
      assert.equal(field.buttons, 0, `${label} has no copy or reveal control`)
      assert.equal(field.technical, false, `${label} uses normal typography`)
    }
  }
  await assertPlainFields(['Recorded state'])
  await page.click('[aria-label="Copy Application ID"]')
  assert.equal(await page.evaluate(() => window.copiedValue), 'test-app')
  assert.equal(await page.$('[aria-label="Copy Holder certificate"]'), null, 'other tabs are not rendered')
  assert.equal(await page.$eval('[aria-label="Reveal PCR0"]', e => e.parentElement.textContent.includes('ab'.repeat(48))), false)
  await page.click('[aria-label="Copy PCR0"]')
  assert.equal(await page.evaluate(() => window.copiedValue), 'ab'.repeat(48), 'copy uses full hidden value')
  await page.click('[aria-label="Reveal PCR0"]')
  assert.ok(await page.$eval('[aria-label="Hide PCR0"]', e => e.parentElement.textContent.includes('ab'.repeat(48))))
  await page.click('[aria-label="Hide PCR0"]')
  const text = await page.evaluate(() => document.body.innerText)
  assert.ok(text.includes('203.0.113.42:49504') && text.includes('203.0.113.43'))
  if (process.env.RELEASE_SCREENSHOT_PATH) await page.screenshot({ path: process.env.RELEASE_SCREENSHOT_PATH.replace('.png', '-drawer.png'), fullPage: false })
  await page.focus('#tab-0')
  await page.keyboard.press('ArrowRight')
  assert.equal(await page.$eval('#tab-1', e => e.getAttribute('aria-selected')), 'true')
  await assertPlainFields(['User verification', 'Lifetime', 'Expires at'])
  await page.click('[aria-label="Copy PCR0"]')
  assert.equal(await page.evaluate(() => window.copiedValue), 'bc'.repeat(48))
  await page.focus('#tab-1')
  await page.keyboard.press('End')
  assert.equal(await page.$eval('#tab-2', e => e.getAttribute('aria-selected')), 'true')
  await assertPlainFields(['Eligible passkeys in bundle', 'Protocol'])
  assert.equal(await page.evaluate(() => document.querySelector('dialog').textContent.includes('certificate index')), false)
  await page.click('[aria-label="Copy Holder certificate"]')
  assert.equal(await page.evaluate(() => window.copiedValue), 'cd'.repeat(20))
  await page.focus('#tab-2')
  await page.keyboard.press('Home')
  assert.equal(await page.$eval('#tab-0', e => e.getAttribute('aria-selected')), 'true')
  for (let i = 0; i < 22; i++) {
    await page.keyboard.press('Tab')
    assert.ok(await page.evaluate(() => !!document.activeElement.closest('dialog')), 'focus stays in modal')
  }
  const finishesBeforeClose = finishCount
  await page.keyboard.press('Escape')
  assert.equal(await page.$eval('dialog', e => e.open), false)
  assert.ok(await page.evaluate(() => document.activeElement.matches('.details-trigger')))
  assert.equal(finishCount, finishesBeforeClose, 'closing details does not cancel')
  await page.setViewport({ width: 390, height: 844 })
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))
  if (process.env.RELEASE_SCREENSHOT_PATH) await page.screenshot({ path: process.env.RELEASE_SCREENSHOT_PATH.replace('.png', '-mobile.png'), fullPage: true })
  await page.click('.details-trigger')
  assert.equal(await page.$eval('dialog', e => Math.round(e.getBoundingClientRect().width)), 390)
  assert.equal(await page.$eval('dialog', e => e.getBoundingClientRect().top), 0)
  await page.click('[aria-label="Reveal PCR0"]')
  assert.ok(await page.$eval('dialog', e => e.scrollWidth <= e.clientWidth), 'revealed values wrap on mobile')
  if (process.env.RELEASE_SCREENSHOT_PATH) await page.screenshot({ path: process.env.RELEASE_SCREENSHOT_PATH.replace('.png', '-mobile-drawer.png'), fullPage: false })
  await page.click('[aria-label="Close verification details"]')
  await page.evaluate(() => [...document.querySelectorAll('button')].find(b => b.textContent.includes('Approve with passkey')).click())
  await page.waitForFunction(() => document.body.textContent.includes('Check your terminal for share acceptance'), { timeout: 10000 }).catch(async error => { console.error(await page.evaluate(() => document.body.innerText)); throw error })
  assert.equal(await page.$('[role=timer]'), null)
  assert.equal(await page.$('dialog'), null)
  assert.equal(await page.$('button'), null)
  assert.ok(!(await page.content()).includes('EDCD 12BF'))
  const assertion = finish.assertion
  const authData = Buffer.from(assertion.response.authenticatorData, 'base64url')
  const clientData = Buffer.from(assertion.response.clientDataJSON, 'base64url')
  assert.equal(JSON.parse(clientData).challenge, challenge)
  assert.equal(JSON.parse(clientData).origin, origin)
  assert.equal(authData[32] & 5, 5, 'presence and verified UV must be set')
  assert.ok(verify('sha256', Buffer.concat([authData, createHash('sha256').update(clientData).digest()]), createPublicKey({ key: Buffer.from(registration.publicKey), format: 'der', type: 'spki' }), Buffer.from(assertion.response.signature, 'base64url')))
  finish = undefined
  cancellationDelay = 150
  await page.goto(`${origin}/qr-release?attempt=cancel#cancellation-test`)
  await page.waitForFunction(() => [...document.querySelectorAll('button')].some(b => b.textContent === 'Cancel'))
  const cancellationResponse = page.waitForResponse(response => response.url().endsWith('/auth/qr-release/finish') && response.request().method() === 'POST')
  await page.evaluate(() => [...document.querySelectorAll('button')].find(b => b.textContent === 'Cancel').click())
  await page.waitForFunction(() => document.body.textContent.includes('Approval cancelled.'))
  assert.equal((await cancellationResponse).status(), 200)
  assert.equal(finish.token, 'cancellation-test')
  assert.equal(finish.assertion, null)
  finish = undefined
  includeMetadata = false
  expires = Math.floor(Date.now()/1000) + 2
  await page.goto(`${origin}/qr-release?attempt=expired#expiry-test`)
  await page.waitForFunction(() => document.body.textContent.includes('Application name unavailable'))
  // Keep a WebAuthn request pending until expiry to verify it is aborted.
  await page.evaluate(() => {
    window.approvalAborted = false
    Object.defineProperty(navigator.credentials, 'get', { value: ({ signal }) => new Promise((resolve, reject) => {
      signal.addEventListener('abort', () => { window.approvalAborted = true; reject(new DOMException('Aborted', 'AbortError')) })
    }) })
  })
  const expiryResponse = page.waitForResponse(response => response.url().endsWith('/auth/qr-release/finish') && response.request().method() === 'POST')
  await page.evaluate(() => [...document.querySelectorAll('button')].find(b => b.textContent.includes('Approve with passkey')).click())
  await page.click('.details-trigger')
  await page.waitForFunction(() => document.body.textContent.includes('This approval link is no longer active.'))
  assert.equal(await page.evaluate(() => window.approvalAborted), true)
  assert.equal((await expiryResponse).status(), 200)
  assert.equal(finish.token, 'expiry-test')
  assert.equal(finish.assertion, null)
  cancellationDelay = 0
  assert.equal(await page.$('button'), null)
  assert.equal(await page.$('dialog'), null)
  assert.equal(await page.$('[role=timer]'), null)
  await page.goto(`${origin}/qr-release`)
  await page.waitForFunction(() => document.body.textContent.includes('This approval link is no longer active.'))
  assert.equal(await page.$('button'), null)
  readStatus = 410
  await page.goto(`${origin}/qr-release?attempt=consumed#old`)
  await page.waitForFunction(() => document.body.textContent.includes('This approval link is no longer active.'))
  assert.equal(await page.$('dialog'), null)
  readStatus = 503
  await page.goto(`${origin}/qr-release?attempt=server-error#error`)
  await page.waitForFunction(() => document.body.textContent.includes('Unable to load approval.'))
  assert.ok(!(await page.content()).includes('no longer active'))
  readStatus = 200
  includeMetadata = true
  expires = Math.floor(Date.now()/1000) + 60
  for (const mode of ['server-error', 'lost-response']) {
    finishStatus = mode === 'server-error' ? 503 : 200
    dropFinish = mode === 'lost-response'
    const before = finishCount
    await page.goto(`${origin}/qr-release?attempt=delivery-${mode}#delivery`)
    await page.waitForSelector('button.primary')
    await page.click('button.primary')
    await page.waitForFunction(() => document.body.textContent.includes('Approval delivery could not be confirmed.'))
    assert.equal(finishCount, before + 1, 'uncertain delivery must not retry or cancel the assertion')
    assert.equal(await page.$('button'), null)
    assert.equal(await page.$('dialog'), null)
  }
  finishStatus = 200; dropFinish = false
  expires = Math.floor(Date.now()/1000) + 3
  await page.goto(`${origin}/qr-release?attempt=finished-timer#success`)
  await page.waitForSelector('button.primary')
  await page.click('button.primary')
  await page.waitForFunction(() => document.body.textContent.includes('Check your terminal for share acceptance'))
  await new Promise(resolve => setTimeout(resolve, 3500))
  assert.ok((await page.evaluate(() => document.body.innerText)).includes('Approval sent'))
  assert.equal(await page.$('[role=timer]'), null)
  if (process.env.RELEASE_SCREENSHOT_PATH) {
    appName = 'dummy_locksmith_test_app'; recordedAddress = '203.0.113.42'
    expires = Math.floor(Date.now()/1000) + 120
    await page.setViewport({ width: 1360, height: 900 })
    await page.goto(`${origin}/qr-release?attempt=layout#layout`)
    await page.waitForSelector('button.primary')
    assert.ok(await page.$eval('.card', e => e.getBoundingClientRect().bottom <= window.innerHeight), 'normal desktop card fits without scrolling')
    await page.screenshot({ path: process.env.RELEASE_SCREENSHOT_PATH, fullPage: true })
    await page.click('.details-trigger')
    await page.screenshot({ path: process.env.RELEASE_SCREENSHOT_PATH.replace('.png', '-drawer.png') })
    await page.keyboard.press('Escape')
    await page.setViewport({ width: 390, height: 844 })
    await page.screenshot({ path: process.env.RELEASE_SCREENSHOT_PATH.replace('.png', '-mobile.png'), fullPage: true })
    await page.click('.details-trigger')
    assert.equal(await page.$eval('dialog', e => e.getBoundingClientRect().top), 0)
    await page.screenshot({ path: process.env.RELEASE_SCREENSHOT_PATH.replace('.png', '-mobile-drawer.png') })
  }
  console.log('PASS: browser approval, raw signature/UV, cancellation, pending-request expiry, metadata escaping, copy and mobile layout (mock relay; no Nitro)')
} finally {
  await browser?.close()
  await new Promise(resolve => server.close(resolve))
}
