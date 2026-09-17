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
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://localhost').pathname
  if (path.startsWith('/auth/qr-release/')) {
    let body = ''; for await (const chunk of request) body += chunk
    const input = JSON.parse(body)
    response.setHeader('content-type', 'application/json')
    if (path.endsWith('/read')) return response.end(JSON.stringify({ options, context: { bundle_id: Array(16).fill(1), holder: 'test-holder', destination_policy: { 0: 'ab'.repeat(48), 1: 'ab'.repeat(48), 2: 'ab'.repeat(48) } }, destination_key: Array(32).fill(2), context_hash: 'test-context-hash' }))
    finish = input
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
  assert.ok((await page.content()).includes('test-context-hash'))
  await page.evaluate(() => [...document.querySelectorAll('button')].find(b => b.textContent.includes('Approve with passkey')).click())
  await page.waitForFunction(() => document.body.textContent.includes('Assertion sent to the CLI'), { timeout: 10000 }).catch(async error => { console.error(await page.evaluate(() => document.body.innerText)); throw error })
  const assertion = finish.assertion
  const authData = Buffer.from(assertion.response.authenticatorData, 'base64url')
  const clientData = Buffer.from(assertion.response.clientDataJSON, 'base64url')
  assert.equal(JSON.parse(clientData).challenge, challenge)
  assert.equal(JSON.parse(clientData).origin, origin)
  assert.equal(authData[32] & 5, 5, 'presence and verified UV must be set')
  assert.ok(verify('sha256', Buffer.concat([authData, createHash('sha256').update(clientData).digest()]), createPublicKey({ key: Buffer.from(registration.publicKey), format: 'der', type: 'spki' }), Buffer.from(assertion.response.signature, 'base64url')))
  finish = undefined
  await page.goto(`${origin}/qr-release?attempt=cancel#cancellation-test`)
  await page.waitForFunction(() => [...document.querySelectorAll('button')].some(b => b.textContent === 'Cancel'))
  await page.evaluate(() => [...document.querySelectorAll('button')].find(b => b.textContent === 'Cancel').click())
  await page.waitForFunction(() => document.body.textContent.includes('Cancelled.'))
  assert.equal(finish.assertion, null)
  console.log('PASS: real browser/platform-passkey approval, raw signature/UV and cancellation (mock relay; no Nitro)')
} finally {
  await browser?.close()
  await new Promise(resolve => server.close(resolve))
}
