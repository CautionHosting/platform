// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
// Actual dashboard + virtual WebAuthn against a stateful mock API (no AWS, no Nitro).
import puppeteer from 'puppeteer'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { resolve, extname } from 'node:path'
import { createHash, createPublicKey, randomBytes, randomUUID, verify } from 'node:crypto'
import assert from 'node:assert/strict'
import { resolveDashboardPreviewRequest } from '../../../frontend/dev/dashboardPreview.js'
const root = resolve(import.meta.dirname, '../../../frontend/dist')
const APP = '7b1d0c2e-5f4a-4e3b-9c8d-1a2b3c4d5e6f'
const A = 'd1000000-0000-4000-8000-000000000001', B = 'd2000000-0000-4000-8000-000000000002', C = 'd3000000-0000-4000-8000-000000000003'
const state = {
  live: A, switchMode: 'ok', destroyMode: 'ok', switchRequests: 0, events: [], listQueries: [], legacyRequests: [],
  deployments: {
    [A]: { status: 'running', commit_sha: 'ff43fef1', commit_subject: 'Rotate keymaker policy' },
    [B]: { status: 'running', debug_mode: true, commit_sha: 'b6e8c921', commit_subject: 'Fix login race' },
    [C]: { status: 'failed', failure_kind: 'provisioning', commit_sha: '1c2d3e41', commit_subject: 'Bump locksmith', error: 'tofu apply failed' },
  },
}
const view = (id) => ({ id, app_id: APP, role: id === state.live ? 'live' : 'candidate', retained: state.deployments[id].status !== 'destroyed', instance_id: `i-${id.slice(1, 4)}`, instance_type: 'm5.xlarge', enclave_cpus: 2, enclave_memory_mb: 4096, estimated_monthly_usd: 140.16, pushed_ref: 'main', created_at: `2026-10-1${id[1]}T10:00:00Z`, public_ip: id === state.live ? '198.51.100.42' : `203.0.113.${id[1]}`, tls_after_switch: false, ...state.deployments[id] })
const appRow = () => ({ id: APP, resource_name: 'key-service', state: 'running', lifecycle: 'deployments', summary_state: 'running', active: true, live_deployment_id: state.live, live_commit_sha: state.deployments[state.live].commit_sha, candidates: Object.keys(state.deployments).filter((id) => id !== state.live && view(id).retained).length, candidate_limit: 3, public_ip: '198.51.100.42', domain: 'key-service.example.com', managed_hostname: `${APP.slice(0, 8)}.apps.caution.sh`, region: 'us-west-2', dns_status: 'ready', git_url: `git@git.test:${APP}.git`, created_at: '2026-10-01T09:00:00Z', configuration: {} })
const legacyApp = { id: '0ld00000-0000-4000-8000-000000000004', resource_name: 'old-service', state: 'running', lifecycle: 'legacy', summary_state: 'running', active: true, public_ip: '203.0.113.50', managed_hostname: 'old.apps.caution.sh', region: 'us-west-2', dns_status: 'ready', created_at: '2026-09-01T09:00:00Z', configuration: { commit_sha: '04fa2381' } }

// A history entry with the API's exact `HistoryEntry` keys (src/api/src/app_deployments/history.rs).
const record = (operation, outcome, target, extra = {}) => {
  const deployment = state.deployments[target]
  state.events.unshift({
    kind: 'operation', id: randomUUID(), at: new Date().toISOString(), completed_at: new Date().toISOString(),
    operation, outcome, previous_deployment_id: null, target_deployment_id: target,
    commit_sha: deployment.commit_sha, commit_subject: deployment.commit_subject, pushed_ref: 'main',
    failure_kind: null, error: null, actor: 'operator', auth_method: 'passkey',
    signed_request_id: null, signed_request_status: null, signed_request_completed_at: null, ...extra,
  })
}

const challenges = new Map(), serverErrors = [], browserErrors = []
let registration
const server = createServer(async (request, response) => {
  const url = new URL(request.url, 'http://localhost'), path = url.pathname
  const json = (status, data) => { response.writeHead(status, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(data)) }
  const readBody = async () => { let body = ''; for await (const chunk of request) body += chunk; return body }
  try {
    if (path === '/auth/sign-request') {
      const input = JSON.parse(await readBody()), id = randomBytes(16).toString('hex'), challenge = randomBytes(32).toString('base64url')
      challenges.set(id, { ...input, challenge })
      return json(200, { challenge_id: id, publicKey: { challenge, rpId: 'localhost', timeout: 30000, userVerification: 'required', allowCredentials: [{ type: 'public-key', id: registration.id }] } })
    }
    if (request.method === 'GET' && path === '/api/resources') return json(200, [appRow(), legacyApp])
    if (request.method === 'GET' && path === `/api/resources/${APP}/deployments`) {
      state.listQueries.push(url.search)
      const retainedOnly = url.searchParams.get('retained') === '1'
      return json(200, Object.keys(state.deployments).map(view).filter((deployment) => !retainedOnly || deployment.retained))
    }
    if (path.startsWith(`/api/resources/${legacyApp.id}/`) && /\/(deployments|history)$/.test(path)) state.legacyRequests.push(path) // a Legacy app must not be asked for either
    if (request.method === 'GET' && path === `/api/resources/${APP}/history`) return json(200, { entries: state.events, next: null })
    const switchMatch = request.method === 'POST' && path.match(new RegExp(`^/api/resources/${APP}/deployments/([0-9a-f-]+)/switch$`))
    if (switchMatch) {
      const id = switchMatch[1], body = await readBody(), challengeId = request.headers['x-fido2-challenge-id']
      const challenge = challenges.get(challengeId)
      assert.ok(challenge, 'fresh signed switch challenge')
      challenges.delete(challengeId)
      assert.equal(challenge.path, `/resources/${APP}/deployments/${id}/switch`)
      assert.equal(challenge.method, 'POST')
      assert.equal(challenge.body_hash, createHash('sha256').update(body).digest('hex'))
      const assertion = JSON.parse(Buffer.from(request.headers['x-fido2-response'], 'base64url'))
      const client = Buffer.from(assertion.response.clientDataJSON, 'base64url'), auth = Buffer.from(assertion.response.authenticatorData, 'base64url')
      assert.equal(JSON.parse(client).challenge, challenge.challenge)
      assert.equal(JSON.parse(client).origin, origin)
      assert.ok(auth[32] & 4, 'user verification')
      assert.ok(verify('sha256', Buffer.concat([auth, createHash('sha256').update(client).digest()]), createPublicKey({ key: Buffer.from(registration.publicKey), format: 'der', type: 'spki' }), Buffer.from(assertion.response.signature, 'base64url')))
      state.switchRequests++
      const input = JSON.parse(body), previous = state.live
      const event = (outcome) => record('switch', outcome, id, { previous_deployment_id: previous, signed_request_id: challengeId, signed_request_status: outcome === 'rejected' ? 409 : 200 })
      if (state.switchMode === 'uncertain') {
        // The switch happens server-side but the answer is lost; reconciliation observed it.
        event('observed'); state.live = id
        response.writeHead(200, { 'Content-Type': 'application/json' }); response.write('{'); setTimeout(() => response.destroy(), 10); return
      }
      if (input.expected_live_deployment_id !== state.live) { event('rejected'); return json(409, { error: 'The live deployment changed; review and confirm again.' }) }
      event('succeeded'); state.live = id
      return json(200, { live_deployment_id: id, previous_live_deployment_id: previous, stable_ip: '198.51.100.42', tls_after_switch: false })
    }
    const destroyMatch = request.method === 'DELETE' && path.match(new RegExp(`^/api/resources/${APP}/deployments/([0-9a-f-]+)$`))
    if (destroyMatch) {
      const id = destroyMatch[1], session = { auth_method: 'session' }
      if (id === state.live) return json(409, { error: 'The live deployment cannot be destroyed.' })
      if (state.destroyMode === 'fail') {
        state.deployments[id].cleanup = 'pending'
        record('deployment_destroy', 'failed', id, session)
        return json(500, { error: 'Deployment destroy failed; retry.' })
      }
      state.deployments[id].status = 'destroyed'
      record('deployment_destroy', 'succeeded', id, session)
      response.writeHead(204); return response.end()
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
    const cred = await navigator.credentials.create({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { id: 'localhost', name: 'Deployments test' }, user: { id: new Uint8Array([1]), name: 'operator', displayName: 'Operator' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { residentKey: 'required', userVerification: 'required' }, attestation: 'none' } })
    return { id: cred.id, publicKey: Array.from(new Uint8Array(cred.response.getPublicKey())) }
  })
  const button = async text => {
    const handle = await page.evaluateHandle(text => [...document.querySelectorAll('button')].find(button => button.textContent.trim() === text), text)
    assert.ok(handle.asElement(), `button ${text}`); await handle.asElement().click(); await handle.dispose()
  }
  const textIncludes = text => page.waitForFunction(text => document.body.innerText.includes(text), {}, text)
  const switchTo = async (shortTarget) => {
    await page.click(`[aria-label="Inspect deployment ${shortTarget}"]`)
    await button('Switch live')
    await page.click('.deployment-confirm input[type="checkbox"]')
    await button('Approve with passkey')
  }
  // Every success, stale or uncertain answer is followed by a refresh. Wait for the
  // refreshed Live row (the first row) before the next step acts on it or flips the mock.
  const liveIs = (short) => page.waitForFunction((short) => {
    const row = document.querySelector('.deployments-table tbody tr')
    return row?.cells[3].textContent.trim() === 'Live' && row.cells[0].textContent.includes(short)
  }, {}, short)
  const openApp = async () => {
    await textIncludes('key-service')
    await page.evaluate(() => [...document.querySelectorAll('.app-name-text')].find((el) => el.textContent.trim() === 'key-service').click())
    await textIncludes('Rotate keymaker policy')
  }
  await page.goto(`${origin}/`); await page.reload()
  // List: Active/All columns; Legacy label.
  await textIncludes('key-service')
  assert.ok((await page.$eval('.apps-list-table', (el) => el.textContent)).includes('Legacy'))
  // Legacy app: single-deployment line, no deployment actions, and no deployments/history requests.
  await page.evaluate(() => [...document.querySelectorAll('.app-name-text')].find((el) => el.textContent.trim() === 'old-service').click())
  await textIncludes('Legacy · single deployment')
  assert.ok((await page.$eval('.legacy-lifecycle', (el) => el.textContent)).includes('04fa238'))
  assert.equal(await page.$('.deployments-table'), null)
  assert.equal(await page.evaluate(() => [...document.querySelectorAll('button')].some((el) => ['Switch live', 'Destroy deployment'].includes(el.textContent.trim()))), false)
  assert.deepEqual(state.legacyRequests, [])
  await page.reload()
  await openApp(); await liveIs('d1000000')
  assert.deepEqual(await page.$$eval('.deployments-table tbody tr', (rows) => rows.map((row) => row.cells[3].textContent.trim())), ['Live', 'Candidate', 'Candidate'])
  assert.deepEqual([...new Set(state.listQueries)], ['?retained=1']) // the dashboard asks for retained deployments only
  // Debug mode shows in the list (B only), the inspector and the Switch-live confirmation.
  assert.deepEqual(await page.$$eval('.deployments-table tbody tr', (rows) => rows.filter((row) => row.cells[4].textContent.includes('debug')).map((row) => row.cells[0].textContent.trim())), ['d2000000'])
  await page.click('[aria-label="Inspect deployment d2000000"]')
  await page.waitForFunction(() => [...document.querySelectorAll('.deployment-inspector dt')].some((el) => el.textContent.trim() === 'Debug mode'))
  await button('Switch live'); await textIncludes('This deployment runs in debug mode.'); await button('Cancel')
  await page.click('[aria-label="Inspect deployment d1000000"]'); await textIncludes('Deployment d1000000')
  assert.equal(await page.evaluate(() => [...document.querySelectorAll('.deployment-inspector dt')].some((el) => el.textContent.trim() === 'Debug mode')), false)
  // A → B, signed with the real virtual passkey.
  await switchTo('d2000000'); await textIncludes('d2000000 is live at 198.51.100.42')
  assert.equal(state.live, B)
  await liveIs('d2000000')
  // Stale: another operator switches back meanwhile; the UI refuses, refreshes and does not retry.
  state.live = A
  await switchTo('d1000000') // UI still shows B live → signs expected B; the server has A → 409
  await textIncludes('The live deployment changed')
  await liveIs('d1000000') // the refresh shows the server's live deployment
  assert.equal(state.switchRequests, 2)
  // Passkey cancellation sends nothing.
  await page.evaluate(() => { window.__get = navigator.credentials.get; navigator.credentials.get = async () => { throw new DOMException('Cancelled', 'NotAllowedError') } })
  await switchTo('d2000000'); await textIncludes('Passkey approval was cancelled'); assert.equal(state.switchRequests, 2)
  await page.evaluate(() => { navigator.credentials.get = window.__get })
  // Uncertain delivery: the server switched to B but the answer is lost. The UI never claims
  // success, never retries, and the refresh shows the server's live deployment.
  state.switchMode = 'uncertain'; await switchTo('d2000000'); await textIncludes('outcome is unknown')
  assert.equal(await page.$eval('.deployment-outcome', (el) => el.textContent.includes('is live')), false)
  await liveIs('d2000000'); assert.equal(state.live, B); assert.equal(state.switchRequests, 3) // one request, no retry
  state.switchMode = 'ok'
  // A fresh load shows the same server state.
  await page.reload(); await openApp(); await liveIs('d2000000')
  // Rollback to A.
  await switchTo('d1000000'); await textIncludes('d1000000 is live'); await liveIs('d1000000'); assert.equal(state.live, A)
  // The live deployment offers no Destroy; a destroy answered 5xx reads as unknown, refreshes, and is retried.
  await page.click('[aria-label="Inspect deployment d1000000"]'); assert.equal(await page.$('.deployment-inspector .btn-danger'), null)
  state.destroyMode = 'fail'; await page.click('[aria-label="Inspect deployment d3000000"]'); await button('Destroy deployment'); await page.click('.deployment-confirm .btn-danger'); await textIncludes('The destroy outcome is unknown; refresh to check.')
  // The component refreshes after the unknown outcome: the mock's pending cleanup appears in the inspector.
  await page.waitForFunction(() => [...document.querySelectorAll('.deployment-inspector dt')].some((el) => el.textContent.trim() === 'Cleanup'))
  state.destroyMode = 'ok'; await page.click('[aria-label="Inspect deployment d3000000"]'); await button('Destroy deployment'); await page.click('.deployment-confirm .btn-danger'); await textIncludes('d3000000 was destroyed')
  // Copy feedback stays in the icon, with an announcement and no toast.
  await page.evaluate(() => { window.copied = []; Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async (text) => window.copied.push(text) } }) })
  await page.click('[aria-label="Inspect deployment d2000000"]'); await page.click('[aria-label="Copy verification command"]')
  assert.deepEqual(await page.evaluate(() => window.copied), [`caution verify -d ${B}`])
  await page.waitForSelector('[aria-label="verification command copied"]')
  assert.equal(await page.$('.toast'), null)
  // History shows the switches, the rejection and both destroy outcomes.
  await page.click('.app-history summary'); await textIncludes('Switch d1000000 → d2000000 · Succeeded'); await textIncludes('Rejected')
  // Layout: no horizontal overflow; the inspector follows the list on narrow screens.
  for (const width of [1580, 1000]) {
    await page.setViewport({ width, height: 1100 })
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `${width}: no page overflow`)
  }
  assert.deepEqual(serverErrors, []); assert.deepEqual(browserErrors, [])
  console.log('PASS: dashboard switch/rollback with virtual-passkey signatures, stale confirmation, cancellation, uncertain outcome, live-destroy guard, unknown destroy outcome, debug mode, copy feedback, history and layout. Mock API only.')
} finally { if (browser) await browser.close(); await new Promise(resolve => server.close(resolve)) }
