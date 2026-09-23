// Real gateway/database ceremonies with virtual UV-capable and touch-only keys.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID, randomBytes, createHash } from 'node:crypto'
import puppeteer from 'puppeteer'

const base = process.env.GATEWAY_URL
const container = process.env.QUORUM_DB_CONTAINER
const database = 'caution_quorum_test'
assert.ok(base?.startsWith('http://localhost:') && container, 'Use the isolated recovery-verification test runner')
const sql = statement => execFileSync('docker', ['exec', container, 'psql', '-U', 'postgres', '-d', database, '-Atc', statement], { encoding: 'utf8' }).trim()
const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'], ...(process.env.PUPPETEER_EXECUTABLE_PATH ? { executablePath: process.env.PUPPETEER_EXECUTABLE_PATH } : {}) })

async function request(page, path, body, headers = {}) {
  return page.evaluate(async ({ path, body, headers }) => {
    const csrf = document.cookie.match(/caution_csrf=([^;]+)/)?.[1]
    const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST',
      headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
    const text = await response.text()
    let data; try { data = JSON.parse(text) } catch { data = text }
    return { status: response.status, data }
  }, { path, body, headers })
}
async function create(page, begin, verified) {
  return page.evaluate(async ({ begin, verified }) => {
    const decode = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
    const encode = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
    const publicKey = begin.publicKey
    publicKey.challenge = decode(publicKey.challenge); publicKey.user.id = decode(publicKey.user.id)
    publicKey.excludeCredentials = (publicKey.excludeCredentials || []).map(c => ({ ...c, id: decode(c.id) }))
    publicKey.authenticatorSelection.userVerification = verified ? 'required' : 'discouraged'
    const credential = await navigator.credentials.create({ publicKey })
    return { id: credential.id, rawId: encode(credential.rawId), type: credential.type, session: begin.session,
      response: { attestationObject: encode(credential.response.attestationObject), clientDataJSON: encode(credential.response.clientDataJSON) },
      extensions: credential.getClientExtensionResults() }
  }, { begin, verified })
}
async function assertion(page, begin, uv = 'required', credentialId) {
  return page.evaluate(async ({ begin, uv, credentialId }) => {
    const decode = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
    const encode = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
    const publicKey = begin.publicKey
    publicKey.challenge = decode(publicKey.challenge)
    publicKey.allowCredentials = credentialId ? [{ type: 'public-key', id: decode(credentialId) }] : publicKey.allowCredentials.map(c => ({ ...c, id: decode(c.id) }))
    publicKey.userVerification = uv
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 2500)
    try {
      const credential = await navigator.credentials.get({ publicKey, signal: controller.signal })
      return { id: credential.id, rawId: encode(credential.rawId), type: credential.type,
        response: { authenticatorData: encode(credential.response.authenticatorData), clientDataJSON: encode(credential.response.clientDataJSON), signature: encode(credential.response.signature), userHandle: null }, extensions: credential.getClientExtensionResults() }
    } finally { clearTimeout(timer) }
  }, { begin: structuredClone(begin), uv, credentialId })
}
async function account(protocol, verified, suffix) {
  const context = await browser.createBrowserContext()
  const page = await context.newPage(); const cdp = await page.createCDPSession()
  await cdp.send('WebAuthn.enable')
  const options = { protocol, transport: 'usb', hasResidentKey: false, hasUserVerification: verified, isUserVerified: verified, automaticPresenceSimulation: true }
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options })
  await page.goto(`${base}/health`)
  const code = randomUUID(); const username = `uv${Date.now()}${suffix}`
  sql(`INSERT INTO beta_codes(code) VALUES ('${code}')`)
  const begin = await request(page, '/auth/register/begin', { alpha_code: code, username })
  assert.equal(begin.status, 200, JSON.stringify(begin))
  const registration = await create(page, begin.data, verified)
  const finish = await request(page, '/auth/register/finish', registration)
  assert.equal(finish.status, 200, JSON.stringify(finish))
  const list = await request(page, '/passkeys')
  assert.equal(list.status, 200, JSON.stringify(list))
  assert.equal(list.data[0].uv_verified, verified)
  return { page, cdp, authenticatorId, row: list.data[0], registration }
}
async function beginFor(account) {
  const result = await request(account.page, `/passkeys/${account.row.id}/recovery-verification/begin`, {})
  assert.equal(result.status, 200, JSON.stringify(result))
  assert.equal(result.data.publicKey.userVerification, 'required')
  return result.data
}
async function finishFor(account, begin, signed, page = account.page) {
  return request(page, `/passkeys/${account.row.id}/recovery-verification/finish`, { ...signed, session: begin.session, uv_verified: true })
}
try {
  const capable = await account('ctap2', false, 'a')
  const touch = await account('u2f', false, 'b')
  const verified = await account('ctap2', true, 'c')
  assert.equal((await request(touch.page, `/passkeys/${capable.row.id}/recovery-verification/begin`, {})).status, 404)

  let begin = await beginFor(capable)
  let signed = await assertion(capable.page, begin, 'discouraged')
  assert.equal(Buffer.from(signed.response.authenticatorData, 'base64url')[32] & 4, 0)
  assert.equal((await finishFor(capable, begin, signed)).status, 400, 'UV false must fail even with a client eligibility claim')
  assert.equal((await request(capable.page, '/passkeys')).data[0].uv_verified, false)

  begin = await beginFor(capable)
  signed = await assertion(capable.page, begin, 'discouraged')
  const forged = Buffer.from(signed.response.authenticatorData, 'base64url'); forged[32] |= 4
  signed.response.authenticatorData = forged.toString('base64url')
  assert.equal((await finishFor(capable, begin, signed)).status, 400, 'unsigned UV flag modification must fail')

  // Model enabling PIN/UV on an existing key: retain the exact credential and
  // private key while changing the virtual authenticator's capabilities.
  const { credentials } = await capable.cdp.send('WebAuthn.getCredentials', { authenticatorId: capable.authenticatorId })
  await capable.cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: capable.authenticatorId })
  ;({ authenticatorId: capable.authenticatorId } = await capable.cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  }))
  for (const credential of credentials) await capable.cdp.send('WebAuthn.addCredential', { authenticatorId: capable.authenticatorId, credential })
  begin = await beginFor(capable)
  signed = await assertion(capable.page, begin)
  assert.equal((await finishFor(capable, begin, signed, touch.page)).status, 403)
  assert.equal((await finishFor(capable, begin, signed)).status, 410, 'foreign finish also consumes the challenge')

  begin = await beginFor(capable)
  signed = await assertion(verified.page, begin, 'required', verified.registration.id)
  assert.equal((await finishFor(capable, begin, signed)).status, 400, 'another key cannot qualify the selected credential')

  begin = await beginFor(capable)
  signed = await assertion(capable.page, begin)
  const success = await finishFor(capable, begin, signed)
  assert.equal(success.status, 200, JSON.stringify(success))
  assert.equal(success.data.uv_verified, true)
  assert.equal((await finishFor(capable, begin, signed)).status, 410)
  assert.equal((await request(capable.page, '/passkeys')).data[0].uv_verified, true)
  assert.equal(sql(`SELECT uv_verified FROM fido2_credentials WHERE id = '${capable.row.id}'`), 't')

  begin = await beginFor(touch)
  await assert.rejects(assertion(touch.page, begin), /NotAllowedError|AbortError/)
  signed = await assertion(touch.page, begin, 'discouraged')
  assert.equal((await finishFor(touch, begin, signed)).status, 400)
  assert.equal((await request(touch.page, '/passkeys')).data[0].uv_verified, false)

  // Add a second actual credential, retaining the original session's key so
  // deleting the selected credential tests finish-time ownership, not logout.
  const path = '/passkeys/register/begin'
  const bodyHash = await capable.page.evaluate(async () => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('{}')))].map(b => b.toString(16).padStart(2, '0')).join(''))
  const challenge = await request(capable.page, '/auth/sign-request', { method: 'POST', path, body_hash: bodyHash })
  assert.equal(challenge.status, 200, JSON.stringify(challenge))
  const auth = await assertion(capable.page, challenge.data)
  const added = await request(capable.page, path, {}, { 'X-Fido2-Challenge-Id': challenge.data.challenge_id, 'X-Fido2-Response': Buffer.from(JSON.stringify(auth)).toString('base64url') })
  assert.equal(added.status, 200, JSON.stringify(added))
  await capable.cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: capable.authenticatorId })
  await capable.cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })
  const newRegistration = await create(capable.page, added.data, true)
  assert.equal((await request(capable.page, '/passkeys/register/finish', newRegistration)).status, 200)
  const list = await request(capable.page, '/passkeys')
  capable.row = list.data.find(row => row.id !== capable.row.id)
  assert.equal(capable.row.uv_verified, true)
  begin = await beginFor(capable); signed = await assertion(capable.page, begin)
  sql(`DELETE FROM fido2_credentials WHERE id = '${capable.row.id}'`)
  assert.equal((await finishFor(capable, begin, signed)).status, 404)
  for (const uv of [false, true]) {
    const token = randomBytes(32).toString('hex')
    const hash = createHash('sha256').update(Buffer.from(token, 'hex')).digest('hex')
    sql(`INSERT INTO webauthn_reset_tokens(token_hash, user_id, expires_at)
      SELECT '${hash}', user_id, NOW() + INTERVAL '2 minutes' FROM fido2_credentials WHERE id = '${verified.row.id}'`)
    const reset = await request(verified.page, '/auth/reset/begin', { token })
    assert.equal(reset.status, 200, JSON.stringify(reset))
    await verified.cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: verified.authenticatorId })
    ;({ authenticatorId: verified.authenticatorId } = await verified.cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: uv, isUserVerified: uv, automaticPresenceSimulation: true },
    }))
    const registration = await create(verified.page, reset.data, uv)
    const finish = await request(verified.page, '/auth/reset/finish', registration)
    assert.equal(finish.status, 200, JSON.stringify(finish))
    const id = Buffer.from(registration.id, 'base64url').toString('hex')
    const keys = (await request(verified.page, '/passkeys')).data
    assert.equal(keys.find(key => key.credential_id === id).uv_verified, uv, 'reset must retain verified registration evidence')
  }
  console.log('Recovery verification: registration/reset evidence, UV upgrade, U2F, forged UV, owner/key binding, replay and deletion passed')
} finally { await browser.close() }
