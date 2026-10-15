// Real public Vue page, mocked observations; no live Nitro verification.
import puppeteer from 'puppeteer'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { resolve, extname } from 'node:path'
import assert from 'node:assert/strict'
const root = resolve(import.meta.dirname, '../../../frontend/dist')
const passed = { status: 'passed', reason: null }
const failed = { status: 'failed', reason: 'Authenticated measurements do not match an active policy set' }
const measurements = { 0: 'a'.repeat(96), 1: 'b'.repeat(96), 2: 'c'.repeat(96), 3: 'd'.repeat(96), 4: '0'.repeat(96), 5: '0'.repeat(96), 8: '0'.repeat(96) }
const pinned = { 0: measurements[0], 1: measurements[1], 2: measurements[2], 8: measurements[8] }
const service = { id: 'keymaker', name: 'Keymaker', url: 'https://keymaker.example.com', readiness: passed, attestation: passed, measurements,
  policies: [{ purpose: 'Bundle generation', result: failed, sets: [{ pcrs: pinned, expires_at_unix_seconds: null }, { pcrs: { ...pinned, 0: 'e'.repeat(96) }, expires_at_unix_seconds: 1 }] }],
  service_reported_source: { repository: `https://codeberg.org/caution/${'long-source-name-'.repeat(15)}.git`, commit: 'a'.repeat(40) } }
const checkedAt = new Date(Date.now() - 120000).toISOString()
let pending = 1, requests = 0, authRequests = 0, status = 200, entriesOverride = null
const server = createServer(async (req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname
  if (path.startsWith('/auth/') || path.startsWith('/api/')) authRequests++
  if (path === '/.well-known/caution/build-inputs') {
    requests++
    const isPending = pending-- > 0
    res.writeHead(status, { 'content-type': 'application/json' })
    return res.end(JSON.stringify({ locksmith: { repo: 'https://codeberg.org/caution/locksmith.git', commit: 'b'.repeat(40) }, services: {
      pending: isPending, checked_at: isPending ? null : checkedAt, entries: isPending ? [] : entriesOverride || [service, { ...service, id: 'key-service', name: 'Key service', url: 'https://key-service.example.com', policies: [{ ...service.policies[0], purpose: 'Certificate issuance' }, { ...service.policies[0], purpose: 'Share release' }] }]
    } }))
  }
  const file = path.startsWith('/assets/') ? resolve(root, `.${path}`) : resolve(root, 'index.html')
  if (!file.startsWith(root + '/')) { res.writeHead(404); return res.end() }
  res.setHeader('content-type', { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml' }[extname(file)] || 'application/octet-stream')
  try { res.end(await readFile(file)) } catch { res.writeHead(404); res.end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
let browser
try {
  browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'], ...(process.env.PUPPETEER_EXECUTABLE_PATH ? { executablePath: process.env.PUPPETEER_EXECUTABLE_PATH } : {}) })
  const page = await browser.newPage()
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  await page.evaluateOnNewDocument(() => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async value => {
      if (window.failCopy) throw new Error('Clipboard denied')
      window.copiedValue = value
    } } })
  })
  const base = `http://localhost:${server.address().port}`
  const maker = 'article[aria-label="Keymaker service evidence"]'
  const keyService = 'article[aria-label="Key service service evidence"]'
  const refresh = async () => {
    await page.click('.intro button')
    await page.waitForFunction(() => !document.querySelector('.intro button').disabled)
  }
  const select = async key => {
    await page.click(`.service-selector a[href="#${key}"]`)
    await page.waitForFunction(key => document.querySelector(`.service-selector a[href="#${key}"]`).getAttribute('aria-current') === 'true', {}, key)
  }
  const open = async selector => { await page.$eval(selector, e => { e.open = true }); await page.evaluate(() => new Promise(r => requestAnimationFrame(r))) }
  await page.goto(`${base}/components#key-service`)
  await page.waitForSelector('article')
  assert.equal(requests, 2)
  assert.equal(authRequests, 0)
  assert.match(await page.$eval('.freshness time', e => e.textContent), /2 minutes ago/)
  assert.equal(await page.$eval(keyService, e => e.checkVisibility()), true)
  await select('keymaker')
  await page.goBack()
  await page.waitForFunction(() => location.hash === '#key-service')
  assert.equal(await page.$eval(keyService, e => e.checkVisibility()), true)
  await page.goForward()
  await page.waitForFunction(() => location.hash === '#keymaker')
  assert.equal(await page.$eval(maker, e => e.checkVisibility()), true)
  assert.match(await page.$eval(maker + ' .service-result', e => e.innerText), /Configured check failed/)
  assert.match(await page.$eval(maker + ' .checks', e => e.innerText), /Authenticated measurements/)
  assert.equal(await page.$eval('.framework', e => e.open), false)
  assert.equal(await page.$eval(maker + ' .cli-command', e => e.checkVisibility()), false)
  const link = await page.$eval(maker + ' .primary', e => ({ href: e.getAttribute('href'), target: e.target, rel: e.rel }))
  assert.equal(link.target, '_blank')
  assert.match(link.rel, /noopener/)
  assert.deepEqual([...new URL(link.href, base).searchParams], [['url', 'https://keymaker.example.com/attestation']])
  await page.click(maker + ' .cli-toggle')
  assert.equal(await page.$eval(maker + ' pre', e => e.textContent), `caution --url '${base}' verify --service keymaker`)
  await page.click(maker + ' .copy-command')
  assert.match(await page.evaluate(() => window.copiedValue), /verify --service keymaker$/)
  await page.evaluate(() => { window.failCopy = true })
  await page.click(maker + ' .copy-command')
  assert.match(await page.$eval('.copy-feedback', e => e.innerText), /Could not copy/)
  await page.evaluate(() => { window.failCopy = false })
  await page.click(maker + ' .source button[aria-label="Copy Keymaker commit"]')
  assert.equal(await page.evaluate(() => window.copiedValue), 'a'.repeat(40))
  await open(maker + ' [data-check="Attestation"]')
  assert.equal(await page.$(maker + ' .measurements [data-pcr="4"]'), null)
  assert.ok(await page.$(maker + ' .measurements [data-pcr="8"]'))
  assert.match(await page.$eval(maker + ' .measurements [data-pcr="3"]', e => e.innerText), /Observed only/)
  await page.click(maker + ' .measurements [data-pcr="8"] button')
  assert.equal(await page.evaluate(() => window.copiedValue), '0'.repeat(96))
  await page.click(maker + ' .evidence-controls label:nth-child(2) input')
  await page.click(maker + ' .evidence-controls label:first-child input')
  assert.ok(await page.$(maker + ' .measurements [data-pcr="4"]'))
  assert.equal(await page.$eval(maker + ' .measurements [data-pcr="0"] code', e => e.textContent), measurements[0])
  await page.focus(maker + ' [data-check="Attestation"] > summary')
  await page.keyboard.press('Enter')
  assert.equal(await page.$eval(maker + ' [data-check="Attestation"]', e => e.open), false)
  await page.keyboard.press('Enter')
  await refresh()
  assert.equal(await page.$eval(maker + ' [data-check="Attestation"]', e => e.open), true)
  assert.equal(await page.$eval(maker + ' .cli-command', e => e.checkVisibility()), true)
  assert.equal(await page.$eval('.freshness time', e => e.getAttribute('datetime')), checkedAt)
  assert.equal(await page.$eval(maker + ' .evidence-controls input', e => e.checked), true)
  const accepted = { ...service, policies: [{ ...service.policies[0], result: passed,
    sets: [...service.policies[0].sets, { pcrs: pinned }, { pcrs: pinned }], matched_set_indices: [3, 2] }] }
  entriesOverride = [accepted, { ...accepted, id: 'key-service', name: 'Key service', policies: ['Certificate issuance', 'Share release'].map(purpose => ({ ...accepted.policies[0], purpose })) }]
  await refresh()
  assert.match(await page.$eval(maker + ' .service-result', e => e.innerText), /Configured checks passed/)
  await open(maker + ' .policy')
  assert.deepEqual(await page.$$eval(maker + ' .policy > .check-evidence > .policy-set', nodes => nodes.map(e => e.dataset.setIndex)), ['2', '3'])
  assert.equal(await page.$eval(maker + ' .other-sets', e => e.open), true) // Existing disclosure survives the new snapshot.
  await page.click(maker + ' .other-sets > summary')
  assert.equal(await page.$eval(maker + ' .other-sets', e => e.open), false)
  assert.match(await page.$eval(maker + ' .other-sets > summary', e => e.innerText), /Other approved sets/)
  await open(maker + ' .other-sets')
  assert.match(await page.$eval(maker + ' .other-sets', e => e.innerText), /Approved set 1/)
  assert.match(await page.$eval(maker + ' .other-sets', e => e.innerText), /Cutoff 1970/)
  for (const width of [1360, 760, 390, 320]) {
    await page.setViewport({ width, height: 1000 })
    for (const theme of ['light', 'dark']) {
      const toggle = await page.$(`button[aria-label="Switch to ${theme} mode"]`)
      if (toggle) await toggle.click()
      assert.equal(await page.$eval(maker + ' .policy', e => e.open), true)
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `${width} ${theme}`)
      await page.screenshot({ path: `/tmp/components-passport-${width}-${theme}.png`, fullPage: true })
      if (width === 320 || width === 1360) {
        await page.$eval(maker + ' .policy', e => e.scrollIntoView())
        await page.screenshot({ path: `/tmp/components-passport-evidence-${width}-${theme}.png` })
        await page.evaluate(() => scrollTo(0, 0))
      }
    }
  }
  for (const width of [1360, 390, 320]) {
    await page.setViewport({ width, height: 1000 })
    for (const theme of ['light', 'dark']) {
      const toggle = await page.$(`button[aria-label="Switch to ${theme} mode"]`)
      if (toggle) await toggle.click()
      await page.$$eval('article details', nodes => nodes.forEach(e => { e.open = false }))
      await page.evaluate(() => new Promise(r => requestAnimationFrame(r)))
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
      await page.screenshot({ path: `/tmp/components-passport-compact-${width}-${theme}.png`, fullPage: true })
    }
  }
  await page.setViewport({ width: 1360, height: 1000 })
  await select('key-service')
  await open(keyService + ' [data-check="Share release policy"]')
  await refresh()
  assert.equal(await page.$eval(keyService + ' [data-check="Share release policy"]', e => e.open), true)
  assert.equal(await page.$eval(keyService, e => e.checkVisibility()), true)
  // Old snapshots keep comparisons, without inferred accepted-set claims or synthetic CLI IDs.
  const legacy = { ...service, id: undefined, policies: [{ ...service.policies[0], result: passed }] }
  entriesOverride = [legacy]
  await refresh()
  await open(maker + ' .policy')
  assert.equal(await page.$(maker + ' [data-accepted="true"]'), null)
  await open(maker + ' .other-sets')
  assert.match(await page.$eval(maker + ' .comparison', e => e.innerText), /Same value/)
  assert.doesNotMatch(await page.$eval(maker + ' pre', e => e.textContent), /--service/)
  entriesOverride = [{ ...accepted, policies: [{ ...accepted.policies[0], matched_set_indices: ['2', -1, 99] }] }]
  await refresh()
  assert.equal(await page.$(maker + ' [data-accepted="true"]'), null)
  await page.click('.framework > summary')
  await page.click('.framework .copy-repository')
  assert.equal(await page.evaluate(() => window.copiedValue), 'https://codeberg.org/caution/locksmith.git')
  await refresh()
  assert.equal(await page.$eval('.framework', e => e.open), true)
  const outage = { ...service, readiness: { status: 'failed', reason: 'Request failed' }, attestation: { status: 'failed', reason: 'Request timed out' }, measurements: {}, service_reported_source: null,
    policies: [{ ...service.policies[0], result: { status: 'failed', reason: 'No authenticated measurements' }, matched_set_indices: [] }] }
  for (const [entry, tone] of [[outage, 'unavailable'], [{ ...outage, readiness: passed, attestation: { status: 'failed', reason: 'Attestation authentication failed' } }, 'failed'], [{ ...accepted, readiness: { status: 'failed', reason: 'Service is not ready' } }, 'pending']]) {
    entriesOverride = [entry]
    await refresh()
    assert.ok(await page.$(maker + ` .service-result.${tone}`))
    if (tone === 'pending') assert.ok(await page.$(maker + ' .reason.pending'))
  }
  entriesOverride = [outage]
  await refresh()
  await open(maker + ' .policy')
  assert.equal(await page.$(maker + ' .measurements'), null)
  assert.equal(await page.$(maker + ' .comparison small'), null)
  assert.deepEqual(await page.$$eval(maker + ' .comparison thead th', nodes => nodes.map(e => e.textContent)), ['PCR', 'Allowed', 'PCR', 'Allowed'])
  entriesOverride = [service]
  service.url = 'https://user:secret@keymaker.example.com'
  service.attestation = undefined
  await refresh()
  assert.equal(await page.$(maker + ' .primary'), null)
  assert.equal(await page.$(maker + ' .measurements'), null)
  service.attestation = passed
  service.measurements = { ...measurements, 0: '0'.repeat(96), 1: undefined }
  await refresh()
  await open(maker + ' [data-check="Attestation"]')
  assert.match(await page.$eval(maker + ' .measurements [data-pcr="1"]', e => e.innerText), /Unavailable/)
  await page.goto(`${base}/components#unknown`)
  await page.waitForSelector('article')
  assert.equal(await page.$eval(maker, e => e.checkVisibility()), true)
  pending = 100
  await refresh()
  assert.match(await page.$eval('.refresh-message', e => e.innerText), /Refresh/)
  const stoppedAt = requests
  await new Promise(resolve => setTimeout(resolve, 1500))
  assert.equal(requests, stoppedAt)
  status = 503
  await refresh()
  assert.match(await page.$eval('.refresh-message', e => e.innerText), /unavailable/)
  assert.equal((await page.$$('article')).length, 0)
  assert.deepEqual(errors, [])
  console.log('PASS: Passport navigation/history, server accepted-set references, legacy snapshots, independent statuses, safe verifier/CLI, clipboard, retained disclosures, bounded refresh, both themes and 320–1360px layouts')
} finally { await browser?.close(); await new Promise(resolve => server.close(resolve)) }
