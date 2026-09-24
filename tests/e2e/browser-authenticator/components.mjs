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
const service = { name: 'Keymaker', url: 'https://keymaker.example.com', readiness: passed, attestation: passed, measurements,
  policies: [{ purpose: 'Bundle generation', result: failed, sets: [{ pcrs: pinned, expires_at_unix_seconds: null }, { pcrs: { ...pinned, 0: 'e'.repeat(96) }, expires_at_unix_seconds: 1 }] }],
  service_reported_source: { repository: `https://codeberg.org/caution/${'long-source-name-'.repeat(15)}.git`, commit: 'a'.repeat(40) } }
let pending = 1, requests = 0, authRequests = 0, status = 200
const server = createServer(async (req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname
  if (path.startsWith('/auth/') || path.startsWith('/api/')) authRequests++
  if (path === '/.well-known/caution/build-inputs') {
    requests++
    const isPending = pending-- > 0
    res.writeHead(status, { 'content-type': 'application/json' })
    return res.end(JSON.stringify({ locksmith: { repo: 'https://codeberg.org/caution/locksmith.git', commit: 'b'.repeat(40) }, services: {
      pending: isPending, checked_at: isPending ? null : '2026-09-24T12:00:00Z', entries: isPending ? [] : [service, { ...service, name: 'Key service', url: 'https://key-service.example.com', policies: [{ ...service.policies[0], purpose: 'Certificate issuance' }, { ...service.policies[0], purpose: 'Share release' }] }]
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
  browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] })
  const page = await browser.newPage()
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  await page.evaluateOnNewDocument(() => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async value => {
      if (window.failCopy) throw new Error('Clipboard denied')
      window.copiedValue = value
    } } })
  })
  await page.goto(`http://localhost:${server.address().port}/components`)
  await page.waitForSelector('article')
  assert.equal(requests, 2)
  assert.equal(authRequests, 0)
  assert.match(await page.$eval('main', e => e.innerText), /Service-reported source/)
  assert.match(await page.$eval('main', e => e.innerText), /Readiness\s+✓\s+Ready/)
  assert.match(await page.$eval('main', e => e.innerText), /Failed\s+Authenticated measurements/)
  assert.equal(await page.$eval('pre', e => e.textContent), "caution verify --attestation-url 'https://keymaker.example.com/attestation'")
  const link = await page.$eval('article .primary', e => ({ href: e.getAttribute('href'), target: e.target, rel: e.rel }))
  assert.equal(link.target, '_blank')
  assert.match(link.rel, /noopener/)
  const verifier = new URL(link.href, 'https://platform.example.com')
  assert.deepEqual([...verifier.searchParams], [['url', 'https://keymaker.example.com/attestation']])
  await page.click('article .source button[aria-label="Copy Keymaker commit"]')
  assert.equal(await page.evaluate(() => window.copiedValue), 'a'.repeat(40))
  await page.click('article .copy-command')
  assert.match(await page.evaluate(() => window.copiedValue), /^caution verify --attestation-url/)
  await page.evaluate(() => { window.failCopy = true })
  await page.click('article .copy-command')
  assert.match(await page.$eval('.copy-feedback', e => e.innerText), /Could not copy/)
  await page.evaluate(() => { window.failCopy = false })
  await page.click('article .evidence > summary')
  assert.equal(await page.$('article .measurements [data-pcr="4"]'), null)
  assert.ok(await page.$('article .measurements [data-pcr="8"]'))
  assert.match(await page.$eval('article .measurements [data-pcr="3"]', e => e.innerText), /Observed only/)
  await page.click('article .measurements [data-pcr="8"] button')
  assert.equal(await page.evaluate(() => window.copiedValue), '0'.repeat(96))
  await page.click('article .evidence-controls label:nth-child(2) input')
  assert.ok(await page.$('article .measurements [data-pcr="4"]'))
  await page.click('article .evidence-controls label:first-child input')
  assert.equal(await page.$eval('article .measurements [data-pcr="0"] code', e => e.textContent), measurements[0])
  assert.match(await page.$eval('article .comparison', e => e.innerText), /Same value/)
  assert.match(await page.$eval('article .policy', e => e.innerText), /Different value/)
  assert.match(await page.$eval('article .policy', e => e.innerText), /Cutoff 1970/)
  await page.focus('article .evidence > summary')
  await page.keyboard.press('Enter')
  assert.equal(await page.$eval('article .evidence', e => e.open), false)
  await page.keyboard.press('Enter')
  assert.equal(await page.$eval('article .evidence', e => e.open), true)
  await page.$$eval('details', list => list.forEach(e => { e.open = true }))
  for (const width of [1360, 390]) {
    await page.setViewport({ width, height: 1000 })
    for (const theme of ['light', 'dark']) {
      const button = await page.$(`button[aria-label="Switch to ${theme} mode"]`)
      if (button) await button.click()
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
      await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))
      await page.screenshot({ path: `/tmp/components-${width}-${theme}.png`, fullPage: true })
      await page.$$eval('details', list => list.forEach(e => { e.open = false }))
      await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))
      await page.screenshot({ path: `/tmp/components-compact-${width}-${theme}.png`, fullPage: true })
      await page.$$eval('details', list => list.forEach(e => { e.open = true }))
    }
  }
  await page.click('.intro button')
  await page.waitForFunction(() => !document.querySelector('.intro button').disabled)
  assert.equal(requests, 3)
  // Missing evidence, malformed URLs and zero core PCRs remain visible.
  service.url = 'https://user:secret@keymaker.example.com'
  service.readiness = failed
  service.attestation = undefined
  service.measurements = { ...measurements, 0: '0'.repeat(96), 1: undefined }
  await page.click('.intro button')
  await page.waitForFunction(() => !document.querySelector('.intro button').disabled)
  assert.equal(await page.$('article:first-child .primary'), null)
  assert.match(await page.$eval('article .checks', e => e.innerText), /Attestation\s+—\s+Unavailable/)
  await page.$eval('article .evidence', e => { e.open = true })
  assert.ok(await page.$('article .measurements [data-pcr="0"]'))
  assert.match(await page.$eval('article .measurements [data-pcr="1"]', e => e.innerText), /Unavailable/)
  assert.match(await page.$eval('article .comparison', e => e.innerText), /Missing or invalid/)
  // A long pending check stops within ten seconds and stays stopped.
  pending = 100
  await page.click('.intro button')
  await page.waitForFunction(() => !document.querySelector('.intro button').disabled, { timeout: 12000 })
  assert.match(await page.$eval('[role=status]', e => e.innerText), /Refresh/)
  const stoppedAt = requests
  await new Promise(resolve => setTimeout(resolve, 1500))
  assert.equal(requests, stoppedAt)
  status = 503
  await page.click('.intro button')
  await page.waitForFunction(() => !document.querySelector('.intro button').disabled)
  assert.match(await page.$eval('[role=status]', e => e.innerText), /unavailable/)
  assert.equal((await page.$$('article')).length, 0)
  assert.deepEqual(errors, [])
  console.log('PASS: public routing, independent statuses, safe verifier links, clipboard success/failure, zero and missing PCRs, policy sets, keyboard disclosure, bounded refresh, four responsive/theme layouts')
} finally { await browser?.close(); await new Promise(resolve => server.close(resolve)) }
