// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import test from 'node:test'
import { getSourceUrl, selectAttestationManifest } from '../src/utils/attestationMetadata.js'

const signedManifest = { app_source: { url: 'https://example.com/signed' } }
const externalManifest = {
  app_source: { url: 'https://example.com/substituted' },
  framework_source: 'https://example.com/unsigned-framework',
}

test('prefers the authenticated userData manifest without merging external sources', () => {
  assert.deepEqual(selectAttestationManifest({ verified: true, userData: signedManifest }, externalManifest), {
    manifest: signedManifest,
    manifestVerified: true,
  })
})

test('preserves an authenticated manifest when there is no external manifest', () => {
  assert.deepEqual(selectAttestationManifest({ verified: true, userData: signedManifest }), {
    manifest: signedManifest,
    manifestVerified: true,
  })
})

test('marks external metadata unverified when authenticated userData is not a manifest', () => {
  for (const userData of [null, undefined, { raw: 'aabbcc' }, { unrelated: true }, [], 'opaque']) {
    assert.deepEqual(selectAttestationManifest({ verified: true, userData }, externalManifest), {
      manifest: externalManifest,
      manifestVerified: false,
    })
  }
})

test('never authenticates metadata from an unsuccessful verifier result', () => {
  for (const verified of [false, undefined, 'true']) {
    assert.deepEqual(selectAttestationManifest({ verified, userData: signedManifest }, externalManifest), {
      manifest: externalManifest,
      manifestVerified: false,
    })
  }
})

test('omits absent or non-manifest metadata', () => {
  for (const manifest of [null, undefined, 'opaque', [], { raw: 'aabbcc' }]) {
    assert.deepEqual(selectAttestationManifest({ verified: true, userData: manifest }, manifest), {
      manifest: null,
      manifestVerified: false,
    })
  }
})

const sourceForms = {
  string: (url) => url,
  urls: (url) => ({ urls: [url] }),
  url: (url) => ({ url }),
}

for (const [name, source] of Object.entries(sourceForms)) {
  test(`rejects non-HTTP(S) source links in ${name} form`, () => {
    for (const url of [
      'javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'java\nscript:alert(1)',
      'data:text/html,<script>alert(1)</script>', 'file:///etc/passwd',
      'ftp://example.com/repo', 'httpx://example.com/repo',
      '//example.com/repo', '/repo', 'https://',
    ]) {
      assert.equal(getSourceUrl(source(url)), null, url)
    }
  })
}

test('preserves HTTP(S) source links and first-URL precedence', () => {
  for (const source of Object.values(sourceForms)) {
    for (const url of ['https://example.com/repo?ref=main#readme', 'http://example.com/repo']) {
      assert.equal(getSourceUrl(source(url)), url)
    }
  }
  assert.equal(
    getSourceUrl({ urls: ['https://example.com/first', 'https://example.com/second'], url: 'https://example.com/legacy' }),
    'https://example.com/first',
  )
  assert.equal(getSourceUrl({ urls: [], url: 'https://example.com/legacy' }), 'https://example.com/legacy')
})

test('rejects missing or malformed source URL values without coercion', () => {
  for (const source of [null, undefined, '', {}, 42, { url: 42 }, { urls: [42] }, { urls: 'https://example.com' }]) {
    assert.equal(getSourceUrl(source), null, JSON.stringify(source))
  }
})
