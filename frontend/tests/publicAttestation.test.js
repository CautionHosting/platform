// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  MAX_EXPECTED_PCR_FILE_SIZE,
  compareOptionalExpectedPcrs,
  compareVerifiedPcrs,
  describeAttestationError,
  ensureUint8ArrayBase64,
  forgetRememberedPcrs,
  hasDebugPcrs,
  loadRememberedPcrs,
  normalizeAttestationInput,
  parseExpectedPcrFile,
  parseExpectedPcrs,
  quotePosixShellArgument,
  readExpectedPcrFile,
  resolveAttestationTarget,
  saveRememberedPcrs,
} from '../src/utils/publicAttestation.js'

test('installs the base64 method required by the attestation widget', () => {
  class TestBytes extends Uint8Array {}
  ensureUint8ArrayBase64(TestBytes)

  assert.equal(new TestBytes([0, 1, 2, 253, 254, 255]).toBase64(), 'AAEC/f7/')
})

test('explains cross-origin fetch failures without masking other errors', () => {
  assert.match(
    describeAttestationError(
      new Error('Failed to fetch'),
      'https://app.example.com/attestation',
      'https://dashboard.example.com',
    ),
    /cross-origin.*CORS/i,
  )
  assert.equal(
    describeAttestationError(
      new Error('Failed to fetch'),
      'https://dashboard.example.com/attestation',
      'https://dashboard.example.com',
    ),
    'Failed to fetch',
  )
  assert.equal(
    describeAttestationError(
      new Error('Invalid signature'),
      'https://app.example.com/attestation',
      'https://dashboard.example.com',
    ),
    'Invalid signature',
  )
})

test('uses the app attestation endpoint when url names an origin', () => {
  assert.deepEqual(
    resolveAttestationTarget('?url=https%3A%2F%2Fdemo.example.com'),
    {
      appUrl: 'https://demo.example.com/',
      attestationUrl: 'https://demo.example.com/attestation',
    },
  )
})

test('preserves an explicit attestation endpoint path', () => {
  assert.deepEqual(
    resolveAttestationTarget('?url=https%3A%2F%2Fdemo.example.com%2Fcustom-attestation'),
    {
      appUrl: 'https://demo.example.com/custom-attestation',
      attestationUrl: 'https://demo.example.com/custom-attestation',
    },
  )
})

test('returns no target when the url query parameter is absent', () => {
  assert.equal(resolveAttestationTarget(''), null)
})

test('normalizes HTTPS domain input and preserves an explicit endpoint', () => {
  assert.equal(normalizeAttestationInput('demo.example.com'), 'https://demo.example.com/')
  assert.equal(
    normalizeAttestationInput('https://demo.example.com/custom-attestation'),
    'https://demo.example.com/custom-attestation',
  )
  assert.throws(() => normalizeAttestationInput(''), /HTTPS application domain or attestation URL/i)
})

test('rejects insecure, raw-IP, non-HTTPS, and credential-bearing targets', () => {
  const useCli = /Caution CLI.*HTTP or raw-IP/i

  assert.throws(() => normalizeAttestationInput('http://demo.example.com'), useCli)
  assert.throws(() => normalizeAttestationInput('https://192.0.2.10/attestation'), useCli)
  assert.throws(() => normalizeAttestationInput('https://[2001:db8::1]/attestation'), useCli)
  assert.throws(() => resolveAttestationTarget('?url=http%3A%2F%2Fdemo.example.com'), useCli)
  assert.throws(() => resolveAttestationTarget('?url=javascript%3Aalert(1)'), useCli)
  assert.throws(
    () => resolveAttestationTarget('?url=https%3A%2F%2Fuser%3Asecret%40demo.example.com'),
    /credentials/i,
  )
})

test('quotes untrusted URLs as one POSIX shell argument', () => {
  assert.equal(
    quotePosixShellArgument("https://demo.example/a'b;$(touch /tmp/x)`id`&c"),
    `'https://demo.example/a'"'"'b;$(touch /tmp/x)\`id\`&c'`,
  )
})

test('parses labeled PCR0, PCR1, and PCR2 SHA-384 hashes', () => {
  const pcr0 = 'a'.repeat(96)
  const pcr1 = 'B'.repeat(96)
  const pcr2 = '0x' + 'c'.repeat(96)

  assert.deepEqual(parseExpectedPcrs(`PCR0=${pcr0}\nPCR1: ${pcr1}\nPCR2 ${pcr2}`), {
    PCR0: pcr0,
    PCR1: pcr1.toLowerCase(),
    PCR2: pcr2.slice(2),
  })
})

test('parses three unlabeled hashes in PCR order and rejects incomplete input', () => {
  const hashes = ['1'.repeat(96), '2'.repeat(96), '3'.repeat(96)]
  assert.deepEqual(parseExpectedPcrs(hashes.join('\n')), {
    PCR0: hashes[0],
    PCR1: hashes[1],
    PCR2: hashes[2],
  })

  assert.throws(() => parseExpectedPcrs(hashes.slice(0, 2).join('\n')), /PCR0, PCR1, and PCR2/i)
  assert.throws(() => parseExpectedPcrs(`PCR0=${'f'.repeat(95)}\nPCR1=${hashes[1]}\nPCR2=${hashes[2]}`), /96 hexadecimal/i)
})

test('parses canonical enclave.pcrs build output', () => {
  const pcrs = {
    PCR0: 'a'.repeat(96),
    PCR1: 'b'.repeat(96),
    PCR2: 'c'.repeat(96),
  }
  const content = Object.entries(pcrs).map(([name, hash]) => `${hash} ${name}`).join('\n')

  assert.deepEqual(parseExpectedPcrs(content), pcrs)
  assert.deepEqual(parseExpectedPcrFile(content), { pcrs, source: 'build' })
})

test('parses trusted_hashes.json without treating its metadata as verification', () => {
  const pcrs = {
    PCR0: 'a'.repeat(96),
    PCR1: 'b'.repeat(96),
    PCR2: 'c'.repeat(96),
  }
  const content = JSON.stringify({
    pcr0: pcrs.PCR0,
    pcr1: pcrs.PCR1,
    pcr2: pcrs.PCR2,
    verified_at: '2026-08-12T12:00:00Z',
    tls: { domain: 'app.example.com', certfp: 'd'.repeat(64) },
  })

  assert.deepEqual(parseExpectedPcrs(content), pcrs)
  assert.deepEqual(parseExpectedPcrFile(content), { pcrs, source: 'cli' })
})

test('rejects malformed and oversized expected PCR files', async () => {
  await assert.rejects(
    readExpectedPcrFile({ size: MAX_EXPECTED_PCR_FILE_SIZE + 1, text: async () => '' }),
    /64 KiB/i,
  )
  await assert.rejects(
    readExpectedPcrFile({ size: 12, text: async () => 'PCR0=manual' }),
    /enclave\.pcrs.*trusted_hashes\.json/i,
  )
  assert.throws(
    () => parseExpectedPcrFile(JSON.stringify({ pcr0: 'a'.repeat(96) })),
    /enclave\.pcrs.*trusted_hashes\.json/i,
  )
})

test('compares all expected PCRs against cryptographically verified values', () => {
  const expected = {
    PCR0: 'a'.repeat(96),
    PCR1: 'b'.repeat(96),
    PCR2: 'c'.repeat(96),
  }

  assert.deepEqual(compareVerifiedPcrs({ verified: true, pcrs: expected }, expected), {
    matches: true,
    mismatches: [],
    comparisons: Object.entries(expected).map(([name, value]) => ({
      name,
      expected: value,
      authenticated: value,
      matches: true,
    })),
  })

  const actual = { ...expected, PCR1: 'd'.repeat(96) }
  assert.deepEqual(compareVerifiedPcrs({ verified: true, pcrs: actual }, expected), {
    matches: false,
    mismatches: ['PCR1'],
    comparisons: Object.entries(expected).map(([name, value]) => ({
      name,
      expected: value,
      authenticated: actual[name],
      matches: name !== 'PCR1',
    })),
  })
  assert.deepEqual(compareVerifiedPcrs({ verified: false, pcrs: expected }, expected), {
    matches: false,
    mismatches: ['PCR0', 'PCR1', 'PCR2'],
    comparisons: Object.entries(expected).map(([name, value]) => ({
      name,
      expected: value,
      authenticated: null,
      matches: false,
    })),
  })
})

test('detects only verified debug attestations with all-zero PCR0, PCR1, and PCR2', () => {
  const zeroPcrs = {
    PCR0: '0'.repeat(96),
    PCR1: '0'.repeat(96),
    PCR2: '0'.repeat(96),
  }

  assert.equal(hasDebugPcrs({ verified: true, pcrs: zeroPcrs }), true)
  assert.equal(hasDebugPcrs({ verified: false, pcrs: zeroPcrs }), false)
  assert.equal(hasDebugPcrs({ verified: true, pcrs: { ...zeroPcrs, PCR2: '1'.repeat(96) } }), false)
  assert.equal(hasDebugPcrs({ verified: true, pcrs: { PCR0: zeroPcrs.PCR0 } }), false)
})

test('treats expected PCR comparison as an optional extra check', () => {
  const pcrs = {
    PCR0: 'a'.repeat(96),
    PCR1: 'b'.repeat(96),
    PCR2: 'c'.repeat(96),
  }

  assert.deepEqual(compareOptionalExpectedPcrs({ verified: true, pcrs }, ''), {
    checked: false,
    matches: true,
    mismatches: [],
    comparisons: [],
  })
  assert.deepEqual(
    compareOptionalExpectedPcrs(
      { verified: true, pcrs },
      `PCR0=${pcrs.PCR0}\nPCR1=${pcrs.PCR1}\nPCR2=${pcrs.PCR2}`,
    ),
    {
      checked: true,
      matches: true,
      mismatches: [],
      comparisons: Object.entries(pcrs).map(([name, value]) => ({
        name,
        expected: value,
        authenticated: value,
        matches: true,
      })),
    },
  )
})

function createMemoryStorage() {
  const values = new Map()
  return {
    values,
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  }
}

test('remembers complete PCR profiles for the exact attestation endpoint', () => {
  const storage = createMemoryStorage()
  const endpoint = 'https://app.example.com/attestation?profile=release'
  const otherEndpoint = 'https://app.example.com/attestation?profile=staging'
  const pcrs = {
    PCR0: 'a'.repeat(96),
    PCR1: 'b'.repeat(96),
    PCR2: 'c'.repeat(96),
  }
  const savedAt = '2026-08-12T12:00:00.000Z'

  saveRememberedPcrs(storage, endpoint, pcrs, savedAt)
  assert.deepEqual(loadRememberedPcrs(storage, endpoint), { pcrs, savedAt })
  assert.equal(loadRememberedPcrs(storage, otherEndpoint), null)

  const replacement = { ...pcrs, PCR2: 'd'.repeat(96) }
  saveRememberedPcrs(storage, endpoint, replacement, savedAt)
  assert.deepEqual(loadRememberedPcrs(storage, endpoint)?.pcrs, replacement)

  forgetRememberedPcrs(storage, endpoint)
  assert.equal(loadRememberedPcrs(storage, endpoint), null)
})

test('ignores corrupt or unsupported remembered PCR state', () => {
  const storage = createMemoryStorage()
  const endpoint = 'https://app.example.com/attestation'
  const pcrs = {
    PCR0: 'a'.repeat(96),
    PCR1: 'b'.repeat(96),
    PCR2: 'c'.repeat(96),
  }

  saveRememberedPcrs(storage, endpoint, pcrs)
  const [key] = storage.values.keys()
  storage.values.set(key, '{bad json')
  assert.equal(loadRememberedPcrs(storage, endpoint), null)

  storage.values.set(key, JSON.stringify({ version: 2, pcrs, savedAt: new Date().toISOString() }))
  assert.equal(loadRememberedPcrs(storage, endpoint), null)
})
