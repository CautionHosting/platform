// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  compareOptionalExpectedPcrs,
  compareVerifiedPcrs,
  describeAttestationError,
  ensureUint8ArrayBase64,
  normalizeAttestationInput,
  parseExpectedPcrs,
  quotePosixShellArgument,
  resolveAttestationTarget,
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

test('compares all expected PCRs against cryptographically verified values', () => {
  const expected = {
    PCR0: 'a'.repeat(96),
    PCR1: 'b'.repeat(96),
    PCR2: 'c'.repeat(96),
  }

  assert.deepEqual(compareVerifiedPcrs({ verified: true, pcrs: expected }, expected), {
    matches: true,
    mismatches: [],
  })

  const actual = { ...expected, PCR1: 'd'.repeat(96) }
  assert.deepEqual(compareVerifiedPcrs({ verified: true, pcrs: actual }, expected), {
    matches: false,
    mismatches: ['PCR1'],
  })
  assert.deepEqual(compareVerifiedPcrs({ verified: false, pcrs: expected }, expected), {
    matches: false,
    mismatches: ['PCR0', 'PCR1', 'PCR2'],
  })
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
    },
  )
})
