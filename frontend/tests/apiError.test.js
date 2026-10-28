// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import test from 'node:test'
import { apiError, apiErrorFromText, withGuidance } from '../src/utils/apiError.js'

const REGENERATE =
  'Re-generate the bundle with `caution quorum init`, then upload it again.'

test('a body with only a message renders as before', () => {
  assert.equal(apiError({ error: 'not found' }, 'fallback'), 'not found')
  assert.equal(apiError({ message: 'not found' }, 'fallback'), 'not found')
  assert.equal(apiError({}, 'fallback'), 'fallback')
  assert.equal(apiError(null, 'fallback'), 'fallback')
  assert.equal(apiError(undefined, 'fallback'), 'fallback')
})

test('a report adds its guidance on its own line', () => {
  const body = {
    error: 'invalid quorum bundle',
    errors: [
      { error: 'invalid quorum bundle', notes: [], warnings: [] },
      { error: 'expected proofed v1 quorum bundle', notes: [REGENERATE], warnings: [] },
    ],
  }

  assert.equal(apiError(body, 'fallback'), `invalid quorum bundle\n${REGENERATE}`)
})

test('guidance is shown once, notes before warnings, in chain order', () => {
  const body = {
    error: 'the key service is unavailable',
    errors: [
      { error: 'the key service is unavailable', notes: ['retry shortly'], warnings: ['nothing was stored'] },
      { error: 'a later link', notes: ['retry shortly', 'a second note'] },
    ],
  }

  assert.equal(
    apiError(body, 'fallback'),
    'the key service is unavailable\nretry shortly\nnothing was stored\na second note'
  )
})

test('a non-string or blank guidance entry is ignored', () => {
  const body = {
    error: 'failed',
    errors: [{ error: 'failed', notes: ['  ', null, 42, 'keep me'], warnings: [] }],
  }

  assert.equal(apiError(body, 'fallback'), 'failed\nkeep me')
})

test('an errors field that is not an array is not guidance', () => {
  assert.equal(apiError({ error: 'failed', errors: 'not an array' }, 'fallback'), 'failed')
})

test('withGuidance keeps the caller message order', () => {
  const body = { error: 'error wins for apiError', message: 'message wins here' }

  assert.equal(withGuidance(body.message || body.error, body), 'message wins here')
})

test('a JSON body is parsed, a plain body is shown as it arrived', () => {
  const report = JSON.stringify({
    error: 'invalid quorum bundle',
    errors: [{ error: 'invalid quorum bundle', notes: [REGENERATE], warnings: [] }],
  })

  assert.equal(apiErrorFromText(report, 'fallback'), `invalid quorum bundle\n${REGENERATE}`)
  assert.equal(apiErrorFromText('upstream said no', 'fallback'), 'upstream said no')
  assert.equal(apiErrorFromText('', 'fallback'), 'fallback')
  assert.equal(apiErrorFromText('   ', 'fallback'), 'fallback')
})

test('a JSON body with no message falls back to the caller wording', () => {
  assert.equal(apiErrorFromText('{"detail": "unexpected"}', 'fallback'), 'fallback')
})
