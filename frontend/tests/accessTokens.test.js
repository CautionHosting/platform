// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import test from 'node:test'
import {
  DEFAULT_EXPIRY_DAYS,
  MAX_NAME_LEN,
  buildAccessTokenPayload,
  describeAccessTokenExpiry,
  isAccessTokenExpired,
  validateAccessTokenForm,
} from '../src/utils/accessTokens.js'

test('name is required and trimmed', () => {
  assert.equal(validateAccessTokenForm({ name: '   ' }), 'name is required')
  assert.equal(validateAccessTokenForm({ name: 'ci' }), null)
  assert.equal(
    validateAccessTokenForm({ name: 'x'.repeat(MAX_NAME_LEN + 1) }),
    `name must be at most ${MAX_NAME_LEN} characters`,
  )
})

test('expiry is validated only when enabled', () => {
  assert.equal(validateAccessTokenForm({ name: 'ci', expiryEnabled: true, expiryDays: 0 }), 'expiry must be a whole number of days between 1 and 3650')
  assert.equal(validateAccessTokenForm({ name: 'ci', expiryEnabled: true, expiryDays: 'forever' }), 'expiry must be a whole number of days between 1 and 3650')
  assert.equal(validateAccessTokenForm({ name: 'ci', expiryEnabled: true, expiryDays: 90 }), null)
  // Disabled: the day value is ignored.
  assert.equal(validateAccessTokenForm({ name: 'ci', expiryEnabled: false, expiryDays: 0 }), null)
})

test('payload trims and maps optional fields', () => {
  assert.deepEqual(
    buildAccessTokenPayload({ name: '  ci  ', description: '  ', expiryDays: DEFAULT_EXPIRY_DAYS, roleIds: ['a', 'b'] }),
    { name: 'ci', description: null, expires_in_days: DEFAULT_EXPIRY_DAYS, role_ids: ['a', 'b'] },
  )
  assert.deepEqual(
    buildAccessTokenPayload({ name: 'ci', description: 'build server', expiryEnabled: false }),
    { name: 'ci', description: 'build server', expires_in_days: null, role_ids: [] },
  )
})

test('expiry helpers', () => {
  const now = Date.parse('2026-01-01T00:00:00Z')
  assert.equal(isAccessTokenExpired(null, now), false)
  assert.equal(isAccessTokenExpired('2025-01-01T00:00:00Z', now), true)
  assert.equal(isAccessTokenExpired('2027-01-01T00:00:00Z', now), false)
  assert.equal(describeAccessTokenExpiry(null), 'Never expires')
  assert.equal(describeAccessTokenExpiry('2025-01-01T00:00:00Z', now), 'Expired')
  assert.equal(describeAccessTokenExpiry('2027-03-04T00:00:00Z', now), 'Expires 2027-03-04')
})
