// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import test from 'node:test'
import {
  APP_NAME_MAX_LENGTH,
  APP_NAME_MIN_LENGTH,
  normalizeAppName,
  validateAppName,
} from '../src/utils/appName.js'

const TOO_SHORT = `App names must be between ${APP_NAME_MIN_LENGTH} and ${APP_NAME_MAX_LENGTH} characters.`
const TOO_LONG = TOO_SHORT
const BAD_BOUNDARY = 'App names must start and end with a letter or number.'

test('valid app names are accepted', () => {
  for (const name of ['my-app', 'my_app', 'My-App_v2', 'app--name', 'api-v2', 'a1b']) {
    assert.equal(validateAppName(name), null, `expected "${name}" to be accepted`)
  }
})

test('surrounding whitespace is trimmed before validation', () => {
  assert.equal(validateAppName('  my-app  '), null)
  assert.equal(normalizeAppName('  my-app  '), 'my-app')
})

test('names outside the length bounds are rejected', () => {
  assert.equal(validateAppName(''), TOO_SHORT)
  assert.equal(validateAppName('ab'), TOO_SHORT)
  assert.equal(validateAppName(undefined), TOO_SHORT)
  assert.equal(validateAppName(null), TOO_SHORT)
  assert.equal(validateAppName('a'.repeat(APP_NAME_MAX_LENGTH)), null)
  assert.equal(validateAppName('a'.repeat(APP_NAME_MAX_LENGTH + 1)), TOO_LONG)
})

test('illegal characters are reported before boundary violations', () => {
  assert.match(validateAppName('app.name'), /cannot contain "\."/)
  assert.match(validateAppName('app name'), /cannot contain " "/)
  // Broken on both counts: the illegal character wins.
  assert.match(validateAppName('_app.name'), /cannot contain "\."/)
})

test('names must start and end with a letter or number', () => {
  assert.equal(validateAppName('_app'), BAD_BOUNDARY)
  assert.equal(validateAppName('app_'), BAD_BOUNDARY)
  assert.equal(validateAppName('-app'), BAD_BOUNDARY)
  assert.equal(validateAppName('app-'), BAD_BOUNDARY)
})
