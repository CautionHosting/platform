// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import test from 'node:test'
import {
  DEFAULT_ORGANIZATION_NAME,
  ORGANIZATION_CREATION_OUTCOME,
  ORGANIZATION_NAME_MAX_LENGTH,
  ORGANIZATION_NAME_MIN_LENGTH,
  canRemoveOrganizationMember,
  needsOrganizationSetup,
  organizationCreationErrorMessage,
  organizationCreationOutcome,
  parseResponseBody,
  validateOrganizationName,
} from '../src/utils/organizations.js'

const TOO_SHORT = `Organization names must be between ${ORGANIZATION_NAME_MIN_LENGTH} and ${ORGANIZATION_NAME_MAX_LENGTH} characters.`

test('the default organization name satisfies the same rules as user input', () => {
  assert.equal(validateOrganizationName(DEFAULT_ORGANIZATION_NAME), null)
})

test('organization names accept the API character set', () => {
  for (const name of ['AB', 'Acme Corp', 'My Company 2024', 'Tech_Startup', 'a-b_c d']) {
    assert.equal(validateOrganizationName(name), null, `expected "${name}" to be accepted`)
  }
})

test('organization names are trimmed before validation', () => {
  assert.equal(validateOrganizationName('  Acme Corp  '), null)
  assert.equal(validateOrganizationName(' Acme '), null)
})

test('organization names reject the rules the API enforces', () => {
  assert.equal(validateOrganizationName(''), TOO_SHORT)
  assert.equal(validateOrganizationName('A'), TOO_SHORT)
  assert.equal(validateOrganizationName(undefined), TOO_SHORT)
  assert.equal(validateOrganizationName('A'.repeat(ORGANIZATION_NAME_MAX_LENGTH + 1)), TOO_SHORT)
  assert.notEqual(validateOrganizationName('Acme!'), null)
  assert.notEqual(validateOrganizationName('Acme  Corp'), null)
  assert.notEqual(validateOrganizationName('-Acme'), null)
  assert.notEqual(validateOrganizationName('Acme-'), null)
  assert.notEqual(validateOrganizationName('Acme Corp.'), null)
})

test('organization names accept the exact length boundaries', () => {
  assert.equal(validateOrganizationName('AB'), null)
  assert.equal(validateOrganizationName(`A${'b'.repeat(ORGANIZATION_NAME_MAX_LENGTH - 2)}A`), null)
  assert.equal(
    validateOrganizationName(`A${'b'.repeat(ORGANIZATION_NAME_MAX_LENGTH - 1)}A`),
    TOO_SHORT,
  )
})

test('the organization setup gate applies only to a known org-less account', () => {
  assert.equal(
    needsOrganizationSetup({ isAuthenticated: true, userStatus: { has_organization: false } }),
    true,
  )
  assert.equal(
    needsOrganizationSetup({ isAuthenticated: true, userStatus: { has_organization: true } }),
    false,
  )
  // Unknown or absent status must never withhold the dashboard.
  assert.equal(needsOrganizationSetup({ isAuthenticated: true, userStatus: {} }), false)
  assert.equal(needsOrganizationSetup({ isAuthenticated: true, userStatus: null }), false)
  assert.equal(needsOrganizationSetup({ isAuthenticated: true }), false)
  assert.equal(
    needsOrganizationSetup({ isAuthenticated: false, userStatus: { has_organization: false } }),
    false,
  )
})

test('the account tab stays reachable without an organization', () => {
  const options = { isAuthenticated: true, userStatus: { has_organization: false } }

  assert.equal(needsOrganizationSetup({ ...options, hash: 'account' }), false)
  assert.equal(needsOrganizationSetup({ ...options, hash: '#account' }), false)
  assert.equal(needsOrganizationSetup({ ...options, hash: '#users' }), true)
  assert.equal(needsOrganizationSetup({ ...options, hash: '' }), true)
  assert.equal(needsOrganizationSetup(options), true)
})

test('response bodies are parsed only when they carry JSON', () => {
  assert.deepEqual(parseResponseBody('{"error":"username_required"}'), {
    error: 'username_required',
  })
  assert.equal(parseResponseBody(''), null)
  assert.equal(parseResponseBody('not json'), null)
  assert.equal(parseResponseBody('null'), null)
  assert.equal(parseResponseBody('"a string"'), null)
  assert.equal(parseResponseBody(undefined), null)
})

test('organization creation outcomes follow the API and gateway contract', () => {
  const outcome = organizationCreationOutcome

  assert.equal(outcome(200, { id: 'org' }), ORGANIZATION_CREATION_OUTCOME.created)
  assert.equal(outcome(204), ORGANIZATION_CREATION_OUTCOME.created)
  assert.equal(outcome(401), ORGANIZATION_CREATION_OUTCOME.unauthenticated)
  assert.equal(outcome(409, { error: 'conflict' }), ORGANIZATION_CREATION_OUTCOME.already_member)
  assert.equal(
    outcome(403, { error: 'username_required' }),
    ORGANIZATION_CREATION_OUTCOME.username_required,
  )
  assert.equal(
    outcome(403, { code: 'legal_acceptance_required' }),
    ORGANIZATION_CREATION_OUTCOME.legal_required,
  )
  // A 403 for any other reason is neither recoverable action.
  assert.equal(outcome(403, { message: 'forbidden' }), ORGANIZATION_CREATION_OUTCOME.error)
  assert.equal(outcome(403), ORGANIZATION_CREATION_OUTCOME.error)
  assert.equal(outcome(400, { message: 'bad request' }), ORGANIZATION_CREATION_OUTCOME.error)
  assert.equal(outcome(500), ORGANIZATION_CREATION_OUTCOME.error)
})

test('failed creation messages prefer the API wording', () => {
  assert.equal(
    organizationCreationErrorMessage(
      { message: 'Name already taken' },
      '{"message":"Name already taken"}',
      'fallback',
    ),
    'Name already taken',
  )
  assert.equal(
    organizationCreationErrorMessage({ error: 'conflict' }, '{"error":"conflict"}', 'fallback'),
    'conflict',
  )
  assert.equal(organizationCreationErrorMessage({}, '', 'fallback'), 'fallback')
  assert.equal(organizationCreationErrorMessage(null, ' plain text ', 'fallback'), 'plain text')
  assert.equal(organizationCreationErrorMessage(null, '   ', 'fallback'), 'fallback')
  assert.equal(organizationCreationErrorMessage(null, '', 'fallback'), 'fallback')
})

test('member removal is limited to owners and admins acting on other members', () => {
  const options = { currentUserId: 'me', memberUserId: 'them', memberRole: 'member' }

  assert.equal(canRemoveOrganizationMember({ ...options, role: 'owner' }), true)
  assert.equal(canRemoveOrganizationMember({ ...options, role: 'admin' }), true)
  assert.equal(canRemoveOrganizationMember({ ...options, role: 'Owner' }), true)
  // Roles the API refuses to let manage the organization.
  assert.equal(canRemoveOrganizationMember({ ...options, role: 'member' }), false)
  assert.equal(canRemoveOrganizationMember({ ...options, role: 'viewer' }), false)
  assert.equal(canRemoveOrganizationMember({ ...options, role: null }), false)
  assert.equal(canRemoveOrganizationMember({ ...options, role: '' }), false)
  // A user never removes themselves from this page.
  assert.equal(
    canRemoveOrganizationMember({ role: 'owner', currentUserId: 'me', memberUserId: 'me' }),
    false,
  )
  // Only an owner may remove an owner, so the organization keeps an owner.
  assert.equal(
    canRemoveOrganizationMember({ ...options, role: 'owner', memberRole: 'owner' }),
    true,
  )
  assert.equal(
    canRemoveOrganizationMember({ ...options, role: 'admin', memberRole: 'owner' }),
    false,
  )
  assert.equal(
    canRemoveOrganizationMember({ ...options, role: 'admin', memberRole: 'Owner' }),
    false,
  )
  // Without the caller's identity the action is not offered.
  assert.equal(
    canRemoveOrganizationMember({ role: 'owner', currentUserId: null, memberUserId: 'them' }),
    false,
  )
  assert.equal(
    canRemoveOrganizationMember({ role: 'owner', currentUserId: 'me', memberUserId: null }),
    false,
  )
  assert.equal(canRemoveOrganizationMember(), false)
})
