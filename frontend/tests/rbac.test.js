// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import test from 'node:test'
import {
  draftFromRule,
  groupRoutes,
  methodTone,
  objectsFromParamInputs,
  paramInputsFromObjects,
  pathParameterNames,
  ruleFromDraft,
  syncDraftParams,
  validateRule,
} from '../src/utils/rbac.js'

test('path parameters are extracted from a route template', () => {
  assert.deepEqual(pathParameterNames('/users/me'), [])
  assert.deepEqual(pathParameterNames('/resources/{id}'), ['id'])
  assert.deepEqual(pathParameterNames('/organizations/{id}/members/{user_id}'), [
    'id',
    'user_id',
  ])
  assert.deepEqual(pathParameterNames(null), [])
})

test('a valid parameterless rule is accepted', () => {
  assert.equal(
    validateRule({ effect: 'allow', method: 'GET', path: '/users/me', objects: null, priority: 0 }),
    null,
  )
})

test('path matching accepts wildcards and root', () => {
  assert.equal(validateRule({ effect: 'allow', method: '*', path: '*', priority: 0 }), null)
  assert.equal(validateRule({ effect: 'allow', method: 'GET', path: '/resources/*', priority: 0 }), null)
  assert.equal(validateRule({ effect: 'allow', method: 'GET', path: '/', priority: 0 }), null)
  assert.match(validateRule({ effect: 'allow', method: 'GET', path: '', priority: 0 }), /path/)
  assert.match(validateRule({ effect: 'allow', method: 'GET', path: 'resources', priority: 0 }), /path/)
})

test('rule validation mirrors the API', () => {
  assert.match(validateRule({ effect: 'maybe', method: 'GET', path: '/x', priority: 0 }), /effect/)
  assert.match(validateRule({ effect: 'allow', method: 'FETCH', path: '/x', priority: 0 }), /method/)
  assert.match(validateRule({ effect: 'allow', method: 'GET', path: 'x', priority: 0 }), /path/)
  assert.match(validateRule({ effect: 'allow', method: 'GET', path: '/x', priority: -1 }), /priority/)
  // objects must not be present on a parameterless path
  assert.match(
    validateRule({ effect: 'allow', method: 'GET', path: '/x', objects: {}, priority: 0 }),
    /omitted/,
  )
  // a parameterized path requires covering objects
  assert.match(
    validateRule({ effect: 'allow', method: 'GET', path: '/resources/{id}', priority: 0 }),
    /required/,
  )
  assert.equal(
    validateRule({
      effect: 'allow',
      method: 'GET',
      path: '/resources/{id}',
      objects: { id: ['*'] },
      priority: 0,
    }),
    null,
  )
  assert.match(
    validateRule({
      effect: 'allow',
      method: 'GET',
      path: '/resources/{id}',
      objects: { other: ['*'] },
      priority: 0,
    }),
    /missing/,
  )
  assert.match(
    validateRule({
      effect: 'allow',
      method: 'GET',
      path: '/resources/{id}',
      objects: { id: '*' },
      priority: 0,
    }),
    /array/,
  )
})

test('objects are built from parameter inputs', () => {
  assert.equal(objectsFromParamInputs('/users/me', {}), null)
  assert.deepEqual(objectsFromParamInputs('/resources/{id}', {}), { id: ['*'] })
  assert.deepEqual(objectsFromParamInputs('/resources/{id}', { id: 'a, b' }), {
    id: ['a', 'b'],
  })
  assert.deepEqual(
    objectsFromParamInputs('/organizations/{id}/members/{user_id}', { id: '*', user_id: 'u1' }),
    { id: ['*'], user_id: ['u1'] },
  )
})

test('parameter inputs round-trip through objects', () => {
  const objects = { id: ['*'], user_id: ['u1', 'u2'] }
  assert.deepEqual(paramInputsFromObjects('/organizations/{id}/members/{user_id}', objects), {
    id: '*',
    user_id: 'u1, u2',
  })
})

test('drafts round-trip rules, with blank inputs meaning any', () => {
  const rule = {
    effect: 'allow',
    method: 'GET',
    path: '/organizations/{id}/members/{user_id}',
    objects: { id: ['*'], user_id: ['a', 'b'] },
    priority: 2,
  }
  const draft = draftFromRule(rule)
  assert.deepEqual(draft.params, { id: '', user_id: 'a, b' })
  assert.equal(draft.error, null)
  assert.deepEqual(ruleFromDraft(draft), rule)

  const plain = draftFromRule({ effect: 'deny', method: '*', path: '/users/me', objects: null, priority: 0 })
  assert.deepEqual(plain.params, {})
  assert.equal(ruleFromDraft(plain).objects, null)
  assert.notEqual(draftFromRule().key, draftFromRule().key)
})

test('draft parameters follow the path and keep typed values', () => {
  assert.deepEqual(syncDraftParams('/resources/{id}/deployments/{deployment_id}', { id: 'app_1', stale: 'x' }), {
    id: 'app_1',
    deployment_id: '',
  })
  assert.deepEqual(syncDraftParams('/resources', { id: 'app_1' }), {})
})

test('routes are grouped by their first segment in order', () => {
  const groups = groupRoutes([
    { method: 'GET', path: '/users/me' },
    { method: 'GET', path: '/quorum-bundles' },
    { method: 'PATCH', path: '/users/me' },
  ])
  assert.deepEqual(
    groups.map((group) => [group.name, group.routes.length]),
    [
      ['Users', 2],
      ['Quorum bundles', 1],
    ],
  )
})

test('methods map to a tone', () => {
  assert.equal(methodTone('GET'), 'read')
  assert.equal(methodTone('POST'), 'write')
  assert.equal(methodTone('PATCH'), 'write')
  assert.equal(methodTone('DELETE'), 'delete')
  assert.equal(methodTone('*'), 'any')
})
