// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import test from 'node:test'
import {
  APP_LIST_PREFERENCES_STORAGE_KEY,
  DEFAULT_APP_LIST_PREFERENCES,
  countTerminatedApps,
  filterAndSortApps,
  getAppListPreferencesFromStorageEvent,
  getNextAppListPreferences,
  persistAppListPreferences,
  readAppListPreferences,
  resolveAppListPreferences,
  sortApps,
} from '../src/utils/appList.js'

const preferences = (overrides = {}) => ({
  ...DEFAULT_APP_LIST_PREFERENCES,
  ...overrides,
})

const ids = (apps) => apps.map((app) => app.id)

const createStorage = ({ stored = null, throws = false } = {}) => {
  const values = new Map(stored == null ? [] : [[APP_LIST_PREFERENCES_STORAGE_KEY, stored]])
  const localStorage = {
    getItem(key) {
      if (throws) throw new Error('storage unavailable')
      return values.get(key) ?? null
    },
    setItem(key, value) {
      if (throws) throw new Error('storage unavailable')
      values.set(key, value)
    },
  }

  return { localStorage, values, windowRef: { localStorage } }
}

test('preferences validate known columns and directions', () => {
  assert.deepEqual(resolveAppListPreferences(null), DEFAULT_APP_LIST_PREFERENCES)
  assert.deepEqual(
    resolveAppListPreferences({ hideTerminated: true, sortColumn: 'bogus', sortDirection: 'asc' }),
    DEFAULT_APP_LIST_PREFERENCES,
  )
  assert.deepEqual(
    resolveAppListPreferences({ hideTerminated: true, sortColumn: 'created', sortDirection: 'desc' }),
    { hideTerminated: true, sortColumn: 'created', sortDirection: 'desc' },
  )
})

test('preferences persist, restore, and fall back when storage is unavailable', () => {
  const { values, windowRef } = createStorage()
  const selected = { hideTerminated: true, sortColumn: 'created', sortDirection: 'desc' }

  persistAppListPreferences(selected, windowRef)
  assert.deepEqual(readAppListPreferences(windowRef), selected)
  assert.deepEqual(JSON.parse(values.get(APP_LIST_PREFERENCES_STORAGE_KEY)), selected)

  const unavailable = createStorage({ throws: true }).windowRef
  assert.deepEqual(readAppListPreferences(unavailable), DEFAULT_APP_LIST_PREFERENCES)
  assert.deepEqual(persistAppListPreferences(selected, unavailable), selected)

  const invalidJson = createStorage({ stored: '{invalid' }).windowRef
  assert.deepEqual(readAppListPreferences(invalidJson), DEFAULT_APP_LIST_PREFERENCES)
})

test('storage events synchronize valid preferences and ignore unrelated storage', () => {
  const { localStorage, windowRef } = createStorage()
  const selected = { hideTerminated: true, sortColumn: 'name', sortDirection: 'desc' }

  assert.deepEqual(
    getAppListPreferencesFromStorageEvent({
      key: APP_LIST_PREFERENCES_STORAGE_KEY,
      newValue: JSON.stringify(selected),
      storageArea: localStorage,
    }, windowRef),
    selected,
  )
  assert.equal(
    getAppListPreferencesFromStorageEvent({ key: 'unrelated', newValue: '{}' }, windowRef),
    null,
  )
  assert.equal(
    getAppListPreferencesFromStorageEvent({
      key: APP_LIST_PREFERENCES_STORAGE_KEY,
      newValue: JSON.stringify(selected),
      storageArea: {},
    }, windowRef),
    null,
  )
  assert.deepEqual(
    getAppListPreferencesFromStorageEvent({ key: null, newValue: null }, windowRef),
    DEFAULT_APP_LIST_PREFERENCES,
  )
})

test('new sort columns choose useful directions and repeated selections toggle', () => {
  const created = getNextAppListPreferences(DEFAULT_APP_LIST_PREFERENCES, 'created')
  assert.equal(created.sortDirection, 'desc')
  assert.equal(getNextAppListPreferences(created, 'created').sortDirection, 'asc')

  const name = getNextAppListPreferences(created, 'name')
  assert.equal(name.sortDirection, 'asc')
  assert.equal(getNextAppListPreferences(name, 'name').sortDirection, 'desc')
})

test('default status order keeps active and actionable apps above terminated history', () => {
  const apps = [
    { id: 'terminated', state: 'terminated', created_at: '2026-08-13T12:00:00Z' },
    { id: 'unknown', state: 'reconciling', created_at: '2026-08-13T11:00:00Z' },
    { id: 'stopped', state: 'stopped', created_at: '2026-08-13T10:00:00Z' },
    { id: 'running-old', state: 'running', created_at: '2026-08-12T10:00:00Z' },
    { id: 'failed', state: 'failed', created_at: '2026-08-13T09:00:00Z' },
    { id: 'pending', state: 'pending', created_at: '2026-08-13T08:00:00Z' },
    { id: 'initialized', state: 'initialized', created_at: '2026-08-13T07:00:00Z' },
    { id: 'terminating', state: 'terminating', created_at: '2026-08-13T06:00:00Z' },
    { id: 'running-new', state: 'running', created_at: '2026-08-13T13:00:00Z' },
  ]

  assert.deepEqual(ids(sortApps(apps, DEFAULT_APP_LIST_PREFERENCES)), [
    'running-new',
    'running-old',
    'initialized',
    'pending',
    'failed',
    'stopped',
    'terminating',
    'unknown',
    'terminated',
  ])
  assert.deepEqual(
    ids(sortApps(apps, preferences({ sortColumn: 'status', sortDirection: 'desc' }))),
    [
      'terminated',
      'unknown',
      'terminating',
      'stopped',
      'failed',
      'pending',
      'initialized',
      'running-new',
      'running-old',
    ],
  )
})

test('name, deployment, region, and created columns sort in both directions', () => {
  const apps = [
    {
      id: 'bravo',
      resource_name: 'Bravo',
      region: 'eu-west-1',
      created_at: '2026-08-11T10:00:00Z',
      configuration: {},
    },
    {
      id: 'alpha',
      resource_name: 'alpha',
      region: 'ap-southeast-2',
      created_at: '2026-08-13T10:00:00Z',
      configuration: { managed_onprem: {} },
    },
  ]

  for (const [sortColumn, ascending, descending] of [
    ['name', ['alpha', 'bravo'], ['bravo', 'alpha']],
    ['deployment', ['alpha', 'bravo'], ['bravo', 'alpha']],
    ['region', ['alpha', 'bravo'], ['bravo', 'alpha']],
    ['created', ['bravo', 'alpha'], ['alpha', 'bravo']],
  ]) {
    assert.deepEqual(ids(sortApps(apps, preferences({ sortColumn, sortDirection: 'asc' }))), ascending)
    assert.deepEqual(ids(sortApps(apps, preferences({ sortColumn, sortDirection: 'desc' }))), descending)
  }
})

test('missing values remain last and equal values retain source order', () => {
  const apps = [
    { id: 'first', resource_name: 'same', region: 'eu-west-1' },
    { id: 'missing', resource_name: '', region: null },
    { id: 'second', resource_name: 'same', region: 'eu-west-1' },
  ]

  assert.deepEqual(
    ids(sortApps(apps, preferences({ sortColumn: 'name', sortDirection: 'asc' }))),
    ['first', 'second', 'missing'],
  )
  assert.deepEqual(
    ids(sortApps(apps, preferences({ sortColumn: 'region', sortDirection: 'desc' }))),
    ['first', 'second', 'missing'],
  )
})

test('created sorting accepts API timestamp strings and ordinal date arrays', () => {
  const apps = [
    { id: 'rust', created_at: '2026-08-12 10:00:00.000000000 +00:00:00' },
    { id: 'missing', created_at: null },
    { id: 'array', created_at: [2026, 225, 10, 0, 0, 0] },
  ]

  assert.deepEqual(
    ids(sortApps(apps, preferences({ sortColumn: 'created', sortDirection: 'desc' }))),
    ['array', 'rust', 'missing'],
  )
})

test('terminated filtering happens before search and does not hide failed apps', () => {
  const apps = [
    { id: 'running', resource_name: 'payments', state: 'running', configuration: {} },
    { id: 'failed', resource_name: 'payments-failed', state: 'failed', configuration: {} },
    { id: 'terminated', resource_name: 'payments-old', state: 'terminated', configuration: {} },
  ]

  assert.equal(countTerminatedApps(apps), 1)
  assert.deepEqual(
    ids(filterAndSortApps(apps, 'payments', preferences({ hideTerminated: true }))),
    ['running', 'failed'],
  )
  assert.deepEqual(
    ids(filterAndSortApps(apps, 'terminated', preferences({ hideTerminated: true }))),
    [],
  )
})
