// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import { getDeploymentLabel } from './appDetails.js'

export const APP_LIST_PREFERENCES_STORAGE_KEY = 'caution-apps-list-preferences'

export const DEFAULT_APP_LIST_PREFERENCES = Object.freeze({
  hideTerminated: false,
  sortColumn: 'status',
  sortDirection: 'asc',
})

const SORT_COLUMNS = new Set(['name', 'status', 'deployment', 'region', 'created'])
const SORT_DIRECTIONS = new Set(['asc', 'desc'])
const STATUS_RANK = new Map([
  ['running', 0],
  ['pending', 1],
  ['initialized', 1],
  ['failed', 2],
  ['stopped', 3],
  ['terminating', 4],
  ['terminated', 6],
])
const UNKNOWN_STATUS_RANK = 5

const normalizeText = (value) =>
  typeof value === 'string' ? value.trim().toLowerCase() : ''

const parseCreatedAt = (value) => {
  if (Array.isArray(value)) {
    const [year, ordinal, hour = 0, minute = 0, second = 0] = value
    const timestamp = Date.UTC(year, 0, ordinal, hour, minute, second)
    return Number.isFinite(timestamp) ? timestamp : null
  }

  if (typeof value !== 'string' && !(value instanceof Date)) return null

  let normalized = typeof value === 'string'
    ? value.replace(
      /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d+)?) ([+-]\d{2}:\d{2}):\d{2}$/,
      '$1T$2$3',
    )
    : value
  if (typeof normalized === 'string' && !/(?:Z|[+-]\d{2}:\d{2})$/i.test(normalized)) {
    normalized += 'Z'
  }
  const timestamp = new Date(normalized).getTime()
  return Number.isFinite(timestamp) ? timestamp : null
}

const compareText = (left, right) => normalizeText(left).localeCompare(normalizeText(right))

const compareCreated = (left, right) => (parseCreatedAt(left) ?? 0) - (parseCreatedAt(right) ?? 0)

const statusRank = (state) => STATUS_RANK.get(normalizeText(state)) ?? UNKNOWN_STATUS_RANK

const compareStatus = (left, right) => {
  const rankDifference = statusRank(left) - statusRank(right)
  return rankDifference || compareText(left, right)
}

const getSortValue = (app, column) => {
  if (column === 'name') return normalizeText(app.resource_name)
  if (column === 'deployment') return normalizeText(getDeploymentLabel(app))
  if (column === 'region') return normalizeText(app.region)
  if (column === 'created') return parseCreatedAt(app.created_at)
  return app.state
}

const getPrimaryComparison = (left, right, column) => {
  if (column === 'status') return compareStatus(left.state, right.state)

  const leftValue = getSortValue(left, column)
  const rightValue = getSortValue(right, column)
  return column === 'created'
    ? leftValue - rightValue
    : leftValue.localeCompare(rightValue)
}

export const resolveAppListPreferences = (value) => {
  if (
    value == null
    || typeof value !== 'object'
    || typeof value.hideTerminated !== 'boolean'
    || !SORT_COLUMNS.has(value.sortColumn)
    || !SORT_DIRECTIONS.has(value.sortDirection)
  ) {
    return { ...DEFAULT_APP_LIST_PREFERENCES }
  }

  return {
    hideTerminated: value.hideTerminated,
    sortColumn: value.sortColumn,
    sortDirection: value.sortDirection,
  }
}

const parseAppListPreferences = (value) => {
  if (typeof value !== 'string') return { ...DEFAULT_APP_LIST_PREFERENCES }

  try {
    return resolveAppListPreferences(JSON.parse(value))
  } catch {
    return { ...DEFAULT_APP_LIST_PREFERENCES }
  }
}

export const readAppListPreferences = (windowRef = window) => {
  try {
    return parseAppListPreferences(
      windowRef.localStorage.getItem(APP_LIST_PREFERENCES_STORAGE_KEY),
    )
  } catch {
    return { ...DEFAULT_APP_LIST_PREFERENCES }
  }
}

export const persistAppListPreferences = (preferences, windowRef = window) => {
  const resolved = resolveAppListPreferences(preferences)

  try {
    windowRef.localStorage.setItem(
      APP_LIST_PREFERENCES_STORAGE_KEY,
      JSON.stringify(resolved),
    )
  } catch {
    // The current tab still uses the selected preferences when storage is unavailable.
  }

  return resolved
}

export const getAppListPreferencesFromStorageEvent = (event, windowRef = window) => {
  if (event.key && event.key !== APP_LIST_PREFERENCES_STORAGE_KEY) return null

  if (event.storageArea) {
    try {
      if (event.storageArea !== windowRef.localStorage) return null
    } catch {
      return null
    }
  }

  return parseAppListPreferences(event.newValue)
}

export const getNextAppListPreferences = (preferences, sortColumn) => {
  const current = resolveAppListPreferences(preferences)
  if (!SORT_COLUMNS.has(sortColumn)) return current

  const sortDirection = current.sortColumn === sortColumn
    ? (current.sortDirection === 'asc' ? 'desc' : 'asc')
    : (sortColumn === 'created' ? 'desc' : 'asc')

  return { ...current, sortColumn, sortDirection }
}

export const countTerminatedApps = (apps) =>
  apps.filter((app) => normalizeText(app?.state) === 'terminated').length

export const sortApps = (apps, preferences) => {
  const resolved = resolveAppListPreferences(preferences)
  const direction = resolved.sortDirection === 'asc' ? 1 : -1

  return apps
    .map((app, index) => ({ app, index }))
    .sort((left, right) => {
      if (resolved.sortColumn !== 'status') {
        const leftValue = getSortValue(left.app, resolved.sortColumn)
        const rightValue = getSortValue(right.app, resolved.sortColumn)
        const leftMissing = leftValue == null || leftValue === ''
        const rightMissing = rightValue == null || rightValue === ''
        if (leftMissing !== rightMissing) return leftMissing ? 1 : -1
      }

      const primary = getPrimaryComparison(left.app, right.app, resolved.sortColumn)
      if (primary) return primary * direction

      if (resolved.sortColumn === 'status') {
        const newestFirst = compareCreated(right.app.created_at, left.app.created_at)
        if (newestFirst) return newestFirst
      }

      return left.index - right.index
    })
    .map(({ app }) => app)
}

export const filterAndSortApps = (apps, query, preferences) => {
  const resolved = resolveAppListPreferences(preferences)
  const normalizedQuery = normalizeText(query)
  const visibleApps = resolved.hideTerminated
    ? apps.filter((app) => normalizeText(app?.state) !== 'terminated')
    : apps

  const matchingApps = normalizedQuery
    ? visibleApps.filter((app) => [
      app?.resource_name,
      app?.id,
      app?.region,
      app?.state,
      app?.public_ip,
      app?.managed_hostname,
      app?.dns_status,
      app?.configuration?.domain,
      app?.configuration?.instance_type,
      getDeploymentLabel(app),
    ].some((value) => normalizeText(value).includes(normalizedQuery)))
    : visibleApps

  return sortApps(matchingApps, resolved)
}
