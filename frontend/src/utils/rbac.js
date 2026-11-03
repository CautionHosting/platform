// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

/**
 * Client-side handling for RBAC roles and route rules.
 *
 * Mirrors the API's rule validation so the editor can flag a bad row before
 * saving. The API stays authoritative; these messages describe the same rules.
 */

export const RBAC_METHODS = [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
  '*',
]

/** Names of the `{param}` placeholders in an axum route template. */
export function pathParameterNames(path) {
  if (typeof path !== 'string') return []
  const names = []
  let rest = path
  for (;;) {
    const start = rest.indexOf('{')
    if (start === -1) break
    const end = rest.indexOf('}', start + 1)
    if (end === -1) break
    names.push(rest.slice(start + 1, end))
    rest = rest.slice(end + 1)
  }
  return names
}

/**
 * Validates one rule. Returns a message, or `null` when acceptable. `objects`
 * must cover exactly the path's parameters with arrays of strings.
 */
export function validateRule({ effect, method, path, objects, priority } = {}) {
  if (effect !== 'allow' && effect !== 'deny') return "effect must be 'allow' or 'deny'"
  if (!RBAC_METHODS.includes(method)) return 'invalid method'
  if (typeof path !== 'string' || path.length === 0 || (path !== '*' && !path.startsWith('/'))) {
    return 'path must be an absolute route template or *'
  }
  const numericPriority = Number(priority)
  if (!Number.isInteger(numericPriority) || numericPriority < 0) {
    return 'priority must be a non-negative integer'
  }

  const params = pathParameterNames(path)
  if (params.length === 0) {
    if (objects != null) return 'objects must be omitted for a path without parameters'
    return null
  }

  if (objects == null || typeof objects !== 'object' || Array.isArray(objects)) {
    return 'objects is required for a path with parameters'
  }
  if (Object.keys(objects).length !== params.length) {
    return "objects must cover exactly the path's parameters"
  }
  for (const name of params) {
    if (!Object.prototype.hasOwnProperty.call(objects, name)) {
      return `objects is missing parameter '${name}'`
    }
    const allowed = objects[name]
    if (!Array.isArray(allowed)) return `objects['${name}'] must be an array`
    if (allowed.some((entry) => typeof entry !== 'string')) {
      return `objects['${name}'] must contain only strings`
    }
  }
  return null
}

/**
 * Builds a rule's `objects` from per-parameter inputs. A blank input means
 * "any" (`["*"]`); otherwise the value is a comma-separated list.
 */
export function objectsFromParamInputs(path, values = {}) {
  const params = pathParameterNames(path)
  if (params.length === 0) return null
  const objects = {}
  for (const name of params) {
    const raw = String(values[name] ?? '').trim()
    objects[name] =
      raw === ''
        ? ['*']
        : raw
            .split(',')
            .map((entry) => entry.trim())
            .filter(Boolean)
  }
  return objects
}

/** Renders a rule's `objects` back into per-parameter input strings. */
export function paramInputsFromObjects(path, objects = {}) {
  const params = pathParameterNames(path)
  const values = {}
  for (const name of params) {
    const allowed = objects?.[name]
    values[name] = Array.isArray(allowed) ? allowed.join(', ') : ''
  }
  return values
}

let draftKeySeq = 0

/**
 * Turns a rule into the editor's draft shape: one text input per path
 * parameter, where blank means "any" (`["*"]`). `key` keeps list rendering
 * stable while rows are added and removed.
 */
export function draftFromRule({
  effect = 'allow',
  method = 'GET',
  path = '',
  objects = null,
  priority = 0,
} = {}) {
  const params = {}
  for (const name of pathParameterNames(path)) {
    const allowed = objects?.[name]
    const isAny = !Array.isArray(allowed) || (allowed.length === 1 && allowed[0] === '*')
    params[name] = isAny ? '' : allowed.join(', ')
  }
  draftKeySeq += 1
  return { key: draftKeySeq, effect, method, path, params, priority, error: null }
}

/** Turns an editor draft back into the API's rule shape. */
export function ruleFromDraft({ effect, method, path, params, priority }) {
  return {
    effect,
    method,
    path,
    objects: objectsFromParamInputs(path, params),
    priority: Number(priority),
  }
}

/** Keeps a draft's parameter inputs in step with its path, keeping typed values. */
export function syncDraftParams(path, params = {}) {
  const next = {}
  for (const name of pathParameterNames(path)) {
    next[name] = params[name] ?? ''
  }
  return next
}

/** Groups route inventory entries by their first path segment, in order. */
export function groupRoutes(routes = []) {
  const groups = []
  const byName = new Map()
  for (const route of routes) {
    const segment = String(route.path || '').split('/')[1] || ''
    const words = segment.replace(/-/g, ' ')
    const name = words ? words.charAt(0).toUpperCase() + words.slice(1) : 'Other'
    if (!byName.has(name)) {
      const group = { name, routes: [] }
      byName.set(name, group)
      groups.push(group)
    }
    byName.get(name).routes.push(route)
  }
  return groups
}

/** A colour family for a method tag: reads, writes, deletes, or any. */
export function methodTone(method) {
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return 'read'
  if (method === 'DELETE') return 'delete'
  if (method === '*') return 'any'
  return 'write'
}
