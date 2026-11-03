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
 * Whether an `objects` map constrains nothing: present, non-empty, and every
 * parameter's list is only wildcards (`["*"]`). Such a rule needs no detail
 * expansion.
 */
export function objectsAreWildcard(objects) {
  if (objects == null || typeof objects !== 'object' || Array.isArray(objects)) return false
  const values = Object.values(objects)
  if (values.length === 0) return false
  return values.every(
    (allowed) => Array.isArray(allowed) && allowed.length > 0 && allowed.every((v) => v === '*'),
  )
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
