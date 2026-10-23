// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

/**
 * Application naming rules.
 *
 * Mirrors the shared Rust rules in `caution-config::app_name` so the rename
 * form can reject a bad name before a round trip. The Platform API stays
 * authoritative; the messages here describe the same rules.
 */

export const APP_NAME_MIN_LENGTH = 3
export const APP_NAME_MAX_LENGTH = 63

const APP_NAME_BODY_PATTERN = /^[a-zA-Z0-9_-]*$/
const ALPHANUMERIC_PATTERN = /[a-zA-Z0-9]/

const normalize = (value) => (typeof value === 'string' ? value.trim() : '')

/**
 * Whether a name satisfies the API's app-name rules.
 *
 * @returns {string|null} A user-facing message, or `null` when acceptable.
 */
export function validateAppName(value) {
  const name = normalize(value)

  if (name.length < APP_NAME_MIN_LENGTH || name.length > APP_NAME_MAX_LENGTH) {
    return `App names must be between ${APP_NAME_MIN_LENGTH} and ${APP_NAME_MAX_LENGTH} characters.`
  }

  // Report an illegal character before a boundary violation: it is the more
  // specific complaint and matches the server's ordering.
  const invalid = [...name].find((character) => !APP_NAME_BODY_PATTERN.test(character))
  if (invalid) {
    return `App names cannot contain "${invalid}". Use letters, numbers, hyphens and underscores.`
  }

  if (!ALPHANUMERIC_PATTERN.test(name[0]) || !ALPHANUMERIC_PATTERN.test(name[name.length - 1])) {
    return 'App names must start and end with a letter or number.'
  }

  return null
}

/** Trim surrounding whitespace, matching how the API treats the submitted name. */
export function normalizeAppName(value) {
  return normalize(value)
}
