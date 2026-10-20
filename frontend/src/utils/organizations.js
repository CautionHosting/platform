// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

/**
 * Organization naming and setup-gate helpers.
 *
 * A user can end up belonging to no organization at all: `remove_member`
 * deletes their last membership, and every organization-scoped API route
 * answers 500 for a user without one. The dashboard is therefore not usable
 * for such a user, and the frontend must send them to the organization
 * creation page instead.
 */

export const DEFAULT_ORGANIZATION_NAME = 'My organization'
export const ORGANIZATION_NAME_MIN_LENGTH = 2
export const ORGANIZATION_NAME_MAX_LENGTH = 100

/**
 * The account tab stays reachable without an organization because it is where
 * a user claims a username, and the platform refuses organization creation
 * until a username is claimed.
 */
export const ORGANIZATION_SETUP_EXEMPT_DASHBOARD_HASHES = ['account']

const ORGANIZATION_NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9 _-]*[a-zA-Z0-9]$/

const normalize = (value) => (typeof value === 'string' ? value.trim() : '')

/**
 * Outcomes of a request to create an organization, as the organization creation
 * page must act on them.
 *
 * @readonly
 * @enum {string}
 */
export const ORGANIZATION_CREATION_OUTCOME = Object.freeze({
  /** The organization exists and the caller owns it. */
  created: 'created',
  /** The caller already belongs to an organization, so nothing was created. */
  already_member: 'already_member',
  /** The gateway refuses organization creation until a username is claimed. */
  username_required: 'username_required',
  /** The API requires acceptance of a current legal document first. */
  legal_required: 'legal_required',
  /** The session is missing or expired. */
  unauthenticated: 'unauthenticated',
  /** Any other refusal or server failure. */
  error: 'error',
})

/** Parses a response body, returning `null` when it is absent or not JSON. */
export function parseResponseBody(text) {
  if (typeof text !== 'string' || text.length === 0) return null
  try {
    const parsed = JSON.parse(text)
    return parsed !== null && typeof parsed === 'object' ? parsed : null
  } catch {
    return null
  }
}

/**
 * Classifies the API's answer to an organization creation request. The page
 * acts on the outcome, so the status contract lives here where it is tested
 * rather than inline in the component.
 */
export function organizationCreationOutcome(status, body = null) {
  if (status >= 200 && status < 300) return ORGANIZATION_CREATION_OUTCOME.created
  if (status === 401) return ORGANIZATION_CREATION_OUTCOME.unauthenticated
  if (status === 409) return ORGANIZATION_CREATION_OUTCOME.already_member
  if (status === 403) {
    if (body?.error === 'username_required') return ORGANIZATION_CREATION_OUTCOME.username_required
    if (body?.code === 'legal_acceptance_required') return ORGANIZATION_CREATION_OUTCOME.legal_required
  }
  return ORGANIZATION_CREATION_OUTCOME.error
}

/**
 * A message to show for a failed creation attempt. Prefers the API's own
 * wording and falls back to the raw body for non-JSON failures.
 */
export function organizationCreationErrorMessage(body, text, fallback) {
  if (body) {
    return body.message || body.error || fallback
  }
  const raw = normalize(text)
  return raw || fallback
}

/**
 * Mirrors the Platform API's organization-name validation so the form can
 * reject a bad name before a round trip. The API stays authoritative; the
 * messages here describe the same rules.
 *
 * @returns {string|null} A user-facing message, or `null` when acceptable.
 */
export function validateOrganizationName(value) {
  const name = normalize(value)

  if (
    name.length < ORGANIZATION_NAME_MIN_LENGTH ||
    name.length > ORGANIZATION_NAME_MAX_LENGTH
  ) {
    return `Organization names must be between ${ORGANIZATION_NAME_MIN_LENGTH} and ${ORGANIZATION_NAME_MAX_LENGTH} characters.`
  }

  if (!ORGANIZATION_NAME_PATTERN.test(name)) {
    return 'Use letters, numbers, spaces, hyphens and underscores, starting and ending with a letter or number.'
  }

  if (name.includes('  ')) {
    return 'Organization names cannot contain consecutive spaces.'
  }

  return null
}

/**
 * Whether the authenticated user must create an organization before the
 * dashboard can do anything. An unknown status (older API, request still in
 * flight) or an unknown `has_organization` value is treated as "no gate", so
 * the dashboard is never withheld on a guess.
 *
 * @param {object} options
 * @param {boolean} options.isAuthenticated
 * @param {object|null} options.userStatus Response body of `/api/user/status`.
 * @param {string} [options.hash] Current location hash, with or without `#`.
 */
export function needsOrganizationSetup({ isAuthenticated, userStatus, hash = '' } = {}) {
  if (!isAuthenticated) return false
  if (userStatus?.has_organization !== false) return false

  const normalizedHash = hash.replace(/^#/, '')
  return !ORGANIZATION_SETUP_EXEMPT_DASHBOARD_HASHES.includes(normalizedHash)
}
