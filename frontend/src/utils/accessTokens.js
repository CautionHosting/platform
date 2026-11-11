// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

/**
 * Client-side handling for organization access tokens.
 *
 * Mirrors the API's validation so the mint form can flag a bad value before
 * saving, and builds the create payload. The API stays authoritative
 * (docs/access-tokens-spec.md D2/D7).
 */

export const DEFAULT_EXPIRY_DAYS = 90
export const MAX_NAME_LEN = 100
export const MAX_DESCRIPTION_LEN = 500
export const MIN_EXPIRY_DAYS = 1
export const MAX_EXPIRY_DAYS = 3650

/**
 * Validates the mint form. Returns a message, or `null` when acceptable.
 * Expiry is optional but recommended: when enabled, the day count must be an
 * integer in range.
 */
export function validateAccessTokenForm({
  name,
  description,
  expiryEnabled = true,
  expiryDays = DEFAULT_EXPIRY_DAYS,
} = {}) {
  const trimmed = typeof name === 'string' ? name.trim() : ''
  if (trimmed.length === 0) return 'name is required'
  if (trimmed.length > MAX_NAME_LEN) return `name must be at most ${MAX_NAME_LEN} characters`
  if (description != null && String(description).trim().length > MAX_DESCRIPTION_LEN) {
    return `description must be at most ${MAX_DESCRIPTION_LEN} characters`
  }
  if (expiryEnabled) {
    const days = Number(expiryDays)
    if (!Number.isInteger(days) || days < MIN_EXPIRY_DAYS || days > MAX_EXPIRY_DAYS) {
      return `expiry must be a whole number of days between ${MIN_EXPIRY_DAYS} and ${MAX_EXPIRY_DAYS}`
    }
  }
  return null
}

/**
 * Builds the `POST /organizations/{id}/access-tokens` body. Roles are chosen at
 * mint and immutable afterwards. A disabled expiry sends `expires_in_days: null`.
 */
export function buildAccessTokenPayload({
  name,
  description,
  expiryEnabled = true,
  expiryDays = DEFAULT_EXPIRY_DAYS,
  roleIds = [],
} = {}) {
  const trimmedDescription = typeof description === 'string' ? description.trim() : ''
  return {
    name: typeof name === 'string' ? name.trim() : '',
    description: trimmedDescription === '' ? null : trimmedDescription,
    expires_in_days: expiryEnabled ? Number(expiryDays) : null,
    role_ids: Array.from(roleIds),
  }
}

/** Whether a token's `expires_at` (ISO string or null) is in the past. */
export function isAccessTokenExpired(expiresAt, now = Date.now()) {
  if (!expiresAt) return false
  const parsed = Date.parse(expiresAt)
  if (Number.isNaN(parsed)) return false
  return parsed <= now
}

/**
 * A short human description of a token's expiry, for the list. `null`/absent
 * means no expiry.
 */
export function describeAccessTokenExpiry(expiresAt, now = Date.now()) {
  if (!expiresAt) return 'Never expires'
  const parsed = Date.parse(expiresAt)
  if (Number.isNaN(parsed)) return 'Unknown'
  return parsed <= now ? 'Expired' : `Expires ${new Date(parsed).toISOString().slice(0, 10)}`
}
