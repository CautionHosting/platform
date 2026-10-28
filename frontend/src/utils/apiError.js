// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// Rendering for API error bodies.
//
// Some endpoints answer with a structured report:
// `{"error": "…", "errors": [{"error": "…", "notes": ["…"], "warnings": ["…"]}]}`.
// The message says what failed; the notes and warnings say what to do about it.
// Everything else (a plain string, a body with only `error` or `message`) renders
// as it did before, so `apiError` replaces `data.error || fallback` in place.

// Unique guidance lines from every link of a report, in chain order.
const guidanceLines = (body) => {
  const links = Array.isArray(body?.errors) ? body.errors : []
  const lines = []
  for (const link of links) {
    for (const item of [...(link?.notes ?? []), ...(link?.warnings ?? [])]) {
      const line = typeof item === 'string' ? item.trim() : ''
      if (line && !lines.includes(line)) lines.push(line)
    }
  }
  return lines
}

/**
 * Appends the guidance a report carries to a message, one line each.
 *
 * Callers that prefer `message` over `error` (the order some bodies use) keep
 * that choice and still get the guidance.
 */
export const withGuidance = (message, body) => {
  const lines = guidanceLines(body)
  if (!lines.length) return message
  return [message, ...lines].join('\n')
}

/** The body's own message, or the fallback, plus any guidance it carries. */
export const apiError = (body, fallback) => {
  const parsed = body && typeof body === 'object' ? body : null
  const message = parsed ? parsed.error || parsed.message || fallback : fallback
  return withGuidance(message, parsed)
}

/**
 * Parses a response body that may be JSON, then renders it.
 *
 * A body that is not JSON is shown as it arrived, so nothing is lost.
 */
export const apiErrorFromText = (text, fallback) => {
  const raw = typeof text === 'string' ? text.trim() : ''
  if (!raw) return fallback
  try {
    const parsed = JSON.parse(raw)
    const message = parsed?.error || parsed?.message
    return withGuidance(message || fallback, parsed)
  } catch {
    return raw
  }
}
