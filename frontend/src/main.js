// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import * as Sentry from '@sentry/vue'
import { createApp } from 'vue'
import App from './App.vue'

const FILTERED = '[Filtered]'
const SENSITIVE_KEY_PATTERN = /authorization|cookie|token|secret|password|private[_-]?key|api[_-]?key|database[_-]?url|dsn|smtp|paddle|webhook|attestation|nonce|certificate|pcr|locksmith|shard|credential|webauthn/i

function scrubValue(value) {
  if (Array.isArray(value)) {
    return value.map(scrubValue)
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, nestedValue]) => [
        key,
        SENSITIVE_KEY_PATTERN.test(key) ? FILTERED : scrubValue(nestedValue),
      ]),
    )
  }

  return typeof value === 'string' && SENSITIVE_KEY_PATTERN.test(value) ? FILTERED : value
}

function scrubEvent(event) {
  delete event.request
  delete event.user

  if (event.contexts) {
    event.contexts = scrubValue(event.contexts)
  }
  if (event.extra) {
    event.extra = scrubValue(event.extra)
  }

  return event
}

const app = createApp(App)

if (import.meta.env.VITE_SENTRY_DSN) {
  Sentry.init({
    app,
    dsn: import.meta.env.VITE_SENTRY_DSN,
    environment: import.meta.env.VITE_SENTRY_ENVIRONMENT,
    release: import.meta.env.VITE_SENTRY_RELEASE,
    sendDefaultPii: false,
    tracesSampleRate: 0,
    beforeSend: scrubEvent,
  })
}

app.mount('#app')
