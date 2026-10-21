// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import { init, vueIntegration, globalHandlersIntegration, browserApiErrorsIntegration, captureException, makeFetchTransport, SDK_VERSION } from '@sentry/vue'
import { createDashboardReporter } from './sentryPolicy.js'

let reporter

export function configureSentry(app) {
  reporter = createDashboardReporter({ init, vueIntegration, globalHandlersIntegration, browserApiErrorsIntegration, captureException, makeFetchTransport, SDK_VERSION }, app, {
    dsn: import.meta.env.VITE_SENTRY_DSN,
    environment: import.meta.env.VITE_SENTRY_ENVIRONMENT,
    release: import.meta.env.VITE_SENTRY_RELEASE,
  }, window.location)
}

export function setDashboardReportingActive(active) {
  reporter?.setActive(active)
}

export function reportServerResponse(status) {
  reporter?.reportResponse(status)
}
