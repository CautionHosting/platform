// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

const errorTypes = new Set(['Error', 'TypeError', 'RangeError', 'ReferenceError', 'SyntaxError', 'URIError', 'EvalError', 'AggregateError', 'HttpServerError'])

function sanitizeFrame(frame, origin) {
  try {
    const url = new URL(frame.filename)
    if (url.origin !== origin || !/^\/assets\/[\w.-]+\.js$/.test(url.pathname)) return null
    if (!Number.isSafeInteger(frame.lineno) || frame.lineno < 1) return null
    const clean = { filename: `${origin}${url.pathname}`, lineno: frame.lineno, in_app: true }
    if (Number.isSafeInteger(frame.colno) && frame.colno >= 0) clean.colno = frame.colno
    return clean
  } catch {
    return null
  }
}

export function sanitizeEvent(event, location) {
  if (event.exception?.values?.some(({ type }) => type === 'AbortError' || type === 'NotAllowedError')) return null
  const values = (event.exception?.values || []).slice(-5).flatMap((exception) => {
    const frames = (exception.stacktrace?.frames || []).slice(-50)
      .map((frame) => sanitizeFrame(frame, location.origin)).filter(Boolean)
    if (!frames.length) return []
    return [{
      type: errorTypes.has(exception.type) ? exception.type : 'Error',
      value: '[redacted]',
      stacktrace: { frames },
      mechanism: { type: 'generic', handled: exception.mechanism?.handled === true },
    }]
  })
  if (!values.length) return null
  return {
    event_id: /^[a-f0-9]{32}$/.test(event.event_id) ? event.event_id : undefined,
    timestamp: Number.isFinite(event.timestamp) ? event.timestamp : undefined,
    platform: 'javascript',
    level: 'error',
    exception: { values },
    tags: { service: 'frontend', ...(/^5[0-9]{2}$/.test(event.tags?.http_status) ? { http_status: event.tags.http_status } : {}) },
  }
}

export function createDashboardReporter(sdk, app, config, location) {
  let active = false
  let initialized = false
  let generation = 0
  const captured = new WeakMap()
  const approved = new WeakMap()
  const enabled = () => active && isDashboardLocation(location.pathname)

  return {
    reportResponse(status) {
      if (!initialized || !enabled() || !Number.isInteger(status) || status < 500 || status > 599) return
      try {
        const error = new Error('Dashboard request failed')
        error.name = 'HttpServerError'
        sdk.captureException(error, { tags: { http_status: String(status) } })
      } catch {
        active = false
      }
    },
    setActive(value) {
      if (active !== (value === true)) generation++
      active = value === true
      if (!enabled() || initialized || !config.dsn || !config.environment || !config.release) return
      try {
        sdk.init({
          app,
          ...config,
          sendDefaultPii: false,
          dataCollection: { userInfo: false },
          attachProps: false,
          defaultIntegrations: false,
          integrations: [
            { name: 'DashboardCaptureOrigin', preprocessEvent(_event, hint) {
              if (enabled()) captured.set(hint, generation)
            } },
            sdk.vueIntegration({ attachErrorHandler: false }), sdk.globalHandlersIntegration(), sdk.browserApiErrorsIntegration(),
          ],
          maxBreadcrumbs: 0,
          sendClientReports: false,
          tracePropagationTargets: [],
          enableLogs: false,
          enableMetrics: false,
          beforeSend(event, hint) {
            if (!enabled() || captured.get(hint) !== generation) return null
            captured.delete(hint)
            const clean = sanitizeEvent(event, location)
            if (clean) approved.set(clean, generation)
            return clean
          },
          transport(options) {
            const transport = sdk.makeFetchTransport({ ...options, fetchOptions: { credentials: 'omit', referrerPolicy: 'no-referrer' } })
            return {
              send(envelope) {
                if (!enabled()) return Promise.resolve({})
                // Internal SDK diagnostics bypass beforeSend; only forward approved errors.
                // Rebuild at the wire boundary because the SDK adds metadata afterward.
                const items = envelope[1].flatMap(([header, event]) => {
                  if (header.type !== 'event' || approved.get(event) !== generation) return []
                  approved.delete(event)
                  const clean = sanitizeEvent(event, location)
                  return clean ? [[{ type: 'event' }, {
                    ...clean, release: config.release, environment: config.environment,
                    sdk: { name: 'sentry.javascript.vue', version: sdk.SDK_VERSION, settings: { infer_ip: 'never' } },
                  }]] : []
                })
                if (!items.length) return Promise.resolve({})
                return transport.send([{ event_id: items[0][1].event_id }, items])
              },
              flush: (timeout) => transport.flush(timeout),
            }
          },
        })
        const originalHandler = app.config.errorHandler
        app.config.errorHandler = function (error, vm, info) {
          // Record eligibility before deferred work; leaving the dashboard cancels it.
          if (enabled()) {
            const originGeneration = generation
            queueMicrotask(() => {
              if (!enabled() || generation !== originGeneration) return
              try { sdk.captureException(error, { mechanism: { type: 'vue', handled: typeof originalHandler === 'function' } }) } catch {}
            })
          }
          if (typeof originalHandler === 'function') return originalHandler.call(this, error, vm, info)
          throw error
        }
        initialized = true
      } catch {
        active = false
      }
    },
  }
}

export function isDashboardLocation(pathname) {
  return pathname === '/' || pathname === '/dashboard'
}
