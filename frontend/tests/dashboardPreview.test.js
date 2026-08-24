// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import test from 'node:test'
import {
  DASHBOARD_PREVIEW_ENV,
  isDashboardPreviewEnabled,
  resolveDashboardPreviewRequest,
} from '../dev/dashboardPreview.js'

const parse = (response) => JSON.parse(response.body)

test('preview mode is enabled only for vite serve with the explicit env flag', () => {
  assert.equal(isDashboardPreviewEnabled({ command: 'serve', env: { [DASHBOARD_PREVIEW_ENV]: '1' } }), true)
  assert.equal(isDashboardPreviewEnabled({ command: 'serve', env: { [DASHBOARD_PREVIEW_ENV]: '0' } }), false)
  assert.equal(isDashboardPreviewEnabled({ command: 'build', env: { [DASHBOARD_PREVIEW_ENV]: '1' } }), false)
})

test('dashboard preview serves representative app and builder fixtures', () => {
  const apps = parse(resolveDashboardPreviewRequest('GET', '/api/resources'))
  assert.equal(apps.length >= 2, true)
  assert.equal(apps[0].resource_name, 'payments-enclave')
  assert.equal(apps[0].state, 'running')
  assert.equal(apps[0].dns_status, 'ready')
  assert.equal(apps[0].git_url.includes('preview-payments-enclave'), true)
  assert.equal(apps[0].configuration.cpus, 4)
  assert.equal(apps[0].configuration.memory_mb, 2048)
  assert.equal(Boolean(apps[0].configuration.managed_onprem), true)
  assert.equal(apps[0].estimated_monthly_cost > 0, true)
  assert.equal(apps[0].enclave_id.startsWith('i-0preview'), true)

  assert.equal(apps[1].state, 'stopped')
  assert.equal(apps[1].configuration.cpus, undefined)
  assert.equal(apps[1].configuration.memory_mb, undefined)
  assert.equal(apps[1].dns_status, 'publishing')
  assert.equal(Boolean(apps[1].dns_error), true)
  assert.deepEqual(
    [...new Set(apps.map((app) => app.state))].sort(),
    ['failed', 'pending', 'running', 'stopped', 'terminated', 'terminating'],
  )

  const builder = parse(resolveDashboardPreviewRequest('GET', `/api/resources/${apps[0].id}/builder-config`))
  assert.equal(builder.builder_size, 'medium')
  assert.equal(builder.options.length, 3)
  assert.equal(
    resolveDashboardPreviewRequest('GET', `/api/resources/${apps.at(-1).id}/builder-config`).status,
    200,
  )
})

test('dashboard preview serves the authenticated account fixture shape', () => {
  const status = parse(resolveDashboardPreviewRequest('GET', '/api/user/status'))
  assert.equal(status.username, 'preview-operator')
  assert.equal(status.email_verified, true)
  assert.equal(status.legal.terms_of_service.requires_action, false)

  const me = parse(resolveDashboardPreviewRequest('GET', '/api/users/me'))
  assert.equal(me.email, 'operator@example.com')

  const username = parse(resolveDashboardPreviewRequest('GET', '/user/username'))
  assert.equal(username.username, 'preview-operator')
  assert.equal(username.username_is_placeholder, false)
})

test('dashboard preview serves the ssh, pgp, passkey, credential, and bundle fixtures expected by the dashboard', () => {
  const ssh = parse(resolveDashboardPreviewRequest('GET', '/ssh-keys'))
  assert.equal(ssh.keys[0].fingerprint.startsWith('SHA256:'), true)
  assert.equal(Boolean(ssh.keys[0].last_used_at), true)
  assert.equal(ssh.keys[0].key_type, 'ssh-ed25519')

  const pgp = parse(resolveDashboardPreviewRequest('GET', '/pgp-keys'))
  assert.equal(Boolean(pgp.keys[0].fingerprint), true)

  const passkeys = parse(resolveDashboardPreviewRequest('GET', '/passkeys'))
  assert.equal(passkeys[0].id, 'passkey_preview_1')
  assert.equal(Boolean(passkeys[0].created_at), true)
  assert.equal(Boolean(passkeys[0].last_used_at), true)

  const credentials = parse(resolveDashboardPreviewRequest('GET', '/api/credentials'))
  assert.equal(credentials[0].is_default, true)

  const bundles = parse(resolveDashboardPreviewRequest('GET', '/api/quorum-bundles'))
  assert.equal(Boolean(bundles[0].created_at), true)
  assert.equal(Boolean(bundles[0].data.secret_recipient_public_key), true)
})

test('dashboard preview serves organization and billing fixtures with the expected collections', () => {
  const orgs = parse(resolveDashboardPreviewRequest('GET', '/api/organizations'))
  assert.equal(orgs[0].name, 'Preview Organization')

  const settings = parse(resolveDashboardPreviewRequest('GET', `/api/organizations/${orgs[0].id}/settings`))
  assert.equal(settings.require_pin, true)

  const members = parse(resolveDashboardPreviewRequest('GET', `/api/organizations/${orgs[0].id}/members`))
  assert.equal(members.length >= 2, true)

  const invitations = parse(resolveDashboardPreviewRequest('GET', `/api/organizations/${orgs[0].id}/invitations`))
  assert.equal(Boolean(invitations[0].created_at), true)

  const usage = parse(resolveDashboardPreviewRequest('GET', '/api/billing/usage'))
  assert.equal(usage.items.length >= 2, true)
  assert.equal(usage.subscription_items.length >= 1, true)
  assert.equal(usage.billing_period_start, '2026-08-01')
  assert.equal(usage.billing_period_end, '2026-09-01')
  assert.equal(usage.lifetime_cost > usage.total_cost, true)
  assert.equal(new Set(usage.items.map((item) => item.id)).size, usage.items.length)
  assert.equal(usage.items.every((item) => typeof item.rate === 'number'), true)
  assert.equal(usage.items.every((item) => Boolean(item.region)), true)
  assert.equal(usage.items.every((item) => !Number.isNaN(Date.parse(item.last_recorded_at))), true)

  const actualTotal = [...usage.items, ...usage.subscription_items]
    .reduce((sum, item) => sum + item.cost, 0)
  assert.equal(Number(actualTotal.toFixed(2)), usage.total_cost)

  const balance = parse(resolveDashboardPreviewRequest('GET', '/api/billing/credits/balance'))
  assert.equal(balance.balance_display, '$1,842.50')

  const packages = parse(resolveDashboardPreviewRequest('GET', '/api/billing/credits/packages'))
  assert.equal(packages.packages.length, 2)

  const subscription = parse(resolveDashboardPreviewRequest('GET', '/api/billing/subscription'))
  assert.equal(subscription.subscription.status, 'active')
  assert.equal(subscription.subscription.allocated_enclaves, 3)
  assert.equal(subscription.subscription.enclave_limit, 4)
  assert.equal(subscription.subscription.hourly_rate_usd > 0, true)

  const tiers = parse(resolveDashboardPreviewRequest('GET', '/api/billing/subscription/tiers'))
  assert.equal(tiers.tiers.length, 3)
})

test('dashboard preview serves build inputs and health fixtures', () => {
  const buildInputs = parse(resolveDashboardPreviewRequest('GET', '/.well-known/caution/build-inputs'))
  assert.equal(Boolean(buildInputs.bootproof.commit), true)
  assert.equal(Boolean(buildInputs.platform.commit), true)

  const health = parse(resolveDashboardPreviewRequest('GET', '/health'))
  assert.equal(health.preview, true)
})

test('query strings do not change fixture routing', () => {
  const response = resolveDashboardPreviewRequest('GET', '/api/resources?tab=apps&foo=bar')
  assert.equal(response.status, 200)
})

test('head requests are allowed for protected preview routes', () => {
  const response = resolveDashboardPreviewRequest('HEAD', '/api/resources')
  assert.equal(response.status, 200)
})

test('state-changing requests are blocked even when the method input is lowercase', () => {
  const response = resolveDashboardPreviewRequest('post', '/api/resources/app_preview_1')
  assert.equal(response.status, 405)
  assert.equal(parse(response).error, 'dashboard_preview_read_only')
  assert.equal(response.headers.allow, 'GET, HEAD')
})

test('unknown api, auth, and user routes are converted into explicit 404 fixtures', () => {
  for (const path of ['/api/not-real', '/auth/not-real', '/user/not-real']) {
    const response = resolveDashboardPreviewRequest('GET', path)
    assert.equal(response.status, 404)
    assert.equal(parse(response).error, 'dashboard_preview_not_found')
  }
})

test('non-protected asset requests still fall through to vite', () => {
  assert.equal(resolveDashboardPreviewRequest('GET', '/src/main.js'), null)
  assert.equal(resolveDashboardPreviewRequest('GET', '/favicon.ico'), null)
})
