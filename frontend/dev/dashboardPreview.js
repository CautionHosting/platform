// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

export const DASHBOARD_PREVIEW_ENV = 'CAUTION_DASHBOARD_PREVIEW'

const organizationId = 'org_preview_1'

const previewUserStatus = {
  user_id: 'user_preview_1',
  username: 'preview-operator',
  username_is_placeholder: false,
  email_verified: true,
  legal: {
    privacy_notice: {
      title: 'Privacy Notice',
      url: 'https://caution.co/privacy.html',
      accepted_at: '2026-08-12T09:30:00Z',
      requires_action: false,
    },
    terms_of_service: {
      title: 'Terms of Service',
      url: 'https://caution.co/terms.html',
      accepted_at: '2026-08-12T09:30:00Z',
      requires_action: false,
    },
  },
}

const previewApps = [
  {
    id: 'app_preview_1',
    resource_name: 'payments-enclave',
    state: 'running',
    enclave_id: 'i-0previewpayments123',
    region: 'eu-central-1',
    public_ip: '203.0.113.10',
    managed_hostname: 'payments-edge.preview.caution.sh',
    dns_status: 'ready',
    git_url: 'git@codeberg.org:caution/preview-payments-enclave.git',
    created_at: '2026-08-12T08:15:00Z',
    estimated_monthly_cost: 189.75,
    configuration: {
      cpus: 4,
      domain: 'payments.preview.caution.sh',
      instance_type: 'c6i.xlarge',
      memory_mb: 2048,
      managed_onprem: {
        aws_account_id: '123456789012',
        aws_region: 'eu-central-1',
        vpc_id: 'vpc-0abc123preview',
        deployment_id: 'deploy-preview-001',
      },
    },
  },
  {
    id: 'app_preview_2',
    resource_name: 'hello-world',
    state: 'stopped',
    enclave_id: 'i-0previewhello456',
    region: '',
    public_ip: null,
    managed_hostname: '',
    dns_status: 'publishing',
    dns_error: 'The preview DNS record could not be published.',
    git_url: 'git@codeberg.org:caution/preview-hello-world.git',
    created_at: '2026-08-10T13:00:00Z',
    estimated_monthly_cost: 24.1,
    configuration: {
      domain: 'hello.preview.caution.sh',
    },
  },
  {
    id: 'app_preview_3',
    resource_name: 'analytics-bootstrap',
    state: 'pending',
    region: 'eu-west-1',
    public_ip: null,
    managed_hostname: '',
    dns_status: 'reserved',
    git_url: 'git@codeberg.org:caution/preview-analytics.git',
    created_at: '2026-08-13T07:45:00Z',
    configuration: { instance_type: 'm5.large' },
  },
  {
    id: 'app_preview_4',
    resource_name: 'image-processor',
    state: 'failed',
    region: 'us-east-1',
    public_ip: null,
    managed_hostname: '',
    dns_status: 'unavailable',
    git_url: 'git@codeberg.org:caution/preview-image-processor.git',
    created_at: '2026-08-12T17:20:00Z',
    configuration: { instance_type: 'c6i.large' },
  },
  {
    id: 'app_preview_5',
    resource_name: 'reports-service',
    state: 'terminating',
    region: 'eu-central-1',
    public_ip: null,
    managed_hostname: '',
    dns_status: 'unavailable',
    git_url: 'git@codeberg.org:caution/preview-reports.git',
    created_at: '2026-08-11T11:10:00Z',
    configuration: { instance_type: 'm5.large' },
  },
  {
    id: 'app_preview_6',
    resource_name: 'legacy-api',
    state: 'terminated',
    region: 'us-west-2',
    public_ip: null,
    managed_hostname: '',
    dns_status: 'unavailable',
    git_url: 'git@codeberg.org:caution/preview-legacy-api.git',
    created_at: '2026-08-09T14:30:00Z',
    configuration: { instance_type: 'm5.large' },
  },
]

const previewBuilderConfig = {
  builder_size: 'medium',
  options: [
    { id: 'small', label: 'Small', vcpus: 2, ram_gb: 4 },
    { id: 'medium', label: 'Medium', vcpus: 4, ram_gb: 8 },
    { id: 'large', label: 'Large', vcpus: 8, ram_gb: 16 },
  ],
}

const previewOrganizations = [{ id: organizationId, name: 'Preview Organization' }]
const previewOrgSettings = { require_pin: true }

const previewMembers = [
  {
    id: 'member_preview_1',
    user_id: 'user_preview_1',
    email: 'operator@example.com',
    username: 'preview-operator',
    role: 'owner',
    joined_at: '2026-08-09T11:00:00Z',
  },
  {
    id: 'member_preview_2',
    user_id: 'user_preview_2',
    email: 'dev@example.com',
    username: 'preview-dev',
    role: 'developer',
    joined_at: '2026-08-11T15:00:00Z',
  },
]

const previewInvitations = [
  {
    id: 'invite_preview_1',
    email: 'security@example.com',
    role: 'auditor',
    created_at: '2026-08-12T10:20:00Z',
    expires_at: '2026-08-19T10:20:00Z',
  },
]

const previewPasskeys = [
  {
    id: 'passkey_preview_1',
    kind: 'Security key',
    credential_id: 'previewcredentialid000123456789',
    transports: ['usb', 'nfc'],
    is_current_session: true,
    created_at: '2026-08-09T11:00:00Z',
    last_used_at: '2026-08-13T07:25:00Z',
  },
  {
    id: 'passkey_preview_2',
    kind: 'Platform passkey',
    credential_id: 'previewcredentialid000987654321',
    transports: ['internal'],
    is_current_session: false,
    created_at: '2026-08-10T09:45:00Z',
    last_used_at: '2026-08-12T18:40:00Z',
  },
]

const previewSshKeys = {
  keys: [
    {
      id: 'ssh_preview_1',
      name: 'MacBook Pro',
      key_type: 'ssh-ed25519',
      fingerprint: 'SHA256:K9Vw92v2zJ4n1jVfL7Q2Xq7sYwqFQ0s9x0preview',
      public_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPreviewMacBookKey operator@example.com',
      created_at: '2026-08-09T11:10:00Z',
      last_used_at: '2026-08-13T07:10:00Z',
    },
  ],
}

const previewPgpKeys = {
  keys: [
    {
      id: 'pgp_preview_1',
      name: 'Release signing key',
      fingerprint: 'F45D2E88A1C4B58E9E4D8D7012AB34CD56EF7890',
      created_at: '2026-08-09T11:12:00Z',
    },
  ],
}

const previewCredentials = [
  { id: 'cred_preview_1', name: 'Production AWS', identifier: 'AKIA...PREVIEW', is_default: true },
  { id: 'cred_preview_2', name: 'Staging AWS', identifier: 'AKIA...STAGING', is_default: false },
]

const previewBundles = [
  {
    id: 'bundle_preview_1',
    name: 'payments-secrets',
    created_at: '2026-08-11T16:20:00Z',
    labels: { service: 'payments', env: 'prod' },
    data: {
      secret_recipient_public_key: 'age1previewrecipientkey000000000000000000000000000000000000',
    },
  },
]

const previewBillingUsage = {
  total_cost: 412.38,
  projected_cost: 489.12,
  billing_period_start: '2026-08-01T00:00:00Z',
  billing_period_end: '2026-08-31T23:59:59Z',
  items: [
    {
      id: 'usage_preview_1',
      resource_id: 'app_preview_1',
      resource_name: 'payments-enclave',
      resource_type: 'compute',
      quantity: 128,
      unit: 'hours',
      rate: '1.12',
      cost: 143.36,
      projected_cost: 173.6,
    },
    {
      id: 'usage_preview_2',
      resource_id: 'app_preview_2',
      resource_name: 'hello-world',
      resource_type: 'compute',
      quantity: 48,
      unit: 'hours',
      rate: '0.37',
      cost: 17.76,
      projected_cost: 22.94,
    },
  ],
  subscription_items: [
    {
      id: 'sub_usage_preview_1',
      subscription_id: 'sub_preview_1',
      tier: 'Managed 4',
      resource_name: 'Managed enclaves subscription',
      resource_type: 'subscription',
      quantity: 1,
      unit: 'month',
      rate: '251.26',
      cost: 251.26,
      projected_cost: 251.26,
    },
  ],
}

const previewCreditBalance = { balance_cents: 184250, balance_display: '$1,842.50' }
const previewCreditPackages = {
  packages: [
    { purchase_display: '$100', credit_display: '$105', bonus_percent: 5 },
    { purchase_display: '$500', credit_display: '$550', bonus_percent: 10 },
  ],
}
const previewSubscription = {
  subscription: {
    id: 'sub_preview_1',
    tier_name: 'Managed 4',
    status: 'active',
    price_cents_per_cycle: 25000,
    enclaves: 4,
    started_at: '2026-08-01T08:00:00Z',
  },
}
const previewSubscriptionTiers = {
  tiers: [
    { id: 'tier_preview_1', name: 'Managed 1', enclaves: 1, price_cents_per_cycle: 10000 },
    { id: 'tier_preview_2', name: 'Managed 4', enclaves: 4, price_cents_per_cycle: 25000 },
    { id: 'tier_preview_3', name: 'Managed 10', enclaves: 10, price_cents_per_cycle: 50000 },
  ],
}

const previewBuildInputs = {
  bootproof: {
    repo: 'https://codeberg.org/caution/bootproof.git',
    commit: '7f5c0d4d0b84c9cbe1e5d1789f9b0182ab8f5d12',
  },
  platform: {
    repo: 'https://codeberg.org/caution/platform.git',
    commit: '8baa7dfb6b99a0d97bdc18a3393d0fe999999999',
  },
}

const protectedPrefixes = ['/api', '/auth', '/ssh-keys', '/pgp-keys', '/passkeys', '/.well-known', '/health', '/user']
const readOnlyMethods = new Set(['GET', 'HEAD'])

const isProtectedPath = (path) =>
  protectedPrefixes.some((prefix) => path === prefix || path.startsWith(`${prefix}/`))

const jsonResponse = (status, body, extraHeaders = {}) => ({
  status,
  headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...extraHeaders,
  },
  body: JSON.stringify(body),
})

export const isDashboardPreviewEnabled = ({ command, env }) =>
  command === 'serve' && env[DASHBOARD_PREVIEW_ENV] === '1'

export const resolveDashboardPreviewRequest = (input, rawUrl) => {
  const methodInput = typeof input === 'object' ? input.method || 'GET' : input || 'GET'
  const method = methodInput.toUpperCase()
  const url = typeof input === 'object' ? input.url || '/' : rawUrl || '/'
  const path = new URL(url, 'http://127.0.0.1').pathname

  if (!isProtectedPath(path)) {
    return null
  }

  if (!readOnlyMethods.has(method)) {
    return jsonResponse(
      405,
      {
        error: 'dashboard_preview_read_only',
        message: 'This dashboard preview is read-only. Use the real local stack for state changes.',
      },
      { allow: 'GET, HEAD' },
    )
  }

  if (path === '/api/user/status') return jsonResponse(200, previewUserStatus)
  if (path === '/api/users/me') return jsonResponse(200, { email: 'operator@example.com', email_verified: true })
  if (path === '/user/username') {
    return jsonResponse(200, {
      username: previewUserStatus.username,
      username_is_placeholder: false,
    })
  }
  if (path === '/api/resources') return jsonResponse(200, previewApps)
  if (previewApps.some((app) => path === `/api/resources/${app.id}/builder-config`)) {
    return jsonResponse(200, previewBuilderConfig)
  }
  if (path === '/ssh-keys') return jsonResponse(200, previewSshKeys)
  if (path === '/pgp-keys') return jsonResponse(200, previewPgpKeys)
  if (path === '/api/credentials') return jsonResponse(200, previewCredentials)
  if (path === '/api/quorum-bundles') return jsonResponse(200, previewBundles)
  if (path === '/api/organizations') return jsonResponse(200, previewOrganizations)
  if (path === `/api/organizations/${organizationId}/settings`) return jsonResponse(200, previewOrgSettings)
  if (path === `/api/organizations/${organizationId}/members`) return jsonResponse(200, previewMembers)
  if (path === `/api/organizations/${organizationId}/invitations`) return jsonResponse(200, previewInvitations)
  if (path === '/passkeys') return jsonResponse(200, previewPasskeys)
  if (path === '/api/billing/usage') return jsonResponse(200, previewBillingUsage)
  if (path === '/api/billing/credits/balance') return jsonResponse(200, previewCreditBalance)
  if (path === '/api/billing/credits/packages') return jsonResponse(200, previewCreditPackages)
  if (path === '/api/billing/subscription') return jsonResponse(200, previewSubscription)
  if (path === '/api/billing/subscription/tiers') return jsonResponse(200, previewSubscriptionTiers)
  if (path === '/.well-known/caution/build-inputs') return jsonResponse(200, previewBuildInputs)
  if (path === '/health') return jsonResponse(200, { ok: true, preview: true })

  return jsonResponse(404, {
    error: 'dashboard_preview_not_found',
    message: 'No preview fixture exists for this endpoint.',
  })
}

export function dashboardPreviewPlugin(previewEnabled) {
  return {
    name: 'caution-dashboard-preview',
    configureServer(server) {
      if (!previewEnabled) return

      server.middlewares.use((req, res, next) => {
        const resolved = resolveDashboardPreviewRequest({
          method: req.method || 'GET',
          url: req.url || '/',
        })

        if (!resolved) {
          next()
          return
        }

        res.statusCode = resolved.status
        for (const [name, value] of Object.entries(resolved.headers || {})) {
          res.setHeader(name, value)
        }

        if (req.method === 'HEAD') {
          res.end()
          return
        }

        res.end(resolved.body)
      })
    },
  }
}
