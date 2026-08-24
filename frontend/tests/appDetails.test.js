// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import test from 'node:test'
import {
  formatRuntimeSummary,
  formatStatusLabel,
  getAppEstimatedMonthlyCost,
  getDeploymentLabel,
  getDnsGuidance,
  isManaged,
} from '../src/utils/appDetails.js'

test('deployment helpers distinguish customer-managed and fully managed apps', () => {
  const managed = { configuration: { managed_onprem: {} } }
  const hosted = { configuration: {} }

  assert.equal(isManaged(managed), true)
  assert.equal(getDeploymentLabel(managed), 'Customer-managed')
  assert.equal(isManaged(hosted), false)
  assert.equal(getDeploymentLabel(hosted), 'Fully managed')
  assert.equal(isManaged({ configuration: { managed_onprem: null } }), false)
  assert.equal(getDeploymentLabel(undefined), 'Fully managed')
})

test('runtime summary combines available running app sizing', () => {
  assert.equal(
    formatRuntimeSummary({ state: 'running', configuration: { cpus: 4, memory_mb: 2048 } }),
    '4 vCPU · 2 GB RAM',
  )
  assert.equal(
    formatRuntimeSummary({ state: 'running', configuration: { cpus: 2, memory_mb: 1536 } }),
    '2 vCPU · 1.5 GB RAM',
  )
  assert.equal(
    formatRuntimeSummary({ state: 'running', configuration: { memory_mb: 512 } }),
    '512 MB RAM',
  )
  assert.equal(formatRuntimeSummary({ state: 'running', configuration: { cpus: 1 } }), '1 vCPU')
})

test('runtime summary preserves the running-state guard and handles sparse data', () => {
  assert.equal(
    formatRuntimeSummary({ state: 'stopped', configuration: { cpus: 4, memory_mb: 2048 } }),
    'Available after successful deployment',
  )
  assert.equal(formatRuntimeSummary({}), 'Available after successful deployment')
  assert.equal(formatRuntimeSummary(undefined), 'Available after successful deployment')
  assert.equal(formatRuntimeSummary({ state: 'running' }), 'Unavailable')
  assert.equal(formatRuntimeSummary({ state: 'running', configuration: {} }), 'Unavailable')
})

test('DNS guidance is present only when both domain and target are available', () => {
  assert.equal(
    getDnsGuidance({
      managed_hostname: 'app-123.apps.caution.example',
      configuration: { domain: 'payments.example.com' },
    }),
    'Point payments.example.com to this target with a CNAME record.',
  )
  assert.equal(getDnsGuidance({ configuration: { domain: 'payments.example.com' } }), '')
  assert.equal(getDnsGuidance({ managed_hostname: 'app-123.apps.caution.example' }), '')
  assert.equal(getDnsGuidance(undefined), '')
})

test('monthly estimates use the newest compute-hour rate and accept zero', () => {
  const app = { id: 'app-1', estimated_monthly_cost: 99 }
  const items = [
    {
      applicationId: 'app-1', resourceType: 'network', unit: 'gb', rate: 9,
      lastRecordedAt: '2026-08-21T12:00:00Z',
    },
    {
      applicationId: 'app-1', resourceType: 'compute', unit: 'hours', rate: 0.2,
      lastRecordedAt: '2026-08-20T12:00:00Z',
    },
    {
      applicationId: 'app-1', resourceType: 'compute', unit: 'hours', rate: 0.3,
      lastRecordedAt: '2026-08-21T12:00:00Z',
    },
  ]

  assert.equal(getAppEstimatedMonthlyCost(app, items), '219.00')
  assert.equal(getAppEstimatedMonthlyCost(app, [{
    applicationId: 'app-1', resourceType: 'compute', unit: 'hours', rate: 0,
    lastRecordedAt: '2026-08-21T12:00:00Z',
  }]), '0.00')
  assert.equal(getAppEstimatedMonthlyCost(app, []), '99.00')
})

test('status labels format DNS states and missing values for display', () => {
  assert.equal(formatStatusLabel('ready'), 'Ready')
  assert.equal(formatStatusLabel('pending_dns'), 'Pending DNS')
  assert.equal(formatStatusLabel('dns-publishing'), 'DNS Publishing')
  assert.equal(formatStatusLabel(''), 'Unavailable')
  assert.equal(formatStatusLabel(null), 'Unavailable')
})
