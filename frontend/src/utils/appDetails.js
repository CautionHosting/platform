// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

const formatMemory = (memoryMb) => {
  if (!Number.isFinite(memoryMb) || memoryMb <= 0) return ''
  if (memoryMb < 1024) return `${memoryMb} MB`

  const memoryGb = memoryMb / 1024
  return `${Number.isInteger(memoryGb) ? memoryGb : memoryGb.toFixed(1)} GB`
}

export const isManaged = (app) => app?.configuration?.managed_onprem != null

export const getDeploymentLabel = (app) =>
  isManaged(app) ? 'Customer-managed' : 'Fully managed'

export const formatRuntimeSummary = (app) => {
  if (app?.state !== 'running') return 'Available after successful deployment'

  const cpus = app.configuration?.cpus
  const memory = formatMemory(app.configuration?.memory_mb)
  const parts = []

  if (Number.isFinite(cpus) && cpus > 0) parts.push(`${cpus} vCPU`)
  if (memory) parts.push(`${memory} RAM`)

  return parts.join(' · ') || 'Unavailable'
}

export const getDnsGuidance = (app) => {
  const domain = app?.configuration?.domain
  if (!domain || !app?.managed_hostname) return ''

  return `Point ${domain} to this target with a CNAME record.`
}

export const getAppEstimatedMonthlyCost = (app, billingItems = []) => {
  const billingItem = billingItems
    .filter((item) =>
      item.applicationId === app?.id
      && item.resourceType === 'compute'
      && item.unit === 'hours'
      && item.rate != null
      && Number.isFinite(Number(item.rate)))
    .reduce((latest, item) => {
      if (!latest) return item
      return Date.parse(item.lastRecordedAt) > Date.parse(latest.lastRecordedAt) ? item : latest
    }, null)

  if (billingItem) return (Number(billingItem.rate) * 730).toFixed(2)

  const fallback = Number(app?.estimated_monthly_cost)
  return app?.estimated_monthly_cost != null && Number.isFinite(fallback)
    ? fallback.toFixed(2)
    : null
}

export const formatStatusLabel = (status) => {
  if (typeof status !== 'string' || !status.trim()) return 'Unavailable'

  return status
    .trim()
    .split(/[_\s-]+/)
    .map((word) => (word.toLowerCase() === 'dns'
      ? 'DNS'
      : `${word.charAt(0).toUpperCase()}${word.slice(1).toLowerCase()}`))
    .join(' ')
}
