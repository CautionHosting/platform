// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

export const getQuorumBundleFiles = (bundle) => {
  const payload = bundle?.data?.data ?? bundle?.data
  const publicKey = payload?.public_key ?? payload?.secret_recipient_public_key
  const shardfile = payload?.shardfile
  return {
    publicKey: typeof publicKey === 'string' ? publicKey : '',
    shardfile: typeof shardfile === 'string' ? shardfile : '',
  }
}

export const serializeQuorumBundle = (bundle) => {
  const data = bundle?.data
  return data && typeof data === 'object' && !Array.isArray(data) && Object.keys(data).length
    ? JSON.stringify(data, null, 2) : null
}

export const getQuorumBundleSummary = (bundle) => {
  const payload = bundle?.data?.data ?? bundle?.data
  const keys = payload?.keyring
  const validThreshold = Number.isInteger(payload?.threshold) && Number.isInteger(payload?.max)
    && payload.threshold > 0 && payload.threshold <= payload.max
    && (!Array.isArray(keys) || payload.max === keys.length)
  const custody = Array.isArray(keys) && keys.length && keys.every(key =>
    key && Object.keys(key).length === 1 && (key.OpenPGP || key.WebAuthn))
    ? [
        [keys.filter(key => key.OpenPGP).length, 'PGP'],
        [keys.filter(key => key.WebAuthn).length, 'passkey-backed'],
      ].filter(([count]) => count).map(([count, label]) => `${count} ${label}`).join(' · ')
    : ''
  return {
    threshold: validThreshold ? `${payload.threshold} of ${payload.max} holders` : '',
    custody,
  }
}

// The embedded UUID identifies the bundle; the API record ID identifies its storage row.
export const getEmbeddedBundleId = bundle => {
  const bytes = bundle?.data?.data?.bundle_id
  if (!Array.isArray(bytes) || bytes.length !== 16 || !bytes.every(b => Number.isInteger(b) && b >= 0 && b <= 255)) return null
  const value = bytes.map(b => b.toString(16).padStart(2, '0')).join('')
  return `${value.slice(0,8)}-${value.slice(8,12)}-${value.slice(12,16)}-${value.slice(16,20)}-${value.slice(20)}`
}
export const bundleTitle = bundle => {
  const id = getEmbeddedBundleId(bundle)
  const identity = id ? id.slice(0, 8) : `Platform record ${(bundle?.id || '').slice(0, 8)}`
  return bundle?.name ? `${bundle.name} · ${identity}` : id ? `Bundle ${identity}` : identity
}
export const abbreviateBundleValue = value => value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-8)}` : value
export const bundleIdentifiers = (bundle, publicKeyHash) => [
  { label: 'Bundle ID', value: getEmbeddedBundleId(bundle) },
  { label: 'Bundle hash', value: bundle.bundle_hash },
  { label: 'Public key SHA-256', value: publicKeyHash },
  { label: 'Platform record ID', value: bundle.id },
].filter(item => typeof item.value === 'string' && item.value)
