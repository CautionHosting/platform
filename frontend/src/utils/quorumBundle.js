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
