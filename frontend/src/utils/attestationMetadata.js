// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

function isSourceManifest(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    ['app_source', 'enclave_source', 'framework_source'].some((name) => value[name])
}

export function selectAttestationManifest(verifyResult, externalManifest) {
  if (verifyResult?.verified === true && isSourceManifest(verifyResult.userData)) {
    return { manifest: verifyResult.userData, manifestVerified: true }
  }
  return {
    manifest: isSourceManifest(externalManifest) ? externalManifest : null,
    manifestVerified: false,
  }
}

export function getSourceUrl(source) {
  const value = typeof source === 'string'
    ? source
    : (Array.isArray(source?.urls) ? source.urls[0] : null) || source?.url
  if (typeof value !== 'string') return null

  try {
    const url = new URL(value)
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null
  } catch {
    return null
  }
}
