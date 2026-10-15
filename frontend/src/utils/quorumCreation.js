// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

export const MAX_DASHBOARD_HOLDERS = 10
export const MAX_KEYRING_BYTES = 512 * 1024
export const MAX_CREATION_BYTES = 1024 * 1024
export const GENERATION_PATH = '/quorum-bundles/from-org-users'
const bytes = value => new TextEncoder().encode(value).byteLength

export function cautionCustodyUnavailable(member) {
  if (!(member.webauthn_credentials > 0)) return 'No registered passkeys. Register a passkey or use external PGP.'
  if (member.webauthn_credentials > 64) return 'More than 64 passkeys. Reduce the credential count or use external PGP.'
  if (!(member.webauthn_uv_credentials > 0)) return 'Verify a passkey for quorum approval with PIN/biometrics in Authentication, or use external PGP.'
  return null
}

export function recoveryMethods(member) {
  return [
    ...(member.pgp_keys.length ? ['existing_pgp'] : []),
    ...(!cautionCustodyUnavailable(member) ? ['caution_backed_pgp'] : []),
  ]
}

export function initialSelection(member) {
  const methods = recoveryMethods(member)
  return {
    user_id: member.user_id,
    key_source: methods.length === 1 ? methods[0] : '',
    pgp_key_id: member.pgp_keys.length === 1 ? member.pgp_keys[0].id : '',
  }
}

export function creationRequest({ name, threshold, selections, members, certificates }) {
  const participants = selections.map(selection => {
    const member = members.find(member => member.user_id === selection.user_id)
    if (!member || !recoveryMethods(member).includes(selection.key_source)) {
      throw new Error('Choose an approval method for each selected holder.')
    }
    const pgp = selection.key_source === 'existing_pgp'
    if (pgp && !member.pgp_keys.some(key => key.id === selection.pgp_key_id)) {
      throw new Error('Choose a registered PGP key for each external PGP holder.')
    }
    return { user_id: member.user_id, key_source: selection.key_source, pgp_key_id: pgp ? selection.pgp_key_id : null }
  })
  const pgpCertificates = certificates.map(cert => cert.armor)
  const count = participants.length + pgpCertificates.length
  if (count < 1) throw new Error('Select at least one holder.')
  if (count > MAX_DASHBOARD_HOLDERS) throw new Error(`Select at most ${MAX_DASHBOARD_HOLDERS} holders.`)
  if (new Set(participants.map(holder => holder.user_id)).size !== participants.length) throw new Error('Select each member only once.')
  validateHolderFingerprints(selections, members, certificates)
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > count) throw new Error(`Choose a threshold between 1 and ${count}.`)
  const request = {
    name: name.trim() || null, threshold, participants, pgp_certificates: pgpCertificates,
    allow_caution_backed_keys: participants.some(holder => holder.key_source === 'caution_backed_pgp'),
  }
  if (bytes(JSON.stringify(request)) > MAX_CREATION_BYTES) throw new Error('The creation request exceeds 1 MiB. Use a smaller keyring.')
  return request
}

export function validateHolderFingerprints(selections, members, certificates) {
  const fingerprints = certificates.map(cert => cert.fingerprint)
  for (const selection of selections) {
    if (selection.key_source !== 'existing_pgp') continue
    const key = members.find(member => member.user_id === selection.user_id)?.pgp_keys.find(key => key.id === selection.pgp_key_id)
    if (key) fingerprints.push(key.fingerprint)
  }
  const seen = new Set()
  for (const fingerprint of fingerprints) {
    const normalized = fingerprint.replace(/\s/g, '').toUpperCase()
    if (seen.has(normalized)) throw new Error(`Duplicate PGP holder: ${normalized}`)
    seen.add(normalized)
  }
}

export async function parsePublicHolder(text) {
  const certificates = await parsePublicKeyring(text)
  if (certificates.length !== 1) throw new Error('Add one public certificate at a time.')
  return certificates[0]
}

export async function parsePublicKeyring(text) {
  if (bytes(text) > MAX_KEYRING_BYTES) throw new Error('Public keyrings must be at most 512 KiB.')
  if (/-----BEGIN PGP PRIVATE KEY BLOCK-----/.test(text)) throw new Error('Private keys cannot be uploaded. Export only public certificates.')
  const blocks = text.match(/-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/g) || []
  const remainder = text.replace(/-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/g, '').trim()
  if (!blocks.length || remainder) throw new Error('Provide complete armored public-key blocks only.')
  const pgp = await import('openpgp')
  const config = { ...pgp.config, ignoreMalformedPackets: false, ignoreUnsupportedPackets: false }
  const classes = [pgp.PublicKeyPacket, pgp.PublicSubkeyPacket, pgp.SecretKeyPacket, pgp.SecretSubkeyPacket, pgp.SignaturePacket, pgp.UserIDPacket, pgp.UserAttributePacket]
  const allowed = Object.fromEntries(classes.map(packet => [packet.tag, packet]))
  const certificates = []
  const fingerprints = new Set()
  for (const block of blocks) {
    const { data } = await pgp.unarmor(block)
    // Inspect the entire packet stream before Key construction can discard packets.
    const packets = await pgp.PacketList.fromBinary(data, allowed, config)
    if (packets.some(packet => [pgp.enums.packet.secretKey, pgp.enums.packet.secretSubkey].includes(packet.constructor.tag))) {
      throw new Error('Private keys cannot be uploaded. Export only public certificates.')
    }
    if (packets[0]?.constructor.tag !== pgp.enums.packet.publicKey) throw new Error('A public keyring must start with a public certificate.')
    const keys = await pgp.readKeys({ binaryKeys: packets.write(), config })
    for (const key of keys) {
      const fingerprint = key.getFingerprint().toUpperCase()
      if (fingerprints.has(fingerprint)) throw new Error(`Duplicate certificate: ${fingerprint}`)
      fingerprints.add(fingerprint)
      certificates.push({ fingerprint, userId: key.getUserIDs()[0] || 'Unnamed certificate', armor: key.armor() })
      if (certificates.length > 254) throw new Error('A quorum supports at most 254 holders.')
    }
  }
  return certificates
}

export async function responseError(response, fallback) {
  const text = await response.text().catch(() => '')
  try { const json = JSON.parse(text); return json.error || json.message || fallback } catch { return text || fallback }
}

export function createBundleSubmitter({ sign, fetch, timeoutMs = 180000 }) {
  let pending = false
  return async request => {
    if (pending) throw new Error('Bundle creation is already in progress.')
    const body = JSON.stringify(request)
    if (bytes(body) > MAX_CREATION_BYTES) throw new Error('The creation request exceeds 1 MiB.')
    pending = true
    let dispatched = false
    let timer
    try {
      const headers = await sign('POST', GENERATION_PATH, body)
      const controller = new AbortController()
      timer = setTimeout(() => controller.abort(), timeoutMs)
      dispatched = true
      const response = await fetch(`/api${GENERATION_PATH}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body, signal: controller.signal,
      })
      if (!response.ok) {
        const error = new Error(await responseError(response, 'Unable to create the bundle.'))
        error.uncertain = response.status >= 500 || response.status === 408
        throw error
      }
      const bundle = await response.json()
      if (!bundle?.id || !bundle.data) throw new Error('The server returned an incomplete creation result.')
      return bundle
    } catch (error) {
      if (dispatched && error.uncertain === undefined) error.uncertain = true
      throw error
    } finally {
      clearTimeout(timer)
      pending = false
    }
  }
}
