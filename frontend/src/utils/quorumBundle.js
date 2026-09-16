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
