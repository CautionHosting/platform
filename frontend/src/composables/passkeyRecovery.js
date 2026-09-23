import { releaseOptions, releaseAssertion } from './releaseApproval.js'

export async function verifyPasskeyRecovery(id, fetch, getCredential = options => navigator.credentials.get(options)) {
  const path = `/passkeys/${encodeURIComponent(id)}/recovery-verification`
  const begin = await fetch(`${path}/begin`, { method: 'POST' })
  if (!begin.ok) throw new Error(await begin.text() || 'Unable to start quorum approval verification.')
  const options = await begin.json()
  const credential = await getCredential({ publicKey: releaseOptions(options) })
  const finish = await fetch(`${path}/finish`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...releaseAssertion(credential), session: options.session }),
  })
  if (!finish.ok) throw new Error(await finish.text() || 'Unable to verify this passkey for quorum approval.')
  if ((await finish.json()).uv_verified !== true) throw new Error('Quorum approval verification was not confirmed.')
}
