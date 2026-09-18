import { base64urlToUint8Array, uint8ArrayToBase64url } from './useWebAuthn.js'

export function releaseOptions(options) {
  const publicKey = { ...options.publicKey }
  publicKey.challenge = base64urlToUint8Array(publicKey.challenge)
  publicKey.allowCredentials = (publicKey.allowCredentials || []).map(c => ({ ...c, id: base64urlToUint8Array(c.id) }))
  publicKey.userVerification = 'required'
  delete publicKey.hints
  return publicKey
}

export function releaseAssertion(credential) {
  if (!credential) throw new Error('No passkey assertion returned.')
  const response = credential.response
  const encode = bytes => uint8ArrayToBase64url(new Uint8Array(bytes))
  return {
    id: credential.id, rawId: encode(credential.rawId), type: credential.type,
    response: {
      authenticatorData: encode(response.authenticatorData),
      clientDataJSON: encode(response.clientDataJSON),
      signature: encode(response.signature),
      userHandle: response.userHandle ? encode(response.userHandle) : null,
    }, extensions: credential.getClientExtensionResults(),
  }
}
