<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="qr-login">
    <div class="qr-card">
      <h2 class="qr-title">CLI Login Request</h2>

      <div v-if="state === 'ready'">
        <p class="qr-description">
          Authenticate with your security key to log in to the CLI.
        </p>
        <button @click="authenticate" class="btn-dark btn qr-btn">
          Authenticate with security key
        </button>
      </div>

      <div v-else-if="state === 'authenticating'">
        <p class="qr-status">Tap your security key...</p>
      </div>

      <div v-else-if="state === 'completing'">
        <p class="qr-status">Completing authentication...</p>
      </div>

      <div v-else-if="state === 'success'">
        <p class="qr-success">Authentication complete. You can close this tab.</p>
      </div>

      <div v-else-if="state === 'error'">
        <p class="qr-error" v-html="errorMessage"></p>
        <button @click="reset" class="btn-dark btn qr-btn">
          Try again
        </button>
      </div>

      <div v-else-if="state === 'invalid'">
        <p class="qr-error">Invalid or expired login request. Please generate a new QR code from the CLI.</p>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { base64urlToUint8Array, uint8ArrayToBase64url } from '../composables/useWebAuthn.js'

export default {
  name: 'QrLogin',
  setup() {
    const state = ref('ready')
    const errorMessage = ref('')
    const token = ref('')

    onMounted(() => {
      const params = new URLSearchParams(window.location.search)
      token.value = params.get('token') || ''
      if (!token.value) {
        state.value = 'invalid'
      } else if (!window.PublicKeyCredential) {
        errorMessage.value = 'Your browser does not support WebAuthn. Please use a modern browser.'
        state.value = 'error'
      }
    })

    async function authenticate() {
      if (!token.value) {
        state.value = 'invalid'
        return
      }

      state.value = 'authenticating'
      errorMessage.value = ''

      try {
        // Step 1: Start authentication with the QR token
        const beginResponse = await fetch('/auth/qr-login/authenticate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: token.value }),
        })

        if (!beginResponse.ok) {
          const text = await beginResponse.text()
          if (text.includes('expired') || text.includes('already')) {
            state.value = 'invalid'
            return
          }
          throw new Error(text || 'Failed to begin authentication')
        }

        const beginData = await beginResponse.json()

        // Step 2: Get assertion from security key
        const publicKey = beginData.publicKey
        publicKey.challenge = base64urlToUint8Array(publicKey.challenge)

        if (publicKey.allowCredentials) {
          publicKey.allowCredentials = publicKey.allowCredentials.map((cred) => ({
            type: cred.type,
            id: base64urlToUint8Array(cred.id),
            ...(cred.transports && cred.transports.length > 0
              ? { transports: cred.transports }
              : {}),
          }))
        }

        // Delete hints to allow all authenticator types (platform passkey, NFC, hybrid, etc.)
        delete publicKey.hints

        let assertion
        try {
          assertion = await navigator.credentials.get({ publicKey })
        } catch (credError) {
          if (credError.name === 'NotAllowedError') {
            throw new Error(
              'Authentication was blocked by your browser. Make sure you are using the same authenticator you registered with.'
            )
          }
          throw credError
        }

        if (!assertion) {
          throw new Error('No assertion received')
        }

        // Step 3: Finish authentication
        state.value = 'completing'

        const authenticatorData = new Uint8Array(assertion.response.authenticatorData)
        const clientDataJSON = new Uint8Array(assertion.response.clientDataJSON)
        const signature = new Uint8Array(assertion.response.signature)

        const finishResponse = await fetch('/auth/qr-login/authenticate/finish', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            id: assertion.id,
            rawId: uint8ArrayToBase64url(new Uint8Array(assertion.rawId)),
            type: assertion.type,
            response: {
              authenticatorData: uint8ArrayToBase64url(authenticatorData),
              clientDataJSON: uint8ArrayToBase64url(clientDataJSON),
              signature: uint8ArrayToBase64url(signature),
              userHandle: assertion.response.userHandle
                ? uint8ArrayToBase64url(new Uint8Array(assertion.response.userHandle))
                : null,
            },
            session: beginData.session,
            token: beginData.token,
          }),
        })

        if (!finishResponse.ok) {
          const text = await finishResponse.text()
          throw new Error(text || 'Failed to complete authentication')
        }

        state.value = 'success'
      } catch (err) {
        errorMessage.value = err.message || 'Authentication failed. Please try again.'
        state.value = 'error'
      }
    }

    function reset() {
      state.value = 'ready'
      errorMessage.value = ''
    }

    return {
      state,
      errorMessage,
      authenticate,
      reset,
    }
  },
}
</script>

<style scoped>
.qr-login {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  padding: var(--spacing3);
}

.qr-card {
  background: white;
  border-radius: var(--radius-lg);
  padding: var(--spacing5);
  max-width: 420px;
  width: 100%;
  box-shadow: var(--shadow-md);
  text-align: center;
}

.qr-title {
  font-size: var(--heading3-font-size);
  font-weight: var(--heading3-font-weight);
  margin-bottom: var(--spacing3);
  color: var(--color-dark);
}

.qr-description {
  font-size: var(--body-font-size);
  color: var(--color-grey);
  margin-bottom: var(--spacing4);
  line-height: var(--body-line-height);
}

.qr-btn {
  width: 100%;
  padding: 14px 24px;
  font-size: var(--button-font-size);
  font-weight: var(--button-font-weight);
  border: none;
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: background var(--transition-base);
}

.btn-dark {
  background: var(--color-dark);
  color: white;
}

.btn-dark:hover {
  opacity: 0.9;
}

.qr-status {
  font-size: var(--body-font-size);
  color: var(--color-grey);
  padding: var(--spacing4) 0;
}

.qr-success {
  font-size: var(--body-font-size);
  color: var(--color-accent-green);
  font-weight: 500;
  padding: var(--spacing4) 0;
}

.qr-error {
  font-size: var(--body-font-size);
  color: #d32f2f;
  margin-bottom: var(--spacing3);
  line-height: var(--body-line-height);
}
</style>
