<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="qr-login">
    <div class="qr-card">
      <h2 class="qr-title">{{ title }}</h2>

      <div v-if="state === 'loading'">
        <p class="qr-status">Loading login details...</p>
      </div>

      <div v-else-if="state === 'ready'">
        <p v-if="!isSign" class="qr-warning" data-testid="qr-login-warning">
          Did you just start this CLI login? If not, stop.
        </p>
        <p class="qr-description">
          {{ description }}
        </p>
        <template v-if="!isSign">
          <p class="qr-context">
            This will authorize a CLI session started at {{ requestTime }}. Verification code:
            <strong data-testid="qr-login-code">{{ verificationCode }}</strong>
          </p>
          <label class="qr-confirm">
            <input v-model="confirmed" type="checkbox" data-testid="qr-login-confirm">
            I started this CLI login myself
          </label>
        </template>
        <button
          @click="authenticate"
          :disabled="!isSign && !confirmed"
          class="btn-dark btn qr-btn"
          :data-testid="isSign ? undefined : 'qr-login-submit'"
        >
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
        <p class="qr-success">{{ successMessage }}</p>
      </div>

      <div v-else-if="state === 'error'">
        <p class="qr-error">{{ errorMessage }}</p>
        <button @click="reset" class="btn-dark btn qr-btn">
          Try again
        </button>
      </div>

      <div v-else-if="state === 'invalid'">
        <p class="qr-error">{{ invalidMessage }}</p>
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
    // Detect mode from URL path
    const isSign = window.location.pathname === '/qr-sign'
    const authPrefix = isSign ? '/auth/qr-sign' : '/auth/qr-login'

    const state = ref(isSign ? 'ready' : 'loading')
    const errorMessage = ref('')
    const token = ref('')
    const confirmed = ref(false)
    const verificationCode = ref('')
    const requestTime = ref('')
    const contextLoaded = ref(false)

    const title = isSign ? 'CLI Signing Request' : 'CLI Login Request'
    const description = isSign
      ? 'Authenticate with your security key to approve the CLI operation.'
      : 'This grants a CLI session.'
    const successMessage = isSign
      ? 'Operation approved. You can close this tab.'
      : 'Authentication complete. You can close this tab.'
    const invalidMessage = isSign
      ? 'Invalid or expired signing request. Please generate a new QR code from the CLI.'
      : 'Invalid or expired login request. Please generate a new QR code from the CLI.'

    async function loadLoginContext() {
      contextLoaded.value = false
      try {
        const response = await fetch('/auth/qr-login/context', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: token.value }),
        })
        if (!response.ok) {
          throw new Error('Unable to load login details')
        }
        const context = await response.json()
        if (!/^\d{6}$/.test(context.verification_code) || !context.created_at || !context.expires_at) {
          throw new Error('Incomplete login details')
        }
        const createdAt = new Date(context.created_at)
        const expiresAt = new Date(context.expires_at)
        if (Number.isNaN(createdAt.getTime()) || Number.isNaN(expiresAt.getTime())) {
          throw new Error('Invalid login time')
        }
        verificationCode.value = context.verification_code
        requestTime.value = createdAt.toLocaleString()
        contextLoaded.value = true
        state.value = 'ready'
      } catch (err) {
        errorMessage.value = 'Unable to verify this CLI login. Stop and start a new login from the CLI.'
        state.value = 'error'
      }
    }

    onMounted(async () => {
      const params = new URLSearchParams(window.location.search)
      token.value = params.get('token') || ''
      if (!token.value) {
        state.value = 'invalid'
        return
      }
      if (!window.PublicKeyCredential) {
        errorMessage.value = 'Your browser does not support WebAuthn. Please use a modern browser.'
        state.value = 'error'
        return
      }
      if (!isSign) {
        await loadLoginContext()
      }
    })

    async function authenticate() {
      if (!token.value) {
        state.value = 'invalid'
        return
      }
      if (!isSign && !confirmed.value) {
        return
      }

      state.value = 'authenticating'
      errorMessage.value = ''

      try {
        // Step 1: Start authentication with the QR token
        const beginResponse = await fetch(`${authPrefix}/authenticate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(isSign ? { token: token.value } : { token: token.value, confirmed: true }),
        })

        if (!beginResponse.ok) {
          const text = await beginResponse.text()
          if (text.includes('expired') || text.includes('already') || text.includes('not found')) {
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

        const finishBody = {
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
          token: beginData.token,
        }

        // QR login also needs the session key
        if (beginData.session) {
          finishBody.session = beginData.session
        }

        const finishResponse = await fetch(`${authPrefix}/authenticate/finish`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(finishBody),
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
      confirmed.value = false
      errorMessage.value = ''
      if (isSign || contextLoaded.value) {
        state.value = 'ready'
      } else {
        state.value = 'loading'
        loadLoginContext()
      }
    }

    return {
      state,
      errorMessage,
      confirmed,
      verificationCode,
      requestTime,
      isSign,
      title,
      description,
      successMessage,
      invalidMessage,
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

.qr-warning {
  color: #8a3b00;
  font-weight: 600;
  line-height: var(--body-line-height);
  margin-bottom: var(--spacing3);
}

.qr-context {
  color: var(--color-grey);
  line-height: var(--body-line-height);
  margin-bottom: var(--spacing3);
}

.qr-confirm {
  display: flex;
  align-items: flex-start;
  gap: var(--spacing2);
  margin: 0 0 var(--spacing4);
  text-align: left;
}

.qr-confirm input {
  margin-top: 0.2em;
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

.qr-btn:disabled {
  cursor: not-allowed;
  opacity: 0.5;
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
