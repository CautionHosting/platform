<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="login-container">
    <div class="login-card">
      <h1>Caution</h1>
      <p class="subtitle">Cloud Resource Management</p>

      <div v-if="error" class="error-message">
        {{ error }}
      </div>

      <div v-if="status" class="status-message">
        {{ status }}
      </div>

      <div v-if="!authenticated">
        <p class="instructions">
          Authenticate with Passkey
        </p>

        <div class="button-group">
          <button
            @click="handleLogin"
            :disabled="loading"
            class="btn btn-primary"
          >
            {{ loading ? 'Working...' : 'Login' }}
          </button>

          <button
            @click="handleRegister"
            :disabled="loading"
            class="btn btn-secondary"
          >
            {{ loading ? 'Working...' : 'Register New Key' }}
          </button>
        </div>

        <p class="help-text">
          You can also use the CLI (<a href="todo">docs</a>)
        </p>
        <pre class="code-block">Linux: <a href=""></a></pre>
        <pre class="code-block">MacOS <a href=""></a></pre>
      </div>

      <div v-else>
        <p class="success-message">
          Authentication successful! Redirecting...
        </p>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'

// Helper to convert base64url to Uint8Array
function base64urlToUint8Array(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

// Helper to convert Uint8Array to base64url
function uint8ArrayToBase64url(array) {
  const binary = String.fromCharCode(...array)
  const base64 = btoa(binary)
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

export default {
  name: 'Login',
  props: {
    session: String
  },
  setup(props) {
    const authenticated = ref(false)
    const loading = ref(false)
    const error = ref(null)
    const status = ref(null)

    onMounted(async () => {
      // Check for WebAuthn support
      if (!window.PublicKeyCredential) {
        error.value = 'Your browser does not support FIDO2/WebAuthn. Please use Chrome, Firefox, or Safari.'
        return
      }

      if (props.session) {
        try {
          // Verify session and check onboarding status
          const response = await fetch('/api/user/status', {
            headers: {
              'X-Session-ID': props.session
            }
          })

          if (response.ok) {
            const data = await response.json()
            authenticated.value = true

            // Redirect based on onboarding status
            if (!data.email_verified || !data.payment_method_added) {
              window.location.href = `/onboarding?session=${props.session}`
            } else {
              // User is fully onboarded, redirect to dashboard
              window.location.href = `/dashboard?session=${props.session}`
            }
          } else {
            error.value = 'Invalid session. Please authenticate using the CLI.'
          }
        } catch (err) {
          error.value = 'Failed to verify session. Please try again.'
        }
      }
    })

    async function handleRegister() {
      error.value = null
      status.value = null
      loading.value = true

      try {
        // Step 1: Begin registration
        status.value = 'Starting registration...'
        const beginResponse = await fetch('/auth/register/begin', {
          method: 'POST',
          credentials: 'include'
        })

        if (!beginResponse.ok) {
          const errorText = await beginResponse.text()
          throw new Error(errorText || 'Failed to begin registration')
        }

        const beginData = await beginResponse.json()

        // Step 2: Create credential with security key
        status.value = 'Please tap your security key...'

        const publicKey = beginData.publicKey
        publicKey.challenge = base64urlToUint8Array(publicKey.challenge)
        publicKey.user.id = base64urlToUint8Array(publicKey.user.id)

        const credential = await navigator.credentials.create({ publicKey })

        if (!credential) {
          throw new Error('No credential created')
        }

        // Step 3: Finish registration
        status.value = 'Completing registration...'

        const attestationObject = new Uint8Array(credential.response.attestationObject)
        const clientDataJSON = new Uint8Array(credential.response.clientDataJSON)

        const finishResponse = await fetch('/auth/register/finish', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            id: credential.id,
            rawId: uint8ArrayToBase64url(new Uint8Array(credential.rawId)),
            type: credential.type,
            response: {
              attestationObject: uint8ArrayToBase64url(attestationObject),
              clientDataJSON: uint8ArrayToBase64url(clientDataJSON)
            },
            session: beginData.session
          })
        })

        if (!finishResponse.ok) {
          const errorText = await finishResponse.text()
          throw new Error(errorText || 'Failed to complete registration')
        }

        const result = await finishResponse.json()
        authenticated.value = true
        status.value = 'Registration successful!'

        // Redirect to onboarding
        setTimeout(() => {
          window.location.href = `/onboarding?session=${result.session_id}`
        }, 1000)

      } catch (err) {
        error.value = err.message || 'Registration failed. Please try again.'
      } finally {
        loading.value = false
      }
    }

    async function handleLogin() {
      error.value = null
      status.value = null
      loading.value = true

      try {
        // Step 1: Begin login
        status.value = 'Starting login...'
        const beginResponse = await fetch('/auth/login/begin', {
          method: 'POST',
          credentials: 'include'
        })

        if (!beginResponse.ok) {
          const errorText = await beginResponse.text()
          throw new Error(errorText || 'Failed to begin login')
        }

        const beginData = await beginResponse.json()

        // Step 2: Get assertion from security key
        status.value = 'Please tap your security key...'

        const publicKey = beginData.publicKey
        publicKey.challenge = base64urlToUint8Array(publicKey.challenge)

        if (publicKey.allowCredentials) {
          publicKey.allowCredentials = publicKey.allowCredentials.map(cred => ({
            ...cred,
            id: base64urlToUint8Array(cred.id)
          }))
        }

        const assertion = await navigator.credentials.get({ publicKey })

        if (!assertion) {
          throw new Error('No assertion received')
        }

        // Step 3: Finish login
        status.value = 'Completing login...'

        const authenticatorData = new Uint8Array(assertion.response.authenticatorData)
        const clientDataJSON = new Uint8Array(assertion.response.clientDataJSON)
        const signature = new Uint8Array(assertion.response.signature)

        const finishResponse = await fetch('/auth/login/finish', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            id: assertion.id,
            rawId: uint8ArrayToBase64url(new Uint8Array(assertion.rawId)),
            type: assertion.type,
            response: {
              authenticatorData: uint8ArrayToBase64url(authenticatorData),
              clientDataJSON: uint8ArrayToBase64url(clientDataJSON),
              signature: uint8ArrayToBase64url(signature),
              userHandle: assertion.response.userHandle ?
                uint8ArrayToBase64url(new Uint8Array(assertion.response.userHandle)) : null
            },
            session: beginData.session
          })
        })

        if (!finishResponse.ok) {
          const errorText = await finishResponse.text()
          throw new Error(errorText || 'Failed to complete login')
        }

        const result = await finishResponse.json()
        authenticated.value = true
        status.value = 'Login successful!'

        // Check onboarding status and redirect
        setTimeout(async () => {
          const statusResponse = await fetch('/api/user/status', {
            headers: { 'X-Session-ID': result.session_id }
          })

          if (statusResponse.ok) {
            const userData = await statusResponse.json()
            if (!userData.email_verified || !userData.payment_method_added) {
              window.location.href = `/onboarding?session=${result.session_id}`
            } else {
              window.location.href = `/dashboard?session=${result.session_id}`
            }
          } else {
            window.location.href = `/onboarding?session=${result.session_id}`
          }
        }, 1000)

      } catch (err) {
        error.value = err.message || 'Login failed. Please try again.'
      } finally {
        loading.value = false
      }
    }

    return {
      authenticated,
      loading,
      error,
      status,
      handleRegister,
      handleLogin
    }
  }
}
</script>

<style scoped>
.login-container {
  width: 100%;
  max-width: 500px;
  margin: 0 auto;
}

.login-card {
  background: white;
  border-radius: 16px;
  padding: 40px;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
}

h1 {
  font-size: 32px;
  font-weight: 700;
  color: #333;
  margin-bottom: 8px;
  text-align: center;
}

.subtitle {
  font-size: 16px;
  color: #666;
  text-align: center;
  margin-bottom: 32px;
}

.instructions {
  font-size: 16px;
  color: #555;
  margin-bottom: 24px;
  text-align: center;
  font-weight: 500;
}

.button-group {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 32px;
}

.btn {
  width: 100%;
  padding: 14px 24px;
  font-size: 16px;
  font-weight: 600;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: #2980b9;
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(52, 152, 219, 0.3);
}

.btn-secondary {
  background: #95a5a6;
  color: white;
}

.btn-secondary:hover:not(:disabled) {
  background: #7f8c8d;
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(149, 165, 166, 0.3);
}

.help-text {
  font-size: 13px;
  color: #777;
  text-align: center;
  margin: 24px 0 12px 0;
}

.code-block {
  background: #f5f5f5;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 12px 16px;
  font-family: 'Monaco', 'Courier New', monospace;
  font-size: 13px;
  color: #333;
  margin-bottom: 8px;
  overflow-x: auto;
}

.error-message {
  background: #fee;
  border: 1px solid #fcc;
  border-radius: 8px;
  padding: 12px 16px;
  color: #c33;
  margin-bottom: 20px;
  font-size: 14px;
}

.status-message {
  background: #e3f2fd;
  border: 1px solid #90caf9;
  border-radius: 8px;
  padding: 12px 16px;
  color: #1976d2;
  margin-bottom: 20px;
  font-size: 14px;
  text-align: center;
}

.success-message {
  background: #efe;
  border: 1px solid #cfc;
  border-radius: 8px;
  padding: 12px 16px;
  color: #2e7d32;
  text-align: center;
  font-size: 14px;
}
</style>
