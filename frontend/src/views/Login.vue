<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="login-container">
    <div class="login-card">
      <img src="../assets/caution-logo-black.svg" alt="Caution" class="logo" />
      <p class="subtitle">The Verifiable Compute Platform</p>

      <div v-if="error" class="error-message">
        {{ error }}
      </div>

      <div v-if="status" class="status-message">
        {{ status }}
      </div>

      <div v-if="!authenticated">
        <div class="button-group">
          <button
            @click="handleLogin"
            :disabled="loading"
            class="btn btn-primary"
          >
            {{ loading ? 'Working...' : 'Login' }}
          </button>
        </div>

        <div class="register-section">
          <p class="register-label">New user? Enter your beta code to register:</p>
          <p class="register-label">Register using a smart card (Yubikey, NitroKey), it's required for CLI interactions</p>
          <input
            v-model="betaCode"
            type="text"
            placeholder="Enter alpha code"
            class="beta-code-input"
            :disabled="loading"
          />
          <button
            @click="handleRegister"
            :disabled="loading || !betaCode.trim()"
            class="btn btn-secondary"
          >
            {{ loading ? 'Working...' : 'Register with Alpha Code' }}
          </button>
        </div>
        <br/>
        <pre class="code-block">https://codeberg.org/caution/platform<a href=""></a></pre>
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
    const betaCode = ref('')

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
        // Step 1: Begin registration with beta code
        status.value = 'Validating beta code...'
        const beginResponse = await fetch('/auth/register/begin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ beta_code: betaCode.value.trim() })
        })

        if (!beginResponse.ok) {
          const errorText = await beginResponse.text()
          throw new Error(errorText || 'Failed to begin registration')
        }

        const beginData = await beginResponse.json()

        // Step 2: Create credential with security key
        status.value = 'Please tap your security key...'

        const publicKey = beginData.publicKey
        console.log('Registration publicKey from server:', JSON.stringify(publicKey, null, 2))
        console.log('Registration RP ID:', publicKey.rp?.id)
        console.log('Registration RP Name:', publicKey.rp?.name)

        publicKey.challenge = base64urlToUint8Array(publicKey.challenge)
        publicKey.user.id = base64urlToUint8Array(publicKey.user.id)

        console.log('About to call navigator.credentials.create()')
        const credential = await navigator.credentials.create({ publicKey })
        console.log('Credential created successfully:', credential?.id)

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

        console.log('Raw beginData:', JSON.stringify(beginData, null, 2))

        const publicKey = beginData.publicKey
        console.log('publicKey.rpId:', publicKey.rpId)
        console.log('publicKey.challenge (before conversion):', publicKey.challenge)
        console.log('publicKey.allowCredentials (before conversion):', publicKey.allowCredentials)

        publicKey.challenge = base64urlToUint8Array(publicKey.challenge)

        if (publicKey.allowCredentials) {
          publicKey.allowCredentials = publicKey.allowCredentials.map(cred => {
            console.log('Converting credential:', JSON.stringify(cred, null, 2))
            console.log('  ID:', cred.id)
            console.log('  Type:', cred.type)
            console.log('  Transports:', cred.transports)
            return {
              type: cred.type,
              id: base64urlToUint8Array(cred.id),
              // Only include transports if they exist and are valid
              ...(cred.transports && cred.transports.length > 0 ? { transports: cred.transports } : {})
            }
          })
        }

        delete publicKey.hints

        console.log('Final publicKey object:', publicKey)
        console.log('Calling navigator.credentials.get()...')

        let assertion
        try {
          assertion = await navigator.credentials.get({ publicKey })
          console.log('navigator.credentials.get() SUCCEEDED')
          console.log('  Assertion ID:', assertion.id)
          console.log('  Assertion type:', assertion.type)
        } catch (credError) {
          console.error('navigator.credentials.get() FAILED:')
          console.error('  Error name:', credError.name)
          console.error('  Error message:', credError.message)
          console.error('  Error code:', credError.code)
          console.error('  Error stack:', credError.stack)
          console.error('  Full error:', credError)
          // Log all enumerable properties
          console.error('  Error properties:', Object.keys(credError))
          for (const key of Object.keys(credError)) {
            console.error(`    ${key}:`, credError[key])
          }
          throw credError
        }

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
      betaCode,
      handleRegister,
      handleLogin
    }
  }
}
</script>

<style scoped>
.logo {
  display: block;
  width: 220px;
  height: auto;
  margin: 0 auto 32px;
}

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

.register-section {
  margin-top: 32px;
  padding-top: 24px;
  border-top: 1px solid #e0e0e0;
}

.register-label {
  font-size: 14px;
  color: #666;
  margin-bottom: 12px;
  text-align: center;
}

.beta-code-input {
  width: 100%;
  padding: 12px 16px;
  font-size: 16px;
  border: 1px solid #ddd;
  border-radius: 8px;
  margin-bottom: 12px;
  box-sizing: border-box;
  font-family: 'Monaco', 'Courier New', monospace;
  text-align: center;
  letter-spacing: 2px;
}

.beta-code-input:focus {
  outline: none;
  border-color: #3498db;
  box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
}

.beta-code-input:disabled {
  background: #f5f5f5;
  cursor: not-allowed;
}
</style>
