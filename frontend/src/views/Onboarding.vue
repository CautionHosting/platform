<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="onboarding-container">
    <div class="onboarding-card">
      <div v-if="error" class="error-message">{{ error }}</div>

      <!-- Email Verification -->
      <div v-if="step === 1">
        <h1>Verify your email</h1>
        <p>Enter your email address to receive a verification link.</p>

        <form @submit.prevent="submitEmail">
          <label for="email">Email</label>
          <input
            id="email"
            v-model="email"
            type="email"
            placeholder="you@example.com"
            required
            :disabled="emailSent"
          />

          <button type="submit" class="btn-primary" :disabled="loading || emailSent">
            {{ emailSent ? 'Check your inbox' : 'Send verification link' }}
          </button>
        </form>

        <p v-if="emailSent" class="info-message">
          We sent a verification link to <strong>{{ email }}</strong>.
        </p>
      </div>

      <!-- Verified -->
      <div v-if="step === 2" class="verified">
        <h1>Your email has been successfully verified.</h1>
        <button @click="goToDashboard" class="btn-primary">Go to Dashboard</button>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { authFetch } from '../composables/useWebAuthn.js'

export default {
  name: 'Onboarding',
  setup() {
    const step = ref(0)
    const email = ref('')
    const emailSent = ref(false)
    const loading = ref(false)
    const error = ref(null)

    onMounted(async () => {
      try {
        const response = await authFetch('/api/user/status')
        if (response.ok) {
          const data = await response.json()
          step.value = data.email_verified ? 2 : 1
        } else if (response.status === 404) {
          step.value = 2
        } else {
          error.value = `Failed to load status (${response.status})`
          step.value = 1
        }
      } catch (err) {
        error.value = 'Failed to connect to server'
        step.value = 1
      }
    })

    const submitEmail = async () => {
      loading.value = true
      error.value = null
      try {
        const response = await authFetch('/api/onboarding/send-verification', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: email.value }),
        })
        const data = await response.json().catch(() => ({}))
        if (response.ok && data.success !== false) {
          emailSent.value = true
          pollEmailVerification()
        } else {
          error.value = data.error || data.message || 'Failed to send verification email'
        }
      } catch {
        error.value = 'Failed to connect to server'
      } finally {
        loading.value = false
      }
    }

    const pollEmailVerification = () => {
      const interval = setInterval(async () => {
        try {
          const response = await authFetch('/api/user/status')
          if (response.ok) {
            const data = await response.json()
            if (data.email_verified) {
              clearInterval(interval)
              step.value = 2
            }
          }
        } catch {
          // Continue polling
        }
      }, 3000)
    }

    const goToDashboard = () => {
      window.location.href = '/'
    }

    return { step, email, emailSent, loading, error, submitEmail, goToDashboard }
  },
}
</script>

<style scoped>
.onboarding-container {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 80vh;
  padding: 2rem;
}

.onboarding-card {
  background: white;
  border-radius: 12px;
  padding: 3rem;
  max-width: 440px;
  width: 100%;
  border: 1px solid var(--border-color-light, #eee);
}

h1 {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--color-text-primary, #0f0f0f);
  margin-bottom: 0.5rem;
}

p {
  color: var(--color-text-secondary, #666);
  font-size: 0.9rem;
  line-height: 1.5;
  margin-bottom: 1.5rem;
}

label {
  display: block;
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--color-text-primary, #0f0f0f);
  margin-bottom: 0.4rem;
}

input {
  width: 100%;
  padding: 0.7rem 0.85rem;
  border: 1px solid var(--border-color-medium, #ddd);
  border-radius: 8px;
  font-size: 0.9rem;
  font-family: inherit;
  margin-bottom: 1rem;
  box-sizing: border-box;
  transition: border-color 0.15s ease;
}

input:focus {
  outline: none;
  border-color: var(--color-primary-black, #0f0f0f);
}

input:disabled {
  background: var(--gray-100, #f5f5f5);
  cursor: not-allowed;
}

.btn-primary {
  width: 100%;
  padding: 0.7rem 1.5rem;
  background: var(--color-primary-black, #0f0f0f);
  color: white;
  border: none;
  border-radius: 8px;
  font-family: inherit;
  font-size: 0.95rem;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.15s ease;
}

.btn-primary:hover:not(:disabled) {
  background: #333;
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.error-message {
  background: var(--color-danger-bg, #fff5f5);
  border: 1px solid var(--color-danger-border, #ffcdd2);
  border-radius: 8px;
  padding: 0.7rem 1rem;
  color: var(--color-danger, #dc3545);
  margin-bottom: 1rem;
  font-size: 0.85rem;
}

.info-message {
  background: var(--color-info-bg, #e3f2fd);
  border-radius: 8px;
  padding: 0.7rem 1rem;
  color: var(--color-info, #1976d2);
  font-size: 0.85rem;
  margin-top: 0.5rem;
  margin-bottom: 0;
}

.verified {
  text-align: center;
}

.verified h1 {
  margin-bottom: 1.5rem;
}
</style>
