<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="onboarding-container">
    <div class="onboarding-card">
      <h1>Complete Your Setup</h1>
      <p class="subtitle">Just one step to get started</p>

      <div v-if="error" class="error-message">
        {{ error }}
      </div>

      <!-- Step 1: Email Verification -->
      <div v-if="step === 1" class="step-content">
        <h2>Verify Your Email</h2>
        <p>Enter your email address to receive a verification link.</p>

        <form @submit.prevent="submitEmail">
          <div class="form-group">
            <label for="email">Email Address</label>
            <input
              id="email"
              v-model="email"
              type="email"
              placeholder="you@example.com"
              required
              :disabled="emailSent"
            />
          </div>

          <button type="submit" class="btn-primary" :disabled="loading || emailSent">
            {{ emailSent ? 'Email Sent - Check Your Inbox' : 'Send Verification Email' }}
          </button>
        </form>

        <p v-if="emailSent" class="info-message">
          We've sent a verification link to {{ email }}. Click the link in the email to continue.
        </p>
      </div>

      <!-- Step 2: Complete -->
      <div v-if="step === 2" class="step-content">
        <div class="success-icon">✓</div>
        <h2>You're All Set!</h2>
        <p>Your account is ready. You can now create and deploy applications.</p>

        <button @click="goToDashboard" class="btn-primary">
          Go to Dashboard
        </button>
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
    const step = ref(1)
    const email = ref('')
    const emailSent = ref(false)
    const loading = ref(false)
    const error = ref(null)

    onMounted(async () => {
      // Check onboarding status
      try {
        const response = await authFetch('/api/user/status')

        if (response.ok) {
          const data = await response.json()

          if (data.email_verified) {
            // Email verified, go to complete step
            step.value = 2
          } else {
            step.value = 1
          }
        } else if (response.status === 404) {
          // User status endpoint not found, skip to dashboard
          step.value = 2
        } else {
          const errorText = await response.text()
          error.value = `Failed to load user status (${response.status})`
          console.error('Status check failed:', response.status, errorText)
        }
      } catch (err) {
        error.value = `Failed to connect to server: ${err.message}`
        console.error('Status check error:', err)
      }
    })

    const submitEmail = async () => {
      loading.value = true
      error.value = null

      try {
        const response = await authFetch('/api/onboarding/send-verification', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ email: email.value })
        })

        if (response.ok) {
          emailSent.value = true
          // Poll for email verification
          pollEmailVerification()
        } else {
          const data = await response.json()
          error.value = data.error || 'Failed to send verification email'
        }
      } catch (err) {
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
        } catch (err) {
          // Continue polling
        }
      }, 3000)
    }

    const goToDashboard = () => {
      window.location.href = '/dashboard'
    }

    return {
      step,
      email,
      emailSent,
      loading,
      error,
      submitEmail,
      goToDashboard
    }
  }
}
</script>

<style scoped>
.onboarding-container {
  width: 100%;
  max-width: 600px;
  margin: 0 auto;
}

.onboarding-card {
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

h2 {
  font-size: 24px;
  font-weight: 600;
  color: #333;
  margin-bottom: 12px;
}

.subtitle {
  font-size: 16px;
  color: #666;
  text-align: center;
  margin-bottom: 32px;
}

.step-content {
  margin-top: 32px;
}

.step-content p {
  color: #666;
  margin-bottom: 24px;
  font-size: 14px;
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  font-size: 14px;
  font-weight: 500;
  color: #333;
  margin-bottom: 8px;
}

.form-group input {
  width: 100%;
  padding: 12px 16px;
  border: 1px solid #ddd;
  border-radius: 8px;
  font-size: 14px;
  transition: border-color 0.2s ease;
  box-sizing: border-box;
}

.form-group input:focus {
  outline: none;
  border-color: #667eea;
}

.form-group input:disabled {
  background: #f5f5f5;
  cursor: not-allowed;
}

.btn-primary {
  width: 100%;
  padding: 14px 24px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
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

.info-message {
  background: #e7f3ff;
  border: 1px solid #b3d9ff;
  border-radius: 8px;
  padding: 12px 16px;
  color: #0066cc;
  margin-top: 16px;
  font-size: 14px;
}

.success-icon {
  width: 80px;
  height: 80px;
  border-radius: 50%;
  background: #48bb78;
  color: white;
  font-size: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 24px;
}
</style>