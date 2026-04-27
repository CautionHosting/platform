<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <AuthLayout
    :login-loading="loginLoading"
    @login="handleLogin"
  >
    <template #access-text>
      Email
      <a
        href="mailto:info@caution.co?subject=Caution%20Early%20Access%20Inquiry&body=Hi%20Caution%20Team%2C%0A%0AI%20am%20interested%20in%20getting%20early%20access%20to%20Caution's%20managed%20services..."
        >info@caution.co</a
      > to request an access code.
    </template>

    <template #right-panel>
      <div v-if="!authenticated" class="form-container">
        <h2 class="form-title">Create an account</h2>

        <div class="register-form">
          <div class="register-field" :class="{ 'register-field--error': validationError && !status && !error }">
            <input
              v-model="alphaCode"
              type="text"
              placeholder="Enter code"
              class="register-input"
              :disabled="loading"
              @keyup.enter="onRegister"
              @input="validationError = false"
            />
            <button
              @click="onRegister"
              :disabled="loading"
              class="btn-dark btn register-submit"
            >
              <svg class="btn-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg>
              {{ loading ? "Working..." : "Register with passkey" }}
            </button>
          </div>

          <p class="tos-notice">
            By creating an account, you agree to the Caution
            <a href="https://caution.co/terms.html" target="_blank" rel="noopener noreferrer">terms of service</a>
            and
            <a href="https://caution.co/privacy.html" target="_blank" rel="noopener noreferrer">privacy notice</a>.
          </p>
          <p class="register-prompt account-switch">
            Already have an account?
            <a href="/login" @click.prevent="handleLogin" class="link-btn">Log in</a>.
          </p>

        </div>

        <div class="messages-container">
          <div
            v-if="validationError && !status && !error"
            class="validation-message"
          >
            Please enter a valid access code to continue.
          </div>

          <div v-if="status" class="status-message">
            {{ status }}
          </div>

          <div v-if="error" class="error-message">{{ error }}</div>
        </div>
      </div>

      <div v-else class="form-container">
        <p class="success-message">
          Authentication successful! Redirecting...
        </p>
      </div>
    </template>
  </AuthLayout>
</template>

<script>
import { ref, onMounted } from "vue";
import AuthLayout from "../components/AuthLayout.vue";
import { useWebAuthn } from "../composables/useWebAuthn.js";

export default {
  name: "Login",
  components: {
    AuthLayout,
  },
  props: {
    session: String,
  },
  setup(props) {
    const alphaCode = ref("");
    const validationError = ref(false);

    const {
      authenticated,
      loading,
      loginLoading,
      error,
      status,
      checkWebAuthnSupport,
      verifySession,
      handleLogin,
      handleRegister,
    } = useWebAuthn();

    onMounted(async () => {
      checkWebAuthnSupport();
      if (props.session) {
        await verifySession(props.session);
      }
    });

    async function onRegister() {
      const result = await handleRegister(alphaCode.value);
      if (result.validationError) {
        validationError.value = true;
      } else {
        validationError.value = false;
      }
    }

    return {
      authenticated,
      loading,
      loginLoading,
      error,
      status,
      alphaCode,
      validationError,
      handleLogin,
      onRegister,
    };
  },
};
</script>
