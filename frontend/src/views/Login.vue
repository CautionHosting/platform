<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <AuthLayout
    :login-loading="loginLoading"
    platform-text="CLI available for Linux x86_64 today"
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
              placeholder="Enter access code"
              class="register-input"
              :disabled="loading"
              @keyup.enter="onRegister"
              @input="validationError = false"
            />
            <button
              @click="onRegister"
              :disabled="loading"
              class="btn-dark btn"
            >
              {{ loading ? "Working..." : "Continue" }}
            </button>
          </div>

        </div>

        <div class="form-footer">
          <p class="register-prompt">
            Already have an account?
            <a href="/login" @click.prevent="handleLogin" class="link-btn">Log in</a>.
          </p>
          <p class="form-footer-legal">
            <a href="https://caution.co/terms.html" target="_blank" rel="noopener noreferrer">Terms of Service</a>
            <span class="form-footer-dot">|</span>
            <a href="https://caution.co/privacy.html" target="_blank" rel="noopener noreferrer">Privacy Notice</a>
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
