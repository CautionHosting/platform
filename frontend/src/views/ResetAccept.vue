<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <AuthLayout
    :login-loading="loginLoading"
    @login="handleLogin"
  >
    <template #access-text>
      Reset your passkey to regain access.
    </template>

    <template #right-panel>
      <div v-if="!authenticated" class="form-container">
        <h2 class="form-title">Set up a new passkey</h2>

        <div class="register-form">
          <button
            @click="resetPasskey"
            :disabled="loading"
            class="btn-dark btn register-submit"
          >
            <svg class="btn-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg>
            {{ loading ? "Working..." : "Set up new passkey" }}
          </button>

          <p class="register-prompt account-switch">
            Already have an account?
            <a href="/login" @click.prevent="handleLogin" class="link-btn">Log in</a>.
          </p>
        </div>

        <div class="messages-container">
          <div v-if="status" class="status-message">{{ status }}</div>
          <div v-if="error" class="error-message">{{ error }}</div>
        </div>
      </div>

      <div v-else class="form-container">
        <p class="success-message">Authentication successful! Redirecting...</p>
      </div>
    </template>
  </AuthLayout>
</template>

<script>
import { onMounted } from "vue";
import AuthLayout from "../components/AuthLayout.vue";
import { useWebAuthn } from "../composables/useWebAuthn.js";

export default {
  name: "ResetAccept",
  components: {
    AuthLayout,
  },
  setup() {
    const token = window.location.hash.slice(1) || "";

    const {
      authenticated,
      loading,
      loginLoading,
      error,
      status,
      checkWebAuthnSupport,
      handleLogin,
      registerWithPasskey,
    } = useWebAuthn();

    const resetPasskey = () => {
      return registerWithPasskey({
        beginUrl: "/auth/reset/begin",
        beginBody: { token },
        finishUrl: "/auth/reset/finish",
        validatingStatus: "Validating reset link...",
      });
    };

    onMounted(() => {
      checkWebAuthnSupport();
    });

    return {
      authenticated,
      loading,
      loginLoading,
      error,
      status,
      handleLogin,
      resetPasskey,
    };
  },
};
</script>
