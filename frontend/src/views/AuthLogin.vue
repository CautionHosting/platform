<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <AuthLayout
    :login-loading="loginLoading"
    platform-text="CLI available for Linux x86_64 today"
    @login="handleLogin"
  >
    <template #access-text>
      Log in with your security key on the right. New to Caution?
      Create an account with an access code <a href="/">here</a>.
    </template>

    <template #right-panel>
      <div v-if="!authenticated" class="login-container">
        <h2 class="login-title">Welcome back</h2>

        <button
          @click="handleLogin"
          :disabled="loading"
          class="btn-dark btn login-btn"
        >
          <svg class="btn-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg>
          {{ loading ? "Authenticating..." : "Log in with security key" }}
        </button>

        <p class="login-prompt">
          New here?
          <a href="/" class="link-btn">Create an account</a>.
        </p>

        <div class="login-messages">
          <div v-if="status" class="status-message">
            {{ status }}
          </div>

          <div v-if="error" class="error-message">{{ error }}</div>
        </div>
      </div>

      <div v-else class="login-container">
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
  name: "AuthLogin",
  components: {
    AuthLayout,
  },
  props: {
    session: String,
  },
  setup(props) {
    const {
      authenticated,
      loading,
      loginLoading,
      error,
      status,
      checkWebAuthnSupport,
      verifySession,
      handleLogin,
    } = useWebAuthn();

    onMounted(async () => {
      checkWebAuthnSupport();
      if (props.session) {
        await verifySession(props.session);
      }
    });

    return {
      authenticated,
      loading,
      loginLoading,
      error,
      status,
      handleLogin,
    };
  },
};
</script>
