<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <AuthLayout
    :login-loading="loginLoading"
    platform-text="CLI available for Linux x86_64 today"
    @login="handleLogin"
  >
    <template #access-text>
      Click <strong>Log in</strong> on the right to continue. New to Caution?
      Create an account with an access code <a href="/">here</a>.
    </template>

    <template #right-panel>
      <div v-if="!authenticated" class="login-container">
        <h2 class="login-title">
          Log in with<br />
          your security key
        </h2>

        <button
          @click="handleLogin"
          :disabled="loading"
          class="btn-dark btn login-btn"
        >
          {{ loading ? "Authenticating..." : "Log in" }}
        </button>

        <p class="login-prompt">
          New to Caution?
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
