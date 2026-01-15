<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <AuthLayout
    :login-loading="loginLoading"
    platform-text="CLI available for Linux x86_64 today"
    @login="handleLogin"
  >
    <template #extra-features>
      <li>
        Software is in alpha and <strong>not production ready</strong>
      </li>
    </template>

    <template #access-text>
      Enter your alpha code on the right to continue. If you don't have a
      code, request one at
      <a
        href="mailto:info@caution.co?subject=Caution%20Early%20Access%20Inquiry&body=Hi%20Caution%20Team%2C%0A%0AI%20am%20interested%20in%20getting%20early%20access%20to%20Caution's%20managed%20services..."
        >info@caution.co</a
      >.
    </template>

    <template #right-panel>
      <div v-if="!authenticated" class="form-container">
        <h2 class="form-title">Enter your alpha code</h2>

        <div
          class="input-group"
          :class="{
            'input-group--error': validationError && !status && !error,
          }"
        >
          <input
            v-model="alphaCode"
            type="text"
            placeholder="Enter alpha code"
            class="alpha-input"
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
        <p class="register-prompt">
          Already have an account?
          <a href="/login" @click.prevent="handleLogin" class="link-btn"
            >Log in</a
          >.
        </p>

        <div class="messages-container">
          <div
            v-if="validationError && !status && !error"
            class="validation-message"
          >
            Please enter a valid alpha code to continue.
          </div>

          <div v-if="status" class="status-message">
            {{ status }}
          </div>

          <div v-if="error" class="error-message" v-html="error"></div>
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
