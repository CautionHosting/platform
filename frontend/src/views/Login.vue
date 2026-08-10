<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <AuthLayout
    center-left-panel
    :login-loading="loginLoading"
    @login="onHeaderLogin"
  >
    <template #left-panel>
      <template v-if="!isLoginMode">
        <h1 class="info-title">Need an access code?</h1>
        <p class="info access-code-copy">
          Book 20 minutes with an engineer to discuss your deployment. You’ll get
          answers, an access code, and clear next steps.
        </p>
        <a
          class="btn-light btn access-code-cta"
          href="https://caution.co/contact.html"
        >
          Book a call
          <svg
            aria-hidden="true"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <path d="M5 12h14" />
            <path d="m13 6 6 6-6 6" />
          </svg>
        </a>
      </template>
      <h1 v-else class="info-title login-signup-prompt">
        New here?<br />
        <a href="/" @click.prevent="isLoginMode = false">Create an account</a>.
      </h1>
    </template>

    <template #right-panel>
      <!-- Registration Form -->
      <div v-if="!authenticated && !isLoginMode" class="form-container">
        <h2 class="form-title">Create an account</h2>

        <div class="register-form register-form--compact">
          <div class="register-field" :class="{ 'register-field--error': validationError && !status && !error }">
            <input
              v-model="username"
              type="text"
              placeholder="Choose a username"
              class="register-input"
              autocomplete="username"
              data-testid="register-username"
              :disabled="loading"
              @keyup.enter="onRegister"
              @input="validationError = false"
            />
          </div>

          <div class="register-field" :class="{ 'register-field--error': validationError && !status && !error }">
            <input
              v-model="alphaCode"
              type="text"
              placeholder="Enter access code"
              class="register-input"
              data-testid="register-code"
              :disabled="loading"
              @keyup.enter="onRegister"
              @input="validationError = false"
            />
          </div>

          <button
            @click="onRegister"
            :disabled="loading || !username.trim()"
            class="btn-dark btn register-submit register-submit--full"
            data-testid="register-submit"
          >
            <svg class="btn-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg>
            {{ loading ? "Working..." : "Register with passkey" }}
          </button>

          <p v-if="activeLegalDocuments.length" class="tos-notice">
            By creating an account, you agree to the Caution
            <template v-for="(doc, index) in activeLegalDocuments" :key="doc.document_type">
              <a :href="doc.url" target="_blank" rel="noopener noreferrer">{{ doc.title.toLowerCase() }}</a
              ><template v-if="index < activeLegalDocuments.length - 2">, </template
              ><template v-else-if="index === activeLegalDocuments.length - 2"> and </template
              ></template>.
          </p>
          <p class="register-prompt account-switch">
            Already have an account?
            <a href="/login" @click.prevent="isLoginMode = true" class="link-btn">Log in</a>.
          </p>

        </div>

        <div class="messages-container">
          <div
            v-if="validationError && !status && !error"
            class="validation-message"
          >
            Please enter both a username and access code to continue.
          </div>

          <div v-if="status" class="status-message">
            {{ status }}
          </div>

          <div v-if="error" class="error-message">{{ error }}</div>
        </div>
      </div>

      <!-- Login Form -->
      <div v-else-if="!authenticated && isLoginMode" class="login-container">
        <h2 class="login-title">Welcome back</h2>

        <div class="register-form register-form--compact">
          <div class="register-field">
            <input
              v-model="loginUsername"
              type="text"
              placeholder="Enter your username"
              class="register-input"
              autocomplete="username"
              required
              :disabled="loginLoading"
              @keyup.enter="onLogin"
            />
          </div>

          <button
            @click="onLogin"
            :disabled="loginLoading || !loginUsername.trim()"
            class="btn-dark btn register-submit register-submit--full"
          >
            <svg class="btn-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg>
            {{ loginLoading ? "Working..." : "Log in with passkey" }}
          </button>
        </div>

        <p class="legacy-login-hint">
          No username yet? Run <code>caution login</code> in the Caution CLI to
          add one and log in.
        </p>

        <div class="login-messages">
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

// Keeps the complete registration layout visible when the Vite development
// server is running without the API. Production always uses the API response
// so the notice remains aligned with the documents recorded at signup.
const developmentLegalDocuments = [
  {
    document_type: "privacy_notice",
    title: "Privacy Notice",
    url: "https://caution.co/privacy.html",
  },
  {
    document_type: "terms_of_service",
    title: "Terms Of Service",
    url: "https://caution.co/terms.html",
  },
];

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
    const username = ref("");
    const validationError = ref(false);
    const isLoginMode = ref(false);
    const loginUsername = ref("");
    const activeLegalDocuments = ref([]);

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

      // Drives both what the registration notice shows and, via
      // gateway::create_user, what consent gets recorded at signup - keep
      // them backed by the same source instead of hardcoding link text here.
      try {
        const response = await fetch("/api/legal/active-documents");
        if (!response.ok) {
          throw new Error(`Failed to load legal documents: ${response.status}`);
        }

        activeLegalDocuments.value = await response.json();
      } catch {
        if (import.meta.env.DEV) {
          activeLegalDocuments.value = developmentLegalDocuments;
        }
        // In production, leave the list empty rather than showing stale links.
      }
    });

    async function onRegister() {
      const result = await handleRegister(alphaCode.value, username.value);
      if (result.validationError) {
        validationError.value = true;
      } else {
        validationError.value = false;
      }
    }

    async function onLogin() {
      await handleLogin(loginUsername.value.trim());
    }

    function onHeaderLogin() {
      isLoginMode.value = true;
    }

    return {
      authenticated,
      loading,
      loginLoading,
      error,
      status,
      alphaCode,
      username,
      validationError,
      isLoginMode,
      loginUsername,
      activeLegalDocuments,
      handleLogin,
      onRegister,
      onLogin,
      onHeaderLogin,
    };
  },
};
</script>
