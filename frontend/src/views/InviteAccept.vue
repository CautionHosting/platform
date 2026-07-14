<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <AuthLayout
    :login-loading="loginLoading"
    @login="handleLogin"
  >
    <template #access-text>
      Accept your organization invite with a passkey.
    </template>

    <template #right-panel>
      <div v-if="!authenticated" class="form-container">
        <h2 class="form-title">Join {{ invite?.organization_name || "Caution" }}</h2>

        <div v-if="loadingInvite" class="status-message">Loading invite...</div>
        <div v-else-if="inviteError" class="error-message">{{ inviteError }}</div>
        <div v-else class="register-form">
          <p class="tos-notice">
            You are joining as {{ invite.email }}. By creating an account, you agree to the Caution
            <a href="https://caution.co/terms.html" target="_blank" rel="noopener noreferrer">terms of service</a>
            and
            <a href="https://caution.co/privacy.html" target="_blank" rel="noopener noreferrer">privacy notice</a>.
          </p>

          <button
            @click="acceptInvite"
            :disabled="loading"
            class="btn-dark btn register-submit"
          >
            <svg class="btn-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg>
            {{ loading ? "Working..." : "Register with passkey" }}
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
import { onMounted, ref } from "vue";
import AuthLayout from "../components/AuthLayout.vue";
import { useWebAuthn } from "../composables/useWebAuthn.js";

export default {
  name: "InviteAccept",
  components: {
    AuthLayout,
  },
  setup() {
    const invite = ref(null);
    const inviteError = ref("");
    const loadingInvite = ref(true);
    const token = new URLSearchParams(window.location.search).get("token") || "";

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

    const loadInvite = async () => {
      if (!token) {
        inviteError.value = "Invalid invite link.";
        loadingInvite.value = false;
        return;
      }

      try {
        const response = await fetch(`/auth/invite?token=${encodeURIComponent(token)}`, {
          credentials: "include",
        });
        if (!response.ok) {
          throw new Error(await response.text());
        }
        invite.value = await response.json();
      } catch (err) {
        inviteError.value = err.message || "Invalid invite link.";
      } finally {
        loadingInvite.value = false;
      }
    };

    const acceptInvite = () => {
      return registerWithPasskey({
        beginUrl: "/auth/invite/register/begin",
        beginBody: { token },
        finishUrl: "/auth/invite/register/finish",
        validatingStatus: "Validating invitation...",
      });
    };

    onMounted(() => {
      checkWebAuthnSupport();
      loadInvite();
    });

    return {
      invite,
      inviteError,
      loadingInvite,
      authenticated,
      loading,
      loginLoading,
      error,
      status,
      handleLogin,
      acceptInvite,
    };
  },
};
</script>
