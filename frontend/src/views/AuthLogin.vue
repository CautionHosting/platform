<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="login-page">
    <!-- Mobile Menu Overlay -->
    <div
      class="mobile-menu-overlay"
      :class="{ active: mobileMenuOpen }"
      @click="closeMobileMenu"
    ></div>

    <!-- Main Content -->
    <div class="login-split">
      <!-- Left Panel - Dark -->
      <div class="left-panel">
        <div class="left-content">
          <h1 class="tagline">Get started with verified enclave deployments</h1>
        </div>
      </div>

      <!-- Right Panel - Light -->
      <div class="right-panel">
        <div class="right-content">
          <div v-if="error" class="error-message">
            {{ error }}
          </div>

          <div v-if="status" class="status-message">
            {{ status }}
          </div>

          <div v-if="!authenticated" class="form-container">
            <p class="eyebrow">EARLY ACCESS</p>
            <h2 class="form-title">Use your smart card to log in</h2>

            <button
              @click="handleLogin"
              :disabled="loading"
              class="btn login-cta"
            >
              {{ loading ? "Authenticating..." : "Log in" }}
            </button>

            <p class="register-prompt">
              Need an account?
              <a href="/" class="link-btn">
                Get started
              </a>
            </p>
          </div>

          <div v-else class="form-container">
            <p class="success-message">
              Authentication successful! Redirecting...
            </p>
          </div>
        </div>
      </div>
    </div>

  </div>
</template>

<script>
import { ref, onMounted } from "vue";

// Helper to convert base64url to Uint8Array
function base64urlToUint8Array(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Helper to convert Uint8Array to base64url
function uint8ArrayToBase64url(array) {
  const binary = String.fromCharCode(...array);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export default {
  name: "AuthLogin",
  props: {
    session: String,
  },
  setup(props) {
    const authenticated = ref(false);
    const loading = ref(false);
    const error = ref(null);
    const status = ref(null);
    const mobileMenuOpen = ref(false);

    const closeMobileMenu = () => {
      mobileMenuOpen.value = false;
    };

    onMounted(async () => {
      // Check for WebAuthn support
      if (!window.PublicKeyCredential) {
        error.value =
          "Your browser does not support FIDO2/WebAuthn. Please use Chrome, Firefox, or Safari.";
        return;
      }

      if (props.session) {
        try {
          // Verify session and check onboarding status
          const response = await fetch("/api/user/status", {
            headers: {
              "X-Session-ID": props.session,
            },
          });

          if (response.ok) {
            authenticated.value = true;
            window.location.href = `/dashboard?session=${props.session}`;
          } else {
            error.value = "Invalid session. Please authenticate using the CLI.";
          }
        } catch (err) {
          error.value = "Failed to verify session. Please try again.";
        }
      }
    });

    async function handleLogin(e) {
      // Prevent default redirect behavior from header component
      if (e && e.preventDefault) {
        e.preventDefault();
      }

      error.value = null;
      status.value = null;
      loading.value = true;

      try {
        // Step 1: Begin login
        status.value = "Starting login...";
        const beginResponse = await fetch("/auth/login/begin", {
          method: "POST",
          credentials: "include",
        });

        if (!beginResponse.ok) {
          const errorText = await beginResponse.text();
          throw new Error(errorText || "Failed to begin login");
        }

        const beginData = await beginResponse.json();

        // Step 2: Get assertion from security key
        status.value = "Please tap your security key...";

        const publicKey = beginData.publicKey;
        publicKey.challenge = base64urlToUint8Array(publicKey.challenge);

        if (publicKey.allowCredentials) {
          publicKey.allowCredentials = publicKey.allowCredentials.map(
            (cred) => ({
              type: cred.type,
              id: base64urlToUint8Array(cred.id),
              ...(cred.transports && cred.transports.length > 0
                ? { transports: cred.transports }
                : {}),
            })
          );
        }

        delete publicKey.hints;

        let assertion;
        try {
          assertion = await navigator.credentials.get({ publicKey });
        } catch (credError) {
          console.error("WebAuthn error:", credError);
          throw credError;
        }

        if (!assertion) {
          throw new Error("No assertion received");
        }

        // Step 3: Finish login
        status.value = "Completing login...";

        const authenticatorData = new Uint8Array(
          assertion.response.authenticatorData
        );
        const clientDataJSON = new Uint8Array(
          assertion.response.clientDataJSON
        );
        const signature = new Uint8Array(assertion.response.signature);

        const finishResponse = await fetch("/auth/login/finish", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            id: assertion.id,
            rawId: uint8ArrayToBase64url(new Uint8Array(assertion.rawId)),
            type: assertion.type,
            response: {
              authenticatorData: uint8ArrayToBase64url(authenticatorData),
              clientDataJSON: uint8ArrayToBase64url(clientDataJSON),
              signature: uint8ArrayToBase64url(signature),
              userHandle: assertion.response.userHandle
                ? uint8ArrayToBase64url(
                    new Uint8Array(assertion.response.userHandle)
                  )
                : null,
            },
            session: beginData.session,
          }),
        });

        if (!finishResponse.ok) {
          const errorText = await finishResponse.text();
          throw new Error(errorText || "Failed to complete login");
        }

        const result = await finishResponse.json();
        authenticated.value = true;
        status.value = "Login successful!";

        // Redirect to dashboard
        setTimeout(() => {
          window.location.href = `/dashboard?session=${result.session_id}`;
        }, 1000);
      } catch (err) {
        error.value = err.message || "Login failed. Please try again.";
        status.value = null;
      } finally {
        loading.value = false;
      }
    }

    return {
      authenticated,
      loading,
      error,
      status,
      mobileMenuOpen,
      closeMobileMenu,
      handleLogin,
    };
  },
};
</script>

<style scoped>
/* Login Page Container */
.login-page {
  width: 100%;
  min-height: 100vh;
  overflow-x: hidden;
}

/* Mobile Menu Blur Overlay */
.mobile-menu-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  opacity: 0;
  visibility: hidden;
  transition: opacity 0.3s ease, visibility 0.3s ease;
  z-index: 9998;
}

.mobile-menu-overlay.active {
  opacity: 1;
  visibility: visible;
}

@media (min-width: 769px) {
  .mobile-menu-overlay {
    display: none;
  }
}

/* ==========================================================================
   SPLIT LAYOUT
   ========================================================================== */

.login-split {
  display: flex;
  width: 100%;
  height: 100vh;
  overflow: hidden;
}

/* Left Panel - Dark */
.left-panel {
  flex: 1;
  background: var(--color-dark);
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: flex-end;
  padding: 40px;
  padding-top: 120px;
  overflow: hidden;
}

.left-content {
  width: 95%;
  max-width: 725px;
  padding: 60px 40px 60px 0;
}

.tagline {
  font-size: clamp(2.3rem, 4vw, 3.7rem);
  font-weight: 550;
  color: white;
  line-height: 1.15;
}

/* Right Panel - Light */
.right-panel {
  flex: 1;
  background: radial-gradient(circle at 50% 25%, white 0%, transparent 60%)
      no-repeat,
    var(--color-blue-light);
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: flex-start;
  position: relative;
  padding-top: 100px;
  overflow: hidden;
}

/* Right Content */
.right-content {
  width: 95%;
  max-width: 725px;
  height: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px 0 40px 40px;
  position: relative;
}

.form-container {
  text-align: center;
  max-width: 600px;
  width: 100%;
}

.register-prompt {
  margin-top: 40px;
  font-size: clamp(0.85rem, 2vw, 1rem);
  color: #666;
}

.eyebrow {
  font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", Menlo, Consolas,
    "Courier New", monospace;
  font-size: 12px;
  font-weight: 500;
  letter-spacing: 0.1em;
  color: #666;
  margin-bottom: 16px;
}

.form-title {
  font-size: clamp(2.3rem, 4vw, 3rem);
  font-weight: 550;
  color: #0f0f0f;
  margin-bottom: 32px;
}

/* Login CTA Button - styled like nav CTA */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--spacing3);
  text-align: center;
  text-decoration: none;
  cursor: pointer;
  white-space: nowrap;
  position: relative;
  font-size: clamp(0.9rem, 2vw, 1.05rem);
  font-weight: 400;
  font-family: inherit;
  color: white;
  letter-spacing: 0.02em;
  padding: 12px 32px;
  border-radius: 60px;
  background: linear-gradient(
    180deg,
    rgb(55, 55, 55) 0%,
    rgb(35, 35, 35) 40%,
    rgb(25, 25, 25) 100%
  );
  border: 1.5px solid rgba(80, 80, 80, 0.6);
  outline: 1px solid rgba(0, 0, 0, 0.8);
  outline-offset: 0px;
  box-shadow: inset 0 1px 0 0 rgba(255, 255, 255, 0.08),
    inset 0 0 20px 0 rgba(255, 255, 255, 0.03);
  transition: all 0.3s ease;
}

.btn::before {
  content: "";
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  height: 100%;
  background: radial-gradient(
    ellipse 75% 35% at center bottom,
    rgba(255, 255, 255, 0.2) 0%,
    rgba(255, 255, 255, 0.08) 25%,
    rgba(255, 255, 255, 0.02) 50%,
    transparent 70%
  );
  pointer-events: none;
  border-radius: 60px;
  transition: background 0.3s ease;
}

.btn:hover {
  color: var(--color-pink);
  box-shadow: inset 0 1px 0 0 rgba(255, 255, 255, 0.12),
    inset 0 0 20px 0 rgba(255, 255, 255, 0.05);
}

.btn:hover::before {
  background: radial-gradient(
    ellipse 75% 40% at center bottom,
    rgba(255, 255, 255, 0.22) 0%,
    rgba(255, 255, 255, 0.14) 25%,
    rgba(255, 255, 255, 0.04) 50%,
    transparent 70%
  );
}

.btn:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.link-btn {
  color: #666;
  font-size: clamp(0.75rem, 2vw, 1rem);
  font-weight: 500;
  text-decoration: underline;
  margin-left: 4px;
  transition: color 0.3s ease;
}

.link-btn:hover {
  color: var(--color-pink);
}

/* Messages */
.error-message {
  background: #fee;
  border: 1px solid #fcc;
  border-radius: 8px;
  padding: 12px 16px;
  color: #c33;
  margin-bottom: 20px;
  font-size: 14px;
  text-align: center;
}

.status-message {
  background: rgba(255, 255, 255, 0.9);
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 12px 16px;
  color: #333;
  margin-bottom: 20px;
  font-size: 14px;
  text-align: center;
}

.success-message {
  background: #efe;
  border: 1px solid #cfc;
  border-radius: 8px;
  padding: 12px 16px;
  color: #2e7d32;
  text-align: center;
  font-size: 14px;
}

/* ==========================================================================
   RESPONSIVE
   ========================================================================== */

@media (max-width: 768px) {
  .left-panel {
    display: none;
  }

  .right-panel {
    flex: 1;
    width: 100%;
    align-items: center;
    padding-top: 80px;
  }

  .right-content {
    max-width: 100%;
    padding: 24px;
  }

  .form-title {
    font-size: clamp(1.75rem, 4vw, 2.75rem);
  }
}
</style>
