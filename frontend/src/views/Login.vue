<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="login-page">
    <!-- Header Navbar -->
    <header class="header-navbar">
      <div class="container">
        <nav class="nav-top-bar">
          <!-- Logo -->
          <a href="https://caution.co/" class="nav-logo">
            <img
              src="../assets/caution-logo-white.svg"
              alt="Caution"
              class="logo-desktop"
            />
            <img
              src="../assets/caution-logo-black.svg"
              alt="Caution"
              class="logo-mobile"
            />
          </a>

          <!-- Desktop Navigation -->
          <div class="nav-desktop">
            <a href="https://caution.co/about.html" class="nav-link">About</a>
            <a href="https://caution.co/blog.html" class="nav-link">Blog</a>
            <button
              @click="handleLogin"
              :disabled="loading"
              class="nav-link nav-login-btn"
            >
              Log in
            </button>
            <a href="https://caution.co/early-access.html" class="nav-cta">
              Get early access
            </a>
          </div>

          <!-- Mobile Menu Button -->
          <button
            class="mobile-menu-button"
            aria-label="Toggle menu"
            @click="toggleMobileMenu"
          >
            <span class="hamburger">
              <span class="hamburger-line"></span>
              <span class="hamburger-line"></span>
              <span class="hamburger-line"></span>
            </span>
          </button>
        </nav>

        <!-- Mobile Menu -->
        <div class="mobile-menu" :class="{ active: mobileMenuOpen }">
          <div class="mobile-menu-content">
            <a href="https://caution.co/about.html" class="mobile-menu-link"
              >About</a
            >
            <a href="https://codeberg.org/Caution/" class="mobile-menu-link"
              >Source</a
            >
            <a href="https://caution.co/blog.html" class="mobile-menu-link"
              >Blog</a
            >
            <button
              @click="
                handleLogin;
                closeMobileMenu();
              "
              :disabled="loading"
              class="mobile-menu-link mobile-login-btn"
            >
              Log in
            </button>
            <a
              href="https://caution.co/early-access.html"
              class="mobile-menu-cta"
            >
              Get early access
            </a>
          </div>
        </div>
      </div>
    </header>

    <!-- Mobile Menu Overlay -->
    <div
      class="mobile-menu-overlay"
      :class="{ active: mobileMenuOpen }"
      @click="closeMobileMenu"
    ></div>

    <!-- Main Content -->
    <div class="login-split" :class="{ 'mobile-menu-open': mobileMenuOpen }">
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
            <h2 class="form-title">Enter your alpha code</h2>

            <div class="input-group">
              <input
                v-model="betaCode"
                type="text"
                placeholder="Enter alpha code"
                class="alpha-input"
                :disabled="loading"
                @keyup.enter="handleRegister"
              />
              <button
                @click="handleRegister"
                :disabled="loading || !betaCode.trim()"
                class="btn"
              >
                {{ loading ? "Working..." : "Get started" }}
              </button>
            </div>

            <p class="login-prompt">
              Already have an account?
              <button @click="handleLogin" :disabled="loading" class="link-btn">
                Log in
              </button>
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
  name: "Login",
  props: {
    session: String,
  },
  setup(props) {
    const authenticated = ref(false);
    const loading = ref(false);
    const error = ref(null);
    const status = ref(null);
    const betaCode = ref("");
    const mobileMenuOpen = ref(false);

    const toggleMobileMenu = () => {
      mobileMenuOpen.value = !mobileMenuOpen.value;
    };

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

    async function handleRegister() {
      error.value = null;
      status.value = null;
      loading.value = true;

      try {
        // Step 1: Begin registration with beta code
        status.value = "Validating alpha code...";
        const beginResponse = await fetch("/auth/register/begin", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ beta_code: betaCode.value.trim() }),
        });

        if (!beginResponse.ok) {
          const errorText = await beginResponse.text();
          throw new Error(errorText || "Failed to begin registration");
        }

        const beginData = await beginResponse.json();

        // Step 2: Create credential with security key
        status.value = "Please tap your security key...";

        const publicKey = beginData.publicKey;
        console.log(
          "Registration publicKey from server:",
          JSON.stringify(publicKey, null, 2)
        );
        console.log("Registration RP ID:", publicKey.rp?.id);
        console.log("Registration RP Name:", publicKey.rp?.name);

        publicKey.challenge = base64urlToUint8Array(publicKey.challenge);
        publicKey.user.id = base64urlToUint8Array(publicKey.user.id);

        console.log("About to call navigator.credentials.create()");
        const credential = await navigator.credentials.create({ publicKey });
        console.log("Credential created successfully:", credential?.id);

        if (!credential) {
          throw new Error("No credential created");
        }

        // Step 3: Finish registration
        status.value = "Completing registration...";

        const attestationObject = new Uint8Array(
          credential.response.attestationObject
        );
        const clientDataJSON = new Uint8Array(
          credential.response.clientDataJSON
        );

        const finishResponse = await fetch("/auth/register/finish", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            id: credential.id,
            rawId: uint8ArrayToBase64url(new Uint8Array(credential.rawId)),
            type: credential.type,
            response: {
              attestationObject: uint8ArrayToBase64url(attestationObject),
              clientDataJSON: uint8ArrayToBase64url(clientDataJSON),
            },
            session: beginData.session,
          }),
        });

        if (!finishResponse.ok) {
          const errorText = await finishResponse.text();
          throw new Error(errorText || "Failed to complete registration");
        }

        const result = await finishResponse.json();
        authenticated.value = true;
        status.value = "Registration successful!";

        // Redirect to dashboard
        setTimeout(() => {
          window.location.href = `/dashboard?session=${result.session_id}`;
        }, 1000);
      } catch (err) {
        error.value = err.message || "Registration failed. Please try again.";
      } finally {
        loading.value = false;
      }
    }

    async function handleLogin() {
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

        console.log("Raw beginData:", JSON.stringify(beginData, null, 2));

        const publicKey = beginData.publicKey;
        console.log("publicKey.rpId:", publicKey.rpId);
        console.log(
          "publicKey.challenge (before conversion):",
          publicKey.challenge
        );
        console.log(
          "publicKey.allowCredentials (before conversion):",
          publicKey.allowCredentials
        );

        publicKey.challenge = base64urlToUint8Array(publicKey.challenge);

        if (publicKey.allowCredentials) {
          publicKey.allowCredentials = publicKey.allowCredentials.map(
            (cred) => {
              console.log(
                "Converting credential:",
                JSON.stringify(cred, null, 2)
              );
              console.log("  ID:", cred.id);
              console.log("  Type:", cred.type);
              console.log("  Transports:", cred.transports);
              return {
                type: cred.type,
                id: base64urlToUint8Array(cred.id),
                // Only include transports if they exist and are valid
                ...(cred.transports && cred.transports.length > 0
                  ? { transports: cred.transports }
                  : {}),
              };
            }
          );
        }

        delete publicKey.hints;

        console.log("Final publicKey object:", publicKey);
        console.log("Calling navigator.credentials.get()...");

        let assertion;
        try {
          assertion = await navigator.credentials.get({ publicKey });
          console.log("navigator.credentials.get() SUCCEEDED");
          console.log("  Assertion ID:", assertion.id);
          console.log("  Assertion type:", assertion.type);
        } catch (credError) {
          console.error("navigator.credentials.get() FAILED:");
          console.error("  Error name:", credError.name);
          console.error("  Error message:", credError.message);
          console.error("  Error code:", credError.code);
          console.error("  Error stack:", credError.stack);
          console.error("  Full error:", credError);
          // Log all enumerable properties
          console.error("  Error properties:", Object.keys(credError));
          for (const key of Object.keys(credError)) {
            console.error(`    ${key}:`, credError[key]);
          }
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
      } finally {
        loading.value = false;
      }
    }

    return {
      authenticated,
      loading,
      error,
      status,
      betaCode,
      mobileMenuOpen,
      toggleMobileMenu,
      closeMobileMenu,
      handleRegister,
      handleLogin,
    };
  },
};
</script>

<style scoped>
/* Login Page Container */
.login-page {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  width: 100vw;
  height: 100vh;
  overflow: hidden;
}

/* ==========================================================================
   HEADER & NAVIGATION
   ========================================================================== */

.header-navbar {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  z-index: 9999;
  transform: translateY(0);
  transition: transform 0.3s ease-in-out, background 0.3s ease,
    backdrop-filter 0.3s ease;
}

.header-navbar.navbar--hidden {
  transform: translateY(-100%);
}

.header-navbar.navbar--scrolled {
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
}

.container {
  width: 95%;
  max-width: 1450px;
  margin: 0 auto;
}

@media (max-width: 900px) {
  .container {
    width: 90%;
  }
}

.nav-top-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px 0;
  margin: 16px auto 0 auto;
  position: relative;
}

@media (max-width: 480px) {
  .nav-top-bar {
    margin: var(--spacing1) auto 0 auto;
    padding: var(--spacing3) 0;
  }
}

/* Nav Logo */
.nav-logo {
  max-width: 190px;
  display: block;
}

.nav-logo img {
  width: auto;
  height: clamp(1.6rem, 3.5vw, 2.2rem);
  opacity: 0.85;
  transition: opacity 0.3s ease;
}

.nav-logo img:hover {
  opacity: 1;
}

/* Show white logo on desktop, black on mobile/tablet */
.logo-mobile {
  display: none;
}

@media (max-width: 900px) {
  .logo-desktop {
    display: none;
  }

  .logo-mobile {
    display: block;
  }
}

/* Desktop Navigation */
.nav-desktop {
  display: none;
  gap: 30px;
  align-items: center;
}

@media (min-width: 769px) {
  .nav-desktop {
    display: flex;
  }
}

/* Nav Links - Plain text style */
.nav-link {
  color: #333;
  text-decoration: none;
  font-size: clamp(1rem, 2vw, 1.05rem);
  font-weight: 450;
  transition: color 0.3s ease;
  position: relative;
  z-index: 1;
}

.nav-link:hover {
  color: var(--color-pink);
}

/* Nav Login Button - styled like a link */
.nav-login-btn {
  background: none;
  border: none;
  cursor: pointer;
  font-family: inherit;
}

.nav-login-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

/* Nav CTA Button */
.nav-cta {
  display: inline-flex;
  align-items: center;
  gap: var(--spacing3);
  text-align: center;
  text-decoration: none;
  cursor: pointer;
  white-space: nowrap;
  position: relative;
  font-size: clamp(0.7rem, 2vw, 1.05rem);
  font-weight: 400;
  color: white;
  letter-spacing: 0.02em;
  padding: 8px 20px;
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

.nav-cta::before {
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

.nav-cta:hover {
  color: var(--color-pink);
  box-shadow: inset 0 1px 0 0 rgba(255, 255, 255, 0.12),
    inset 0 0 20px 0 rgba(255, 255, 255, 0.05);
}

.nav-cta:hover::before {
  background: radial-gradient(
    ellipse 75% 40% at center bottom,
    rgba(255, 255, 255, 0.22) 0%,
    rgba(255, 255, 255, 0.14) 25%,
    rgba(255, 255, 255, 0.04) 50%,
    transparent 70%
  );
}

/* Mobile Menu Button */
.mobile-menu-button {
  display: inline-flex;
  height: 40px;
  width: 40px;
  align-items: center;
  justify-content: center;
  border: none;
  background: none;
  cursor: pointer;
}

@media (min-width: 769px) {
  .mobile-menu-button {
    display: none;
  }
}

.hamburger {
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  width: 28px;
  height: 18px;
  position: relative;
}

.hamburger-line {
  display: block;
  width: 100%;
  height: 2px;
  background-color: white;
  border-radius: 2px;
  transition: transform 0.3s ease, opacity 0.3s ease, background-color 0.3s ease;
  transform-origin: center;
}

@media (max-width: 900px) {
  .hamburger-line {
    background-color: #0f0f0f;
  }

  /* When mobile menu is open, make header dark and hamburger white */
  .login-page:has(.mobile-menu.active) .header-navbar {
    background: #0f0f0f;
  }

  .login-page:has(.mobile-menu.active) .hamburger-line {
    background-color: white;
  }

  .login-page:has(.mobile-menu.active) .logo-mobile {
    display: none;
  }

  .login-page:has(.mobile-menu.active) .logo-desktop {
    display: block;
  }
}

/* X state when menu is open */
.login-page:has(.mobile-menu.active) .hamburger-line:nth-child(1) {
  transform: translateY(8px) rotate(45deg);
}

.login-page:has(.mobile-menu.active) .hamburger-line:nth-child(2) {
  opacity: 0;
}

.login-page:has(.mobile-menu.active) .hamburger-line:nth-child(3) {
  transform: translateY(-8px) rotate(-45deg);
}

/* Mobile Menu */
.mobile-menu {
  margin-top: 0;
  max-height: 0;
  overflow: hidden;
  transition: max-height 0.3s ease;
}

.mobile-menu.active {
  max-height: 400px;
}

@media (min-width: 769px) {
  .mobile-menu {
    display: none !important;
  }
}

.mobile-menu-content {
  padding: var(--spacing2);
  display: grid;
  grid-template-columns: 1fr;
  gap: 1rem;
}

.mobile-menu-link {
  display: block;
  border-radius: var(--radius-sm);
  padding: 8px 0;
  font-size: 1.2rem;
  color: white;
  text-decoration: none;
  transition: background-color 0.3s ease, color 0.3s ease;
}

.mobile-menu-link:hover {
  background-color: rgba(255, 255, 255, 0.1);
  color: var(--color-pink);
}

/* Mobile Login Button - styled like a link */
.mobile-login-btn {
  background: none;
  border: none;
  cursor: pointer;
  font-family: inherit;
  text-align: left;
  width: 100%;
}

.mobile-login-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.mobile-menu-cta {
  margin: 8px auto;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--spacing2);
  text-decoration: none;
  width: 100%;
  position: relative;
  font-size: 1.15rem;
  font-weight: 400;
  color: white;
  letter-spacing: 0.02em;
  padding: 12px 24px;
  border-radius: 60px;
  background: linear-gradient(
    180deg,
    rgba(55, 55, 55, 1) 0%,
    rgba(35, 35, 35, 1) 40%,
    rgba(25, 25, 25, 1) 100%
  );
  border: 1.5px solid rgba(80, 80, 80, 0.6);
  outline: 1px solid rgba(0, 0, 0, 0.8);
  outline-offset: 0px;
  box-shadow: inset 0 1px 0 0 rgba(255, 255, 255, 0.08),
    inset 0 0 20px 0 rgba(255, 255, 255, 0.03);
  transition: all 0.3s ease;
}

.mobile-menu-cta::before {
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

.mobile-menu-cta:hover {
  color: var(--color-pink);
  box-shadow: inset 0 1px 0 0 rgba(255, 255, 255, 0.12),
    inset 0 0 20px 0 rgba(255, 255, 255, 0.05);
}

.mobile-menu-cta:hover::before {
  background: radial-gradient(
    ellipse 75% 40% at center bottom,
    rgba(255, 255, 255, 0.22) 0%,
    rgba(255, 255, 255, 0.14) 25%,
    rgba(255, 255, 255, 0.04) 50%,
    transparent 70%
  );
}

.mobile-menu-cta svg {
  width: 16px;
  height: 16px;
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
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  display: flex;
  width: 100%;
  height: 100vh;
  overflow: hidden;
}

/* Left Panel - Dark */
.left-panel {
  flex: 1;
  background: #1a1a1a;
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

.login-prompt {
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

/* Input Group */
.input-group {
  display: flex;
  align-items: center;
  background: white;
  border-radius: 60px;
  padding: 5px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  border: 1px solid #e0e0e0;
  max-width: 350px;
  margin: 0 auto;
}

.alpha-input {
  flex: 1;
  border: none;
  background: transparent;
  padding: 12px 20px 8px 20px;
  font-size: 15px;
  outline: none;
  min-width: 0;
}

.alpha-input::placeholder {
  color: #999;
}

.alpha-input:disabled {
  opacity: 0.6;
}

/* Form CTA Button - styled like nav CTA */
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
  padding: 8px 20px;
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

.link-btn {
  background: none;
  border: none;
  color: #666;
  font-size: clamp(0.75rem, 2vw, 1rem);
  font-weight: 500;
  text-decoration: underline;
  cursor: pointer;
  padding: 0;
  margin-left: 4px;
}

.link-btn:hover {
  color: var(--color-pink);
}

.link-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
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

@media (max-width: 900px) {
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
