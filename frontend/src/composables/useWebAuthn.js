// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import { ref } from "vue";

// Helper to convert base64url to Uint8Array
export function base64urlToUint8Array(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Helper to convert Uint8Array to base64url
export function uint8ArrayToBase64url(array) {
  const binary = String.fromCharCode(...array);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// Helper to get CSRF token from cookie (not HTTP-only, so JS can read it)
export function getCsrfToken() {
  const match = document.cookie.match(/caution_csrf=([^;]+)/);
  return match ? match[1] : null;
}

// Helper for authenticated API calls with CSRF protection
export function authFetch(url, options = {}) {
  const headers = options.headers || {};

  // Add CSRF token for state-changing requests
  if (options.method && options.method !== 'GET') {
    const csrfToken = getCsrfToken();
    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken;
    }
  }

  return fetch(url, {
    ...options,
    headers,
    credentials: 'include',
  });
}

export function useWebAuthn() {
  const authenticated = ref(false);
  const loading = ref(false);
  const loginLoading = ref(false);
  const error = ref(null);
  const status = ref(null);

  function checkWebAuthnSupport() {
    if (!window.PublicKeyCredential) {
      error.value =
        "Your browser does not support FIDO2/WebAuthn. Please use Chrome, Firefox, or Safari.";
      return false;
    }
    return true;
  }

  async function verifySession() {
    try {
      // Session is now in HTTP-only cookie, browser sends it automatically
      const response = await fetch("/api/user/status", {
        credentials: "include",
      });

      if (response.ok) {
        authenticated.value = true;
        window.location.href = "/dashboard";
        return true;
      } else {
        error.value = "Invalid session. Please authenticate using the CLI.";
        return false;
      }
    } catch (err) {
      error.value = "Failed to verify session. Please try again.";
      return false;
    }
  }

  async function handleLogin(e) {
    if (e && e.preventDefault) {
      e.preventDefault();
    }

    // Prevent double invocation
    if (loading.value) {
      return;
    }

    error.value = null;
    status.value = null;
    loading.value = true;
    loginLoading.value = true;

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
      status.value = "Tap your security key";

      const publicKey = beginData.publicKey;
      publicKey.challenge = base64urlToUint8Array(publicKey.challenge);

      if (publicKey.allowCredentials) {
        publicKey.allowCredentials = publicKey.allowCredentials.map((cred) => ({
          type: cred.type,
          id: base64urlToUint8Array(cred.id),
          ...(cred.transports && cred.transports.length > 0
            ? { transports: cred.transports }
            : {}),
        }));
      }

      delete publicKey.hints;

      let assertion;
      try {
        assertion = await navigator.credentials.get({ publicKey });
      } catch (credError) {
        console.error("WebAuthn error:", credError);
        if (credError.name === "NotAllowedError") {
          throw new Error(
            "Authentication was blocked by your browser. Make sure you are using the same authenticator you registered with and tap it promptly. If you registered with a password manager, try using <strong>Chrome</strong> or <strong>Edge</strong> — Firefox has limited passkey support."
          );
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
      const clientDataJSON = new Uint8Array(assertion.response.clientDataJSON);
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

      await finishResponse.json();
      authenticated.value = true;
      status.value = "Login successful!";

      // Redirect to dashboard (session is now in HTTP-only cookie)
      setTimeout(() => {
        window.location.href = "/dashboard";
      }, 1000);
    } catch (err) {
      error.value = err.message || "Login failed. Please try again.";
      status.value = null;
    } finally {
      loading.value = false;
      loginLoading.value = false;
    }
  }

  async function handleRegister(alphaCode) {
    if (!alphaCode || !alphaCode.trim()) {
      return { success: false, validationError: true };
    }

    error.value = null;
    status.value = null;
    loading.value = true;

    try {
      // Step 1: Begin registration with alpha code
      status.value = "Validating alpha code...";
      const beginResponse = await fetch("/auth/register/begin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ alpha_code: alphaCode.trim() }),
      });

      if (!beginResponse.ok) {
        const errorText = await beginResponse.text();
        throw new Error(errorText || "Failed to begin registration");
      }

      const beginData = await beginResponse.json();

      // Step 2: Create credential with security key
      status.value = "Tap your security key";

      const publicKey = beginData.publicKey;
      publicKey.challenge = base64urlToUint8Array(publicKey.challenge);
      publicKey.user.id = base64urlToUint8Array(publicKey.user.id);

      // Convert excludeCredentials IDs from base64url to ArrayBuffer
      if (publicKey.excludeCredentials) {
        publicKey.excludeCredentials = publicKey.excludeCredentials.map((cred) => ({
          type: cred.type,
          id: base64urlToUint8Array(cred.id),
          ...(cred.transports && cred.transports.length > 0
            ? { transports: cred.transports }
            : {}),
        }));
      }

      let credential;
      try {
        credential = await navigator.credentials.create({ publicKey });
      } catch (credError) {
        console.error("WebAuthn registration error:", credError);
        if (credError.name === "InvalidStateError") {
          throw new Error(
            "This authenticator is already registered. If you already have an account, <a href=\"/login\">log in</a> instead."
          );
        }
        if (credError.name === "NotAllowedError") {
          const hasExcluded = publicKey.excludeCredentials && publicKey.excludeCredentials.length > 0;
          if (hasExcluded) {
            throw new Error(
              "This authenticator may already be registered. If you already have an account, try <a href=\"/login\">logging in</a>. Otherwise, try a different authenticator or browser."
            );
          }
          throw new Error(
            "Registration was blocked by your browser. Try using a <strong>hardware security key</strong> or your device's built-in authenticator. If you are using a password manager, try <strong>Chrome</strong> or <strong>Edge</strong> instead of Firefox."
          );
        }
        throw credError;
      }

      if (!credential) {
        throw new Error("No credential created");
      }

      // Step 3: Finish registration
      status.value = "Completing registration...";

      const attestationObject = new Uint8Array(
        credential.response.attestationObject
      );
      const clientDataJSON = new Uint8Array(credential.response.clientDataJSON);

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

      await finishResponse.json();
      authenticated.value = true;
      status.value = "Registration successful!";

      // Redirect to dashboard (session is now in HTTP-only cookie)
      setTimeout(() => {
        window.location.href = "/dashboard";
      }, 1000);

      return { success: true };
    } catch (err) {
      error.value = err.message || "Registration failed. Please try again.";
      status.value = null;
      return { success: false };
    } finally {
      loading.value = false;
    }
  }

  return {
    authenticated,
    loading,
    loginLoading,
    error,
    status,
    checkWebAuthnSupport,
    verifySession,
    handleLogin,
    handleRegister,
  };
}
