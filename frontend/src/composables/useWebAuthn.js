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

  async function verifySession(session) {
    if (!session) return false;

    try {
      const response = await fetch("/api/user/status", {
        headers: {
          "X-Session-ID": session,
        },
      });

      if (response.ok) {
        authenticated.value = true;
        window.location.href = `/dashboard?session=${session}`;
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
      status.value = "Tap your smart card";

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
        if (credError.name === "NotAllowedError") {
          throw new Error(
            "The request could not be completed. Make sure your security key is set up for this account and tap it promptly after clicking <strong>Log in</strong>."
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
      loginLoading.value = false;
    }
  }

  async function handleRegister(betaCode) {
    if (!betaCode || !betaCode.trim()) {
      return { success: false, validationError: true };
    }

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
        body: JSON.stringify({ beta_code: betaCode.trim() }),
      });

      if (!beginResponse.ok) {
        const errorText = await beginResponse.text();
        throw new Error(errorText || "Failed to begin registration");
      }

      const beginData = await beginResponse.json();

      // Step 2: Create credential with security key
      status.value = "Tap your smart card";

      const publicKey = beginData.publicKey;
      publicKey.challenge = base64urlToUint8Array(publicKey.challenge);
      publicKey.user.id = base64urlToUint8Array(publicKey.user.id);

      const credential = await navigator.credentials.create({ publicKey });

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
