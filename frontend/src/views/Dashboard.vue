<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <DashboardLayout
    :title="pageTitle"
    :active-tab="activeTab"
    @tab-change="activeTab = $event"
    @logout="logout"
  >
    <!-- Messages -->
    <div v-if="error" class="message message--error">
      {{ error }}
    </div>
    <div v-if="success" class="message message--success">
      {{ success }}
    </div>

    <!-- Applications Tab -->
    <div v-if="activeTab === 'apps'" class="content-card">
      <div v-if="loadingApps" class="loading">Loading applications...</div>
      <div v-else-if="apps.length === 0 && setupStep === 0" class="empty-state">
        <div class="empty-state-text">
          <p>You do not have any applications yet.</p>
          <p>Create your first application to deploy and verify an enclave.</p>
        </div>
        <button class="btn-create" @click="setupStep = 1">
          Set up your first application
        </button>
      </div>
      <!-- Screen 1: Install CLI -->
      <div
        v-else-if="apps.length === 0 && setupStep === 1"
        class="quick-start-inline"
      >
        <button class="back-link" @click="setupStep = 0">
          <img src="/assets/chevron-left.svg" alt="Back" class="back-icon" />
        </button>

        <h4 class="step-title">Install the Caution CLI</h4>
        <p class="quick-start-description">
          Run the following commands to build and install Caution CLI locally.
          You only need to do this once per environment.
        </p>
        <div class="code-block">
          <button
            class="copy-btn"
            :class="{ copied: copiedBlock === 'install' }"
            @click="copyCode('install')"
            :title="copiedBlock === 'install' ? 'Copied!' : 'Copy to clipboard'"
          >
            <img src="/assets/copy.svg" alt="Copy" class="copy-icon" />
          </button>
          <pre ref="codeInstall">
git clone https://codeberg.org/caution/platform
cd platform
make build-cli
./utils/install.sh</pre
          >
        </div>

        <button class="btn-continue" @click="setupStep = 2">Continue</button>
      </div>

      <!-- Screen 2: Initialize, Deploy, Verify -->
      <div
        v-else-if="apps.length === 0 && setupStep === 2"
        class="quick-start-inline"
      >
        <button class="back-link" @click="setupStep = 1">
          <img src="/assets/chevron-left.svg" alt="Back" class="back-icon" />
        </button>

        <!-- Step 1: Initialize -->
        <div class="quick-start-step">
          <h4 class="step-title">Step 1: Initialize the app</h4>
          <p class="quick-start-description">
            Clone the example enclave, authenticate with your security key, and
            initialize the application with <code>caution init</code>. This
            captures the build environment and locks it for reproducible enclave
            builds.
          </p>
          <div class="code-block">
            <button
              class="copy-btn"
              :class="{ copied: copiedBlock === 'init' }"
              @click="copyCode('init')"
              :title="copiedBlock === 'init' ? 'Copied!' : 'Copy to clipboard'"
            >
              <img src="/assets/copy.svg" alt="Copy" class="copy-icon" />
            </button>
            <pre ref="codeInit">
git clone https://codeberg.org/caution/hello-world-enclave
cd hello-world-enclave

caution login
# Tap your security key when prompted

caution ssh-keys add --from-agent
# Or provide a key file such as ~/.ssh/id_ed25519.pub

caution init</pre
            >
          </div>
        </div>

        <!-- Step 2: Deploy -->
        <div class="quick-start-step">
          <h4 class="step-title">Step 2: Deploy</h4>
          <p class="quick-start-description">
            Push the application with <code>git push caution main</code>.
            Caution builds a reproducible enclave image and provisions the TEE.
          </p>
          <div class="code-block">
            <button
              class="copy-btn"
              :class="{ copied: copiedBlock === 'deploy' }"
              @click="copyCode('deploy')"
              :title="
                copiedBlock === 'deploy' ? 'Copied!' : 'Copy to clipboard'
              "
            >
              <img src="/assets/copy.svg" alt="Copy" class="copy-icon" />
            </button>
            <pre ref="codeDeploy">git push caution main</pre>
          </div>
        </div>

        <!-- Step 3: Verify -->
        <div class="quick-start-step">
          <h4 class="step-title">Step 3: Verify</h4>
          <p class="quick-start-description">
            Run <code>caution verify --reproduce</code> to rebuild the image,
            compare hashes, and confirm exactly what the enclave is running.
          </p>
          <div class="code-block">
            <button
              class="copy-btn"
              :class="{ copied: copiedBlock === 'verify' }"
              @click="copyCode('verify')"
              :title="
                copiedBlock === 'verify' ? 'Copied!' : 'Copy to clipboard'
              "
            >
              <img src="/assets/copy.svg" alt="Copy" class="copy-icon" />
            </button>
            <pre ref="codeVerify">caution verify --reproduce</pre>
          </div>
        </div>
      </div>
      <div v-else class="items-list">
        <div v-for="app in apps" :key="app.id" class="app-card">
          <div class="app-header">
            <span class="app-name">{{
              app.resource_name || "Unnamed App"
            }}</span>
            <span :class="['app-status', `status-${app.state.toLowerCase()}`]">
              {{ app.state }}
            </span>
          </div>
          <div class="app-details">
            <div class="app-detail">
              <span class="detail-label">ID:</span>
              <span class="detail-value">{{ app.id }}</span>
            </div>
            <div v-if="app.public_ip" class="app-detail">
              <span class="detail-label">IP:</span>
              <span class="detail-value">{{ app.public_ip }}</span>
            </div>
            <div v-if="app.public_ip" class="app-links">
              <a
                :href="'http://' + app.public_ip + ':8080'"
                target="_blank"
                class="app-link"
              >
                Open App
              </a>
              <button @click="attestationApp = app" class="app-link-btn">
                Attestation
              </button>
            </div>
          </div>
          <div class="app-actions">
            <button
              @click="destroyApp(app.id, app.resource_name)"
              class="btn-danger"
              :disabled="destroyingApp === app.id"
            >
              {{ destroyingApp === app.id ? "Destroying..." : "Destroy" }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- SSH Keys Tab -->
    <div v-if="activeTab === 'ssh'" class="content-card">
      <div class="form-section">
        <h3 class="form-section-title">Add SSH Key</h3>
        <p class="quick-start-description">
          Add SSH keys to push code to your applications via Git.
        </p>
        <div class="form-group">
          <label class="form-label" for="keyName">Key Name (optional)</label>
          <input
            id="keyName"
            v-model="newKeyName"
            type="text"
            class="form-input"
            placeholder="e.g., Work Laptop"
            :disabled="addingKey"
          />
        </div>
        <div class="form-group">
          <label class="form-label" for="publicKey">Public Key</label>
          <textarea
            id="publicKey"
            v-model="newPublicKey"
            class="form-textarea"
            placeholder="ssh-ed25519 AAAA... or ssh-rsa AAAA..."
            rows="3"
            :disabled="addingKey"
          ></textarea>
        </div>
        <button
          @click="addKey"
          class="btn-primary"
          :disabled="addingKey || !newPublicKey.trim()"
        >
          {{ addingKey ? "Adding..." : "Add SSH Key" }}
        </button>
      </div>

      <div class="items-list">
        <div v-if="loadingKeys" class="loading">Loading SSH keys...</div>
        <div v-else-if="sshKeys.length === 0" class="empty-state">
          No SSH keys added yet.
        </div>
        <div v-else>
          <div v-for="key in sshKeys" :key="key.fingerprint" class="list-item">
            <div class="item-info">
              <span class="item-name">{{ key.name || "Unnamed Key" }}</span>
              <code class="item-meta">{{ key.fingerprint }}</code>
              <span class="item-meta">{{ key.key_type }}</span>
            </div>
            <div class="item-actions">
              <button
                @click="deleteKey(key.fingerprint)"
                class="btn-danger"
                :disabled="deletingKey === key.fingerprint"
              >
                {{ deletingKey === key.fingerprint ? "Deleting..." : "Delete" }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Cloud Credentials Tab -->
    <div v-if="activeTab === 'credentials'" class="content-card">
      <div class="form-section">
        <h3 class="form-section-title">Add AWS Credentials</h3>
        <p class="quick-start-description">
          Add AWS credentials to deploy applications to your own infrastructure.
        </p>
        <div class="form-group">
          <label class="form-label" for="credName">Name</label>
          <input
            id="credName"
            v-model="newCredName"
            type="text"
            class="form-input"
            placeholder="e.g., Production AWS"
            :disabled="addingCred"
          />
        </div>
        <div class="form-group">
          <label class="form-label" for="awsAccessKeyId">Access Key ID</label>
          <input
            id="awsAccessKeyId"
            v-model="newCredAwsKeyId"
            type="text"
            class="form-input"
            placeholder="AKIA..."
            :disabled="addingCred"
          />
        </div>
        <div class="form-group">
          <label class="form-label" for="awsSecretKey">Secret Access Key</label>
          <input
            id="awsSecretKey"
            v-model="newCredAwsSecret"
            type="password"
            class="form-input"
            placeholder="Enter secret access key"
            :disabled="addingCred"
          />
        </div>
        <div class="form-group">
          <label
            style="
              display: flex;
              align-items: center;
              gap: 8px;
              cursor: pointer;
            "
          >
            <input
              type="checkbox"
              v-model="newCredIsDefault"
              :disabled="addingCred"
            />
            Set as default
          </label>
        </div>
        <button
          @click="addCredential"
          class="btn-primary"
          :disabled="
            addingCred ||
            !newCredName.trim() ||
            !newCredAwsKeyId.trim() ||
            !newCredAwsSecret.trim()
          "
        >
          {{ addingCred ? "Adding..." : "Add Credential" }}
        </button>
      </div>

      <div class="items-list">
        <div v-if="loadingCreds" class="loading">Loading credentials...</div>
        <div v-else-if="credentials.length === 0" class="empty-state">
          No AWS credentials added yet.
        </div>
        <div v-else>
          <div v-for="cred in credentials" :key="cred.id" class="list-item">
            <div class="item-info">
              <div style="display: flex; align-items: center; gap: 8px">
                <span class="item-name">{{ cred.name }}</span>
                <span
                  v-if="cred.is_default"
                  class="item-badge item-badge--default"
                  >Default</span
                >
              </div>
              <code class="item-meta">{{ cred.identifier }}</code>
            </div>
            <div class="item-actions">
              <button
                v-if="!cred.is_default"
                @click="setDefaultCredential(cred.id)"
                class="btn-secondary"
                :disabled="settingDefault === cred.id"
              >
                {{ settingDefault === cred.id ? "..." : "Set Default" }}
              </button>
              <button
                @click="deleteCredential(cred.id, cred.name)"
                class="btn-danger"
                :disabled="deletingCred === cred.id"
              >
                {{ deletingCred === cred.id ? "Deleting..." : "Delete" }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <AttestationModal
      v-if="attestationApp"
      :public-ip="attestationApp.public_ip"
      :app-name="attestationApp.resource_name || 'App'"
      @close="attestationApp = null"
    />
  </DashboardLayout>
</template>

<script>
import { ref, computed, onMounted } from "vue";
import DashboardLayout from "../components/DashboardLayout.vue";
import AttestationModal from "../components/AttestationModal.vue";

async function sha256Hex(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64UrlToArrayBuffer(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export default {
  name: "Dashboard",
  components: {
    DashboardLayout,
    AttestationModal,
  },
  props: {
    session: String,
  },
  setup(props) {
    const error = ref(null);
    const success = ref(null);
    const activeTab = ref("apps");
    const setupStep = ref(0);

    // Code block refs and copy state
    const codeInstall = ref(null);
    const codeInit = ref(null);
    const codeDeploy = ref(null);
    const codeVerify = ref(null);
    const copiedBlock = ref(null);

    const copyCode = async (blockName) => {
      const codeRefs = {
        install: codeInstall,
        init: codeInit,
        deploy: codeDeploy,
        verify: codeVerify,
      };
      const codeRef = codeRefs[blockName];
      if (!codeRef?.value) return;

      try {
        await navigator.clipboard.writeText(codeRef.value.textContent);
        copiedBlock.value = blockName;
        setTimeout(() => {
          copiedBlock.value = null;
        }, 2000);
      } catch (err) {
        console.error("Failed to copy:", err);
      }
    };

    // Apps state
    const apps = ref([]);
    const loadingApps = ref(true);
    const destroyingApp = ref(null);
    const attestationApp = ref(null);

    // SSH Keys state
    const sshKeys = ref([]);
    const loadingKeys = ref(true);
    const addingKey = ref(false);
    const deletingKey = ref(null);
    const newKeyName = ref("");
    const newPublicKey = ref("");

    // Credentials state
    const credentials = ref([]);
    const loadingCreds = ref(true);
    const addingCred = ref(false);
    const deletingCred = ref(null);
    const settingDefault = ref(null);
    const newCredName = ref("");
    const newCredAwsKeyId = ref("");
    const newCredAwsSecret = ref("");
    const newCredIsDefault = ref(false);

    const pageTitle = computed(() => {
      if (activeTab.value === "apps") {
        if (setupStep.value === 1) {
          return "Install the Caution CLI";
        }
        if (setupStep.value === 2) {
          return "Set up your application";
        }
        return "Welcome to Caution Alpha!";
      }
      switch (activeTab.value) {
        case "ssh":
          return "SSH Keys";
        case "credentials":
          return "Cloud Credentials";
        default:
          return "Dashboard";
      }
    });

    onMounted(async () => {
      if (!props.session) {
        window.location.href = "/login";
        return;
      }

      // TODO(production): Remove dev mode skip before production deployment
      // In dev mode, skip API calls that will fail without a real session
      if (props.session === "dev-session") {
        console.log("[Dashboard] Dev mode - skipping API calls");
        loadingApps.value = false;
        loadingKeys.value = false;
        loadingCreds.value = false;
        return;
      }
      // END TODO(production)

      await Promise.all([loadApps(), loadKeys(), loadCredentials()]);
    });

    const loadApps = async () => {
      loadingApps.value = true;

      try {
        const response = await fetch("/api/resources", {
          headers: {
            "X-Session-ID": props.session,
          },
        });

        if (response.ok) {
          apps.value = await response.json();
        } else if (response.status === 401) {
          window.location.href = "/login";
        } else {
          const data = await response.json().catch(() => ({}));
          error.value = data.error || "Failed to load apps";
        }
      } catch (err) {
        error.value = "Failed to connect to server";
      } finally {
        loadingApps.value = false;
      }
    };

    const destroyApp = async (id, name) => {
      const displayName = name || `App #${id}`;
      if (
        !confirm(
          `Are you sure you want to destroy "${displayName}"? This cannot be undone.`
        )
      )
        return;

      destroyingApp.value = id;
      error.value = null;
      success.value = null;

      try {
        const response = await fetch(`/api/resources/${id}`, {
          method: "DELETE",
          headers: {
            "X-Session-ID": props.session,
          },
        });

        if (response.ok || response.status === 204) {
          success.value = `App "${displayName}" destroyed`;
          await loadApps();
        } else {
          const data = await response.json().catch(() => ({}));
          error.value = data.error || "Failed to destroy app";
        }
      } catch (err) {
        error.value = "Failed to connect to server";
      } finally {
        destroyingApp.value = null;
      }
    };

    const loadKeys = async () => {
      loadingKeys.value = true;

      try {
        const response = await fetch("/ssh-keys", {
          headers: {
            "X-Session-ID": props.session,
          },
        });

        if (response.ok) {
          const data = await response.json();
          sshKeys.value = data.keys || [];
        } else if (response.status === 401) {
          window.location.href = "/login";
        } else {
          const data = await response.json().catch(() => ({}));
          error.value = data.error || "Failed to load SSH keys";
        }
      } catch (err) {
        error.value = "Failed to connect to server";
      } finally {
        loadingKeys.value = false;
      }
    };

    const addKey = async () => {
      if (!newPublicKey.value.trim()) return;

      addingKey.value = true;
      error.value = null;
      success.value = null;

      try {
        const body = JSON.stringify({
          public_key: newPublicKey.value.trim(),
          name: newKeyName.value.trim() || null,
        });
        const bodyHash = await sha256Hex(body);

        const challengeRes = await fetch("/auth/sign-request", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Session-ID": props.session,
          },
          body: JSON.stringify({
            method: "POST",
            path: "/ssh-keys",
            body_hash: bodyHash,
          }),
        });

        if (!challengeRes.ok) {
          const data = await challengeRes.json().catch(() => ({}));
          throw new Error(data.error || "Failed to get signing challenge");
        }

        const { publicKey, challenge_id } = await challengeRes.json();

        publicKey.challenge = base64UrlToArrayBuffer(publicKey.challenge);
        if (publicKey.allowCredentials) {
          publicKey.allowCredentials = publicKey.allowCredentials.map(
            (cred) => ({
              ...cred,
              id: base64UrlToArrayBuffer(cred.id),
            })
          );
        }

        const credential = await navigator.credentials.get({ publicKey });

        const credentialResponse = {
          id: credential.id,
          rawId: arrayBufferToBase64Url(credential.rawId),
          type: credential.type,
          response: {
            authenticatorData: arrayBufferToBase64Url(
              credential.response.authenticatorData
            ),
            clientDataJSON: arrayBufferToBase64Url(
              credential.response.clientDataJSON
            ),
            signature: arrayBufferToBase64Url(credential.response.signature),
            userHandle: credential.response.userHandle
              ? arrayBufferToBase64Url(credential.response.userHandle)
              : null,
          },
        };

        const fido2Response = btoa(JSON.stringify(credentialResponse))
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=/g, "");

        const response = await fetch("/ssh-keys", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Fido2-Challenge-Id": challenge_id,
            "X-Fido2-Response": fido2Response,
          },
          body: body,
        });

        if (response.ok) {
          const data = await response.json();
          success.value = `SSH key added (${data.fingerprint})`;
          newKeyName.value = "";
          newPublicKey.value = "";
          await loadKeys();
        } else {
          const data = await response.json().catch(() => ({}));
          error.value = data.error || "Failed to add SSH key";
        }
      } catch (err) {
        if (err.name === "NotAllowedError") {
          error.value =
            "Security key authentication was cancelled or timed out";
        } else {
          error.value = err.message || "Failed to add SSH key";
        }
      } finally {
        addingKey.value = false;
      }
    };

    const deleteKey = async (fingerprint) => {
      if (!confirm("Are you sure you want to delete this SSH key?")) return;

      deletingKey.value = fingerprint;
      error.value = null;
      success.value = null;

      try {
        const response = await fetch(
          `/ssh-keys/${encodeURIComponent(fingerprint)}`,
          {
            method: "DELETE",
            headers: {
              "X-Session-ID": props.session,
            },
          }
        );

        if (response.ok || response.status === 204) {
          success.value = "SSH key deleted";
          await loadKeys();
        } else {
          const data = await response.json().catch(() => ({}));
          error.value = data.error || "Failed to delete SSH key";
        }
      } catch (err) {
        error.value = "Failed to connect to server";
      } finally {
        deletingKey.value = null;
      }
    };

    const loadCredentials = async () => {
      loadingCreds.value = true;

      try {
        const response = await fetch("/api/credentials", {
          headers: {
            "X-Session-ID": props.session,
          },
        });

        if (response.ok) {
          credentials.value = await response.json();
        } else if (response.status === 401) {
          window.location.href = "/login";
        } else {
          const data = await response.json().catch(() => ({}));
          error.value = data.error || "Failed to load credentials";
        }
      } catch (err) {
        error.value = "Failed to connect to server";
      } finally {
        loadingCreds.value = false;
      }
    };

    const addCredential = async () => {
      if (
        !newCredName.value.trim() ||
        !newCredAwsKeyId.value.trim() ||
        !newCredAwsSecret.value.trim()
      )
        return;

      addingCred.value = true;
      error.value = null;
      success.value = null;

      try {
        const body = {
          platform: "aws",
          name: newCredName.value.trim(),
          access_key_id: newCredAwsKeyId.value.trim(),
          secret_access_key: newCredAwsSecret.value.trim(),
          is_default: newCredIsDefault.value,
        };

        const response = await fetch("/api/credentials", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Session-ID": props.session,
          },
          body: JSON.stringify(body),
        });

        if (response.ok) {
          success.value = "AWS credential added";
          newCredName.value = "";
          newCredAwsKeyId.value = "";
          newCredAwsSecret.value = "";
          newCredIsDefault.value = false;
          await loadCredentials();
        } else {
          const data = await response.json().catch(() => ({}));
          error.value = data.error || "Failed to add credential";
        }
      } catch (err) {
        error.value = "Failed to connect to server";
      } finally {
        addingCred.value = false;
      }
    };

    const deleteCredential = async (id, name) => {
      if (!confirm(`Are you sure you want to delete "${name}"?`)) return;

      deletingCred.value = id;
      error.value = null;
      success.value = null;

      try {
        const response = await fetch(`/api/credentials/${id}`, {
          method: "DELETE",
          headers: {
            "X-Session-ID": props.session,
          },
        });

        if (response.ok || response.status === 204) {
          success.value = "Credential deleted";
          await loadCredentials();
        } else {
          const data = await response.json().catch(() => ({}));
          error.value = data.error || "Failed to delete credential";
        }
      } catch (err) {
        error.value = "Failed to connect to server";
      } finally {
        deletingCred.value = null;
      }
    };

    const setDefaultCredential = async (id) => {
      settingDefault.value = id;
      error.value = null;
      success.value = null;

      try {
        const response = await fetch(`/api/credentials/${id}/default`, {
          method: "POST",
          headers: {
            "X-Session-ID": props.session,
          },
        });

        if (response.ok) {
          success.value = "Default credential updated";
          await loadCredentials();
        } else {
          const data = await response.json().catch(() => ({}));
          error.value = data.error || "Failed to set default credential";
        }
      } catch (err) {
        error.value = "Failed to connect to server";
      } finally {
        settingDefault.value = null;
      }
    };

    const logout = () => {
      window.location.href = "/login";
    };

    return {
      error,
      success,
      activeTab,
      pageTitle,
      setupStep,
      codeInstall,
      codeInit,
      codeDeploy,
      codeVerify,
      copiedBlock,
      copyCode,
      apps,
      loadingApps,
      destroyingApp,
      attestationApp,
      destroyApp,
      sshKeys,
      loadingKeys,
      addingKey,
      deletingKey,
      newKeyName,
      newPublicKey,
      addKey,
      deleteKey,
      credentials,
      loadingCreds,
      addingCred,
      deletingCred,
      settingDefault,
      newCredName,
      newCredAwsKeyId,
      newCredAwsSecret,
      newCredIsDefault,
      addCredential,
      deleteCredential,
      setDefaultCredential,
      logout,
    };
  },
};
</script>

<style scoped>
/* Modal styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: white;
  border-radius: 16px;
  padding: 32px;
  max-width: 600px;
  width: 90%;
  max-height: 80vh;
  overflow-y: auto;
  position: relative;
}

.modal-close {
  position: absolute;
  top: 16px;
  right: 16px;
  background: none;
  border: none;
  font-size: 24px;
  cursor: pointer;
  color: #666;
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 4px;
}

.modal-close:hover {
  background: #f5f5f5;
  color: #333;
}
</style>
