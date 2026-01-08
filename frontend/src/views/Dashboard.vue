<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <DashboardLayout
    :title="pageTitle"
    :active-tab="activeTab"
    :show-title="false"
    @tab-change="handleTabChange"
    @logout="logout"
  >
    <!-- Messages (exclude SSH key form errors as they appear in-form) -->
    <div v-if="error && !showAddKeyForm" class="message message--error">
      {{ error }}
    </div>
    <div v-if="success" class="message message--success">
      {{ success }}
    </div>

    <!-- Notes sidebar (only show for Cloud credentials) -->
    <template #aside>
      <div v-if="activeTab === 'credentials'" class="notes-card">
        <h3>Cloud credentials</h3>
        <p>Add your AWS credentials to deploy applications to your own infrastructure.</p>
        <p>Your credentials are encrypted and stored securely.</p>
      </div>
    </template>

    <!-- Applications Tab -->
    <template v-if="activeTab === 'apps'">
      <!-- Loading state -->
      <div v-if="loadingApps" class="content-card">
        <div class="loading">Loading applications...</div>
      </div>

      <!-- Apps list (when user has apps) -->
      <div v-else-if="apps.length > 0" class="content-card">
        <div class="items-list">
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

      <!-- Starter Screen (default home screen when no apps) -->
      <template v-else-if="apps.length === 0">
        <div class="content-card guide-intro">
          <div class="guide-intro-content">
            <div class="guide-intro-eyebrow">QUICK START GUIDE</div>
            <h2 class="guide-intro-title">Deploy your first application</h2>
            <p class="guide-intro-description">
              Learn how to use the Caution CLI to deploy your application in a secure enclave and verify exactly what code is running.
            </p>

            <button class="btn-guide" @click="startGuide">
              Get started
            </button>
          </div>
        </div>
      </template>
    </template>

    <!-- Quick Start Guide Tab -->
    <template v-if="activeTab === 'guide'">
      <!-- Guide Intro Screen -->
      <template v-if="setupStep === 0">
        <div class="content-card guide-intro">
          <div class="guide-intro-content">
            <div class="guide-intro-eyebrow">QUICK START GUIDE</div>
            <h2 class="guide-intro-title">{{ apps.length === 0 ? 'Deploy your first application' : 'How to deploy an application' }}</h2>
            <p class="guide-intro-description">
              Learn how to use the Caution CLI to deploy your application in a secure enclave and verify exactly what code is running.
            </p>

            <button class="btn-guide" @click="setupStep = 1">
              Get started
            </button>
          </div>
        </div>
      </template>

      <!-- Step 1: Install CLI -->
      <template v-else-if="setupStep === 1">
        <div class="content-card quick-start-inline">
          <div class="step-header">
            <h2 class="step-title">Step 1. Install the Caution CLI</h2>
          </div>

          <div class="guide-layout guide-layout-step2">
            <div class="guide-content">
              <p class="quick-start-description">
                Install the Caution CLI to deploy and manage enclave applications from your terminal.
              </p>
              <p class="quick-start-description">
                You only need to do this once per environment.
              </p>
            </div>
            <div class="guide-code">
              <div class="code-block">
                <button
                  class="copy-btn"
                  :class="{ copied: copiedBlock === 'install' }"
                  @click="copyCode('install')"
                  :title="copiedBlock === 'install' ? 'Copied' : 'Copy to clipboard'"
                >
                  <img src="/assets/copy.svg" alt="Copy" class="copy-icon" />
                  <span class="copy-btn-text">Copied</span>
                </button>
                <pre ref="codeInstall">
git clone https://codeberg.org/caution/platform
cd platform
make build-cli
./utils/install.sh</pre
                >
              </div>
            </div>
          </div>

          <div class="guide-navigation">
            <button class="btn-continue" @click="setupStep = 0">
              <img
                src="/assets/chevron-left.svg"
                alt=""
                style="width: 20px; height: 20px; margin-right: 8px;"
              />
              <span class="btn-text">Back</span>
            </button>
            <div class="progress-dots">
              <button class="progress-dot active" @click="setupStep = 1"></button>
              <button class="progress-dot" @click="setupStep = 2"></button>
              <button class="progress-dot" @click="setupStep = 3"></button>
              <button class="progress-dot" @click="setupStep = 4"></button>
              <button class="progress-dot" @click="setupStep = 5"></button>
            </div>
            <button class="btn-continue" @click="setupStep = 2">
              <span class="btn-text">Next</span>
              <img
                src="/assets/chevron-right.svg"
                alt=""
                style="width: 20px; height: 20px; margin-left: 8px;"
              />
            </button>
          </div>
        </div>
      </template>

      <!-- Step 2: Clone & Authenticate -->
      <template v-else-if="setupStep === 2">
        <div class="content-card quick-start-inline">
          <div class="step-header">
            <h2 class="step-title">Step 2. Clone an application</h2>
          </div>

          <div class="guide-layout guide-layout-step2">
            <div class="guide-content">
              <p class="quick-start-description">
                Clone the application you want to deploy.</p>
                <p class="quick-start-description">You can use <a href="https://codeberg.org/caution" target="_blank" rel="noopener noreferrer" class="guide-link">one of our demos</a> or your own repository.
              </p>
              <p class="quick-start-description">
                Authenticate with your security key and register your SSH key.
              </p>
            </div>
            <div class="guide-code">
              <div class="code-block">
                <button
                  class="copy-btn"
                  :class="{ copied: copiedBlock === 'clone' }"
                  @click="copyCode('clone')"
                  :title="copiedBlock === 'clone' ? 'Copied' : 'Copy to clipboard'"
                >
                  <img src="/assets/copy.svg" alt="Copy" class="copy-icon" />
                  <span class="copy-btn-text">Copied</span>
                </button>
                <pre ref="codeClone"><span class="code-command">git clone https://codeberg.org/caution/hello-world-enclave</span>
<span class="code-command">cd hello-world-enclave</span>

<span class="code-command">caution login</span>
<span class="code-comment"># Tap your security key when prompted</span>

<span class="code-command">caution ssh-keys add --from-agent</span>
<span class="code-comment"># Or provide a key file such as ~/.ssh/id_ed25519.pub</span></pre
                >
              </div>
            </div>
          </div>

          <div class="guide-navigation">
            <button class="btn-continue" @click="setupStep = 1">
              <img
                src="/assets/chevron-left.svg"
                alt=""
                style="width: 20px; height: 20px; margin-right: 8px;"
              />
              <span class="btn-text">Back</span>
            </button>
            <div class="progress-dots">
              <button class="progress-dot" @click="setupStep = 1"></button>
              <button class="progress-dot active" @click="setupStep = 2"></button>
              <button class="progress-dot" @click="setupStep = 3"></button>
              <button class="progress-dot" @click="setupStep = 4"></button>
              <button class="progress-dot" @click="setupStep = 5"></button>
            </div>
            <button class="btn-continue" @click="setupStep = 3">
              <span class="btn-text">Next</span>
              <img
                src="/assets/chevron-right.svg"
                alt=""
                style="width: 20px; height: 20px; margin-left: 8px;"
              />
            </button>
          </div>
        </div>
      </template>

      <!-- Step 3: Initialize -->
      <template v-else-if="setupStep === 3">
        <div class="content-card quick-start-inline">
          <div class="step-header">
            <h2 class="step-title">Step 3. Initialize project</h2>
          </div>

          <div class="guide-layout guide-layout-balanced">
            <div class="guide-content">
              <p class="quick-start-description">
                Run <code>caution init</code> to capture and lock the build environment for reproducible enclave builds.
              </p>
              <p class="quick-start-description">
                This creates a lockfile that records your system's build environment, ensuring that your enclave can be reproduced bit-for-bit by anyone.
              </p>
            </div>
            <div class="guide-code">
              <div class="code-block code-block-short">
                <button
                  class="copy-btn"
                  :class="{ copied: copiedBlock === 'init' }"
                  @click="copyCode('init')"
                  :title="copiedBlock === 'init' ? 'Copied' : 'Copy to clipboard'"
                >
                  <img src="/assets/copy.svg" alt="Copy" class="copy-icon" />
                  <span class="copy-btn-text">Copied</span>
                </button>
                <pre ref="codeInit">caution init</pre>
              </div>
            </div>
          </div>

          <div class="guide-navigation">
            <button class="btn-continue" @click="setupStep = 2">
              <img
                src="/assets/chevron-left.svg"
                alt=""
                style="width: 20px; height: 20px; margin-right: 8px;"
              />
              <span class="btn-text">Back</span>
            </button>
            <div class="progress-dots">
              <button class="progress-dot" @click="setupStep = 1"></button>
              <button class="progress-dot" @click="setupStep = 2"></button>
              <button class="progress-dot active" @click="setupStep = 3"></button>
              <button class="progress-dot" @click="setupStep = 4"></button>
              <button class="progress-dot" @click="setupStep = 5"></button>
            </div>
            <button class="btn-continue" @click="setupStep = 4">
              <span class="btn-text">Next</span>
              <img
                src="/assets/chevron-right.svg"
                alt=""
                style="width: 20px; height: 20px; margin-left: 8px;"
              />
            </button>
          </div>
        </div>
      </template>

      <!-- Step 4: Deploy -->
      <template v-else-if="setupStep === 4">
        <div class="content-card quick-start-inline">
          <div class="step-header">
            <h2 class="step-title">Step 4. Deploy to enclave</h2>
          </div>

          <div class="guide-layout guide-layout-balanced">
            <div class="guide-content">
              <p class="quick-start-description">
                Push your application with <code>git push caution main</code> to deploy it.
              </p>
              <p class="quick-start-description">
                Caution builds a reproducible enclave image and provisions the TEE.
              </p>
            </div>
            <div class="guide-code">
              <div class="code-block code-block-short">
                <button
                  class="copy-btn"
                  :class="{ copied: copiedBlock === 'deploy' }"
                  @click="copyCode('deploy')"
                  :title="copiedBlock === 'deploy' ? 'Copied' : 'Copy to clipboard'"
                >
                  <img src="/assets/copy.svg" alt="Copy" class="copy-icon" />
                  <span class="copy-btn-text">Copied</span>
                </button>
                <pre ref="codeDeploy">git push caution main</pre>
              </div>
            </div>
          </div>

          <div class="guide-navigation">
            <button class="btn-continue" @click="setupStep = 3">
              <img
                src="/assets/chevron-left.svg"
                alt=""
                style="width: 20px; height: 20px; margin-right: 8px;"
              />
              <span class="btn-text">Back</span>
            </button>
            <div class="progress-dots">
              <button class="progress-dot" @click="setupStep = 1"></button>
              <button class="progress-dot" @click="setupStep = 2"></button>
              <button class="progress-dot" @click="setupStep = 3"></button>
              <button class="progress-dot active" @click="setupStep = 4"></button>
              <button class="progress-dot" @click="setupStep = 5"></button>
            </div>
            <button class="btn-continue" @click="setupStep = 5">
              <span class="btn-text">Next</span>
              <img
                src="/assets/chevron-right.svg"
                alt=""
                style="width: 20px; height: 20px; margin-left: 8px;"
              />
            </button>
          </div>
        </div>
      </template>

      <!-- Step 5: Verify -->
      <template v-else-if="setupStep === 5">
        <div class="content-card quick-start-inline">
          <div class="step-header">
            <h2 class="step-title">Step 5. Verify what runs in the enclave</h2>
          </div>

          <div class="guide-layout guide-layout-balanced">
            <div class="guide-content">
              <p class="quick-start-description">
                Run <code>caution verify --reproduce</code> to rebuild the image, compare hashes, and confirm exactly what code is running inside the enclave.
              </p>
              <p class="quick-start-description">
                Independent verification confirms the deployed enclave matches your source code.
              </p>
            </div>
            <div class="guide-code">
              <div class="code-block code-block-short">
                <button
                  class="copy-btn"
                  :class="{ copied: copiedBlock === 'verify' }"
                  @click="copyCode('verify')"
                  :title="copiedBlock === 'verify' ? 'Copied' : 'Copy to clipboard'"
                >
                  <img src="/assets/copy.svg" alt="Copy" class="copy-icon" />
                  <span class="copy-btn-text">Copied</span>
                </button>
                <pre ref="codeVerify">caution verify --reproduce</pre>
              </div>
            </div>
          </div>

          <div class="guide-navigation">
            <button class="btn-continue" @click="setupStep = 4">
              <img
                src="/assets/chevron-left.svg"
                alt=""
                style="width: 20px; height: 20px; margin-right: 8px;"
              />
              <span class="btn-text">Back</span>
            </button>
            <div class="progress-dots">
              <button class="progress-dot" @click="setupStep = 1"></button>
              <button class="progress-dot" @click="setupStep = 2"></button>
              <button class="progress-dot" @click="setupStep = 3"></button>
              <button class="progress-dot" @click="setupStep = 4"></button>
              <button class="progress-dot active" @click="setupStep = 5"></button>
            </div>
            <button class="btn-continue" @click="setupStep = 6">
              <span class="btn-text">Done</span>
            </button>
          </div>
        </div>
      </template>

      <!-- Completion Screen -->
      <template v-else-if="setupStep === 6">
        <div class="content-card guide-intro">
          <div class="guide-intro-content">
            <h2 class="guide-completion-title">You're ready to deploy with Caution</h2>
            <p class="guide-completion-description">
              You've completed the quick start guide.
              Use these steps to deploy and verify applications using the Caution CLI.
            </p>

            <button class="btn-guide" @click="handleTabChange('apps')">
              Go to applications
            </button>
          </div>
        </div>
      </template>
    </template>

    <!-- SSH Keys Tab -->
    <div v-if="activeTab === 'ssh'" class="content-card">
      <!-- Show form when adding a key -->
      <template v-if="showAddKeyForm">
        <h3 class="form-section-title">Add new SSH key</h3>
        <p class="form-section-description">
          Add SSH keys to push code to your applications via git.
        </p>
        <div class="form-group">
          <label class="form-label" for="keyName">Key name</label>
          <input
            id="keyName"
            v-model="newKeyName"
            type="text"
            class="form-input"
            :disabled="addingKey"
          />
        </div>
        <div class="form-group">
          <label class="form-label" for="publicKey">Public key</label>
          <div class="form-input-wrapper">
            <textarea
              id="publicKey"
              v-model="newPublicKey"
              class="form-textarea"
              placeholder="Begins with 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-ed25519', 'sk-ecdsa-sha2-nistp256@openssh.com', or 'sk-ssh-ed25519@openssh.com'"
              rows="3"
              :disabled="addingKey"
            ></textarea>
            <div class="form-message-container">
              <div v-if="error && showAddKeyForm" class="message message--error">
                {{ error }}
              </div>
              <div v-if="success && showAddKeyForm" class="message message--success">
                {{ success }}
              </div>
            </div>
          </div>
        </div>
        <div class="form-actions">
          <button
            @click="addKey"
            class="btn-primary"
            :disabled="addingKey || !newPublicKey.trim()"
          >
            {{ addingKey ? "Adding..." : "Add SSH key" }}
          </button>
          <button
            @click="showAddKeyForm = false; newKeyName = ''; newPublicKey = ''; error = null; success = null"
            class="btn-secondary"
            :disabled="addingKey"
          >
            Cancel
          </button>
        </div>
      </template>

      <!-- Show list when not adding a key -->
      <template v-else>
        <!-- Header with title and Add button -->
        <div class="content-header">
          <div class="content-header-text">
            <h2 class="content-header-title">Your SSH keys</h2>
            <p class="content-header-description">
              This is a list of SSH keys associated with your account. Remove any keys that you do not recognize.
            </p>
          </div>
          <button
            class="btn-primary"
            @click="showAddKeyForm = true"
          >
            Add SSH key
          </button>
        </div>

        <!-- SSH Keys List -->
        <div class="items-list">
          <div v-if="loadingKeys" class="list-item-empty">Loading SSH keys...</div>
          <div v-else-if="sshKeys.length === 0" class="list-item-empty">
            No SSH keys added yet
          </div>
          <div v-else>
            <div v-for="key in sshKeys" :key="key.fingerprint" class="ssh-key-item">
              <div class="ssh-key-icon">
                <img src="/assets/icons/key_.svg" alt="" />
              </div>
              <div class="ssh-key-info">
                <div class="ssh-key-title">{{ key.name || "Unnamed Key" }}</div>
                <div class="ssh-key-fingerprint">{{ key.fingerprint }}</div>
                <div class="ssh-key-meta">
                  <span class="ssh-key-date">Added on {{ formatDate(key.created_at) }}</span>
                </div>
                <div class="ssh-key-meta">
                  <span class="ssh-key-usage">Last used within the last 5 weeks</span>
                  <span class="ssh-key-separator">|</span>
                  <span class="ssh-key-access">Read/write</span>
                </div>
              </div>
              <button
                @click="deleteKey(key.fingerprint)"
                class="ssh-key-delete"
                :disabled="deletingKey === key.fingerprint"
              >
                {{ deletingKey === key.fingerprint ? "Deleting..." : "Delete" }}
              </button>
            </div>
          </div>
        </div>
      </template>
    </div>

    <!-- Delete Confirmation Modal -->
    <div v-if="showDeleteModal" class="modal-overlay" @click="cancelDelete">
      <div class="modal-content" @click.stop>
        <h3 class="modal-title">Delete SSH key</h3>
        <p class="modal-message">Are you sure you want to delete this SSH key? This action cannot be undone.</p>
        <div class="modal-actions">
          <button @click="cancelDelete" class="btn-secondary">Cancel</button>
          <button @click="confirmDelete" class="btn-danger">Delete</button>
        </div>
      </div>
    </div>

    <!-- Cloud Credentials Tab -->
    <div v-if="activeTab === 'credentials'" class="content-card">
      <h2 class="content-card-title">Cloud credentials</h2>
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
          No AWS credentials added yet
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
import { ref, computed, onMounted, onUnmounted } from "vue";
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
    const codeClone = ref(null);
    const codeInit = ref(null);
    const codeDeploy = ref(null);
    const codeVerify = ref(null);
    const copiedBlock = ref(null);

    const copyCode = async (blockName) => {
      const codeRefs = {
        install: codeInstall,
        clone: codeClone,
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
        }, 1200);
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
    const showAddKeyForm = ref(false);
    const newKeyName = ref("");
    const newPublicKey = ref("");
    const showDeleteModal = ref(false);
    const keyToDelete = ref(null);

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
      return "";
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
          sshKeys.value = [];
          const data = await response.json().catch(() => ({}));
          error.value = data.error || "Failed to load SSH keys";
        }
      } catch (err) {
        sshKeys.value = [];
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
          throw new Error(
            data.error ||
            "Failed to authenticate request. Please try again."
          );
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
          showAddKeyForm.value = false;
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

    const deleteKey = (fingerprint) => {
      keyToDelete.value = fingerprint;
      showDeleteModal.value = true;
    };

    const confirmDelete = async () => {
      if (!keyToDelete.value) return;

      deletingKey.value = keyToDelete.value;
      showDeleteModal.value = false;
      error.value = null;
      success.value = null;

      try {
        const response = await fetch(
          `/ssh-keys/${encodeURIComponent(keyToDelete.value)}`,
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
        keyToDelete.value = null;
      }
    };

    const cancelDelete = () => {
      showDeleteModal.value = false;
      keyToDelete.value = null;
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

    const handleTabChange = (newTab) => {
      activeTab.value = newTab;
      if (newTab === "apps") {
        setupStep.value = 0;
      } else if (newTab === "guide") {
        setupStep.value = 0;
      } else if (newTab === "ssh") {
        showAddKeyForm.value = false;
        newKeyName.value = "";
        newPublicKey.value = "";
        error.value = null;
        success.value = null;
      }
    };

    const formatDate = (dateString) => {
      const date = new Date(dateString);
      const options = { year: 'numeric', month: 'short', day: 'numeric' };
      return date.toLocaleDateString('en-US', options);
    };

    const startGuide = () => {
      activeTab.value = "guide";
      setupStep.value = 1;
    };

    // Keyboard shortcuts for guide navigation
    const handleKeyDown = (event) => {
      // Only handle keyboard shortcuts when in guide tab (starter screen 0 or steps 1-6)
      if (activeTab.value !== "guide" || setupStep.value < 0 || setupStep.value > 6) {
        return;
      }

      // Don't trigger shortcuts if user is typing in an input field
      if (event.target.tagName === "INPUT" || event.target.tagName === "TEXTAREA") {
        return;
      }

      // Arrow Left or 'b' key - go back
      if ((event.key === "ArrowLeft" || event.key === "b") && setupStep.value > 1) {
        event.preventDefault();
        setupStep.value = setupStep.value - 1;
      }
      // Arrow Right or 'n' key - go next (or begin guide from starter screen)
      else if (event.key === "ArrowRight" || event.key === "n") {
        event.preventDefault();
        if (setupStep.value === 0) {
          setupStep.value = 1; // Begin guide from starter screen
        } else if (setupStep.value < 6) {
          setupStep.value = setupStep.value + 1;
        }
      }
    };

    onMounted(async () => {
      if (!props.session) {
        window.location.href = "/login";
        return;
      }

      // Add keyboard event listener
      window.addEventListener("keydown", handleKeyDown);

      await Promise.all([loadApps(), loadKeys(), loadCredentials()]);
    });

    onUnmounted(() => {
      // Clean up keyboard event listener
      window.removeEventListener("keydown", handleKeyDown);
    });

    return {
      error,
      success,
      activeTab,
      pageTitle,
      setupStep,
      codeInstall,
      codeClone,
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
      showAddKeyForm,
      newKeyName,
      newPublicKey,
      showDeleteModal,
      keyToDelete,
      addKey,
      deleteKey,
      confirmDelete,
      cancelDelete,
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
      handleTabChange,
      formatDate,
      startGuide,
    };
  },
};
</script>

<style scoped>
/* Guide intro/starter screen */
.guide-intro {
  height: 500px;
  display: flex;
  flex-direction: column;
}

.guide-intro-content {
  text-align: center;
  flex: 1;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
}

.guide-intro-eyebrow {
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: #666;
  margin-bottom: 16px;
}

.guide-intro-title {
  font-size: clamp(1.5rem, 3vw, 2.25rem);
  font-weight: 600;
  color: #0f0f0f;
  line-height: 1.2;
}

.guide-intro-description {
  font-size: clamp(1.05rem, 2vw, 1.095rem);
  color: rgba(15, 15, 15, 0.875);
  margin: 0 auto;
  line-height: 1.6;
  max-width: 550px;
  margin: 32px auto;
}

.guide-completion-title {
  font-size: clamp(1.5rem, 3vw, 2.25rem);
  font-weight: 600;
  color: #0f0f0f;
  line-height: 1.3;
  margin: 0;
}

.guide-completion-description {
  font-size: 1.1rem;
  color: rgba(15, 15, 15, 0.75);
  margin: 24px auto 36px auto;
  line-height: 1.6;
  max-width: 500px;
}

.guide-intro-meta {
  display: flex;
  justify-content: center;
  gap: 56px;
  padding: 12px;
  flex-wrap: wrap;
}

.intro-meta-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.95rem;
  color: #666;
}

.intro-meta-icon {
  font-size: 1.125rem;
}

.intro-meta-icon-svg {
  width: 18px;
  height: 18px;
  stroke: #666;
  flex-shrink: 0;
}

.guide-intro-actions {
  display: flex;
  justify-content: center;
  gap: 16px;
  align-items: center;
}

/* Quick start inline cards with fixed height */
.quick-start-inline {
  min-height: 500px;
  display: flex;
  flex-direction: column;
  position: relative;
}

/* Step header */
.step-header {
  margin-bottom: 56px;
  flex-shrink: 0;
}

.step-title {
  font-size: clamp(1.35rem, 3vw, 2rem);
  font-weight: 600;
  color: #0f0f0f;
  margin: 0;
  line-height: 1.2;
  text-align: left;
}

.step-metadata {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}

.step-time,
.step-prereq {
  font-size: 0.875rem;
  color: #666;
}

.step-time::before {
  content: "⏱ ";
  opacity: 0.7;
}

.step-prereq::before {
  content: "📋 ";
  opacity: 0.7;
}

/* Guide link styling */
.guide-link {
  color: #0f0f0f;
  font-weight: 500;
  text-decoration: underline dotted;
  transition: all 0.2s ease;
}

.guide-link:hover,
.guide-link:active {
  color: #f048b5;
}

/* Tooltip styling */
.tooltip-wrapper {
  position: relative;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  cursor: help;
}

.tooltip-icon {
  font-size: clamp(1.05rem, 2vw, 1.175rem);
  opacity: 0.75;
  transition: opacity 0.2s ease;
}

.tooltip-wrapper:hover .tooltip-icon {
  opacity: 1;
}

.tooltip-content {
  position: absolute;
  bottom: calc(100% + 8px);
  left: 50%;
  transform: translateX(-50%);
  background: #0f0f0f;
  background-color: rgb(15, 15, 15);
  color: white;
  padding: 12px 16px;
  border-radius: 8px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  font-size: 1.025rem;
  font-weight: 400;
  line-height: 1.5;
  width: 330px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.9), 0 2px 8px rgba(0, 0, 0, 0.6), 0 0 0 1px rgba(0, 0, 0, 0.5);
  opacity: 0;
  visibility: hidden;
  transition: opacity 0.2s ease, visibility 0.2s ease, transform 0.2s ease;
  z-index: 100;
  pointer-events: none;
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
}

.tooltip-content::after {
  content: "";
  position: absolute;
  top: 100%;
  left: 50%;
  transform: translateX(-50%);
  border: 6px solid transparent;
  border-top-color: #0f0f0f;
}

.tooltip-wrapper:hover .tooltip-content {
  opacity: 1;
  visibility: visible;
  transform: translateX(-50%) scale(1.02);
}

.tooltip-title {
  display: block;
  font-weight: 600;
  margin-bottom: 6px;
  color: #f048b5;
  font-size: 0.85em;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}

/* Two-column guide layout */
.guide-layout {
  display: grid;
  grid-template-columns: 0.8fr 1fr;
  gap: 48px;
  align-items: start;
  flex: 1;
  min-height: 0;
}

.guide-layout-step2 {
  grid-template-columns: 0.65fr 1.35fr;
}

.guide-layout-balanced {
  grid-template-columns: 0.8fr 1fr;
}

.guide-content {
  width: 100%;
  min-width: 0;
}

.guide-code {
  width: 100%;
  min-width: 0;
}

/* Guide navigation */
.guide-navigation {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: auto;
  padding-top: 24px;
  flex-shrink: 0;
}

.btn-exit {
  opacity: 0.6;
}

.btn-exit:hover {
  opacity: 1;
}

.keyboard-hint {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  margin-left: 8px;
  padding: 2px 6px;
  font-size: 0.75rem;
  font-weight: 500;
  color: #666;
  background: rgba(0, 0, 0, 0.05);
  border: 1px solid rgba(0, 0, 0, 0.1);
  border-radius: 4px;
  font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace;
  min-width: 24px;
  line-height: 1;
}

.btn-continue .keyboard-hint {
  margin-left: 8px;
}

/* Code syntax highlighting */
.code-command {
  color: #e0e0e0;
}

.code-comment {
  color: #7c7c7c;
  font-style: italic;
}

/* Responsive layout for mobile/tablet */
@media (max-width: 968px) {
  .guide-layout {
    grid-template-columns: 1fr;
    gap: 32px;
  }

  .step-header {
    margin-bottom: 32px;
  }
}

/* Modal styles */
.modal-overlay {
  position: fixed;
  inset: 0;
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
