<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="dashboard-container">
    <img src="../assets/caution-logo-black.svg" alt="Caution" class="logo" />
    <div class="dashboard-card">
      <div class="header">
        <h1>Dashboard</h1>
        <button @click="logout" class="btn-logout">Logout</button>
      </div>

      <div v-if="error" class="error-message">
        {{ error }}
      </div>

      <div v-if="success" class="success-message">
        {{ success }}
      </div>

      <div class="tabs">
        <button
          :class="['tab', { active: activeTab === 'apps' }]"
          @click="activeTab = 'apps'"
        >
          Apps
        </button>
        <button
          :class="['tab', { active: activeTab === 'ssh' }]"
          @click="activeTab = 'ssh'"
        >
          SSH Keys
        </button>
        <button
          :class="['tab', { active: activeTab === 'credentials' }]"
          @click="activeTab = 'credentials'"
        >
          Cloud Credentials
        </button>
      </div>

      <div v-if="activeTab === 'apps'" class="tab-content">
        <section class="section">
          <h2>Applications</h2>
          <p class="section-description">
            Your deployed applications and their status.
          </p>

          <div class="apps-list">
            <div v-if="loadingApps" class="loading">Loading apps...</div>
            <div v-else-if="apps.length === 0" class="quick-start">
              <h3>Quick Start</h3>
              <p class="section-description">
                Download, and install the Caution CLI.
              </p>
              <div class="code-block">
                <pre>
git clone https://codeberg.org/caution/platform
cd platform
make build-cli
./utils/install.sh
                </pre>
              </div>
              <br/>
              <p class="section-description">
                Use the CLI to create and deploy applications.
              </p>
              <div class="code-block">
                <pre>
git clone https://codeberg.org/caution/hello-world-enclave
cd hello-world-enclave
caution login
# Tap your smart card
caution ssh-keys add --from-agent 
# You can also pass a file such as ~/.ssh/id_ed25519.pub
caution init
git push caution main
caution verify --reproduce
                </pre>
              </div>
            </div>
            <div v-else class="apps-grid">
              <div v-for="app in apps" :key="app.id" class="app-card">
                <div class="app-header">
                  <div class="app-header-left">
                    <span class="app-name">{{ app.resource_name || 'Unnamed App' }}</span>
                    <span class="app-id">{{ app.id }}</span>
                  </div>
                  <span :class="['app-status', `status-${app.state.toLowerCase()}`]">
                    {{ app.state }}
                  </span>
                </div>
                <div class="app-body">
                  <div class="app-details">
                    <div class="app-specs">
                      <span class="spec-badge">{{ getEnclaveConfig(app).memory_mb }} MB</span>
                      <span class="spec-badge">{{ getEnclaveConfig(app).cpus }} CPU</span>
                      <span v-if="getInstanceType(app)" class="spec-badge">{{ getInstanceType(app) }}</span>
                      <span v-if="getEnclaveConfig(app).debug" class="spec-badge spec-debug">Debug</span>
                    </div>
                    <div v-if="app.public_ip" class="app-detail">
                      <span class="detail-label">IP:</span>
                      <span class="detail-value">{{ app.public_ip }}</span>
                    </div>
                    <div v-if="app.public_ip || app.domain" class="app-detail">
                      <button @click="showAttestation(app)" class="app-link-btn">
                        Attestation
                      </button>
                    </div>
                    <div v-if="app.domain" class="app-detail app-detail-full">
                      <a :href="'https://' + app.domain" target="_blank" class="app-link">
                        https://{{ app.domain }}
                      </a>
                    </div>
                    <div v-else-if="app.public_ip" class="app-detail app-detail-full">
                      <a :href="'http://' + app.public_ip" target="_blank" class="app-link">
                        http://{{ app.public_ip }}
                      </a>
                    </div>
                  </div>
                  <div class="app-actions">
                    <button
                      @click="destroyApp(app.id, app.resource_name)"
                      class="btn-danger"
                      :disabled="destroyingApp === app.id"
                    >
                      {{ destroyingApp === app.id ? 'Destroying...' : 'Destroy' }}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>

      <div v-if="activeTab === 'credentials'" class="tab-content">
        <section class="section">
          <h2>AWS Credentials</h2>
          <p class="section-description">
            Add AWS credentials to deploy applications to your own infrastructure.
          </p>

          <div class="add-key-form">
            <div class="form-group">
              <label for="credName">Name</label>
              <input
                id="credName"
                v-model="newCredName"
                type="text"
                placeholder="e.g., Production AWS"
                :disabled="addingCred"
              />
            </div>
            <div class="form-group">
              <label for="awsAccessKeyId">Access Key ID</label>
              <input
                id="awsAccessKeyId"
                v-model="newCredAwsKeyId"
                type="text"
                placeholder="AKIA..."
                :disabled="addingCred"
              />
            </div>
            <div class="form-group">
              <label for="awsSecretKey">Secret Access Key</label>
              <input
                id="awsSecretKey"
                v-model="newCredAwsSecret"
                type="password"
                placeholder="Enter secret access key"
                :disabled="addingCred"
              />
            </div>
            <div class="form-group checkbox-group">
              <label>
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
              :disabled="addingCred || !newCredName.trim() || !newCredAwsKeyId.trim() || !newCredAwsSecret.trim()"
            >
              {{ addingCred ? 'Adding...' : 'Add Credential' }}
            </button>
          </div>

          <div class="keys-list">
            <div v-if="loadingCreds" class="loading">Loading credentials...</div>
            <div v-else-if="credentials.length === 0" class="empty-state">
              No AWS credentials added yet.
            </div>
            <div v-else>
              <div v-for="cred in credentials" :key="cred.id" class="cred-item">
                <div class="cred-info">
                  <div class="cred-header">
                    <span class="cred-name">{{ cred.name }}</span>
                    <span v-if="cred.is_default" class="cred-default">Default</span>
                  </div>
                  <code class="cred-identifier">{{ cred.identifier }}</code>
                </div>
                <div class="cred-actions">
                  <button
                    v-if="!cred.is_default"
                    @click="setDefaultCredential(cred.id)"
                    class="btn-secondary"
                    :disabled="settingDefault === cred.id"
                  >
                    {{ settingDefault === cred.id ? '...' : 'Set Default' }}
                  </button>
                  <button
                    @click="deleteCredential(cred.id, cred.name)"
                    class="btn-danger"
                    :disabled="deletingCred === cred.id"
                  >
                    {{ deletingCred === cred.id ? 'Deleting...' : 'Delete' }}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>

      <div v-if="activeTab === 'ssh'" class="tab-content">
        <section class="section">
          <h2>SSH Keys</h2>
          <p class="section-description">
            Add SSH keys to push code to your applications via Git.
          </p>

          <div class="add-key-form">
            <div class="form-group">
              <label for="keyName">Key Name (optional)</label>
              <input
                id="keyName"
                v-model="newKeyName"
                type="text"
                placeholder="e.g., Work Laptop"
                :disabled="addingKey"
              />
            </div>
            <div class="form-group">
              <label for="publicKey">Public Key</label>
              <textarea
                id="publicKey"
                v-model="newPublicKey"
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
              {{ addingKey ? 'Adding...' : 'Add SSH Key' }}
            </button>
          </div>

          <!-- Keys List -->
          <div class="keys-list">
            <div v-if="loadingKeys" class="loading">Loading keys...</div>
            <div v-else-if="sshKeys.length === 0" class="empty-state">
              No SSH keys added yet.
            </div>
            <div v-else>
              <div v-for="key in sshKeys" :key="key.fingerprint" class="key-item">
                <div class="key-info">
                  <span class="key-name">{{ key.name || 'Unnamed Key' }}</span>
                  <code class="key-fingerprint">{{ key.fingerprint }}</code>
                  <span class="key-type">{{ key.key_type }}</span>
                </div>
                <button
                  @click="deleteKey(key.fingerprint)"
                  class="btn-danger"
                  :disabled="deletingKey === key.fingerprint"
                >
                  {{ deletingKey === key.fingerprint ? 'Deleting...' : 'Delete' }}
                </button>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>

  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { showModal as showAttestationModal } from 'attestation-widget'

async function sha256Hex(message) {
  const msgBuffer = new TextEncoder().encode(message)
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

function base64UrlToArrayBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

export default {
  name: 'Dashboard',
  props: {
    session: String
  },
  setup(props) {
    const error = ref(null)
    const success = ref(null)
    const activeTab = ref('apps')

    // Apps state
    const apps = ref([])
    const loadingApps = ref(true)
    const destroyingApp = ref(null)

    const showAttestation = (app) => {
      const url = `http://${app.public_ip}/attestation`
      showAttestationModal({ attestationUrl: url })
    }

    const getEnclaveConfig = (app) => {
      return app.configuration?.enclave_config || { memory_mb: 512, cpus: 2, debug: false }
    }

    const getInstanceType = (app) => {
      return app.configuration?.instance_type || null
    }

    // SSH Keys state
    const sshKeys = ref([])
    const loadingKeys = ref(true)
    const addingKey = ref(false)
    const deletingKey = ref(null)
    const newKeyName = ref('')
    const newPublicKey = ref('')

    // Credentials state
    const credentials = ref([])
    const loadingCreds = ref(true)
    const addingCred = ref(false)
    const deletingCred = ref(null)
    const settingDefault = ref(null)
    const newCredName = ref('')
    const newCredAwsKeyId = ref('')
    const newCredAwsSecret = ref('')
    const newCredIsDefault = ref(false)

    onMounted(async () => {
      if (!props.session) {
        window.location.href = '/login'
        return
      }

      await Promise.all([loadApps(), loadKeys(), loadCredentials()])
    })

    const loadApps = async () => {
      loadingApps.value = true

      try {
        const response = await fetch('/api/resources', {
          headers: {
            'X-Session-ID': props.session
          }
        })

        if (response.ok) {
          apps.value = await response.json()
        } else if (response.status === 401) {
          window.location.href = '/login'
        } else {
          const data = await response.json().catch(() => ({}))
          error.value = data.error || 'Failed to load apps'
        }
      } catch (err) {
        error.value = 'Failed to connect to server'
      } finally {
        loadingApps.value = false
      }
    }

    const destroyApp = async (id, name) => {
      const displayName = name || `App #${id}`
      if (!confirm(`Are you sure you want to destroy "${displayName}"? This cannot be undone.`)) return

      destroyingApp.value = id
      error.value = null
      success.value = null

      try {
        const response = await fetch(`/api/resources/${id}`, {
          method: 'DELETE',
          headers: {
            'X-Session-ID': props.session
          }
        })

        if (response.ok || response.status === 204) {
          success.value = `App "${displayName}" destroyed`
          await loadApps()
        } else {
          const data = await response.json().catch(() => ({}))
          error.value = data.error || 'Failed to destroy app'
        }
      } catch (err) {
        error.value = 'Failed to connect to server'
      } finally {
        destroyingApp.value = null
      }
    }

    const loadKeys = async () => {
      loadingKeys.value = true

      try {
        const response = await fetch('/ssh-keys', {
          headers: {
            'X-Session-ID': props.session
          }
        })

        if (response.ok) {
          const data = await response.json()
          sshKeys.value = data.keys || []
        } else if (response.status === 401) {
          window.location.href = '/login'
        } else {
          const data = await response.json().catch(() => ({}))
          error.value = data.error || 'Failed to load SSH keys'
        }
      } catch (err) {
        error.value = 'Failed to connect to server'
      } finally {
        loadingKeys.value = false
      }
    }

    const addKey = async () => {
      if (!newPublicKey.value.trim()) return

      addingKey.value = true
      error.value = null
      success.value = null

      try {
        const body = JSON.stringify({
          public_key: newPublicKey.value.trim(),
          name: newKeyName.value.trim() || null
        })
        const bodyHash = await sha256Hex(body)

        const challengeRes = await fetch('/auth/sign-request', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Session-ID': props.session
          },
          body: JSON.stringify({
            method: 'POST',
            path: '/ssh-keys',
            body_hash: bodyHash
          })
        })

        if (!challengeRes.ok) {
          const data = await challengeRes.json().catch(() => ({}))
          throw new Error(data.error || 'Failed to get signing challenge')
        }

        const { publicKey, challenge_id } = await challengeRes.json()

        publicKey.challenge = base64UrlToArrayBuffer(publicKey.challenge)
        if (publicKey.allowCredentials) {
          publicKey.allowCredentials = publicKey.allowCredentials.map(cred => ({
            ...cred,
            id: base64UrlToArrayBuffer(cred.id)
          }))
        }

        const credential = await navigator.credentials.get({ publicKey })

        const credentialResponse = {
          id: credential.id,
          rawId: arrayBufferToBase64Url(credential.rawId),
          type: credential.type,
          response: {
            authenticatorData: arrayBufferToBase64Url(credential.response.authenticatorData),
            clientDataJSON: arrayBufferToBase64Url(credential.response.clientDataJSON),
            signature: arrayBufferToBase64Url(credential.response.signature),
            userHandle: credential.response.userHandle
              ? arrayBufferToBase64Url(credential.response.userHandle)
              : null
          }
        }

        const fido2Response = btoa(JSON.stringify(credentialResponse))
          .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')

        const response = await fetch('/ssh-keys', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Fido2-Challenge-Id': challenge_id,
            'X-Fido2-Response': fido2Response
          },
          body: body
        })

        if (response.ok) {
          const data = await response.json()
          success.value = `SSH key added (${data.fingerprint})`
          newKeyName.value = ''
          newPublicKey.value = ''
          await loadKeys()
        } else {
          const data = await response.json().catch(() => ({}))
          error.value = data.error || 'Failed to add SSH key'
        }
      } catch (err) {
        if (err.name === 'NotAllowedError') {
          error.value = 'Security key authentication was cancelled or timed out'
        } else {
          error.value = err.message || 'Failed to add SSH key'
        }
      } finally {
        addingKey.value = false
      }
    }

    const deleteKey = async (fingerprint) => {
      if (!confirm('Are you sure you want to delete this SSH key?')) return

      deletingKey.value = fingerprint
      error.value = null
      success.value = null

      try {
        const response = await fetch(`/ssh-keys/${encodeURIComponent(fingerprint)}`, {
          method: 'DELETE',
          headers: {
            'X-Session-ID': props.session
          }
        })

        if (response.ok || response.status === 204) {
          success.value = 'SSH key deleted'
          await loadKeys()
        } else {
          const data = await response.json().catch(() => ({}))
          error.value = data.error || 'Failed to delete SSH key'
        }
      } catch (err) {
        error.value = 'Failed to connect to server'
      } finally {
        deletingKey.value = null
      }
    }

    const loadCredentials = async () => {
      loadingCreds.value = true

      try {
        const response = await fetch('/api/credentials', {
          headers: {
            'X-Session-ID': props.session
          }
        })

        if (response.ok) {
          credentials.value = await response.json()
        } else if (response.status === 401) {
          window.location.href = '/login'
        } else {
          const data = await response.json().catch(() => ({}))
          error.value = data.error || 'Failed to load credentials'
        }
      } catch (err) {
        error.value = 'Failed to connect to server'
      } finally {
        loadingCreds.value = false
      }
    }

    const addCredential = async () => {
      if (!newCredName.value.trim() || !newCredAwsKeyId.value.trim() || !newCredAwsSecret.value.trim()) return

      addingCred.value = true
      error.value = null
      success.value = null

      try {
        const body = {
          platform: 'aws',
          name: newCredName.value.trim(),
          access_key_id: newCredAwsKeyId.value.trim(),
          secret_access_key: newCredAwsSecret.value.trim(),
          is_default: newCredIsDefault.value
        }

        const response = await fetch('/api/credentials', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Session-ID': props.session
          },
          body: JSON.stringify(body)
        })

        if (response.ok) {
          success.value = 'AWS credential added'
          newCredName.value = ''
          newCredAwsKeyId.value = ''
          newCredAwsSecret.value = ''
          newCredIsDefault.value = false
          await loadCredentials()
        } else {
          const data = await response.json().catch(() => ({}))
          error.value = data.error || 'Failed to add credential'
        }
      } catch (err) {
        error.value = 'Failed to connect to server'
      } finally {
        addingCred.value = false
      }
    }

    const deleteCredential = async (id, name) => {
      if (!confirm(`Are you sure you want to delete "${name}"?`)) return

      deletingCred.value = id
      error.value = null
      success.value = null

      try {
        const response = await fetch(`/api/credentials/${id}`, {
          method: 'DELETE',
          headers: {
            'X-Session-ID': props.session
          }
        })

        if (response.ok || response.status === 204) {
          success.value = 'Credential deleted'
          await loadCredentials()
        } else {
          const data = await response.json().catch(() => ({}))
          error.value = data.error || 'Failed to delete credential'
        }
      } catch (err) {
        error.value = 'Failed to connect to server'
      } finally {
        deletingCred.value = null
      }
    }

    const setDefaultCredential = async (id) => {
      settingDefault.value = id
      error.value = null
      success.value = null

      try {
        const response = await fetch(`/api/credentials/${id}/default`, {
          method: 'POST',
          headers: {
            'X-Session-ID': props.session
          }
        })

        if (response.ok) {
          success.value = 'Default credential updated'
          await loadCredentials()
        } else {
          const data = await response.json().catch(() => ({}))
          error.value = data.error || 'Failed to set default credential'
        }
      } catch (err) {
        error.value = 'Failed to connect to server'
      } finally {
        settingDefault.value = null
      }
    }

    const logout = () => {
      window.location.href = '/login'
    }

    return {
      error,
      success,
      activeTab,
      apps,
      loadingApps,
      destroyingApp,
      showAttestation,
      getEnclaveConfig,
      getInstanceType,
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
      logout
    }
  }
}
</script>

<style scoped>
.dashboard-container {
  width: 100%;
  max-width: 900px;
  margin: 0 auto;
}

.dashboard-card {
  background: white;
  border-radius: 16px;
  padding: 40px;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.logo {
  display: block;
  width: 150px;
  height: auto;
  margin: 0 auto 24px;
}

h1 {
  font-size: 32px;
  font-weight: 700;
  color: #333;
  margin: 0;
}

h2 {
  font-size: 20px;
  font-weight: 600;
  color: #333;
  margin-bottom: 8px;
}

/* Tabs */
.tabs {
  display: flex;
  gap: 4px;
  border-bottom: 2px solid #eee;
  margin-bottom: 24px;
}

.tab {
  padding: 12px 24px;
  background: none;
  border: none;
  font-size: 15px;
  font-weight: 500;
  color: #666;
  cursor: pointer;
  position: relative;
  transition: color 0.2s ease;
}

.tab:hover {
  color: #333;
}

.tab.active {
  color: #667eea;
}

.tab.active::after {
  content: '';
  position: absolute;
  bottom: -2px;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.tab-content {
  animation: fadeIn 0.2s ease;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

.section {
  margin-bottom: 40px;
}

.section-description {
  color: #666;
  margin-bottom: 20px;
  font-size: 14px;
}

/* Apps List */
.apps-list {
  border: 1px solid #eee;
  border-radius: 8px;
  overflow: hidden;
}

.apps-grid {
  display: flex;
  flex-direction: column;
}

.app-card {
  padding: 20px;
  border-bottom: 1px solid #eee;
}

.app-card:last-child {
  border-bottom: none;
}

.app-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 12px;
}

.app-header-left {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.app-name {
  font-weight: 600;
  font-size: 16px;
  color: #333;
}

.app-id {
  font-family: monospace;
  font-size: 11px;
  color: #888;
}

.app-status {
  padding: 4px 10px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
  text-transform: uppercase;
}

.status-running {
  background: #e8f5e9;
  color: #2e7d32;
}

.status-pending, .status-provisioning {
  background: #fff3e0;
  color: #e65100;
}

.status-stopped, .status-terminated {
  background: #fce4ec;
  color: #c62828;
}

.status-starting {
  background: #e3f2fd;
  color: #1565c0;
}

.app-body {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  gap: 16px;
}

.app-details {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  flex: 1;
  min-width: 0;
}

.app-specs {
  display: flex;
  gap: 8px;
  width: 100%;
  margin-bottom: 4px;
}

.spec-badge {
  font-size: 11px;
  padding: 3px 8px;
  border-radius: 4px;
  background: #f0f0f0;
  color: #666;
  font-weight: 500;
}

.spec-debug {
  background: #fff3e0;
  color: #e65100;
}

.app-detail {
  font-size: 13px;
}

.app-detail-full {
  width: 100%;
}

.detail-label {
  color: #999;
  margin-right: 4px;
}

.detail-value {
  color: #333;
  font-family: 'Monaco', 'Courier New', monospace;
}

.app-links {
  display: flex;
  gap: 12px;
}

.app-link {
  font-size: 13px;
  color: #667eea;
  text-decoration: none;
}

.app-link:hover {
  text-decoration: underline;
}

.app-link-btn {
  font-size: 13px;
  color: #667eea;
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  font-family: inherit;
}

.app-link-btn:hover {
  text-decoration: underline;
}

.app-actions {
  flex-shrink: 0;
}

.empty-hint {
  font-size: 13px;
  color: #999;
  margin-top: 8px;
}

.code-block-inline {
  display: inline-block;
  margin-top: 8px;
  padding: 8px 12px;
}

.code-block-inline code {
  color: #f8f8f2;
  font-family: 'Monaco', 'Courier New', monospace;
  font-size: 13px;
}

/* SSH Keys */
.add-key-form {
  background: #f8f9fa;
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 20px;
}

.form-group {
  margin-bottom: 16px;
}

.form-group label {
  display: block;
  font-size: 14px;
  font-weight: 500;
  color: #333;
  margin-bottom: 8px;
}

.form-group input,
.form-group textarea {
  width: 100%;
  padding: 12px 16px;
  border: 1px solid #ddd;
  border-radius: 8px;
  font-size: 14px;
  font-family: inherit;
  transition: border-color 0.2s ease;
  box-sizing: border-box;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #667eea;
}

.form-group textarea {
  font-family: 'Monaco', 'Courier New', monospace;
  resize: vertical;
}

.btn-primary {
  padding: 12px 24px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-logout {
  padding: 8px 16px;
  background: #f5f5f5;
  color: #666;
  border: 1px solid #ddd;
  border-radius: 8px;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.btn-logout:hover {
  background: #eee;
  color: #333;
}

.btn-danger {
  padding: 6px 12px;
  background: #fee;
  color: #c33;
  border: 1px solid #fcc;
  border-radius: 6px;
  font-size: 13px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.btn-danger:hover:not(:disabled) {
  background: #fdd;
}

.btn-danger:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.keys-list {
  border: 1px solid #eee;
  border-radius: 8px;
  overflow: hidden;
}

.loading,
.empty-state {
  padding: 24px;
  text-align: center;
  color: #666;
  font-size: 14px;
}

.quick-start {
  padding: 24px;
}

.quick-start h3 {
  font-size: 18px;
  font-weight: 600;
  color: #333;
  margin: 0 0 12px 0;
}

.key-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  border-bottom: 1px solid #eee;
}

.key-item:last-child {
  border-bottom: none;
}

.key-info {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.key-name {
  font-weight: 500;
  color: #333;
}

.key-fingerprint {
  font-size: 12px;
  color: #666;
  background: #f5f5f5;
  padding: 2px 6px;
  border-radius: 4px;
}

.key-type {
  font-size: 12px;
  color: #999;
}

.code-block {
  background: #2d2d2d;
  border-radius: 8px;
  padding: 16px 20px;
  overflow-x: auto;
}

.code-block pre {
  margin: 0;
  color: #f8f8f2;
  font-family: 'Monaco', 'Courier New', monospace;
  font-size: 13px;
  line-height: 1.6;
}

.error-message {
  background: #fee;
  border: 1px solid #fcc;
  border-radius: 8px;
  padding: 12px 16px;
  color: #c33;
  margin-bottom: 20px;
  font-size: 14px;
}

.success-message {
  background: #efe;
  border: 1px solid #cfc;
  border-radius: 8px;
  padding: 12px 16px;
  color: #2e7d32;
  margin-bottom: 20px;
  font-size: 14px;
}

.checkbox-group label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}

.checkbox-group input[type="checkbox"] {
  width: auto;
  padding: 0;
}

.form-group select {
  width: 100%;
  padding: 12px 16px;
  border: 1px solid #ddd;
  border-radius: 8px;
  font-size: 14px;
  font-family: inherit;
  background: white;
  cursor: pointer;
}

.form-group select:focus {
  outline: none;
  border-color: #667eea;
}

.cred-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  border-bottom: 1px solid #eee;
}

.cred-item:last-child {
  border-bottom: none;
}

.cred-info {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.cred-header {
  display: flex;
  align-items: center;
  gap: 8px;
}

.cred-name {
  font-weight: 500;
  color: #333;
}

.cred-platform {
  font-size: 11px;
  padding: 2px 6px;
  border-radius: 4px;
  background: #e3f2fd;
  color: #1565c0;
  text-transform: uppercase;
}

.cred-default {
  font-size: 11px;
  padding: 2px 6px;
  border-radius: 4px;
  background: #e8f5e9;
  color: #2e7d32;
}

.cred-identifier {
  font-size: 12px;
  color: #666;
  background: #f5f5f5;
  padding: 2px 6px;
  border-radius: 4px;
}

.cred-actions {
  display: flex;
  gap: 8px;
}

.btn-secondary {
  padding: 6px 12px;
  background: #f5f5f5;
  color: #666;
  border: 1px solid #ddd;
  border-radius: 6px;
  font-size: 13px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.btn-secondary:hover:not(:disabled) {
  background: #eee;
  color: #333;
}

.btn-secondary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
</style>