<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="dashboard-container">
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

      <!-- SSH Keys Section -->
      <section class="section">
        <h2>SSH Keys</h2>
        <p class="section-description">
          Add SSH keys to push code to your applications via Git.
        </p>

        <!-- Add Key Form -->
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

      <!-- Quick Start Section -->
      <section class="section">
        <h2>Quick Start</h2>
        <p class="section-description">
          Use the CLI to create and deploy applications.
        </p>
        <div class="code-block">
          <pre>
            cd my-app
            caution init
            # Adjust Procfile as needed
            git push caution main
            caution verify --reproduce
          </pre>
        </div>
      </section>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'

export default {
  name: 'Dashboard',
  props: {
    session: String
  },
  setup(props) {
    const error = ref(null)
    const success = ref(null)
    const sshKeys = ref([])
    const loadingKeys = ref(true)
    const addingKey = ref(false)
    const deletingKey = ref(null)
    const newKeyName = ref('')
    const newPublicKey = ref('')

    onMounted(async () => {
      if (!props.session) {
        window.location.href = '/login'
        return
      }

      await loadKeys()
    })

    const loadKeys = async () => {
      loadingKeys.value = true
      error.value = null

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
        const response = await fetch('/ssh-keys', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Session-ID': props.session
          },
          body: JSON.stringify({
            public_key: newPublicKey.value.trim(),
            name: newKeyName.value.trim() || null
          })
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
        error.value = 'Failed to connect to server'
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

    const logout = () => {
      window.location.href = '/login'
    }

    return {
      error,
      success,
      sshKeys,
      loadingKeys,
      addingKey,
      deletingKey,
      newKeyName,
      newPublicKey,
      addKey,
      deleteKey,
      logout
    }
  }
}
</script>

<style scoped>
.dashboard-container {
  width: 100%;
  max-width: 800px;
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
  margin-bottom: 32px;
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

.section {
  margin-bottom: 40px;
}

.section-description {
  color: #666;
  margin-bottom: 20px;
  font-size: 14px;
}

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
</style>
