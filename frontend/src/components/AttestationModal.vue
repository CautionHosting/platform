<template>
  <div class="modal-overlay" @click.self="$emit('close')">
    <div class="modal-content">
      <div class="modal-header">
        <h2>Attestation</h2>
        <button class="btn-close" @click="$emit('close')">&times;</button>
      </div>

      <div class="modal-body">
        <div class="endpoint-info">
          <span class="label">Endpoint:</span>
          <code>{{ attestationUrl }}</code>
        </div>

        <div class="verification-section">
          <div v-if="result" :class="['result-banner', result.verified ? 'success' : 'error']">
            <template v-if="result.verified">
              ✓ Attestation verification PASSED
            </template>
            <template v-else>
              ✗ Attestation verification FAILED: {{ result.error }}
            </template>
          </div>

          <div v-if="result" class="expandable-sections">
            <details class="expandable-section">
              <summary>Verification Steps</summary>
              <div class="section-content">
                <div class="checks-list">
                  <div v-for="check in checks" :key="check.id" :class="['check-item', check.status]">
                    <span class="check-icon">
                      <template v-if="check.status === 'success'">✓</template>
                      <template v-else-if="check.status === 'error'">✗</template>
                      <template v-else>○</template>
                    </span>
                    <span class="check-message">{{ check.message }}</span>
                  </div>
                </div>
              </div>
            </details>

            <details v-if="result.verified" class="expandable-section">
              <summary>PCR Values</summary>
              <div class="section-content">
                <div class="pcrs-list">
                  <div v-for="(value, name) in result.pcrs" :key="name" class="pcr-item">
                    <span class="pcr-label">{{ name }}:</span>
                    <code class="pcr-value">{{ value }}</code>
                  </div>
                </div>
              </div>
            </details>

            <details v-if="result.verified && result.manifest" class="expandable-section">
              <summary>Sources</summary>
              <div class="section-content">
                <div class="sources-list">
                  <div v-if="result.manifest.app_source" class="source-item">
                    <span class="source-label">App:</span>
                    <div class="source-details">
                      <a v-if="getSourceUrl(result.manifest.app_source)"
                         :href="getSourceUrl(result.manifest.app_source)"
                         target="_blank"
                         class="source-link">
                        {{ getSourceUrl(result.manifest.app_source) }}
                      </a>
                      <span v-else class="source-value">N/A</span>
                      <span v-if="result.manifest.app_source.commit" class="source-meta">
                        @ {{ result.manifest.app_source.commit.slice(0, 12) }}
                      </span>
                      <span v-if="result.manifest.app_source.branch" class="source-branch">
                        ({{ result.manifest.app_source.branch }})
                      </span>
                    </div>
                  </div>
                  <div v-if="result.manifest.enclave_source" class="source-item">
                    <span class="source-label">Enclave:</span>
                    <div class="source-details">
                      <a v-if="getSourceUrl(result.manifest.enclave_source)"
                         :href="getSourceUrl(result.manifest.enclave_source)"
                         target="_blank"
                         class="source-link">
                        {{ getSourceUrl(result.manifest.enclave_source) }}
                      </a>
                      <span v-else class="source-value">{{ formatSource(result.manifest.enclave_source) }}</span>
                      <span v-if="result.manifest.enclave_source.commit" class="source-meta">
                        @ {{ result.manifest.enclave_source.commit.slice(0, 12) }}
                      </span>
                      <span v-if="result.manifest.enclave_source.branch" class="source-branch">
                        ({{ result.manifest.enclave_source.branch }})
                      </span>
                    </div>
                  </div>
                  <div v-if="result.manifest.framework_source" class="source-item">
                    <span class="source-label">Framework:</span>
                    <div class="source-details">
                      <a v-if="getSourceUrl(result.manifest.framework_source)"
                         :href="getSourceUrl(result.manifest.framework_source)"
                         target="_blank"
                         class="source-link">
                        {{ getSourceUrl(result.manifest.framework_source) }}
                      </a>
                      <span v-else class="source-value">{{ formatSource(result.manifest.framework_source) }}</span>
                      <span v-if="result.manifest.framework_source?.commit" class="source-meta">
                        @ {{ result.manifest.framework_source.commit.slice(0, 12) }}
                      </span>
                      <span v-if="result.manifest.framework_source?.branch" class="source-branch">
                        ({{ result.manifest.framework_source.branch }})
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </details>

            <details v-if="rawResponse" class="expandable-section">
              <summary>Raw Response</summary>
              <div class="section-content">
                <pre class="raw-json">{{ JSON.stringify(rawResponse, null, 2) }}</pre>
              </div>
            </details>
          </div>

          <div v-else class="loading-state">
            <BrailleLoader />
            <span class="loading-text">Verifying attestation...</span>
          </div>
        </div>
      </div>

      <div class="modal-footer">
        <button class="btn-secondary" @click="$emit('close')">Close</button>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { verify as verifyNitro } from 'tee-attestation-js/nitro'
import BrailleLoader from './BrailleLoader.vue'

function bytesToHex(bytes) {
  if (!bytes) return ''
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

// Helper to get CSRF token from cookie
function getCsrfToken() {
  const match = document.cookie.match(/caution_csrf=([^;]+)/)
  return match ? match[1] : null
}

// Helper for authenticated API calls with CSRF protection
function authFetch(url, options = {}) {
  const headers = options.headers || {}

  // Add CSRF token for state-changing requests
  if (options.method && options.method !== 'GET') {
    const csrfToken = getCsrfToken()
    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken
    }
  }

  return fetch(url, {
    ...options,
    headers,
    credentials: 'include',
  })
}

export default {
  name: 'AttestationModal',
  components: { BrailleLoader },
  props: {
    resourceId: { type: String, required: true },
    publicIp: { type: String, required: true },
    appName: { type: String, default: 'App' }
  },
  emits: ['close'],
  setup(props) {
    const checks = ref([])
    const result = ref(null)
    const rawResponse = ref(null)
    const attestationUrl = `/api/resources/${props.resourceId}/attestation`

    function addCheck(id, message, status) {
      const existing = checks.value.find(c => c.id === id)
      if (existing) {
        existing.message = message
        existing.status = status
      } else {
        checks.value.push({ id, message, status })
      }
    }

    async function verify() {
      checks.value = []
      result.value = null

      try {
        const nonce = crypto.getRandomValues(new Uint8Array(32))
        addCheck('nonce', `Challenge nonce: ${bytesToHex(nonce)}`, 'success')

        addCheck('request', 'Requesting attestation...', 'pending')
        const response = await authFetch(attestationUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ nonce: Array.from(nonce) })
        })

        if (!response.ok) throw new Error(`Request failed: ${response.status}`)
        addCheck('request', 'Attestation received', 'success')

        const jsonResponse = await response.json()
        rawResponse.value = jsonResponse
        if (jsonResponse.error) throw new Error(jsonResponse.error)

        const attestationB64 = jsonResponse.attestation_document
        if (!attestationB64) throw new Error('No attestation document')

        const attestationBytes = Uint8Array.from(atob(attestationB64), c => c.charCodeAt(0))

        addCheck('verify', 'Verifying attestation...', 'pending')
        const verifyResult = await verifyNitro(attestationBytes, { nonce })

        if (!verifyResult.verified) {
          throw new Error(verifyResult.error || 'Verification failed')
        }

        addCheck('verify', 'Attestation verified (certificate chain, signature, nonce)', 'success')

        const manifest = jsonResponse.manifest || verifyResult.userData
        result.value = { verified: true, pcrs: verifyResult.pcrs, manifest }

      } catch (err) {
        addCheck('error', err.message, 'error')
        result.value = { verified: false, error: err.message }
      }
    }

    function formatSource(source) {
      if (typeof source === 'string') return source
      return source.url || JSON.stringify(source)
    }

    function getSourceUrl(source) {
      if (!source) return null
      if (typeof source === 'string') return source.startsWith('http') ? source : null
      return source.urls?.[0] || source.url || null
    }

    onMounted(() => {
      verify()
    })

    return { checks, result, rawResponse, attestationUrl, formatSource, getSourceUrl }
  }
}
</script>

<style scoped>
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
  border-radius: 12px;
  width: 90%;
  max-width: 700px;
  max-height: 85vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px 24px;
  border-bottom: 1px solid #eee;
}

.modal-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}

.btn-close {
  background: none;
  border: none;
  font-size: 24px;
  color: #999;
  cursor: pointer;
  padding: 0;
  line-height: 1;
}

.btn-close:hover {
  color: #333;
}

.modal-body {
  padding: 24px;
  overflow-y: auto;
  flex: 1;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  padding: 16px 24px;
  border-top: 1px solid #eee;
}

.endpoint-info {
  background: #f8f9fa;
  padding: 12px 16px;
  border-radius: 8px;
  margin-bottom: 20px;
  font-size: 14px;
}

.endpoint-info .label {
  color: #666;
  margin-right: 8px;
}

.endpoint-info code {
  font-family: 'Monaco', monospace;
  color: #333;
}

.loading-state {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  padding: 40px 20px;
  color: #666;
}

.loading-text {
  font-size: 14px;
}

.checks-list {
  margin-bottom: 20px;
}

.check-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 8px 0;
  font-size: 14px;
}

.check-icon {
  width: 20px;
  text-align: center;
  flex-shrink: 0;
}

.check-item.success .check-icon {
  color: #2e7d32;
}

.check-item.error .check-icon {
  color: #c62828;
}

.check-item.pending .check-icon {
  color: #999;
}

.check-message {
  word-break: break-all;
  font-family: 'Monaco', monospace;
  font-size: 13px;
}

.result-banner {
  padding: 16px;
  border-radius: 8px;
  text-align: center;
  font-weight: 600;
  margin: 20px 0;
}

.result-banner.success {
  background: #e8f5e9;
  color: #2e7d32;
}

.result-banner.error {
  background: #ffebee;
  color: #c62828;
}

.expandable-sections {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.expandable-section {
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  overflow: hidden;
}

.expandable-section summary {
  padding: 12px 16px;
  background: #f8f9fa;
  cursor: pointer;
  font-weight: 600;
  font-size: 14px;
  color: #333;
  list-style: none;
  display: flex;
  align-items: center;
  gap: 8px;
}

.expandable-section summary::-webkit-details-marker {
  display: none;
}

.expandable-section summary::before {
  content: '▶';
  font-size: 10px;
  transition: transform 0.2s;
}

.expandable-section[open] summary::before {
  transform: rotate(90deg);
}

.expandable-section summary:hover {
  background: #f0f0f0;
}

.section-content {
  padding: 16px;
  border-top: 1px solid #e0e0e0;
}

.raw-json {
  margin: 0;
  padding: 12px;
  background: #f8f9fa;
  border-radius: 6px;
  font-family: 'Monaco', monospace;
  font-size: 11px;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 300px;
  overflow-y: auto;
}

.pcrs-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.sources-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.pcr-item {
  display: flex;
  gap: 8px;
  padding: 6px 0;
  font-size: 13px;
}

.pcr-label {
  color: #666;
  min-width: 50px;
}

.pcr-value {
  font-family: 'Monaco', monospace;
  word-break: break-all;
  color: #333;
}

.source-item {
  display: flex;
  align-items: baseline;
  gap: 12px;
  padding: 8px 12px;
  background: #f8f9fa;
  border-radius: 6px;
}

.source-label {
  color: #666;
  font-weight: 500;
  min-width: 80px;
  flex-shrink: 0;
}

.source-details {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 8px;
  font-family: 'Monaco', monospace;
  font-size: 12px;
  word-break: break-all;
}

.source-link {
  color: #667eea;
  text-decoration: none;
}

.source-link:hover {
  text-decoration: underline;
}

.source-value {
  color: #333;
}

.source-meta {
  color: #888;
  font-size: 11px;
}

.source-branch {
  color: #2e7d32;
  font-size: 11px;
}

.btn-secondary {
  padding: 10px 20px;
  background: #f5f5f5;
  color: #666;
  border: 1px solid #ddd;
  border-radius: 8px;
  font-size: 14px;
  cursor: pointer;
  text-decoration: none;
}

.btn-secondary:hover {
  background: #eee;
  color: #333;
}
</style>
