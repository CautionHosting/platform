<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial -->
<template>
  <main class="release-approval">
    <div class="eyebrow">caution / Share approval</div>
    <header><h1>{{ title }}</h1><span v-if="active" class="expiry" role="timer">Expires in {{ Math.floor(remaining / 60) }}:{{ String(remaining % 60).padStart(2, '0') }}</span></header>
    <template v-if="active">
      <p>Only approve an attempt you started.</p>
      <section class="card" aria-label="Release summary">
        <dl class="summary">
          <dt>Application</dt><dd>{{ app.name || 'Application name unavailable' }}</dd>
          <template v-if="metadata.organization?.name"><dt>Organization</dt><dd>{{ metadata.organization.name }}</dd></template>
          <dt>Holder</dt><dd>{{ bundle.username || 'Holder name unavailable' }} · Passkey</dd>
          <template v-if="reported.destination_address"><dt>Destination</dt><dd>{{ reported.destination_address }}</dd></template>
          <template v-if="bundle.threshold && bundle.holders"><dt>Quorum</dt><dd>{{ bundle.threshold }} of {{ bundle.holders }} holders required</dd></template>
        </dl>
        <p class="source">Application labels come from Platform. The connection address is reported by your CLI.</p>
        <p v-if="addressMismatch" class="notice">The Platform-recorded address ({{ app.public_ip }}) differs from the CLI-reported destination. Check this difference before approving.</p>
      </section>
      <section class="card actions">
        <h2>Compare with your terminal</h2>
        <strong class="comparison">{{ comparisonCode(request.context_hash) }}</strong>
        <p>Compare all four groups with your terminal. Approve only if they match.</p>
        <p>Your passkey authorizes Caution’s enclave to re-encrypt one share to this destination. The private key stays inside the enclave. Other holders may still be required.</p>
        <p role="status">{{ status }}</p>
        <div class="buttons"><button class="primary" :disabled="state !== 'pending'" @click="approve">Approve with passkey</button><button :disabled="delivering" @click="cancel">Cancel</button></div>
      </section>
      <details class="card"><summary>Verification details</summary>
        <ul>
          <li><b>Comparison code:</b> compares authenticated release context with the CLI. It does not authenticate descriptive application names or addresses.</li>
          <li><b>Destination:</b> the custody enclave checked fresh destination attestation against the requested PCR policy. The CLI also checks it before requesting approval.</li>
          <li><b>Custody service:</b> the gateway checked custody evidence against its configured PCR policy. The CLI independently checks it against its selected policy.</li>
          <li><b>Platform labels:</b> describe organization records; they are not attested application identity.</li>
        </ul>
        <p>To assess measurements independently, compare the PCR values with your independently trusted policy.</p>
        <details><summary>Technical values</summary><dl>
          <template v-for="item in details" :key="item.label"><dt>{{ item.label }}</dt><dd><ReleaseValue :value="item.value" :label="item.label" /></dd></template>
        </dl><h3>Approved destination measurements</h3><dl><template v-for="(pcr, index) in request.context.destination_policy" :key="index"><dt>PCR{{ index }}</dt><dd><ReleaseValue :value="pcr" :label="`destination PCR${index}`" /></dd></template></dl>
        <h3>Gateway custody verification policy</h3><dl><template v-for="(pcr, index) in request.custody_policy" :key="index"><dt>PCR{{ index }}</dt><dd><ReleaseValue :value="pcr" :label="`custody PCR${index}`" /></dd></template></dl>
        </details>
      </details>
    </template>
    <p v-else role="status" class="card">{{ status }}</p>
  </main>
</template>
<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { releaseOptions, releaseAssertion } from '../composables/releaseApproval.js'
import { hex, uuid, comparisonCode, secondsRemaining, destinationAddressDiffers } from '../composables/releaseDetails.js'
import ReleaseValue from '../components/ReleaseValue.vue'
const token = window.location.hash.slice(1)
const request = ref(null), state = ref('loading'), status = ref('Loading release request…'), remaining = ref(0), delivering = ref(false)
let controller, timer
const inactiveMessage = 'This approval link is no longer active. Start a fresh attempt in the CLI.'
const uncertainMessage = 'Approval delivery could not be confirmed. Check your terminal for the result. This page will not retry the submission.'
const active = computed(() => request.value !== null && ['pending', 'submitting'].includes(state.value))
const title = computed(() => ({ loading: 'Loading approval', pending: 'Approve one share', submitting: 'Approve one share', relayed: 'Approval sent', cancelled: 'Approval cancelled', unavailable: 'Approval link inactive', error: 'Approval interrupted' })[state.value])
const metadata = computed(() => request.value?.metadata || {})
const app = computed(() => metadata.value.application || {})
const bundle = computed(() => metadata.value.bundle || {})
const reported = computed(() => request.value?.reported || {})
const addressMismatch = computed(() => destinationAddressDiffers(app.value.public_ip, reported.value.destination_address))
const details = computed(() => {
  const r = request.value
  if (!r) return []
  const c = r.context
  return [
    { label: 'Application ID', value: app.value.id }, { label: 'Domain', value: app.value.domain },
    { label: 'Platform-recorded IP', value: app.value.public_ip }, { label: 'Recorded state', value: app.value.state },
    { label: 'Organization ID', value: uuid(c.organization_id) }, { label: 'Bundle', value: bundle.value.name },
    { label: 'Bundle ID', value: uuid(c.bundle_id) }, { label: 'Eligible passkeys in bundle', value: bundle.value.eligible_passkeys },
    { label: 'Custody URL (CLI-reported)', value: reported.value.custody_url },
    { label: 'Approval origin', value: r.approval_origin }, { label: 'RP ID', value: r.options?.publicKey?.rpId },
    { label: 'User verification', value: 'Required' }, { label: 'Lifetime', value: '3 minutes · Single use' },
    { label: 'Holder certificate', value: c.holder }, { label: 'Bundle hash', value: c.bundle_hash },
    { label: 'Holder position / certificate index (zero-based)', value: c.holder_position === undefined ? null : `${c.holder_position} / ${c.certificate_index}` },
    { label: 'Destination session key', value: hex(r.destination_key) },
    { label: 'Destination attestation hash', value: r.destination_attestation_hash },
    { label: 'Full release context hash', value: r.context_hash }, { label: 'Protocol', value: c.version },
    { label: 'Expires at', value: c.expires_at_unix_seconds ? new Date(c.expires_at_unix_seconds * 1000).toISOString() : null },
  ].filter(item => item.value !== null && item.value !== undefined && item.value !== '')
})
async function post(path, body) {
  const response = await fetch(`/auth/qr-release/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, ...body }) })
  if (!response.ok) {
    const error = new Error(`Approval service returned HTTP ${response.status}.`)
    error.status = response.status
    throw error
  }
  return response.json()
}
function end(next, message) {
  state.value = next
  status.value = message
  clearInterval(timer)
  controller?.abort()
  request.value = null
}
function tick() {
  if (!active.value) return
  remaining.value = secondsRemaining(request.value.context.expires_at_unix_seconds)
  if (!remaining.value) {
    if (delivering.value) end('error', uncertainMessage)
    else {
      end('unavailable', inactiveMessage)
      void post('finish', { assertion: null }).catch(() => {})
    }
  }
}
onMounted(async () => {
  try {
    if (!token) { end('unavailable', inactiveMessage); return }
    request.value = await post('read', {})
    state.value = 'pending'
    status.value = ''
    tick()
    if (active.value) timer = setInterval(tick, 250)
  } catch (error) {
    end(error.status === 410 ? 'unavailable' : 'error', error.status === 410 ? inactiveMessage : 'Unable to load approval. Check your connection and reload this page while the CLI attempt is pending.')
  }
})
onUnmounted(() => { clearInterval(timer); controller?.abort() })
async function cancel() {
  if (!active.value || delivering.value) return
  end('cancelled', 'Approval cancelled. Start a fresh attempt in the CLI to retry.')
  try { await post('finish', { assertion: null }) } catch { /* No assertion was submitted by this page. */ }
}
async function approve() {
  tick()
  if (state.value !== 'pending') return
  state.value = 'submitting'
  status.value = 'Waiting for your passkey…'
  controller = new AbortController()
  try {
    const credential = await navigator.credentials.get({ publicKey: releaseOptions(request.value.options), signal: controller.signal })
    tick()
    if (!active.value) return
    delivering.value = true
    status.value = 'Sending approval…'
    await post('finish', { assertion: releaseAssertion(credential) })
    if (!active.value) return
    end('relayed', 'Approval sent. Check your terminal for share acceptance and quorum status.')
  } catch (error) {
    if (!active.value) return
    if (delivering.value) end(error.status === 410 ? 'unavailable' : 'error', error.status === 410 ? inactiveMessage : uncertainMessage)
    else {
      await cancel()
      if (error.name !== 'NotAllowedError' && error.name !== 'AbortError') end('error', 'Unable to obtain passkey approval. Start a fresh attempt in the CLI.')
    }
  }
}
</script>
<style scoped>
.release-approval { max-width:42rem; margin:2rem auto; padding:1.5rem; color:#e6edf5; }
.eyebrow,.source,dt { color:#a4b4c9; } .eyebrow { margin-bottom:1.5rem; } header { display:flex; justify-content:space-between; align-items:start; gap:1rem; } h1 { font-size:2rem; margin:0; } h2,h3 { font-size:1.05rem; } p,li { line-height:1.55; } li { margin:.7rem 0; } .notice { color:#f1cc77; } .expiry { white-space:nowrap; font-size:.9rem; }
.card { background:#0e1924; border:1px solid #2b4155; border-radius:.65rem; padding:1.25rem; margin:1rem 0; min-width:0; } .summary { display:grid; grid-template-columns:7rem 1fr; gap:.6rem 1rem; margin:0; } dt { font-size:.9rem; margin-top:.8rem; } dd { margin:.3rem 0; overflow-wrap:anywhere; } .summary dt,.summary dd { margin:0; } .source { font-size:.85rem; } .comparison { display:block; font-family:monospace; font-size:1.65rem; letter-spacing:.08em; margin:1rem 0; } summary { cursor:pointer; font-weight:600; } details details { margin-top:1.2rem; } .buttons { display:flex; gap:.7rem; } button { padding:.8rem 1.2rem; border-radius:.4rem; border:1px solid #687c96; background:#172432; color:#fff; cursor:pointer; } button.primary { background:#6850cf; } button:disabled { opacity:.5; cursor:not-allowed; }
@media(max-width:650px) { .release-approval { padding:1rem; margin:0; } header { flex-direction:column; } h1 { font-size:1.7rem; } .comparison { font-size:1.2rem; } .summary { grid-template-columns:1fr; gap:.2rem; } .summary dd { margin-bottom:.7rem; } }
</style>
