<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial -->
<template>
  <main class="release-approval">
    <div class="eyebrow">caution / Share approval</div>
    <header><div><h1>Approve one share</h1><p>Authorize re-encryption to the application below.</p></div><span v-if="request" class="expiry" role="timer">{{ remaining ? `Expires in ${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2,'0')}` : 'Expired' }}</span></header>
    <p class="notice">Only approve an attempt you started. Compare this screen with your CLI.</p>
    <template v-if="request">
      <section class="card"><h2>Destination application</h2><h3>{{ value(app.name) }}</h3><p class="source">Platform metadata — descriptive, not attested identity</p>
        <dl class="grid"><div><dt>Application ID</dt><dd><ReleaseValue :value="app.id" label="application ID" /></dd></div><div><dt>Domain</dt><dd><ReleaseValue :value="app.domain" label="domain" /></dd></div><div><dt>CLI-reported destination</dt><dd><ReleaseValue :value="reported.destination_address" label="destination address" /></dd></div><div><dt>Platform-recorded IP</dt><dd><ReleaseValue :value="app.public_ip" label="recorded IP" /></dd></div><div><dt>Recorded state</dt><dd>{{ value(app.state) }}</dd></div></dl>
        <p class="source">Names and addresses are descriptive. The attested session key and approved measurements identify the recipient. Recorded and CLI-reported addresses may differ.</p>
        <p class="verified">The custody enclave checked destination attestation against the approved PCR policy.</p>
      </section>
      <div class="columns">
        <section class="card"><h2>Your contribution</h2><h3>{{ value(bundle.username) }} · Passkey</h3><dl>
          <dt>Organization</dt><dd>{{ value(metadata.organization?.name) }}</dd><dt>Organization ID</dt><dd><ReleaseValue :value="uuid(request.context.organization_id)" label="organization ID" /></dd>
          <dt>Bundle</dt><dd>{{ value(bundle.name) }}</dd><dt>Bundle ID</dt><dd><ReleaseValue :value="uuid(request.context.bundle_id)" label="bundle ID" /></dd>
          <dt>Quorum</dt><dd>{{ bundle.threshold && bundle.holders ? `${bundle.threshold} of ${bundle.holders} distinct holders` : 'Unavailable' }}</dd>
          <dt>Eligible passkeys in bundle</dt><dd>{{ value(bundle.eligible_passkeys) }}</dd></dl><p>This approval contributes one share. Multiple passkeys still contribute one share.</p>
        </section>
        <section class="card"><h2>Custody &amp; approval</h2><dl>
          <dt>Custody URL · CLI-reported</dt><dd><ReleaseValue :value="reported.custody_url" label="custody URL" /></dd>
          <dt>Approval origin</dt><dd><ReleaseValue :value="request.approval_origin" label="approval origin" /></dd><dt>RP ID</dt><dd>{{ value(request.options?.publicKey?.rpId) }}</dd>
          <dt>User verification</dt><dd>Required</dd><dt>Request lifetime</dt><dd>3 minutes · Single use</dd></dl>
          <p class="verified">Custody evidence verified by gateway.</p><p class="source">The supplied custody hostname is not established by its enclave measurements.</p>
        </section>
      </div>
      <section class="card comparison"><h2>Compare with your CLI</h2><strong>{{ comparisonCode(request.context_hash) }}</strong><p class="source">Prefix of the authenticated release-context hash. Does not cover descriptive app labels or CLI-reported addresses.</p></section>
      <details class="card"><summary>Verification details</summary><p class="source">Authenticated release context. Full values are available below.</p><dl>
        <template v-for="item in details" :key="item.label"><dt>{{ item.label }}</dt><dd><ReleaseValue :value="item.value" :label="item.label" /></dd></template>
      </dl><h3>Approved destination measurements</h3><dl><template v-for="(pcr, index) in request.context.destination_policy" :key="index"><dt>PCR{{ index }}</dt><dd><ReleaseValue :value="pcr" :label="`destination PCR${index}`" /></dd></template></dl>
      <h3>Gateway custody verification policy</h3><p class="source">Measurements the gateway accepted for this custody response.</p><dl><template v-for="(pcr, index) in request.custody_policy" :key="index"><dt>PCR{{ index }}</dt><dd><ReleaseValue :value="pcr" :label="`custody PCR${index}`" /></dd></template></dl><p v-if="!request.custody_policy">Unavailable</p>
      </details>
    </template>
    <section class="card actions"><p>Your passkey authorizes Caution’s enclave to re-encrypt one share for this destination session. The private PGP key and plaintext share remain inside the custody enclave.</p>
      <p role="status">{{ status }}</p><div v-if="request && !finished"><button class="primary" :disabled="busy || remaining === 0" @click="approve">Approve with passkey</button><button @click="cancel">Cancel</button></div>
      <p class="source">Approval does not necessarily unlock the application; its quorum threshold must be reached.</p>
    </section>
  </main>
</template>
<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { releaseOptions, releaseAssertion } from '../composables/releaseApproval.js'
import { hex, uuid, comparisonCode, secondsRemaining, displayValue as value } from '../composables/releaseDetails.js'
import ReleaseValue from '../components/ReleaseValue.vue'
const token = window.location.hash.slice(1)
const request = ref(null), status = ref('Loading release request…'), busy = ref(false), finished = ref(false), remaining = ref(0)
let controller, timer
const metadata = computed(() => request.value?.metadata || {})
const app = computed(() => metadata.value.application || {})
const bundle = computed(() => metadata.value.bundle || {})
const reported = computed(() => request.value?.reported || {})
const details = computed(() => {
  const r = request.value, c = r.context
  return [
    { label: 'Holder certificate', value: c.holder }, { label: 'Bundle hash', value: c.bundle_hash },
    { label: 'Holder position / certificate index (zero-based)', value: `${c.holder_position ?? 'Unavailable'} / ${c.certificate_index ?? 'Unavailable'}` },
    { label: 'Destination session key', value: hex(r.destination_key) },
    { label: 'Destination attestation hash', value: r.destination_attestation_hash },
    { label: 'Full release context hash', value: r.context_hash }, { label: 'Protocol', value: c.version },
    { label: 'Expires at', value: c.expires_at_unix_seconds ? new Date(c.expires_at_unix_seconds * 1000).toISOString() : null },
  ]
})
async function post(path, body) {
  const response = await fetch(`/auth/qr-release/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, ...body }) })
  if (!response.ok) throw new Error('Release request expired or was already consumed. Start a fresh attempt in the CLI.')
  return response.json()
}
function tick() {
  remaining.value = secondsRemaining(request.value?.context.expires_at_unix_seconds)
  if (!remaining.value && !finished.value) {
    finished.value = true
    controller?.abort()
    status.value = 'Release request expired. Start a fresh attempt in the CLI.'
    void post('finish', { assertion: null }).catch(() => {})
  }
}
onMounted(async () => {
  try {
    if (!token) throw new Error('Missing release request.')
    request.value = await post('read', {})
    status.value = 'Approval releases one share to this destination only.'
    tick(); timer = setInterval(tick, 250)
  } catch (error) { status.value = error.message; finished.value = true }
})
onUnmounted(() => { clearInterval(timer); controller?.abort() })
async function cancel() {
  finished.value = true; controller?.abort()
  try { await post('finish', { assertion: null }) } catch { /* expired attempts are already unusable */ }
  status.value = 'Cancelled. Start a fresh attempt in the CLI to retry.'
}
async function approve() {
  tick()
  if (finished.value || busy.value) return
  busy.value = true; controller = new AbortController()
  try {
    const credential = await navigator.credentials.get({ publicKey: releaseOptions(request.value.options), signal: controller.signal })
    tick()
    if (finished.value) return
    await post('finish', { assertion: releaseAssertion(credential) })
    if (finished.value) return
    finished.value = true
    status.value = 'Assertion sent to the CLI. The custody enclave will verify it before releasing your share.'
  } catch (error) {
    if (!finished.value) { await cancel(); status.value = `${error.message} Start a fresh attempt in the CLI.` }
  } finally { busy.value = false }
}
</script>
<style scoped>
.release-approval { max-width:70rem; margin:2rem auto; padding:1.5rem; color:#e6edf5; }
.eyebrow,.source,dt { color:#a4b4c9; } .eyebrow { margin-bottom:1.5rem; } header { display:flex; justify-content:space-between; align-items:start; gap:1rem; } h1 { font-size:2.5rem; margin:0; } h2 { font-size:1.05rem; margin:0 0 1rem; } h3 { font-size:1.15rem; } p { line-height:1.55; } .notice { color:#f1cc77; } .expiry { white-space:nowrap; border:1px solid #7b652f; padding:.7rem; border-radius:.5rem; }
.card { background:#0e1924; border:1px solid #2b4155; border-radius:.65rem; padding:1.4rem; margin:1rem 0; min-width:0; } .columns { display:grid; grid-template-columns:1fr 1fr; gap:1rem; } .columns .card { margin:0; } .grid { display:grid; grid-template-columns:1fr 1fr; gap:1rem; } dt { font-size:.85rem; margin-top:.8rem; } dd { margin:.3rem 0; overflow-wrap:anywhere; } .source { font-size:.85rem; } .verified { color:#a0e5cb; } .comparison strong { font-family:monospace; font-size:1.65rem; letter-spacing:.1em; } summary { cursor:pointer; font-weight:600; } button { padding:.8rem 1.2rem; border-radius:.4rem; border:1px solid #687c96; background:#172432; color:#fff; cursor:pointer; margin-right:.7rem; } button.primary { background:#6850cf; } button:disabled { opacity:.5; cursor:not-allowed; } .actions { text-align:center; }
@media(max-width:650px) { .release-approval { padding:1rem; margin:0; } .columns,.grid { grid-template-columns:1fr; } header { flex-direction:column; } h1 { font-size:2rem; } .comparison strong { font-size:1.2rem; } }
</style>
