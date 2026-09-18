<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial -->
<template>
  <main class="release-approval">
    <div class="eyebrow">caution / Share approval</div>
    <header><h1>{{ title }}</h1><span v-if="active" class="expiry" role="timer">Expires in {{ Math.floor(remaining / 60) }}:{{ String(remaining % 60).padStart(2, '0') }}</span></header>
    <template v-if="active">
      <p class="intro">Only approve an attempt you started.</p>
      <section class="card" aria-label="Release summary">
        <section class="destination">
          <h2>Destination</h2>
          <p class="app-name">{{ app.name || 'Application name unavailable' }}</p>
          <p class="source"><span v-if="metadata.organization?.name">{{ metadata.organization.name }} · </span>Platform-provided labels</p>
          <p v-if="reported.destination_address" class="address">{{ reported.destination_address }}<small>Connection reported by your CLI</small></p>
          <p v-if="addressMismatch" class="notice">The Platform-recorded address ({{ app.public_ip }}) differs from the CLI-reported destination. Check this difference before approving.</p>
        </section>
        <section class="contribution" aria-label="Your contribution">
          <div><h2>Your share</h2><p class="emphasis">{{ bundle.username || 'Holder name unavailable' }}</p><p class="source">Passkey</p></div>
          <div><h2>Quorum</h2><p v-if="bundle.threshold && bundle.holders" class="emphasis">{{ bundle.threshold }} of {{ bundle.holders }} holders required</p><p class="source">This approval contributes one share.</p></div>
        </section>
        <section class="actions">
          <h2>Compare with your terminal</h2>
          <div class="comparison" :aria-label="comparisonCode(request.context_hash)"><span v-for="(group, index) in comparisonCode(request.context_hash).split(' ')" :key="index">{{ group }}</span></div>
          <p class="instruction">Compare all four groups. Approve only if they match.</p>
          <p class="source">The code covers authenticated release context, not app labels or addresses.</p>
          <p class="explanation">Your passkey authorizes re-encryption of one share to this destination. The private key stays inside the custody enclave.</p>
          <p v-if="status" role="status">{{ status }}</p>
          <div class="buttons"><button class="primary" :disabled="state !== 'pending'" @click="approve">Approve with passkey</button><button :disabled="delivering" @click="cancel">Cancel</button></div>
          <p class="source caveat">Other holders may still be required.</p>
        </section>
        <button class="details-trigger" aria-haspopup="dialog" @click="openDetails">Verification &amp; technical details <span aria-hidden="true">→</span></button>
      </section>
      <dialog ref="drawer" class="drawer" aria-labelledby="drawer-title" @keydown.tab="trapFocus">
        <header><h2 id="drawer-title">Verification details</h2><button class="close" aria-label="Close verification details" autofocus @click="drawer.close()">✕</button></header>
        <div class="tabs" role="tablist" aria-label="Verification categories">
          <button v-for="(group, index) in groups" :id="`tab-${index}`" :key="group.title" role="tab" :aria-selected="selectedTab === index" :tabindex="selectedTab === index ? 0 : -1" :aria-controls="`panel-${index}`" @click="selectedTab = index" @keydown="tabKey($event, index)">{{ group.title }}</button>
        </div>
        <section :id="`panel-${selectedTab}`" role="tabpanel" :aria-labelledby="`tab-${selectedTab}`" tabindex="0">
          <p class="check-note">{{ groups[selectedTab].explanation }}</p>
          <section v-for="section in groups[selectedTab].sections" :key="section.title" class="detail-section">
            <h3>{{ section.title }}</h3>
            <dl><template v-for="item in section.items" :key="item.label"><dt>{{ item.label }}</dt><dd><ReleaseValue :key="item.label" :value="item.value" :label="item.label" /></dd></template></dl>
          </section>
          <p v-if="selectedTab !== 2" class="source">Compare full measurements with your independently trusted policy.</p>
        </section>
      </dialog>
    </template>
    <p v-else role="status" class="card terminal">{{ status }}</p>
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
const drawer = ref(null), selectedTab = ref(0)
function openDetails() { selectedTab.value = 0; drawer.value.showModal(); drawer.value.scrollTop = 0 }
function trapFocus(event) {
  const controls = [...drawer.value.querySelectorAll('button:not(:disabled):not([tabindex="-1"]), [tabindex="0"]')]
  const first = controls[0], last = controls.at(-1)
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
}
function tabKey(event, index) {
  const next = { ArrowRight: (index + 1) % 3, ArrowLeft: (index + 2) % 3, Home: 0, End: 2 }[event.key]
  if (next === undefined) return
  event.preventDefault()
  selectedTab.value = next
  drawer.value.querySelector(`#tab-${next}`).focus()
}
const groups = computed(() => {
  const r = request.value
  if (!r) return []
  const c = r.context
  const section = (title, entries) => ({ title, items: entries.filter(([, value]) => value !== null && value !== undefined && value !== '').map(([label, value]) => ({ label, value })) })
  const measurements = policy => Object.entries(policy || {}).map(([index, value]) => [`PCR${index}`, value])
  return [
    { title: 'Destination', explanation: 'The custody enclave checked fresh destination attestation against the requested PCR policy. The CLI also checks the destination before requesting approval. Platform labels and reported addresses are descriptive, not attested application identity.', sections: [
      section('Application & connection', [['Application ID', app.value.id], ['Domain', app.value.domain], ['Recorded state', app.value.state], ['Connection (CLI-reported)', reported.value.destination_address], ['Platform-recorded IP', app.value.public_ip]]),
      section('Attested session', [['Destination session key', hex(r.destination_key)], ['Destination attestation hash', r.destination_attestation_hash]]),
      section('Approved destination measurements', measurements(c.destination_policy)),
    ] },
    { title: 'Custody', explanation: 'The gateway checked custody evidence against its configured PCR policy. The CLI independently checks custody evidence against its selected policy. The reported custody hostname is not established by those measurements.', sections: [
      section('Custody service', [['Custody URL (CLI-reported)', reported.value.custody_url]]),
      section('Passkey approval', [['Approval origin', r.approval_origin], ['RP ID', r.options?.publicKey?.rpId], ['User verification', 'Required'], ['Lifetime', '3 minutes · Single use'], ['Expires at', c.expires_at_unix_seconds ? new Date(c.expires_at_unix_seconds * 1000).toISOString() : null]]),
      section('Gateway custody verification policy', measurements(r.custody_policy)),
    ] },
    { title: 'Bundle', explanation: 'The comparison code covers authenticated release context, not descriptive application names or addresses. Multiple eligible passkeys for this holder still contribute only one share.', sections: [
      section('Bundle identity', [['Organization ID', uuid(c.organization_id)], ['Bundle', bundle.value.name], ['Bundle ID', uuid(c.bundle_id)], ['Bundle hash', c.bundle_hash]]),
      section('Holder', [['Holder certificate', c.holder], ['Eligible passkeys in bundle', bundle.value.eligible_passkeys], ['Holder position / certificate index (zero-based)', c.holder_position === undefined ? null : `${c.holder_position} / ${c.certificate_index}`]]),
      section('Release context', [['Full release context hash', r.context_hash], ['Protocol', c.version]]),
    ] },
  ].map(group => ({ ...group, sections: group.sections.filter(section => section.items.length) }))
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
  drawer.value?.close()
  selectedTab.value = 0
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
.release-approval { max-width:46rem; margin:1.5rem auto; padding:0 1.5rem; color:#e6edf5; }
.eyebrow,.source,dt { color:#a4b4c9; } .eyebrow { margin-bottom:1rem; font-size:.85rem; }
header { display:flex; justify-content:space-between; align-items:center; gap:1rem; } h1 { font-size:1.9rem; margin:0; } h2,h3,p { margin:0; } p { line-height:1.45; }
.intro { margin:.5rem 0 1rem; } .expiry { white-space:nowrap; font-size:.85rem; color:#f1cc77; }
.card { background:#0e1924; border:1px solid #2b4155; border-radius:.75rem; overflow:hidden; }
.destination,.contribution,.actions { padding:1.1rem 1.4rem; } .contribution,.actions { border-top:1px solid #2b4155; }
h2 { font-size:.8rem; font-weight:600; color:#a4b4c9; text-transform:uppercase; letter-spacing:.07em; margin-bottom:.6rem; }
.app-name { font-size:1.3rem; font-weight:650; overflow-wrap:anywhere; } .source { font-size:.85rem; margin-top:.3rem; }
.address { font-family:monospace; margin-top:.6rem; } .address small { display:block; font-family:inherit; color:#a4b4c9; font-size:.8rem; margin-top:.15rem; }
.notice { color:#f1cc77; margin-top:.7rem; font-size:.9rem; } .contribution { display:grid; grid-template-columns:1fr 1fr; gap:1rem; } .emphasis { font-weight:600; overflow-wrap:anywhere; }
.comparison { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:.65rem; margin:.75rem 0; }
.comparison span { border:1px solid #687c96; border-radius:.5rem; padding:.65rem .2rem; text-align:center; font-family:monospace; font-size:1.8rem; letter-spacing:.05em; }
.instruction { font-weight:600; font-size:.95rem; } .explanation { font-size:.9rem; margin:1rem 0; } .buttons { display:flex; gap:.75rem; } button { padding:.7rem 1rem; border-radius:.4rem; border:1px solid #687c96; background:#172432; color:#fff; cursor:pointer; font:inherit; } button.primary { background:#6850cf; flex:1; font-weight:600; } button:disabled { opacity:.5; cursor:not-allowed; } button:focus-visible,[tabindex]:focus-visible { outline:2px solid #bcaaff; outline-offset:3px; }
.caveat { text-align:center; margin-top:.6rem; } .details-trigger { display:flex; justify-content:space-between; width:100%; border:0; border-top:1px solid #2b4155; border-radius:0; padding:1rem 1.4rem; background:transparent; text-align:left; font-size:.9rem; }
.drawer { box-sizing:border-box; position:fixed; inset:0 0 0 auto; margin:0; width:min(36rem,100%); height:100dvh; max-height:100dvh; max-width:100%; padding:1.5rem; border:0; border-left:1px solid #2b4155; background:#0e1924; color:#e6edf5; overflow-y:auto; }
.drawer::backdrop { background:rgb(0 0 0 / .55); } .drawer header h2 { color:#e6edf5; font-size:1.25rem; text-transform:none; letter-spacing:0; margin:0; } .close { border:0; background:transparent; font-size:1.2rem; }
.tabs { display:flex; border-bottom:1px solid #2b4155; margin:1rem 0; } .tabs button { flex:1; border:0; border-bottom:3px solid transparent; border-radius:0; background:transparent; padding:.8rem .2rem; } .tabs button[aria-selected=true] { border-bottom-color:#9575ff; color:#fff; }
.check-note { background:#172432; border-radius:.5rem; padding:1rem; font-size:.9rem; color:#bccbde; } .detail-section { padding:1.2rem 0; border-bottom:1px solid #2b4155; } h3 { font-size:1rem; margin-bottom:.8rem; } dl { margin:0; display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1.25fr); gap:.75rem; align-items:start; } dt { font-size:.85rem; } dd { margin:0; min-width:0; overflow-wrap:anywhere; font-size:.85rem; }
.terminal { padding:1.4rem; margin-top:1rem; }
@media(max-width:600px) { .release-approval { padding:0 1rem; margin:1rem auto; } header { flex-wrap:wrap; gap:.4rem; } h1 { font-size:1.6rem; } .destination,.contribution,.actions { padding:1rem; } .contribution { grid-template-columns:1fr; } .comparison { gap:.4rem; } .comparison span { font-size:1.25rem; } .drawer { width:100%; padding:1rem; } dl { grid-template-columns:1fr; gap:.3rem; } dd { margin-bottom:.6rem; } }
</style>
