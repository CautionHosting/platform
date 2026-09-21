<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->
<template>
  <section class="quorum-create" aria-labelledby="creation-title" :aria-busy="busy">
    <header>
      <button type="button" class="text-button" :disabled="busy" @click="emit('cancel')">← Secrets</button>
      <h2 id="creation-title" ref="heading" tabindex="-1">Create quorum bundle</h2>
      <p>Choose who can recover your application's secrets.</p>
      <ol class="steps" aria-label="Creation steps">
        <li :aria-current="step === 'configure' ? 'step' : undefined">1 · Configure</li>
        <li :aria-current="step === 'review' ? 'step' : undefined">2 · Review &amp; create</li>
      </ol>
    </header>

    <div class="creation-panel">
      <fieldset :disabled="busy">
        <template v-if="step === 'configure'">
          <label for="quorum-name">Bundle name <span class="muted">(optional)</span></label>
          <input id="quorum-name" v-model="name" placeholder="Application secrets" autocomplete="off" />
          <div class="holders-heading">
            <h3>Holders</h3>
            <p class="holder-count hint" aria-live="polite">{{ holderCount ? `${holderCount} selected` : 'No holders selected' }} · Max {{ MAX_DASHBOARD_HOLDERS }}</p>
          </div>
          <label class="sr-only" for="quorum-search">Search members</label>
          <input id="quorum-search" v-model="search" type="search" placeholder="Search members" />
          <p v-if="loading" role="status">Loading members…</p>
          <div v-else-if="loadError" role="alert">
            <p>{{ loadError }}</p><button type="button" class="secondary" @click="loadMembers">Reload members</button>
          </div>
          <p v-else-if="!filteredMembers.length">{{ members.length ? 'No members match your search.' : 'No organization members available.' }}</p>
          <div v-else class="member-list">
            <div v-for="member in filteredMembers" :key="member.user_id" class="member-row">
              <label class="member-name">
                <input type="checkbox" :checked="!!selections[member.user_id]" :disabled="!recoveryMethods(member).length || (!selections[member.user_id] && holderCount >= MAX_DASHBOARD_HOLDERS)" @change="toggleMember(member, $event.target.checked)" />
                <span><strong>{{ member.username }}</strong><span class="muted holder-context">{{ selections[member.user_id]?.key_source === 'caution_backed_pgp' ? `${member.webauthn_credentials} registered passkey${member.webauthn_credentials === 1 ? '' : 's'}` : selections[member.user_id] ? 'Organization member' : availability(member) }}</span></span>
              </label>
              <div v-if="selections[member.user_id]" class="holder-method">
                <select v-if="recoveryMethods(member).length > 1" v-model="selections[member.user_id].key_source" :aria-label="`Recovery method for ${member.username}`">
                  <option disabled value="">Choose recovery method</option>
                  <option v-for="method in recoveryMethods(member)" :key="method" :value="method">{{ methodLabel(method) }}</option>
                </select>
                <span v-else class="method">{{ methodLabel(selections[member.user_id].key_source) }}</span>
                <template v-if="selections[member.user_id].key_source === 'existing_pgp'">
                  <select v-if="member.pgp_keys.length > 1" v-model="selections[member.user_id].pgp_key_id" :aria-label="`PGP key for ${member.username}`">
                    <option disabled value="">Choose PGP key</option>
                    <option v-for="key in member.pgp_keys" :key="key.id" :value="key.id">{{ key.fingerprint }}</option>
                  </select>
                  <code v-if="selectedFingerprint(member)">{{ selectedFingerprint(member) }}</code>
                </template>
              </div>
            </div>
          </div>
          <ul class="certificate-list">
            <li v-for="cert in certificates" :key="cert.fingerprint">
              <div><strong>{{ cert.userId }}</strong><span class="muted holder-context">Manually added</span></div>
              <div class="holder-method"><div class="method-actions"><span>External PGP</span><button type="button" class="text-button" :aria-label="`Remove ${cert.fingerprint}`" @click="removeCertificate(cert.fingerprint)">Remove</button></div><code>{{ cert.fingerprint }}</code></div>
            </li>
          </ul>
          <button ref="addHolderButton" type="button" class="text-button add-holder" :disabled="importOpen || holderCount >= MAX_DASHBOARD_HOLDERS" @click="openImport">Add PGP holder</button>
          <p class="hint share-hint">Each holder contributes one share, even with multiple passkeys.</p>
          <div v-if="importOpen" class="holder-import">
            <label for="quorum-file">Armored public key <span class="muted">(up to 512 KiB)</span></label>
            <input id="quorum-file" type="file" accept=".asc,.txt,.pgp" :disabled="parsing" @change="readFile" />
            <label for="quorum-armor">Or paste public-key armor</label>
            <textarea id="quorum-armor" ref="armorInput" v-model="armor" :disabled="parsing" rows="5" spellcheck="false" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----" @input="importError = ''" />
            <p class="hint">One public certificate per holder. Parsed locally; private keys are rejected.</p>
            <p v-if="importError" role="alert" class="import-error">{{ importError }}</p>
            <button type="button" class="secondary" :disabled="parsing || !armor.trim() || holderCount >= MAX_DASHBOARD_HOLDERS" @click="addHolder">{{ parsing ? 'Reading certificate…' : 'Add holder' }}</button>
            <button type="button" class="text-button" @click="closeImport">Cancel</button>
          </div>
          <div class="threshold">
            <div class="threshold-row"><label for="quorum-threshold">Quorum threshold</label>
            <div class="threshold-control"><input id="quorum-threshold" v-model.number="threshold" :disabled="!holderCount" type="number" min="1" :max="Math.max(holderCount, 1)" step="1" aria-describedby="threshold-help" /><span v-if="validThreshold">of {{ holderCount }} holders required</span><span v-else-if="holderCount">{{ holderCount }} holder{{ holderCount === 1 ? '' : 's' }} selected</span></div></div>
            <p id="threshold-help" class="hint">{{ !holderCount ? 'Select holders to set the quorum.' : validationMessage || `Any ${threshold} holder${threshold === 1 ? '' : 's'} can recover the secret.` }}</p>
          </div>
        </template>

        <template v-else>
          <div class="review-heading">
            <div><p class="hint">Bundle name</p><h3 ref="reviewHeading" tabindex="-1">{{ reviewSnapshot.request.name || 'Unnamed bundle' }}</h3></div>
            <div class="review-quorum"><strong>{{ reviewSnapshot.request.threshold }} of {{ reviewSnapshot.holders.length }} holders required</strong><p class="hint">{{ reviewSnapshot.custodySummary }}</p></div>
          </div>
          <ul class="review-list">
            <li v-for="(holder, index) in reviewSnapshot.holders" :key="index">
              <div class="review-holder"><strong>{{ holder.name }}</strong><span>{{ holder.method }}</span></div>
              <span v-if="holder.fingerprint" class="muted holder-context">{{ holder.manual ? 'Manually added' : 'Organization member' }}</span>
              <span v-else class="muted holder-context">{{ holder.passkeys }} registered passkey{{ holder.passkeys === 1 ? '' : 's' }} · one share</span>
              <code v-if="holder.fingerprint">{{ holder.fingerprint }}</code>
            </li>
          </ul>
        </template>
      </fieldset>
      <details v-if="passkeyCount" class="custody-help">
        <summary>About passkey custody</summary>
        <p class="hint">Caution holds the derived private keys inside an enclave. Holders authorize recovery with their registered passkeys. Credentials are captured when the bundle is created; multiple passkeys still represent one share.</p>
      </details>
      <p v-if="step === 'review'" class="hint creation-note">Your passkey authorizes creation. Holders approve recovery later.</p>
      <div v-if="error" ref="errorElement" class="creation-error" role="alert" tabindex="-1">
        <template v-if="uncertain">
          <strong>Creation outcome unknown</strong>
          <p>The request may have completed. Check your bundles before starting another attempt. It will not be retried automatically.</p>
          <button type="button" class="secondary" @click="emit('check-bundles')">Check bundles</button>
        </template>
        <p v-else>{{ error }}</p>
      </div>
      <footer>
        <button type="button" class="secondary" :disabled="busy" @click="step === 'review' ? back() : emit('cancel')">{{ step === 'review' ? 'Back' : 'Cancel' }}</button>
        <button v-if="step === 'configure'" type="button" class="primary" :disabled="!!validationMessage || importOpen || parsing || busy" @click="review">Review bundle →</button>
        <button v-else type="button" class="primary" :disabled="busy || attempted" @click="create">{{ busy ? 'Authorizing / creating…' : 'Create bundle' }}</button>
      </footer>
    </div>
  </section>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount, nextTick } from 'vue'
import { initialSelection, recoveryMethods, creationRequest, parsePublicHolder, validateHolderFingerprints, MAX_DASHBOARD_HOLDERS, MAX_KEYRING_BYTES } from '../utils/quorumCreation.js'
const props = defineProps({ fetchMembers: { type: Function, required: true }, submit: { type: Function, required: true } })
const emit = defineEmits(['cancel', 'created', 'check-bundles', 'busy'])
const name = ref(''), search = ref(''), threshold = ref(2)
const members = ref([]), selections = ref({}), certificates = ref([]), armor = ref('')
const importOpen = ref(false), importError = ref(''), addHolderButton = ref(null), armorInput = ref(null)
const loading = ref(false), loadError = ref(''), parsing = ref(false), busy = ref(false)
const error = ref(''), uncertain = ref(false), attempted = ref(false), step = ref('configure'), reviewSnapshot = ref(null)
const heading = ref(null), reviewHeading = ref(null), errorElement = ref(null)
let parseEpoch = 0, disposed = false
const filteredMembers = computed(() => members.value.filter(member => member.username.toLowerCase().includes(search.value.toLowerCase())))
const selected = computed(() => members.value.filter(member => selections.value[member.user_id]).map(member => selections.value[member.user_id]))
const holderCount = computed(() => selected.value.length + certificates.value.length)
const externalCount = computed(() => selected.value.filter(holder => holder.key_source === 'existing_pgp').length + certificates.value.length)
const passkeyCount = computed(() => selected.value.filter(holder => holder.key_source === 'caution_backed_pgp').length)
const validThreshold = computed(() => Number.isInteger(threshold.value) && threshold.value >= 1 && threshold.value <= holderCount.value)
function request() { return creationRequest({ name: name.value, threshold: threshold.value, selections: selected.value, members: members.value, certificates: certificates.value }) }
const validationMessage = computed(() => { try { request(); return '' } catch (err) { return err.message } })
const methodLabel = method => method === 'existing_pgp' ? 'External PGP' : 'Passkey · Caution custody'
function selectedFingerprint(member) {
  return member.pgp_keys.find(key => key.id === selections.value[member.user_id]?.pgp_key_id)?.fingerprint
}
function availability(member) {
  const parts = []
  if (member.pgp_keys.length) parts.push(`${member.pgp_keys.length} PGP key${member.pgp_keys.length === 1 ? '' : 's'}`)
  if (member.webauthn_credentials > 0) parts.push(`${member.webauthn_credentials} passkey${member.webauthn_credentials === 1 ? '' : 's'} · Caution custody`)
  return parts.join(' · ') || 'No eligible key'
}
function toggleMember(member, checked) {
  if (checked && holderCount.value >= MAX_DASHBOARD_HOLDERS) return
  if (checked) selections.value[member.user_id] = initialSelection(member)
  else delete selections.value[member.user_id]
}
async function openImport() {
  if (busy.value || holderCount.value >= MAX_DASHBOARD_HOLDERS) return
  importOpen.value = true; await nextTick(); armorInput.value?.focus()
}
function closeImport() {
  parseEpoch++; parsing.value = false; importOpen.value = false; armor.value = ''; importError.value = ''
  nextTick(() => { if (holderCount.value >= MAX_DASHBOARD_HOLDERS) heading.value?.focus(); else addHolderButton.value?.focus() })
}
async function loadMembers() {
  loading.value = true; loadError.value = ''
  try { const result = await props.fetchMembers(); if (!disposed) members.value = result }
  catch (err) { if (!disposed) loadError.value = err.message }
  finally { if (!disposed) loading.value = false }
}
async function addHolder() {
  if (busy.value || parsing.value || !importOpen.value) return
  const epoch = ++parseEpoch
  importError.value = ''; parsing.value = true
  try {
    const certificate = await parsePublicHolder(armor.value)
    if (disposed || epoch !== parseEpoch) return
    if (holderCount.value >= MAX_DASHBOARD_HOLDERS) throw new Error(`Select at most ${MAX_DASHBOARD_HOLDERS} holders.`)
    validateHolderFingerprints(selected.value, members.value, [...certificates.value, certificate])
    certificates.value.push(certificate)
    closeImport()
  } catch (err) { if (!disposed && epoch === parseEpoch) importError.value = err.message }
  finally { if (!disposed && epoch === parseEpoch) parsing.value = false }
}
async function readFile(event) {
  const file = event.target.files?.[0]
  event.target.value = ''
  if (!file) return
  const epoch = ++parseEpoch
  armor.value = ''; importError.value = ''
  if (file.size > MAX_KEYRING_BYTES) { importError.value = 'Public keys must be at most 512 KiB.'; return }
  parsing.value = true
  try { const text = await file.text(); if (!disposed && epoch === parseEpoch) armor.value = text }
  catch { if (!disposed && epoch === parseEpoch) importError.value = 'Unable to read the selected file.' }
  finally { if (!disposed && epoch === parseEpoch) parsing.value = false }
}
function removeCertificate(fingerprint) {
  certificates.value = certificates.value.filter(cert => cert.fingerprint !== fingerprint)
  nextTick(() => { if (importOpen.value) armorInput.value?.focus(); else addHolderButton.value?.focus() })
}
async function review() {
  if (busy.value || importOpen.value || parsing.value || validationMessage.value) return
  error.value = ''; uncertain.value = false; attempted.value = false
  const holders = selected.value.map(selection => {
    const member = members.value.find(member => member.user_id === selection.user_id)
    return { name: member.username, method: methodLabel(selection.key_source), passkeys: member.webauthn_credentials,
      fingerprint: selection.key_source === 'existing_pgp' ? member.pgp_keys.find(key => key.id === selection.pgp_key_id).fingerprint : null }
  })
  holders.push(...certificates.value.map(cert => ({ name: cert.userId, method: 'External PGP', fingerprint: cert.fingerprint, manual: true })))
  const custodySummary = [externalCount.value ? `${externalCount.value} external PGP` : '', passkeyCount.value ? `${passkeyCount.value} Caution custody` : ''].filter(Boolean).join(' · ')
  reviewSnapshot.value = { request: request(), holders, custodySummary }
  step.value = 'review'; await nextTick(); reviewHeading.value?.focus()
}
function back() { step.value = 'configure'; reviewSnapshot.value = null; error.value = ''; uncertain.value = false; attempted.value = false; nextTick(() => heading.value?.focus()) }
async function create() {
  if (busy.value || attempted.value || !reviewSnapshot.value) return
  busy.value = true; emit('busy', true); error.value = ''; attempted.value = true
  try { const bundle = await props.submit(reviewSnapshot.value.request); if (!disposed) emit('created', bundle) }
  catch (err) {
    if (!disposed) { uncertain.value = !!err.uncertain; error.value = err.name === 'NotAllowedError' ? 'Passkey authorization was cancelled or timed out. No creation request was sent.' : err.message; await nextTick(); errorElement.value?.focus() }
  } finally { busy.value = false; emit('busy', false) }
}
function beforeUnload(event) { if (busy.value) { event.preventDefault(); event.returnValue = '' } }
onMounted(() => { heading.value?.focus(); loadMembers(); window.addEventListener('beforeunload', beforeUnload) })
onBeforeUnmount(() => { disposed = true; parseEpoch++; armor.value = ''; certificates.value = []; reviewSnapshot.value = null; window.removeEventListener('beforeunload', beforeUnload) })
</script>

<style scoped>
.quorum-create { color: var(--theme-text-primary); max-width: 860px; margin: 0 auto; }
header { margin-bottom: 20px; } h2 { margin: 16px 0 8px; font-size: 1.8rem; } h3 { font-size: 1rem; margin: 0; }
p { line-height: 1.5; } header p, .muted, .hint { color: var(--theme-text-muted); }
.steps { display: flex; gap: 28px; padding: 0 0 12px; margin: 20px 0 0; list-style: none; color: var(--theme-text-muted); border-bottom: 1px solid var(--theme-border); }
.steps [aria-current] { color: var(--theme-text-primary); font-weight: 600; text-decoration: underline; text-decoration-color: var(--theme-brand); text-underline-offset: 14px; }
.creation-panel { padding: 24px; background: var(--theme-surface); border: 1px solid var(--theme-border); border-radius: 10px; min-width: 0; }
fieldset { padding: 0; margin: 0; border: 0; min-width: 0; }
label { display: block; font-weight: 600; margin: 0 0 8px; }
input:not([type=checkbox]), select, textarea { box-sizing: border-box; width: 100%; min-height: 40px; padding: 9px 12px; background: var(--theme-surface); color: var(--theme-text-primary); border: 1px solid var(--theme-border-strong); border-radius: 6px; font: inherit; font-size: .875rem; }
#quorum-file, #quorum-armor { margin-bottom: 16px; } textarea { resize: vertical; }
input[type=checkbox] { width: 17px; height: 17px; margin: 3px 0 0; accent-color: var(--theme-brand); flex-shrink: 0; }
.holders-heading { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 8px; margin: 24px 0 12px; }.holders-heading p { margin: 0; }
.member-list { margin-top: 8px; }
.member-row, .certificate-list li { display: grid; grid-template-columns: minmax(0, .9fr) minmax(0, 1.2fr); gap: 16px; align-items: start; padding: 14px 0; border-bottom: 1px solid var(--theme-border); font-size: .875rem; }
.member-name { display: flex; align-items: flex-start; gap: 10px; margin: 0; overflow-wrap: anywhere; }.member-name > span { min-width: 0; }
.holder-context { display: block; margin-top: 3px; font-size: .8125rem; font-weight: 400; }.holder-method { display: grid; gap: 6px; min-width: 0; }.holder-method select { min-height: 36px; padding: 6px 10px; }
.method-actions, .review-holder { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; flex-wrap: wrap; }.method-actions .text-button { font-size: .8125rem; }
.holder-import { margin-top: 16px; padding: 16px; border-left: 2px solid var(--theme-border-strong); }.holder-import .text-button { margin-left: 16px; }.import-error { color: var(--theme-danger); }
.hint { font-size: .8125rem; }.share-hint { margin: 8px 0 0; }.threshold { margin-top: 20px; padding-top: 18px; border-top: 1px solid var(--theme-border); }.threshold-row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }.threshold label { margin: 0; }.threshold-control { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; font-size: .875rem; }.threshold input { width: 70px; }.threshold .hint { margin: 8px 0 0; }
.custody-help { margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--theme-border); font-size: .875rem; }.custody-help summary { cursor: pointer; }.custody-help p { margin: 10px 0 0; }.creation-note { margin: 18px 0 0; }
.certificate-list, .review-list { list-style: none; padding: 0; margin: 0; }.certificate-list li > div { min-width: 0; }
.review-heading { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 16px; padding-bottom: 18px; border-bottom: 1px solid var(--theme-border); }.review-heading > div { min-width: 0; }.review-heading h3 { font-size: 1.2rem; overflow-wrap: anywhere; }.review-heading p { margin: 0 0 4px; }.review-quorum { text-align: right; }.review-quorum .hint { margin: 4px 0 0; }
.review-list li { padding: 18px 0; border-bottom: 1px solid var(--theme-border); }.review-list li:last-child { border-bottom: 0; }.review-holder { font-size: .875rem; }
code { display: block; overflow-wrap: anywhere; font-size: .75rem; color: var(--theme-text-muted); margin-top: 2px; }.review-list code { margin-top: 8px; } strong { overflow-wrap: anywhere; }
footer { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; padding-top: 16px; margin-top: 18px; border-top: 1px solid var(--theme-border); gap: 12px; }
button { font: inherit; cursor: pointer; } .primary, .secondary { border-radius: 6px; padding: 10px 16px; font-size: .875rem; }.primary { background: var(--theme-text-primary); color: var(--theme-surface); border: 1px solid var(--theme-text-primary); font-weight: 600; }.secondary { background: var(--theme-surface); color: var(--theme-text-primary); border: 1px solid var(--theme-border-strong); }.text-button { border: 0; background: none; color: var(--theme-text-secondary); padding: 4px 0; text-decoration: underline; }.add-holder { margin-top: 12px; color: var(--theme-brand); text-decoration: none; font-size: .875rem; }.add-holder::before { content: '+ '; }
button:disabled, fieldset:disabled { opacity: .55; }button:disabled { cursor: default; } :is(input, select, textarea, button, summary):focus-visible { outline: 2px solid var(--theme-focus); outline-offset: 3px; }
.creation-error { margin-top: 20px; padding: 16px; border: 1px solid var(--theme-danger-border); background: var(--theme-danger-bg); color: var(--theme-danger); border-radius: 6px; }.creation-error p { margin: 6px 0 12px; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; overflow: hidden; clip: rect(0,0,0,0); }
@media(max-width: 1100px) { .member-row, .certificate-list li { grid-template-columns: minmax(0, 1fr); gap: 8px; }.member-row .holder-method { margin-left: 27px; }.review-quorum { text-align: left; } }
@media(max-width: 600px) { .creation-panel { padding: 16px; }.holder-import { padding: 12px; }.steps { gap: 20px; font-size: .875rem; } }
</style>
