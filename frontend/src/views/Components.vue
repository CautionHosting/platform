<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->
<template>
  <div class="components-page">
    <CompactPageHeader />
    <main>
      <div class="intro">
        <div><p class="eyebrow">PUBLIC INFRASTRUCTURE</p><h1>Components</h1>
          <p class="muted">Hosted services and the evidence behind them.</p></div>
        <button :disabled="loading" @click="refresh">{{ loading ? 'Checking…' : 'Refresh' }}</button>
      </div>
      <p v-if="message" class="refresh-message" role="status" aria-live="polite">{{ message }}</p>
      <div class="freshness muted">
        <strong>Platform snapshot</strong>
        <time v-if="snapshot?.checked_at" :datetime="snapshot.checked_at" :title="snapshot.checked_at" tabindex="0">{{ relativeCheckTime(snapshot.checked_at, now) }}</time>
        <span v-if="snapshot?.checked_at">{{ exactCheckTime }}</span>
        <span>Refresh uses checks cached for up to one minute.</span>
      </div>
      <p class="copy-feedback" role="status" aria-live="polite">{{ copyStatus }}</p>
      <p v-if="data && !snapshot" class="muted">Service checks unavailable in this response.</p>
      <div v-if="services.length" class="services">
        <nav class="service-selector" aria-labelledby="hosted-title">
          <h2 id="hosted-title">Hosted services</h2>
          <a v-for="service in services" :key="service.key" :href="`#${encodeURIComponent(service.key)}`"
            :aria-current="selected === service.key ? 'true' : undefined" class="service-option" @click.prevent="selectService(service.key)">
            <strong>{{ service.name }}</strong><span class="service-role muted">{{ roles[service.name] || 'Hosted enclave service' }}</span>
            <span :class="['selector-status', service.summary.tone]"><span aria-hidden="true">{{ service.summary.icon }}</span> {{ service.summary.label }}</span>
          </a>
        </nav>
        <div class="service-panels">
          <article v-for="service in services" v-show="selected === service.key" :key="service.key" class="card passport" :aria-label="`${service.name} service evidence`">
            <header class="service-header">
              <div><p class="eyebrow">SERVICE EVIDENCE</p><h2>{{ service.name }}</h2>
                <p class="muted role">{{ roles[service.name] || 'Hosted enclave service' }}</p>
                <a v-if="safeUrl(service.url)" :href="safeUrl(service.url)" rel="noopener noreferrer">{{ service.url.replace(/^https:\/\//, '').replace(/\/$/, '') }} <span aria-hidden="true">↗</span></a>
                <span v-else class="muted">Service URL unavailable</span>
              </div><code class="service-id">{{ service.key }}</code>
            </header>
            <div class="service-body">
              <div :class="['service-result', service.summary.tone]">
                <span class="result-icon" aria-hidden="true">{{ service.summary.icon }}</span>
                <div><strong>{{ service.summary.label }}</strong><p>{{ service.checks.length }} separate checks · observed by Platform</p></div>
              </div>
              <p v-if="service.unreachable" class="availability-note muted">Platform couldn’t reach this service during the last check.</p>
              <div v-if="service.verifier" class="actions">
                <a class="button primary" :href="service.verifier.href" target="_blank" rel="noopener noreferrer" :aria-label="`Check ${service.name} attestation (opens in a new tab)`">Check attestation <span aria-hidden="true">↗</span></a>
                <button class="cli-toggle" :aria-expanded="isOpen(service.key, 'cli')" :aria-controls="`cli-${service.key}`" @click="setOpen(service.key, 'cli', !isOpen(service.key, 'cli'))">Reproduce with CLI</button>
              </div>
              <div v-if="service.verifier" v-show="isOpen(service.key, 'cli')" :id="`cli-${service.key}`" class="cli-command">
                <div class="command-heading"><span class="muted">Independent build reproduction</span><button class="copy-command" :aria-label="`Copy ${service.name} verification command`" @click="copy(service.verifier.command, `${service.name} verification command`)">Copy</button></div>
                <pre tabindex="0" :aria-label="`${service.name} verification command`"><code>{{ service.verifier.command }}</code></pre>
              </div>
              <div class="checks-heading"><h3>What was checked</h3><span class="muted">Open a check for its evidence</span></div>
              <div class="checks">
                <details v-for="check in service.checks" :key="check.label" :class="['check', { policy: check.policy }]"
                  :data-check="check.label" :open="isOpen(service.key, check.label)" @toggle="setOpen(service.key, check.label, $event.target.open)">
                  <summary>
                    <span :class="['check-icon', check.presentation.tone]" aria-hidden="true">{{ check.presentation.icon }}</span>
                    <span class="check-label"><strong>{{ check.label }}</strong><small>{{ checkDescription(check, service) }}</small><span v-if="check.reason" :class="['reason', check.presentation.tone]">{{ check.reason }}</span></span>
                    <span :class="['badge', check.presentation.tone]">{{ check.presentation.label }}</span><span class="chevron" aria-hidden="true">›</span>
                  </summary>
                  <div class="check-evidence">
                    <p v-if="check.result?.reason && !check.reason" class="muted">{{ check.result.reason }}</p>
                    <template v-if="check.label === 'Readiness'">
                      <p class="muted">A separate health check. Readiness does not establish attestation authenticity or policy acceptance.</p>
                    </template>
                    <template v-else-if="check.label === 'Attestation'">
                      <p class="muted">Platform checks the AWS Nitro certificate chain, signature and challenge nonce before comparing authenticated measurements. Debug PCR0/1/2 values are rejected.</p>
                      <div v-if="service.hasMeasurements" class="evidence-controls">
                        <label><input v-model="fullValues[service.key]" type="checkbox" /> Show full values</label>
                        <label v-if="service.hiddenCount"><input v-model="allPcrs[service.key]" type="checkbox" /> Show all PCRs · {{ service.hiddenCount }} zero-valued measurements<span v-if="!allPcrs[service.key]"> hidden</span></label>
                      </div>
                      <table v-if="service.hasMeasurements" class="measurements"><caption class="sr-only">{{ service.name }} observed PCR measurements</caption>
                        <thead><tr><th scope="col">PCR</th><th scope="col">Observed</th><th scope="col">Policy use</th></tr></thead>
                        <tbody><tr v-for="row in service.rows.filter(row => allPcrs[service.key] || !row.hidden)" :key="row.index" :data-pcr="row.index">
                          <th scope="row">PCR{{ row.index }}</th>
                          <td><CopyValue :value="row.value" :full="fullValues[service.key]" :label="`${service.name} observed PCR${row.index}`" @copy="copy" /><span v-if="row.value != null && !row.valid" class="invalid">Invalid value</span></td>
                          <td class="muted">{{ row.pinned ? 'Policy-pinned' : 'Observed only' }}</td>
                        </tr></tbody>
                      </table>
                      <p v-else class="muted">No authenticated measurements available for comparison.</p>
                    </template>
                    <template v-else-if="check.policy">
                      <p class="muted">{{ descriptions[check.policy.purpose] || 'Measurements accepted by the configured Platform policy.' }}</p>
                      <p v-if="!service.hasMeasurements" class="muted">No authenticated measurements available for comparison.</p>
                      <p v-if="!check.policy.sets?.length" class="muted">Policy unavailable.</p>
                      <label v-if="check.policy.sets?.length" class="full-values"><input v-model="fullValues[service.key]" type="checkbox" /> Show full values</label>
                      <PolicySetEvidence v-for="set in check.sets.accepted" :key="set.index" :set="set" :measurements="service.measurements"
                        :service-name="service.name" :purpose="check.policy.purpose" :authenticated="service.hasMeasurements" :full="fullValues[service.key]" @copy="copy" />
                      <details v-if="check.sets.other.length" class="other-sets" :open="isOpen(service.key, `${check.label}:sets`, !check.sets.accepted.length)"
                        @toggle="setOpen(service.key, `${check.label}:sets`, $event.target.open)">
                        <summary>{{ check.sets.accepted.length ? 'Other approved sets' : 'Approved sets' }} · {{ check.sets.other.length }}</summary>
                        <PolicySetEvidence v-for="set in check.sets.other" :key="set.index" :set="set" :measurements="service.measurements"
                          :service-name="service.name" :purpose="check.policy.purpose" :authenticated="service.hasMeasurements" :full="fullValues[service.key]" :failed="check.result?.status === 'failed'" @copy="copy" />
                      </details>
                    </template>
                  </div>
                </details>
              </div>
              <div class="source">
                <span class="muted source-label">Service-reported source · not authenticated by the quote</span>
                <a v-if="safeUrl(service.service_reported_source?.repository)" :href="safeUrl(service.service_reported_source.repository)" rel="noopener noreferrer">{{ repositoryLabel(service.service_reported_source.repository) }}</a>
                <span v-if="!safeUrl(service.service_reported_source?.repository) && !service.service_reported_source?.commit" class="muted">Source information unavailable for this check.</span>
                <button v-if="safeUrl(service.service_reported_source?.repository)" class="copy-repository" @click="copy(service.service_reported_source.repository, `${service.name} repository URL`)">Copy repository URL</button>
                <CopyValue v-if="service.service_reported_source?.commit" :value="service.service_reported_source.commit" expandable :label="`${service.name} commit`" @copy="copy" />
              </div>
              <p class="trust-scope muted">Platform snapshot. Independent source reproduction and applicable endpoint binding are checked through the CLI.</p>
              <details class="help" :open="isOpen(service.key, 'help')" @toggle="setOpen(service.key, 'help', $event.target.open)">
                <summary>How to read this evidence</summary>
                <p>Readiness, attestation authentication and each policy result are separate checks. Accepted sets are identified by Platform for this snapshot; they are not an independently trusted baseline.</p>
                <p>Every listed PCR in one approved set must match together. Individual equal values do not establish policy acceptance or override cutoffs. “No expiry” means no policy timestamp cutoff, not certificate expiry.</p>
                <p>Observed-only PCRs are not pinned by these policies. Hidden zero-valued PCRs are unpinned; PCR0/1/2 and policy-pinned values always remain visible.</p>
                <p>Check attestation opens fresh browser verification in a new tab. Import independently trusted PCRs there to check the expected image. Browser verification does not reproduce source; use the CLI to rebuild and compare.</p>
              </details>
            </div>
          </article>
        </div>
      </div>
      <details class="card framework" :open="frameworkOpen" @toggle="frameworkOpen = $event.target.open">
        <summary><span>Framework build inputs</span><span class="muted">{{ dependencies.length }} components · pins for new builds</span></summary>
        <p class="muted">Dependency pins for new builds, separate from deployed-service revisions.</p>
        <table><thead><tr><th scope="col">Component</th><th scope="col">Repository</th><th scope="col">Commit</th></tr></thead>
          <tbody><tr v-for="item in dependencies" :key="item.name"><th scope="row">{{ item.name }}</th>
            <td><a v-if="safeUrl(item.repo)" :href="safeUrl(item.repo)">{{ repositoryLabel(item.repo) }}</a><span v-else>Unavailable</span><button v-if="safeUrl(item.repo)" class="copy-repository" @click="copy(item.repo, `${item.name} repository URL`)">Copy URL</button></td>
            <td><CopyValue :value="item.commit" expandable :label="`${item.name} build commit`" @copy="copy" /></td>
          </tr></tbody>
        </table>
      </details>
      <footer><a href="https://docs.caution.co/">Documentation</a><a href="/.well-known/caution/build-inputs">Discovery JSON</a></footer>
    </main>
  </div>
</template>
<script setup>
import { computed, onMounted, onBeforeUnmount, ref } from 'vue'
import CompactPageHeader from '../components/CompactPageHeader.vue'
import CopyValue from '../components/CopyValue.vue'
import PolicySetEvidence from '../components/PolicySetEvidence.vue'
import { safeUrl, verificationTarget, repositoryLabel, servicePresentation, measurementRows, policySets, relativeCheckTime, serviceKey, selectedServiceKey } from '../utils/components.js'
const data = ref(null)
const snapshot = computed(() => data.value?.services)
const loading = ref(false)
const message = ref('')
const copyStatus = ref('')
const now = ref(Date.now())
const fragment = ref(window.location.hash)
const fullValues = ref({})
const allPcrs = ref({})
const disclosures = ref({})
const frameworkOpen = ref(false)
const roles = { Keymaker: 'Creates quorum bundles', 'Key service': 'Issues custody certificates and releases shares' }
const descriptions = {
  'Bundle generation': 'Keymaker images accepted for quorum-generation proofs.',
  'Certificate issuance': 'Key-service images accepted for certificate-issuance proofs.',
  'Share release': 'Key-service images accepted for passkey-authorized share release.',
}
const services = computed(() => (snapshot.value?.entries || []).map(service => {
  const rows = measurementRows(service)
  const presentation = servicePresentation(service)
  const checks = presentation.checks.map(check => ({ ...check, sets: check.policy ? policySets(check.policy, presentation.hasMeasurements) : null }))
  return { ...service, ...presentation, key: serviceKey(service), checks, rows, hiddenCount: rows.filter(row => row.hidden).length, verifier: verificationTarget(service.url, service.id, window.location.origin) }
}))
const selected = computed(() => selectedServiceKey(services.value, fragment.value))
const exactCheckTime = computed(() => {
  const date = new Date(snapshot.value?.checked_at)
  return Number.isFinite(date.getTime()) ? date.toISOString().slice(0, 19).replace('T', ' ') + ' UTC' : 'Check time unavailable'
})
const dependencies = computed(() => ['platform', 'enclaveos', 'bootproof', 'steve', 'locksmith']
  .filter(name => data.value?.[name]).map(name => ({ name, ...data.value[name] })))
let controller
let ageTimer
let stopped = false
function isOpen(key, label, fallback = false) { return disclosures.value[key]?.[label] ?? fallback }
function setOpen(key, label, open) {
  if (!disclosures.value[key]) disclosures.value[key] = {}
  disclosures.value[key][label] = open
}
function syncFragment() { fragment.value = window.location.hash }
function selectService(key) {
  const next = '#' + encodeURIComponent(key)
  if (next !== window.location.hash) {
    window.history.pushState(window.history.state, '', window.location.pathname + window.location.search + next)
    window.dispatchEvent(new Event('caution:location-change'))
  }
  syncFragment()
}
function checkDescription(check, service) {
  if (check.label === 'Readiness') return 'Service health endpoint'
  if (check.label === 'Attestation') return 'AWS Nitro · certificate chain, signature, nonce'
  if (!service.hasMeasurements) return 'No authenticated measurements'
  if (check.sets.accepted.length) return 'Accepted ' + check.sets.accepted.map(set => `set ${set.index + 1}`).join(', ')
  return 'Compared with configured Platform policy'
}
async function copy(value, label) {
  try {
    await navigator.clipboard.writeText(value)
    copyStatus.value = `Copied ${label}.`
  } catch { copyStatus.value = `Could not copy ${label}. Expand the full value or command and copy it manually.` }
}
async function refresh() {
  if (loading.value) return
  loading.value = true
  message.value = 'Checking services…'
  controller = new AbortController()
  const deadline = Date.now() + 10000
  const timeout = setTimeout(() => controller?.abort(), 10000)
  try {
    do {
      const response = await fetch('/.well-known/caution/build-inputs', { signal: controller.signal, credentials: 'omit', cache: 'no-store' })
      if (!response.ok) throw new Error('Build inputs unavailable. Use Refresh to retry.')
      data.value = await response.json()
      now.value = Date.now()
      if (!snapshot.value?.pending) { message.value = ''; return }
      if (Date.now() + 1000 >= deadline) break
      await new Promise(resolve => setTimeout(resolve, 1000))
    } while (!stopped && Date.now() < deadline)
    message.value = 'Checks are still pending. Use Refresh to check again.'
  } catch (error) {
    data.value = null
    message.value = error.name === 'AbortError' ? 'Check timed out. Use Refresh to retry.' : 'Build inputs unavailable. Use Refresh to retry.'
  } finally { clearTimeout(timeout); loading.value = false }
}
onMounted(() => {
  refresh()
  ageTimer = setInterval(() => { now.value = Date.now() }, 30000)
  window.addEventListener('popstate', syncFragment)
  window.addEventListener('hashchange', syncFragment)
})
onBeforeUnmount(() => {
  stopped = true
  controller?.abort()
  clearInterval(ageTimer)
  window.removeEventListener('popstate', syncFragment)
  window.removeEventListener('hashchange', syncFragment)
})
</script>
<style scoped>
.components-page { min-height: 100vh; background: var(--theme-page); color: var(--theme-text-primary); }
main { max-width: 1120px; padding: 28px 24px 48px; margin: auto; }
.intro { display: flex; justify-content: space-between; align-items: center; gap: 24px; }
h1 { font-size: clamp(1.9rem, 5vw, 2.25rem); margin: 8px 0; letter-spacing: -.04em; }
h2 { font-size: 1.3rem; margin: 0; letter-spacing: -.02em; } h3 { font-size: .85rem; margin: 0; }
p { line-height: 1.55; margin: 8px 0; } .eyebrow { font-size: .68rem; letter-spacing: .13em; }
.muted { color: var(--theme-text-muted); font-size: .82rem; }
.freshness { display: flex; flex-wrap: wrap; gap: 6px 14px; margin-top: 18px; font-size: .75rem; }
.freshness strong { color: var(--theme-text-primary); font-weight: 500; }
.refresh-message, .copy-feedback { font-size: .8rem; }
.copy-feedback { margin: 8px 0; } .copy-feedback:empty { display: none; }
.services { display: grid; grid-template-columns: 195px minmax(0, 1fr); gap: 20px; align-items: start; margin-top: 26px; }
.service-selector { display: grid; gap: 8px; }
.service-selector h2 { font-size: .68rem; font-weight: 500; text-transform: uppercase; letter-spacing: .08em; color: var(--theme-text-muted); margin: 8px 0; }
.service-option { display: grid; gap: 6px; min-width: 0; padding: 15px; border: 1px solid transparent; border-radius: 10px; text-decoration: none; }
.service-option[aria-current] { background: var(--theme-surface); border-color: var(--theme-border); }
.service-option:hover { background: var(--theme-surface-subtle); }
.service-option strong { font-size: .85rem; } .service-role { font-size: .72rem; line-height: 1.5; }
.selector-status { font-size: .7rem; line-height: 1.5; }
.card { background: var(--theme-surface); border: 1px solid var(--theme-border); border-radius: 14px; min-width: 0; }
.service-panels { min-width: 0; }
.service-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; padding: 21px 24px 18px; border-bottom: 1px solid var(--theme-border); }
.service-header > div { min-width: 0; } .service-header .eyebrow { margin: 0 0 8px; }
.service-header a { font-size: .8rem; text-decoration: none; } .role { margin: 5px 0 10px; }
.service-id { color: var(--theme-text-muted); background: var(--theme-surface-subtle); padding: 5px 7px; border-radius: 5px; font-size: .68rem; }
.service-body { padding: 20px 24px; }
a { color: inherit; text-underline-offset: 3px; } a, code, td, th { overflow-wrap: anywhere; }
.service-result { display: flex; align-items: flex-start; gap: 12px; padding: 14px 16px; border-radius: 9px; background: var(--theme-surface-subtle); }
.service-result strong { font-size: .9rem; } .result-icon { font-size: 1.1rem; line-height: 1.4; }
.service-result p { font-size: .72rem; color: var(--theme-text-muted); margin: 4px 0 0; }
.passed { color: var(--theme-success); } .failed { color: var(--theme-danger); } .pending { color: var(--theme-warning); } .unavailable { color: var(--theme-text-muted); }
.service-result.passed { background: var(--theme-success-bg); } .service-result.failed { background: var(--theme-danger-bg); } .service-result.pending { background: var(--theme-warning-bg); }
.availability-note { font-size: .78rem; margin-top: 12px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; margin: 16px 0; }
button, .button { cursor: pointer; background: var(--theme-surface); color: var(--theme-text-primary); border: 1px solid var(--theme-border); border-radius: 8px; padding: 10px 13px; font-size: .8rem; }
.button { text-decoration: none; } .primary { font-weight: 600; background: var(--theme-text-primary); color: var(--theme-surface); border-color: var(--theme-text-primary); }
button:disabled { opacity: .6; }
:is(button, summary, a, input, time, pre):focus-visible { outline: 2px solid var(--theme-focus); outline-offset: 3px; }
.cli-command { background: var(--theme-surface-subtle); border: 1px solid var(--theme-border); border-radius: 8px; padding: 12px; margin: 0 0 18px; }
.command-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.command-heading .copy-command { padding: 3px 8px; font-size: .72rem; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; font-size: .75rem; margin: 10px 0 0; user-select: text; }
.checks-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin: 23px 0 12px; }
.checks-heading > span { font-size: .72rem; }
.checks { border: 1px solid var(--theme-border); border-radius: 10px; }
.check { border-bottom: 1px solid var(--theme-border); } .check:last-child { border-bottom: 0; }
.check > summary { display: grid; grid-template-columns: 16px minmax(0, 1fr) auto 12px; gap: 10px; align-items: center; padding: 13px 14px; list-style: none; }
.check > summary::-webkit-details-marker { display: none; }
summary { cursor: pointer; font-size: .8rem; font-weight: 500; }
.check-label strong { font-size: .8rem; font-weight: 500; }
.check-label small { display: block; color: var(--theme-text-muted); font-size: .72rem; margin-top: 4px; line-height: 1.45; }
.badge { font-size: .72rem; white-space: nowrap; }
.chevron { color: var(--theme-text-muted); font-size: 1.15rem; } .check[open] > summary .chevron { transform: rotate(90deg); }
.reason { display: block; margin-top: 6px; font-size: .78rem; line-height: 1.45; }
.check-evidence { padding: 0 14px 16px 40px; min-width: 0; }
.check-evidence > p:first-child { margin-top: 0; }
.evidence-controls { display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0; font-size: .75rem; }
.evidence-controls label, .full-values { display: flex; align-items: center; gap: 5px; cursor: pointer; }
.full-values { margin-top: 14px; font-size: .75rem; }
table { width: 100%; border-collapse: collapse; table-layout: fixed; font-size: .78rem; }
th, td { text-align: left; padding: 10px 6px; vertical-align: top; border-bottom: 1px solid var(--theme-border); }
thead th { color: var(--theme-text-muted); font-weight: 500; font-size: .72rem; }
.measurements th:first-child { width: 15%; } .measurements th:last-child { width: 24%; }
.invalid { color: var(--theme-danger); display: block; font-size: .7rem; }
.other-sets { margin-top: 16px; } .other-sets > summary { color: var(--theme-text-muted); }
.source { border-top: 1px solid var(--theme-border); padding-top: 14px; margin-top: 18px; display: flex; flex-wrap: wrap; gap: 6px 12px; align-items: baseline; font-size: .8rem; }
.source > a { max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.source-label { flex-basis: 100%; font-size: .72rem; }
.copy-repository { font-size: .68rem; padding: 2px 5px; background: transparent; color: var(--theme-text-muted); }
.trust-scope { margin-top: 16px; font-size: .72rem; }
.help { margin-top: 14px; color: var(--theme-text-muted); } .help summary { font-size: .75rem; } .help p { font-size: .78rem; }
.framework { padding: 14px 16px; margin-top: 22px; }
.framework > summary { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; list-style-position: inside; }
.framework > summary::before { content: '›'; }
.framework[open] > summary::before { content: '⌄'; }
.framework > summary > span:first-child { margin-right: auto; }
.framework > summary .muted { font-size: .72rem; }
.framework th:first-child { width: 22%; }
footer { display: flex; gap: 20px; margin-top: 22px; font-size: .75rem; color: var(--theme-text-muted); }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
@media (max-width: 760px) {
  .services { grid-template-columns: minmax(0, 1fr); gap: 16px; }
  .service-selector { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .service-selector h2 { grid-column: 1 / -1; }
  .checks-heading > span { display: none; }
}
@media (max-width: 420px) {
  main { padding: 24px 16px; } .intro { align-items: flex-start; gap: 12px; } .intro > div { min-width: 0; }
  .service-header, .service-body { padding: 17px 15px; } .service-id { display: none; } .service-option { padding: 12px; }
  .check > summary { grid-template-columns: 13px minmax(0, 1fr) 12px; gap: 6px; padding: 12px 9px; }
  .badge { grid-column: 2; grid-row: 2; } .chevron { grid-column: 3; grid-row: 1 / 3; }
  .check-evidence { padding-left: 28px; padding-right: 9px; }
  .actions > * { flex: 1 1 auto; text-align: center; } .framework { padding: 12px; }
}
@media (pointer: coarse) { :is(button, summary, .button, .service-option) { min-height: 44px; } }
</style>
