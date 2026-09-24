<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->
<template>
  <div class="components-page">
    <CompactPageHeader />
    <main>
      <div class="intro">
        <div><p class="eyebrow">PUBLIC INFRASTRUCTURE</p><h1>Components</h1>
          <p class="muted">Hosted services, their attestation evidence, and framework build inputs.</p></div>
        <button :disabled="loading" @click="refresh">{{ loading ? 'Checking…' : 'Refresh' }}</button>
      </div>
      <p v-if="message" role="status" aria-live="polite">{{ message }}</p>
      <div class="freshness muted">
        <time v-if="snapshot?.checked_at" :datetime="snapshot.checked_at" :title="snapshot.checked_at" tabindex="0">{{ relativeCheckTime(snapshot.checked_at, now) }}</time>
        <span>Platform snapshot · Refresh uses checks cached for up to one minute.</span>
      </div>
      <p class="copy-feedback" role="status" aria-live="polite">{{ copyStatus }}</p>
      <section aria-labelledby="hosted-title">
        <h2 id="hosted-title">Hosted services</h2>
        <p v-if="data && !snapshot" class="muted">Service checks unavailable in this response.</p>
        <div class="services">
          <article v-for="service in services" :key="service.name" class="card">
            <header class="service-header">
              <h3>{{ service.name }}</h3>
              <p class="muted role">{{ roles[service.name] || 'Hosted enclave service' }}</p>
              <a v-if="safeUrl(service.url)" :href="safeUrl(service.url)" rel="noopener noreferrer">{{ service.url.replace(/^https:\/\//, '').replace(/\/$/, '') }}</a>
              <span v-else class="muted">Service URL unavailable</span>
            </header>
            <dl class="checks">
              <div v-for="check in service.checks" :key="check.label" class="check">
                <dt>{{ check.label }}</dt>
                <dd><span :class="['badge', check.presentation.tone]"><span aria-hidden="true">{{ check.presentation.icon }}</span> {{ check.presentation.label }}</span>
                  <p v-if="check.result?.reason" class="reason">{{ check.result.reason }}</p>
                </dd>
              </div>
            </dl>
            <div class="source">
              <span class="muted source-label">Service-reported source</span>
              <a v-if="safeUrl(service.service_reported_source?.repository)" :href="safeUrl(service.service_reported_source.repository)" rel="noopener noreferrer">{{ repositoryLabel(service.service_reported_source.repository) }}</a>
              <span v-else class="muted">Repository unavailable</span>
              <button v-if="safeUrl(service.service_reported_source?.repository)" class="copy-repository" @click="copy(service.service_reported_source.repository, `${service.name} repository URL`)">Copy repository URL</button>
              <CopyValue :value="service.service_reported_source?.commit" expandable :label="`${service.name} commit`" @copy="copy" />
            </div>
            <div v-if="service.verifier" class="actions">
              <a class="button primary" :href="service.verifier.href" target="_blank" rel="noopener noreferrer" :aria-label="`Check ${service.name} attestation (opens in a new tab)`">Check attestation <span aria-hidden="true">↗</span></a>
              <button class="copy-command" @click="copy(service.verifier.command, `${service.name} verification command`)">Copy CLI command</button>
            </div>
            <details v-if="service.verifier" class="cli-command"><summary>CLI verification command</summary><pre><code>{{ service.verifier.command }}</code></pre></details>
            <details class="evidence">
              <summary>Measurements and policies</summary>
              <div class="evidence-controls">
                <label><input v-model="fullValues[service.name]" type="checkbox" /> Show full values</label>
                <label v-if="service.hiddenCount"><input v-model="allPcrs[service.name]" type="checkbox" /> Show all PCRs · {{ service.hiddenCount }} zero-valued measurements<span v-if="!allPcrs[service.name]"> hidden</span></label>
              </div>
              <h4>Observed measurements</h4>
              <table class="measurements"><caption class="sr-only">{{ service.name }} observed PCR measurements</caption>
                <thead><tr><th scope="col">PCR</th><th scope="col">Observed</th><th scope="col">Policy use</th></tr></thead>
                <tbody><tr v-for="row in service.rows.filter(row => allPcrs[service.name] || !row.hidden)" :key="row.index" :data-pcr="row.index">
                  <th scope="row">PCR{{ row.index }}</th>
                  <td><CopyValue :value="row.value" :full="fullValues[service.name]" :label="`${service.name} observed PCR${row.index}`" @copy="copy" /><span v-if="row.value != null && !row.valid" class="invalid">Invalid value</span></td>
                  <td class="muted">{{ row.pinned ? 'Policy-pinned' : 'Observed only' }}</td>
                </tr></tbody>
              </table>
              <p v-if="!service.policies?.length" class="muted">Policy unavailable.</p>
              <section v-for="policy in service.policies" :key="policy.purpose" class="policy">
                <h4>{{ policy.purpose }}</h4><p class="muted">{{ descriptions[policy.purpose] || 'Measurements accepted by the configured Platform policy.' }}</p>
                <p v-if="!policy.sets?.length" class="muted">Policy unavailable.</p>
                <div v-for="(set, index) in policy.sets || []" :key="index" class="policy-set">
                  <p class="set-title">Approved set {{ index + 1 }} <span class="muted">· {{ expiryLabel(set.expires_at_unix_seconds) }}</span></p>
                  <table class="comparison"><caption class="sr-only">{{ policy.purpose }} approved set {{ index + 1 }} comparison</caption>
                    <thead><tr><th scope="col">PCR</th><th scope="col">Observed</th><th scope="col">Allowed</th></tr></thead>
                    <tbody><tr v-for="row in policyRows(set, service.measurements)" :key="row.index">
                      <th scope="row">PCR{{ row.index }}<small :class="{ invalid: row.comparison === 'Different value' || row.comparison === 'Missing or invalid' }">{{ row.comparison }}</small></th>
                      <td><CopyValue :value="row.observed" :full="fullValues[service.name]" :label="`${service.name} observed PCR${row.index}`" @copy="copy" /></td>
                      <td><CopyValue :value="row.allowed" :full="fullValues[service.name]" :label="`${service.name} ${policy.purpose} set ${index + 1} allowed PCR${row.index}`" @copy="copy" /></td>
                    </tr></tbody>
                  </table>
                </div>
              </section>
              <details class="help"><summary>How to read this evidence</summary>
                <p>An approved set is one allowed combination: every listed PCR must match together. Individual equal values do not establish overall policy acceptance; the policy result above also accounts for its cutoff.</p>
                <p>“No expiry” means no policy timestamp cutoff, not certificate expiry. Observed-only PCRs are not pinned by these policies. Hidden zero-valued PCRs are unpinned; PCR0/1/2 and policy-pinned values always remain visible.</p>
              </details>
            </details>
          </article>
        </div>
        <aside class="trust-note muted">
          <p><strong>What these checks establish.</strong> Readiness, attestation authentication and policy matching are separate checks made by Platform. Service-reported repository and commit metadata are not authenticated by the quote.</p>
          <p><strong>Establish your own trust.</strong> Check attestation opens fresh browser verification in a new tab; import independently trusted PCRs there to check the expected image. Browser verification does not reproduce source. Use the CLI to rebuild and compare.</p>
        </aside>
      </section>
      <section aria-labelledby="framework-title">
        <h2 id="framework-title">Framework build inputs</h2>
        <p class="muted">Dependency pins for new builds, separate from deployed-service revisions.</p>
        <div class="card framework"><table><thead><tr><th scope="col">Component</th><th scope="col">Repository</th><th scope="col">Commit</th></tr></thead>
          <tbody><tr v-for="item in dependencies" :key="item.name"><th scope="row">{{ item.name }}</th>
            <td><a v-if="safeUrl(item.repo)" :href="safeUrl(item.repo)">{{ repositoryLabel(item.repo) }}</a><span v-else>Unavailable</span><button v-if="safeUrl(item.repo)" class="copy-repository" @click="copy(item.repo, `${item.name} repository URL`)">Copy URL</button></td>
            <td><CopyValue :value="item.commit" expandable :label="`${item.name} build commit`" @copy="copy" /></td>
          </tr></tbody>
        </table></div>
      </section>
      <footer><a href="https://docs.caution.co/">Documentation</a><a href="/.well-known/caution/build-inputs">Discovery JSON</a></footer>
    </main>
  </div>
</template>
<script setup>
import { computed, onMounted, onBeforeUnmount, ref } from 'vue'
import CompactPageHeader from '../components/CompactPageHeader.vue'
import CopyValue from '../components/CopyValue.vue'
import { safeUrl, verificationTarget, repositoryLabel, checkPresentation, measurementRows, policyRows, relativeCheckTime } from '../utils/components.js'
const data = ref(null)
const snapshot = computed(() => data.value?.services)
const loading = ref(false)
const message = ref('')
const copyStatus = ref('')
const now = ref(Date.now())
const fullValues = ref({})
const allPcrs = ref({})
const roles = { Keymaker: 'Creates quorum bundles', 'Key service': 'Issues custody certificates and releases shares' }
const descriptions = {
  'Bundle generation': 'Keymaker images accepted for quorum-generation proofs.',
  'Certificate issuance': 'Key-service images accepted for certificate-issuance proofs.',
  'Share release': 'Key-service images accepted for passkey-authorized share release.',
}
const services = computed(() => (snapshot.value?.entries || []).map(service => {
  const rows = measurementRows(service)
  const checks = [
    { label: 'Readiness', result: service.readiness, success: 'Ready' },
    { label: 'Attestation', result: service.attestation, success: 'Authenticated' },
    ...(service.policies || []).map(policy => ({ label: policy.purpose + ' policy', result: policy.result, success: 'Matches' })),
  ].map(check => ({ ...check, presentation: checkPresentation(check.result, check.success) }))
  return { ...service, rows, hiddenCount: rows.filter(row => row.hidden).length, checks, verifier: verificationTarget(service.url) }
}))
const dependencies = computed(() => ['platform', 'enclaveos', 'bootproof', 'steve', 'locksmith']
  .filter(name => data.value?.[name]).map(name => ({ name, ...data.value[name] })))
let controller
let ageTimer
let stopped = false
function expiryLabel(seconds) {
  if (seconds == null) return 'No expiry'
  const date = new Date(seconds * 1000)
  return Number.isFinite(date.getTime()) ? `Cutoff ${date.toISOString()}` : 'Invalid expiry'
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
onMounted(() => { refresh(); ageTimer = setInterval(() => { now.value = Date.now() }, 30000) })
onBeforeUnmount(() => { stopped = true; controller?.abort(); clearInterval(ageTimer) })
</script>
<style scoped>
.components-page { min-height: 100vh; background: var(--theme-page); color: var(--theme-text-primary); }
main { max-width: 1120px; padding: 32px 24px 48px; margin: auto; }
.intro { display: flex; justify-content: space-between; align-items: center; gap: 24px; }
h1 { font-size: clamp(2rem, 5vw, 3rem); margin: 8px 0; letter-spacing: -.03em; }
h2 { margin: 28px 0 16px; font-size: 1.25rem; } h3 { font-size: 1.3rem; margin: 0; } h4 { margin: 20px 0 8px; font-size: .95rem; }
p { line-height: 1.55; margin: 8px 0; } .eyebrow { font-size: .7rem; letter-spacing: .13em; }
.muted { color: var(--theme-text-secondary); font-size: .85rem; }
.freshness { display: flex; flex-wrap: wrap; gap: 6px 16px; margin-top: 12px; }
.copy-feedback { min-height: 1.3em; font-size: .8rem; margin: 6px 0 0; }
.services { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 20px; align-items: start; }
.card { background: var(--theme-surface); border: 1px solid var(--theme-border); border-radius: 14px; padding: 22px; min-width: 0; }
.service-header > a { font-size: .85rem; } .role { margin: 4px 0 10px; }
a { color: inherit; text-underline-offset: 3px; } a, code, td, th { overflow-wrap: anywhere; }
.checks { margin: 20px 0; display: grid; gap: 10px; }
.check { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 10px; align-items: baseline; font-size: .82rem; }
dd { margin: 0; text-align: right; } dt { font-weight: 500; }
.badge { display: inline-flex; gap: 5px; align-items: center; border-radius: 5px; padding: 3px 7px; font-size: .75rem; background: var(--theme-surface-subtle); }
.passed { color: var(--theme-success); background: var(--theme-success-bg); }
.failed { color: var(--theme-danger); background: var(--theme-danger-bg); }
.pending { color: var(--theme-warning); background: var(--theme-warning-bg); }
.reason { text-align: left; font-size: .78rem; line-height: 1.4; }
.source { border-top: 1px solid var(--theme-border); padding-top: 12px; display: flex; flex-wrap: wrap; gap: 6px 12px; align-items: baseline; font-size: .8rem; }
.source > a { max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.copy-repository { font-size: .68rem; padding: 2px 5px; background: transparent; color: var(--theme-text-secondary); }
.source-label { flex-basis: 100%; font-size: .72rem; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 18px; }
button, .button { cursor: pointer; background: var(--theme-control); color: var(--theme-control-text); border: 1px solid var(--theme-border); border-radius: 6px; padding: 9px 12px; font-size: .8rem; }
.button { text-decoration: none; } .primary { font-weight: 600; }
button:disabled { opacity: .6; }
:is(button, summary, a, input, time):focus-visible { outline: 2px solid var(--theme-focus); outline-offset: 4px; }
details { margin-top: 14px; } summary { cursor: pointer; font-size: .82rem; font-weight: 600; }
.evidence { border-top: 1px solid var(--theme-border); padding-top: 14px; }
.evidence-controls { display: flex; flex-wrap: wrap; gap: 10px; margin: 16px 0; font-size: .78rem; }
.evidence-controls label { display: flex; align-items: center; gap: 5px; cursor: pointer; }
table { width: 100%; border-collapse: collapse; table-layout: fixed; font-size: .78rem; }
th, td { text-align: left; padding: 10px 6px; vertical-align: top; border-bottom: 1px solid var(--theme-border); }
thead th { color: var(--theme-text-secondary); font-weight: 500; font-size: .7rem; }
.measurements th:first-child { width: 15%; } .measurements th:last-child { width: 24%; }
.comparison th:first-child { width: 22%; }
small { display: block; font-size: .68rem; font-weight: 400; margin-top: 5px; color: var(--theme-text-secondary); }
.invalid { color: var(--theme-danger); display: block; font-size: .7rem; }
.policy { border-top: 1px solid var(--theme-border); margin-top: 18px; } .policy-set { margin-top: 14px; }
.set-title { font-size: .8rem; font-weight: 600; }
.help { color: var(--theme-text-secondary); font-size: .8rem; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; background: var(--theme-surface-subtle); padding: 12px; border-radius: 6px; font-size: .75rem; }
.trust-note { margin-top: 20px; padding-left: 14px; border-left: 2px solid var(--theme-border); }
.framework { padding: 8px 14px; } .framework th:first-child { width: 22%; }
footer { display: flex; gap: 20px; margin-top: 28px; font-size: .8rem; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
@media (max-width: 1000px) { .services { grid-template-columns: minmax(0, 1fr); } }
@media (max-width: 640px) { main { padding: 24px 16px; } .intro { align-items: flex-start; gap: 12px; } .intro > div { min-width: 0; } .card { padding: 16px; } .framework { padding: 6px; } .actions > * { flex-grow: 1; text-align: center; } }
</style>
