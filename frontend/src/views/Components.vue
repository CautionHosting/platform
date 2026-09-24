<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->
<template>
  <div class="components-page">
    <CompactPageHeader />
    <main>
      <div class="intro">
        <div><p class="eyebrow">PUBLIC INFRASTRUCTURE</p><h1>Components</h1>
          <p>Hosted services and framework build inputs. Inspect the evidence and verify independently.</p></div>
        <button :disabled="loading" @click="refresh">{{ loading ? 'Checking…' : 'Refresh' }}</button>
      </div>
      <p role="status" aria-live="polite">{{ message }}</p>
      <p v-if="snapshot?.checked_at" class="muted">Checked {{ snapshot.checked_at }} · Checks are cached for up to one minute.</p>
      <section aria-labelledby="hosted-title">
        <h2 id="hosted-title">Hosted services</h2>
        <article v-for="service in snapshot?.entries || []" :key="service.name" class="card">
          <h3>{{ service.name }}</h3>
          <a v-if="safeUrl(service.url)" :href="safeUrl(service.url)" rel="noopener noreferrer">{{ service.url }}</a>
          <p v-else class="muted">Service URL unavailable</p>
          <dl class="checks">
            <div><dt>Readiness</dt><dd>{{ resultLabel(service.readiness, 'Ready') }}</dd></div>
            <div><dt>Attestation authentication</dt><dd>{{ resultLabel(service.attestation, 'Authenticated') }}</dd></div>
            <div v-for="policy in service.policies" :key="policy.purpose"><dt>{{ policy.purpose }} PCR policy</dt><dd>{{ resultLabel(policy.result, 'Matches') }}</dd></div>
          </dl>
          <p class="muted">Readiness is separate from signature, certificate-chain, nonce and PCR-policy checks.</p>
          <div class="source">
            <strong>Service-reported source</strong>
            <p v-if="service.service_reported_source">
              <a v-if="safeUrl(service.service_reported_source.repository)" :href="safeUrl(service.service_reported_source.repository)" rel="noopener noreferrer">{{ service.service_reported_source.repository }}</a>
              <span v-else>Repository unavailable</span><br />
              <span>Service-reported commit: </span><code>{{ service.service_reported_source.commit || 'Unavailable' }}</code>
            </p>
            <p v-else>Unavailable</p>
            <p class="muted">Repository and commit are reported by the service; a matching attestation does not authenticate this source metadata.</p>
          </div>
          <details><summary>PCR measurements and approved policies</summary>
            <h4>Authenticated measurements</h4>
            <p v-if="!Object.keys(service.measurements || {}).length">Unavailable</p>
            <p v-for="(value, index) in service.measurements" :key="index"><strong>PCR{{ index }}</strong> <code>{{ value }}</code></p>
            <div v-for="policy in service.policies" :key="policy.purpose">
              <h4>{{ policy.purpose }}</h4>
              <p v-if="!policy.sets.length">Policy unavailable</p>
              <div v-for="(set, index) in policy.sets" :key="index" class="policy-set">
                <p>Approved set {{ index + 1 }} · {{ set.expires_at_unix_seconds == null ? 'No expiry' : expiryLabel(set.expires_at_unix_seconds) }}</p>
                <p v-for="(value, pcr) in set.pcrs" :key="pcr"><strong>PCR{{ pcr }}</strong> <code>{{ value }}</code></p>
              </div>
            </div>
          </details>
          <div v-if="safeUrl(service.url)" class="verification">
            <h4>Verify independently</h4>
            <pre><code>{{ command(service.url) }}</code></pre>
            <p class="muted">Rebuild and compare using the reported source. This page reports the Platform’s configured trust policy; it does not establish your own trust.</p>
          </div>
        </article>
      </section>
      <section aria-labelledby="framework-title">
        <h2 id="framework-title">Framework build inputs</h2>
        <p>Dependency pins used for new builds. These are separate from the commits reported by hosted services.</p>
        <dl class="card dependencies"><div v-for="item in dependencies" :key="item.name">
          <dt>{{ item.name }}</dt><dd><a v-if="safeUrl(item.repo)" :href="safeUrl(item.repo)">{{ item.repo }}</a><br /><code>{{ item.commit || 'Unavailable' }}</code></dd>
        </div></dl>
      </section>
      <footer><a href="https://docs.caution.co/">Documentation</a> · <a href="/.well-known/caution/build-inputs">JSON build inputs</a></footer>
    </main>
  </div>
</template>
<script setup>
import { computed, onMounted, onBeforeUnmount, ref } from 'vue'
import CompactPageHeader from '../components/CompactPageHeader.vue'
import { quotePosixShellArgument } from '../utils/publicAttestation.js'
const data = ref(null)
const snapshot = computed(() => data.value?.services)
const loading = ref(false)
const message = ref('')
const dependencies = computed(() => ['platform', 'enclaveos', 'bootproof', 'steve', 'locksmith']
  .filter(name => data.value?.[name]).map(name => ({ name, ...data.value[name] })))
let controller
let stopped = false
function safeUrl(raw) {
  try { const u = new URL(raw); return u.protocol === 'https:' && !u.username && !u.password && !u.search && !u.hash ? u.href : null } catch { return null }
}
function expiryLabel(seconds) {
  const date = new Date(seconds * 1000)
  return Number.isFinite(date.getTime()) ? `Expires ${date.toISOString()}` : 'Invalid expiry'
}
function command(raw) { return `caution verify --attestation-url ${quotePosixShellArgument(safeUrl(raw).replace(/\/$/, '') + '/attestation')}` }
function resultLabel(check, success) { return check?.status === 'passed' ? success : `Failed: ${check?.reason || 'Unavailable'}` }
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
onMounted(refresh)
onBeforeUnmount(() => { stopped = true; controller?.abort() })
</script>
<style scoped>
.components-page { min-height: 100vh; background: var(--theme-page); color: var(--theme-text-primary); }
main { max-width: 1120px; padding: 32px 24px 56px; margin: auto; }
.intro { display: flex; justify-content: space-between; align-items: center; gap: 24px; }
h1 { font-size: clamp(2rem, 5vw, 3rem); margin: 8px 0; } h2 { margin-top: 40px; } h3 { font-size: 1.4rem; margin-top: 0; }
p { line-height: 1.6; margin: 10px 0; } h4 { margin: 18px 0 10px; } details code { display: block; margin-top: 4px; } .eyebrow { font-size: .75rem; letter-spacing: .12em; }
.muted { color: var(--theme-text-secondary); font-size: .9rem; }
.card { background: var(--theme-surface); border: 1px solid var(--theme-border); border-radius: 16px; padding: 24px; margin: 20px 0; }
a { color: inherit; text-underline-offset: 3px; } a, code, dd { overflow-wrap: anywhere; }
.checks, .dependencies { display: grid; gap: 16px; } .checks { grid-template-columns: repeat(2, minmax(0, 1fr)); }
dt { font-weight: 600; } dd { margin: 6px 0 0; } .source, details, .verification { border-top: 1px solid var(--theme-border); margin-top: 24px; padding-top: 20px; }
summary { cursor: pointer; font-weight: 600; } .policy-set { border-left: 2px solid var(--theme-border); padding-left: 16px; }
pre { white-space: pre-wrap; background: var(--theme-surface-subtle); padding: 16px; border-radius: 8px; }
button { cursor: pointer; background: var(--theme-control); color: var(--theme-control-text); border: 1px solid var(--theme-border); border-radius: 8px; padding: 12px 20px; }
button:disabled { opacity: .6; } :is(button, summary, a):focus-visible { outline: 2px solid var(--theme-focus); outline-offset: 4px; }
footer { margin-top: 40px; }
@media (max-width: 640px) { main { padding: 24px 18px; } .intro { align-items: flex-start; flex-direction: column; } .checks { grid-template-columns: 1fr; } .card { padding: 18px; } }
</style>
