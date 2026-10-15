<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->
<script setup>
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import CopyIconButton from './CopyIconButton.vue'
import { appHostname, candidateCountLabel, canDestroy, canSwitch, debugSwitchNotice, deploymentStateLabel, destroyCommand, destroyDeployment, isDebugDeployment, orderDeployments, relativeTime, roleLabel, shortId, shortSha, switchCommand, switchDeployment, switchRequestBody, verifyCommand } from '../utils/deployments.js'

const props = defineProps({
  app: { type: Object, required: true },
  deployments: { type: Array, required: true },
  sign: { type: Function, required: true },
  fetch: { type: Function, required: true },
})
const emit = defineEmits(['changed'])
const rows = computed(() => orderDeployments(props.deployments))
const selectedId = ref(null)
const selected = computed(() => rows.value.find((deployment) => deployment.id === selectedId.value) || null)
const live = computed(() => rows.value.find((deployment) => deployment.role === 'live') || null)
const roleOf = (deployment) => roleLabel(deployment, live.value !== null)
// A lost live deployment has no address: AWS released it.
const endpointOf = (deployment) => deployment.public_ip || (deployment.failure_kind === 'runtime_lost' ? 'unavailable' : '—')
watch(rows, (current) => { if (selectedId.value && !current.some((d) => d.id === selectedId.value)) selectedId.value = null })
const formatTime = (value) => (value ? new Date(value).toLocaleString() : '—')
const commitLine = (deployment) => [deployment.commit_subject, shortSha(deployment.commit_sha)].filter(Boolean).join(' · ')
const appLine = computed(() => `${props.app.resource_name || props.app.id} · ${appHostname(props.app)}`)

// The inspector is a drawer over the page: opening moves focus into it. Escape
// leaves a confirmation first, then closes the drawer; never while a request runs.
const drawer = ref(null)
const closeInspector = () => { selectedId.value = null }
const onKeydown = (event) => {
  if (event.key !== 'Escape' || !selectedId.value || busy.value) return
  if (confirming.value) cancelConfirm()
  else closeInspector()
}
watch(selectedId, async (id) => {
  if (id) { document.addEventListener('keydown', onKeydown); await nextTick(); drawer.value?.focus() }
  else document.removeEventListener('keydown', onKeydown)
})
onBeforeUnmount(() => document.removeEventListener('keydown', onKeydown))
// The three moments of a deployment, in order; a dot is filled once it happened.
const milestones = (deployment) => [
  { label: 'Created', at: deployment.created_at },
  { label: 'Running', at: deployment.running_at },
  { label: 'Live', at: deployment.activated_at },
]

const confirming = ref(null) // 'switch' | 'destroy'
const acknowledged = ref(false)
const tlsAcknowledged = ref(false)
const busy = ref(false)
const outcome = ref(null) // { kind, message }
// The live deployment the operator saw when the confirmation opened. It is what
// the dialog shows and what the signed body expects, so a switch by someone else
// meanwhile comes back as the API's stale 409 instead of being accepted.
const pinnedLiveId = ref(null)
const pinnedLive = computed(() => rows.value.find((deployment) => deployment.id === pinnedLiveId.value) || null)
// Selecting another deployment cancels an open confirmation. The last outcome
// stays visible until the next action starts, even when a refresh removes the
// deployment it was about (a destroyed one closes the inspector).
watch(selectedId, () => { confirming.value = null; acknowledged.value = false; tlsAcknowledged.value = false })
// Every confirmation starts unticked, including after a stale, cancelled or failed attempt.
function startConfirm(kind) { outcome.value = null; pinnedLiveId.value = props.app.live_deployment_id ?? null; acknowledged.value = false; tlsAcknowledged.value = false; confirming.value = kind }
function cancelConfirm() { confirming.value = null; acknowledged.value = false; tlsAcknowledged.value = false }
// A confirmation replaces the drawer's content: it, and the details it returns to, start at the top with focus in the drawer.
watch(confirming, async () => {
  await nextTick()
  if (drawer.value) { drawer.value.scrollTop = 0; drawer.value.focus() }
})

async function confirmSwitch() {
  const target = selected.value
  busy.value = true
  // `expected_live_deployment_id` is the live deployment the dialog showed (the app's `live_deployment_id` when it opened), as in the CLI.
  const result = await switchDeployment({ sign: props.sign, fetch: props.fetch, appId: props.app.id, deploymentId: target.id, body: switchRequestBody(pinnedLiveId.value, target) })
  busy.value = false
  confirming.value = null
  outcome.value = result.outcome === 'switched'
    ? { kind: 'success', message: `${shortId(target.id)} is live at ${result.data.stable_ip}. The previous deployment keeps running and billing.${result.data.tls_after_switch ? ` Verify TLS once the certificate is issued: ${verifyCommand(target)}` : ''}` }
    : { kind: result.outcome, message: result.message }
  if (result.outcome !== 'cancelled') emit('changed') // refresh roles, endpoints and history from the API
}

async function confirmDestroy() {
  const target = selected.value
  busy.value = true
  const result = await destroyDeployment({ fetch: props.fetch, appId: props.app.id, deploymentId: target.id })
  busy.value = false
  confirming.value = null
  outcome.value = result.outcome === 'destroyed'
    ? { kind: 'success', message: `${shortId(target.id)} was destroyed.` }
    : { kind: result.outcome, message: result.message }
  emit('changed')
}
</script>

<template>
  <section class="app-deployments" aria-labelledby="deployments-title">
    <header class="app-deployments-header">
      <h3 id="deployments-title" class="app-detail-section-title">Deployments</h3>
      <p class="app-detail-helper-text">{{ candidateCountLabel(app) }} candidates</p>
      <button type="button" class="text-button app-deployments-refresh" @click="emit('changed')">Refresh</button>
    </header>
    <!-- While the drawer is open, the outcome shows at its top instead: the backdrop would hide this one. -->
    <p v-if="outcome && !selected" :class="['deployment-outcome', `deployment-outcome--${outcome.kind}`]" role="status">{{ outcome.message }}</p>

    <p v-if="rows.length === 0" class="deployment-list-empty">No live deployment. Push to deploy.</p>
    <ul v-else class="deployment-list" aria-label="Deployments">
      <li v-for="deployment in rows" :key="deployment.id" :data-deployment="shortId(deployment.id)" :data-role="roleOf(deployment)" :class="['deployment-row', { 'is-live': deployment.role === 'live', 'is-selected': deployment.id === selectedId }]">
        <button type="button" class="deployment-row-button" :aria-label="`Inspect deployment ${shortId(deployment.id)}`" @click="selectedId = deployment.id">
          <span class="deployment-row-text">
            <span class="deployment-row-title">{{ deployment.commit_subject || shortSha(deployment.commit_sha) }}</span>
            <span class="deployment-row-meta">
              <code>{{ shortId(deployment.id) }}</code> · <code>{{ shortSha(deployment.commit_sha) }}</code> · {{ deployment.pushed_ref || 'unknown ref' }}
              <span v-if="deployment.error" class="deployment-row-error"> · {{ deployment.error }}</span>
            </span>
          </span>
          <span :class="['deployment-role', `deployment-role--${roleOf(deployment).toLowerCase()}`]">{{ roleOf(deployment) }}</span>
          <span class="deployment-row-state">
            <span :class="['app-status-badge', 'deployment-badge', `status-${deployment.status}`]">{{ deploymentStateLabel(deployment) }}</span>
            <span v-if="isDebugDeployment(deployment)" class="deployment-debug">debug</span>
          </span>
          <time class="deployment-row-time" :datetime="deployment.created_at" :title="formatTime(deployment.created_at)">{{ relativeTime(deployment.created_at) }}</time>
          <span class="deployment-row-chevron" aria-hidden="true">›</span>
        </button>
      </li>
    </ul>

    <div v-if="selected" class="deployment-drawer-backdrop" @click="busy || closeInspector()"></div>
    <aside v-if="selected" ref="drawer" :class="['deployment-inspector', { 'is-confirming': confirming }]" tabindex="-1" :aria-label="`Deployment ${shortId(selected.id)}`">
      <!-- A confirmation is a step of its own: it replaces the details until approved, cancelled or left with Back. -->
      <header v-if="confirming" class="deployment-inspector-header deployment-step-header">
        <button type="button" class="deployment-drawer-icon" aria-label="Back" :disabled="busy" @click="cancelConfirm">←</button>
        <h4>{{ confirming === 'switch' ? 'Switch live' : 'Destroy deployment' }}</h4>
        <button type="button" class="deployment-drawer-icon deployment-drawer-close" aria-label="Close" :disabled="busy" @click="closeInspector">×</button>
      </header>
      <header v-else class="deployment-inspector-header">
        <div class="deployment-inspector-heading">
          <h4>Deployment <code>{{ shortId(selected.id) }}</code></h4>
          <span :class="['app-status-badge', 'deployment-badge', `status-${selected.status}`]">{{ deploymentStateLabel(selected) }}</span>
          <span :class="['deployment-role', `deployment-role--${roleOf(selected).toLowerCase()}`]">{{ roleOf(selected) }}</span>
        </div>
        <button type="button" class="deployment-drawer-icon deployment-drawer-close" aria-label="Close" :disabled="busy" @click="closeInspector">×</button>
      </header>
      <p v-if="outcome" :class="['deployment-outcome', `deployment-outcome--${outcome.kind}`]" role="status">{{ outcome.message }}</p>

      <form v-if="confirming === 'switch'" class="deployment-confirm" @submit.prevent="confirmSwitch">
        <div class="deployment-confirm-body">
          <div class="deployment-transition">
            <div class="deployment-card" role="group" aria-label="From">
              <template v-if="pinnedLiveId">
                <code class="deployment-card-id">{{ shortId(pinnedLiveId) }}</code>
                <span v-if="pinnedLive" class="deployment-card-meta" :title="commitLine(pinnedLive)">{{ commitLine(pinnedLive) }}</span>
                <span class="deployment-card-pills"><span class="deployment-pill deployment-pill--live">Live now</span></span>
              </template>
              <span v-else class="deployment-card-empty">No live deployment</span>
            </div>
            <span class="deployment-transition-arrow" aria-hidden="true">→</span>
            <div class="deployment-card deployment-card--target" role="group" aria-label="To">
              <code class="deployment-card-id">{{ shortId(selected.id) }}</code>
              <span class="deployment-card-meta" :title="commitLine(selected)">{{ commitLine(selected) }}</span>
              <span class="deployment-card-pills">
                <span class="deployment-pill">{{ deploymentStateLabel(selected) }}</span>
                <span v-if="isDebugDeployment(selected)" class="deployment-pill deployment-pill--debug">Debug mode</span>
              </span>
            </div>
          </div>

          <div class="deployment-confirm-summary">
            <p>Stable IP <code>{{ app.public_ip || 'unassigned' }}</code> moves to <code>{{ shortId(selected.id) }}</code>.</p>
            <p class="deployment-confirm-app" :title="appLine">{{ appLine }}</p>
          </div>

          <p v-if="debugSwitchNotice(selected)" class="deployment-callout deployment-callout--danger" role="note">{{ debugSwitchNotice(selected) }}</p>
          <p v-if="selected.tls_after_switch" class="deployment-callout deployment-callout--warning" role="note">This deployment obtains its TLS certificate only while it is live. Verify TLS once it is live and the certificate is issued.</p>
          <p class="deployment-confirm-info"><span aria-hidden="true">ⓘ</span><span><template v-if="pinnedLiveId">{{ shortId(pinnedLiveId) }} keeps running and billing. </template>Open connections may drop during cutover.</span></p>

          <div class="deployment-checks">
            <label class="deployment-check"><input v-model="acknowledged" type="checkbox" /><span>I verified and tested <code>{{ shortId(selected.id) }}</code>.</span></label>
            <label v-if="selected.tls_after_switch" class="deployment-check"><input v-model="tlsAcknowledged" type="checkbox" /><span>Application TLS verification is pending; I will verify after switching.</span></label>
          </div>

          <details class="deployment-cli app-detail-disclosure">
            <summary>CLI equivalent</summary>
            <div class="app-detail-command"><code>{{ switchCommand(selected) }}</code><CopyIconButton :value="switchCommand(selected)" label="switch command" /></div>
          </details>
        </div>
        <div class="deployment-confirm-footer">
          <button type="button" class="btn-secondary" :disabled="busy" @click="cancelConfirm">Cancel</button>
          <button type="submit" class="btn-primary" :disabled="busy || !acknowledged || (selected.tls_after_switch && !tlsAcknowledged)">{{ busy ? 'Waiting for passkey…' : 'Approve with passkey' }}</button>
        </div>
      </form>

      <form v-else-if="confirming === 'destroy'" class="deployment-confirm" @submit.prevent="confirmDestroy">
        <div class="deployment-confirm-body">
          <div class="deployment-card" role="group" aria-label="Deployment">
            <code class="deployment-card-id">{{ shortId(selected.id) }}</code>
            <span class="deployment-card-meta" :title="commitLine(selected)">{{ commitLine(selected) }}</span>
            <span class="deployment-card-pills"><span class="deployment-pill">{{ deploymentStateLabel(selected) }}</span></span>
          </div>

          <p class="deployment-callout deployment-callout--danger" role="note"><code>{{ shortId(selected.id) }}</code> · <code>{{ shortSha(selected.commit_sha) }}</code> and its instance will be destroyed.</p>
          <p v-if="live" class="deployment-confirm-info"><span aria-hidden="true">ⓘ</span><span>Live deployment {{ shortId(live.id) }} keeps serving.</span></p>
          <p v-else class="deployment-callout deployment-callout--warning" role="note">No deployment is live; the app stays unavailable.</p>
          <p class="deployment-confirm-app" :title="appLine">{{ appLine }}</p>

          <details class="deployment-cli app-detail-disclosure">
            <summary>CLI equivalent</summary>
            <div class="app-detail-command"><code>{{ destroyCommand(selected) }}</code><CopyIconButton :value="destroyCommand(selected)" label="destroy command" /></div>
          </details>
        </div>
        <div class="deployment-confirm-footer">
          <button type="button" class="btn-secondary" :disabled="busy" @click="cancelConfirm">Cancel</button>
          <button type="submit" class="btn-danger" :disabled="busy">{{ busy ? 'Destroying…' : 'Destroy deployment' }}</button>
        </div>
      </form>

      <template v-else>
        <p class="deployment-inspector-title">{{ selected.commit_subject || 'No commit subject' }}</p>
        <p class="deployment-inspector-meta"><code>{{ shortSha(selected.commit_sha) }}</code> · {{ selected.pushed_ref || 'unknown ref' }}</p>

        <div class="deployment-actions">
          <button v-if="canSwitch(app, selected)" type="button" class="btn-primary" :disabled="busy" @click="startConfirm('switch')">Switch live</button>
          <button v-if="canDestroy(app, selected)" type="button" class="btn-danger" :disabled="busy" @click="startConfirm('destroy')">Destroy deployment</button>
          <p v-if="selected.role === 'live'" class="deployment-note">The live deployment cannot be destroyed. Switch to another deployment first.</p>
        </div>

        <p v-if="selected.error" class="deployment-error-callout" role="note">{{ selected.error }}</p>

        <dl class="deployment-inspector-grid">
          <div class="deployment-inspector-item"><dt>Endpoint</dt><dd>{{ endpointOf(selected) }}<CopyIconButton v-if="selected.public_ip" :value="selected.public_ip" label="endpoint" /></dd></div>
          <div class="deployment-inspector-item"><dt>Instance</dt><dd>{{ selected.instance_id || '—' }} · {{ selected.instance_type || 'unknown' }}</dd></div>
          <div class="deployment-inspector-item"><dt>ID</dt><dd :title="selected.id">{{ shortId(selected.id) }}…<CopyIconButton :value="selected.id" label="deployment ID" /></dd></div>
          <div class="deployment-inspector-item"><dt>Commit</dt><dd :title="selected.commit_sha || ''">{{ shortSha(selected.commit_sha) }}<CopyIconButton v-if="selected.commit_sha" :value="selected.commit_sha" label="commit" /></dd></div>
          <div v-if="isDebugDeployment(selected)" class="deployment-inspector-item"><dt>Debug mode</dt><dd class="deployment-debug">Enabled</dd></div>
          <div v-if="selected.cleanup" class="deployment-inspector-item"><dt>Cleanup</dt><dd>{{ selected.cleanup === 'done' ? 'Done' : 'Pending' }}</dd></div>
        </dl>

        <ol class="deployment-milestones" aria-label="Timeline">
          <li v-for="step in milestones(selected)" :key="step.label" :class="{ 'is-done': step.at }">
            <span class="deployment-milestone-label">{{ step.label }}</span>
            <time v-if="step.at" :datetime="step.at" :title="formatTime(step.at)">{{ relativeTime(step.at) }}</time>
            <span v-else class="deployment-milestone-pending">—</span>
          </li>
        </ol>

        <h5 class="deployment-verify-title">Verify before switching</h5>
        <div class="app-detail-command">
          <code>{{ verifyCommand(selected) }}</code>
          <CopyIconButton :value="verifyCommand(selected)" label="verification command" />
        </div>
        <p v-if="selected.tls_after_switch" class="deployment-note">This deployment obtains its TLS certificate only while it is live. Verify TLS once it is live and the certificate is issued.</p>
        <p class="deployment-note">Running means the host and attestation respond. Verify, unlock and test the deployment yourself before switching.</p>
      </template>
    </aside>
  </section>
</template>

<style scoped>
.app-deployments-header { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.app-deployments-refresh { margin-left: auto; }
.text-button { border: 0; background: none; padding: 0; color: var(--theme-accent); cursor: pointer; }
.deployment-list-empty { padding: 32px; border: 1px dashed var(--theme-border); border-radius: 12px; color: var(--theme-text-muted); text-align: center; }

/* Callouts: a tinted box with a bar in the text colour. An action's outcome is one too. */
.deployment-callout, .deployment-outcome { margin: 0; padding: 11px 14px; border-left: 3px solid currentColor; border-radius: 10px; font-size: 0.9rem; line-height: 1.45; overflow-wrap: anywhere; }
.deployment-callout--danger, .deployment-outcome { background: var(--theme-danger-bg); color: var(--theme-danger); }
.deployment-callout--warning { background: var(--theme-warning-bg); color: var(--theme-warning); }
.deployment-outcome--success { background: var(--theme-success-bg); color: var(--theme-success); }
.deployment-outcome--cancelled { border-left-color: var(--theme-border-strong); background: var(--theme-surface-subtle); color: var(--theme-text-secondary); }
.app-deployments > .deployment-outcome { margin-top: 12px; }
.deployment-inspector > .deployment-outcome { margin-top: 18px; }
.deployment-callout code, .deployment-outcome code { font-size: 0.85rem; }

/* Deployments: one row each, the commit subject first. */
.deployment-list { list-style: none; margin: 12px 0 0; padding: 0; border: 1px solid var(--theme-border); border-radius: 12px; overflow: hidden; }
.deployment-row + .deployment-row { border-top: 1px solid var(--theme-border); }
.deployment-row-button { display: grid; grid-template-columns: minmax(0, 1fr) 7rem 9rem 7rem 1rem; align-items: center; gap: 16px; width: 100%; padding: 14px 18px; border: 0; border-left: 3px solid transparent; background: none; color: inherit; font: inherit; text-align: left; cursor: pointer; transition: background-color 0.15s ease; }
.deployment-row-button:hover, .deployment-row.is-selected .deployment-row-button { background: var(--theme-surface-subtle); }
.deployment-row-button:focus-visible { outline: 2px solid var(--theme-focus); outline-offset: -2px; }
.deployment-row.is-live .deployment-row-button { border-left-color: var(--theme-success); }
.deployment-row-text { display: flex; min-width: 0; flex-direction: column; gap: 3px; }
.deployment-row-title { overflow: hidden; color: var(--theme-text-primary); font-weight: 500; text-overflow: ellipsis; white-space: nowrap; }
.deployment-row-meta { overflow: hidden; color: var(--theme-text-muted); font-size: 0.85rem; text-overflow: ellipsis; white-space: nowrap; }
.deployment-row-meta code { font-size: 0.82rem; }
.deployment-row-error { color: var(--theme-danger); }
.deployment-row-state { display: inline-flex; align-items: center; gap: 6px; }
.deployment-row-time { color: var(--theme-text-muted); font-size: 0.85rem; text-align: right; white-space: nowrap; }
.deployment-row-chevron { color: var(--theme-text-faint); font-size: 1.2rem; }
@media (max-width: 760px) {
  .deployment-row-button { grid-template-columns: minmax(0, 1fr) auto; }
  .deployment-role, .deployment-row-time, .deployment-row-chevron { display: none; }
}

/* Pills */
.deployment-role, .deployment-pill { justify-self: start; padding: 2px 8px; border-radius: 999px; background: var(--theme-surface-muted); color: var(--theme-text-secondary); font-size: 0.75rem; font-weight: 600; letter-spacing: 0.04em; text-transform: uppercase; }
.deployment-role--live, .deployment-pill--live { background: var(--theme-success-bg); color: var(--theme-success); }
.deployment-pill--debug { background: var(--theme-danger-bg); color: var(--theme-danger); }
.deployment-badge { display: inline-flex; align-items: center; gap: 6px; padding: 3px 8px; font-size: 0.8rem; text-transform: none; letter-spacing: normal; white-space: nowrap; }
.deployment-badge::before { content: ''; width: 5px; height: 5px; border-radius: 50%; background: currentColor; }
.deployment-debug { color: var(--theme-danger); font-size: 0.8rem; font-weight: 600; }

/* The inspector: a drawer from the right; the page underneath does not move. */
.deployment-drawer-backdrop { position: fixed; inset: 0; z-index: 900; background: rgba(0, 0, 0, 0.5); }
.deployment-inspector { position: fixed; top: 0; right: 0; bottom: 0; z-index: 901; width: min(560px, 100vw); overflow-y: auto; padding: 28px; border-left: 1px solid var(--theme-border); background: var(--theme-surface); box-shadow: -12px 0 32px rgba(0, 0, 0, 0.25); animation: deployment-drawer-in 0.18s ease-out; }
.deployment-inspector:focus { outline: none; }
@keyframes deployment-drawer-in { from { transform: translateX(24px); opacity: 0; } to { transform: none; opacity: 1; } }
.deployment-inspector-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
.deployment-inspector-heading { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
.deployment-inspector-heading h4 { margin: 0; font-size: 1.05rem; font-weight: 600; }
.deployment-drawer-icon { display: inline-grid; flex-shrink: 0; place-items: center; width: 32px; height: 32px; margin: -4px; padding: 0; border: 0; border-radius: 8px; background: none; color: var(--theme-text-muted); font-size: 1.2rem; line-height: 1; cursor: pointer; transition: background-color 0.15s ease, color 0.15s ease; }
/* The × glyph sits high in its line box; this centres it on the title. */
.deployment-drawer-close { padding-top: 3px; font-size: 1.6rem; }
.deployment-drawer-icon:hover:not(:disabled) { background: var(--theme-surface-muted); color: var(--theme-text-primary); }
.deployment-drawer-icon:focus-visible { outline: 2px solid var(--theme-focus); }
.deployment-drawer-icon:disabled { opacity: 0.4; cursor: not-allowed; }
.deployment-inspector-title { margin: 18px 0 2px; color: var(--theme-text-primary); font-size: 1.15rem; font-weight: 500; }
.deployment-inspector-meta { margin: 0 0 18px; color: var(--theme-text-muted); }
.deployment-actions { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 20px; }
.deployment-actions .deployment-note { margin: 0; }
.deployment-error-callout { margin: 0 0 20px; padding: 12px 14px; border: 1px solid var(--theme-danger-border); border-radius: 8px; background: var(--theme-danger-bg); color: var(--theme-danger); font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace; font-size: 0.85rem; overflow-wrap: anywhere; }
.deployment-inspector-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px 24px; margin: 0 0 20px; }
.deployment-inspector-item { min-width: 0; }
.deployment-inspector-item dt { margin-bottom: 4px; color: var(--theme-text-muted); font-size: 0.75rem; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; }
.deployment-inspector-item dd { display: flex; align-items: center; gap: 6px; margin: 0; color: var(--theme-text-secondary); font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace; font-size: 0.9rem; overflow-wrap: anywhere; }
/* The value rule above would otherwise win over the debug warning colour. */
.deployment-inspector-item dd.deployment-debug { color: var(--theme-danger); }
.deployment-milestones { list-style: none; margin: 0 0 24px; padding: 0 0 0 4px; }
.deployment-milestones li { position: relative; display: flex; justify-content: space-between; padding: 0 0 12px 22px; color: var(--theme-text-muted); }
.deployment-milestones li::before { content: ''; position: absolute; top: 5px; left: 0; width: 9px; height: 9px; border: 2px solid var(--theme-border-strong); border-radius: 50%; background: var(--theme-surface); }
.deployment-milestones li:not(:last-child)::after { content: ''; position: absolute; top: 18px; bottom: 0; left: 5px; width: 1px; background: var(--theme-border); }
.deployment-milestones li.is-done::before { border-color: var(--theme-success); background: var(--theme-success); }
.deployment-milestone-label { color: var(--theme-text-secondary); }
.deployment-verify-title { margin: 0 0 4px; color: var(--theme-text-secondary); font-size: 0.85rem; font-weight: 600; }
.deployment-inspector .app-detail-command { margin-top: 6px; background: var(--theme-surface-subtle); }
/* Small enough that the full command fits the drawer on one line. */
.deployment-inspector .app-detail-command code { font-size: 0.78rem; }
.deployment-note { color: var(--theme-text-muted); font-size: 0.85rem; }

/* A confirmation fills the drawer: the step's content, then its buttons pinned to the bottom edge. */
.deployment-inspector.is-confirming { display: flex; flex-direction: column; padding-bottom: 0; }
.deployment-step-header { align-items: center; }
.deployment-step-header h4 { flex: 1; min-width: 0; margin: 0 0 0 8px; font-size: 1.05rem; font-weight: 600; }
.deployment-confirm { display: flex; flex: 1 0 auto; flex-direction: column; }
.deployment-confirm-body { display: flex; flex-direction: column; gap: 18px; padding: 24px 0 28px; }
.deployment-confirm-body p { margin: 0; }
.deployment-confirm code { font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace; }

.deployment-transition { display: grid; grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr); align-items: stretch; gap: 10px; }
.deployment-transition-arrow { align-self: center; color: var(--theme-text-faint); font-size: 1.15rem; }
.deployment-card { display: flex; min-width: 0; flex-direction: column; gap: 4px; padding: 14px 16px; border: 1px solid var(--theme-border); border-radius: 12px; background: var(--theme-surface-subtle); }
.deployment-card--target { border-color: var(--theme-border-strong); }
.deployment-card-id { color: var(--theme-text-primary); font-size: 1rem; font-weight: 600; }
.deployment-card-meta { overflow: hidden; color: var(--theme-text-muted); font-size: 0.85rem; text-overflow: ellipsis; white-space: nowrap; }
.deployment-card-pills { display: flex; flex-wrap: wrap; gap: 6px; margin-top: auto; padding-top: 6px; }
.deployment-card-pills .deployment-pill { font-size: 0.68rem; letter-spacing: 0.06em; }
.deployment-card-empty { margin: auto 0; color: var(--theme-text-muted); font-size: 0.9rem; }

.deployment-confirm-summary { display: flex; flex-direction: column; gap: 4px; }
.deployment-confirm-summary > p:first-child { color: var(--theme-text-primary); font-size: 0.95rem; }
.deployment-confirm-summary code { font-size: 0.9rem; font-weight: 600; }
.deployment-confirm-app { overflow: hidden; color: var(--theme-text-muted); font-size: 0.85rem; text-overflow: ellipsis; white-space: nowrap; }
.deployment-confirm-info { display: flex; gap: 8px; color: var(--theme-text-muted); font-size: 0.85rem; line-height: 1.45; }

.deployment-checks { display: flex; flex-direction: column; gap: 8px; }
.deployment-check { display: flex; align-items: flex-start; gap: 10px; padding: 12px 14px; border: 1px solid var(--theme-border); border-radius: 10px; color: var(--theme-text-secondary); font-size: 0.9rem; line-height: 1.4; cursor: pointer; transition: border-color 0.15s ease, background-color 0.15s ease; }
.deployment-check:hover { border-color: var(--theme-border-strong); }
.deployment-check:has(input:checked) { border-color: var(--theme-success-border); background: var(--theme-success-bg); }
.deployment-check input { flex-shrink: 0; width: 16px; height: 16px; margin: 1px 0 0; accent-color: var(--theme-success-strong); cursor: pointer; }
.deployment-check code { font-size: 0.85rem; font-weight: 600; }

.deployment-cli > summary { color: var(--theme-text-muted); font-size: 0.85rem; }
.deployment-cli > summary:hover { color: var(--theme-text-secondary); }
/* Tighter than the verify box: the longer switch and destroy commands still fit on one line. */
.deployment-cli .app-detail-command { gap: 10px; margin-top: 10px; padding: 10px 12px 10px 14px; }
.deployment-cli .app-detail-command code { font-size: 0.75rem; }

.deployment-confirm-footer { position: sticky; bottom: 0; display: flex; justify-content: flex-end; align-items: center; gap: 8px; margin: auto -28px 0; padding: 16px 28px 24px; border-top: 1px solid var(--theme-border); background: var(--theme-surface); }
.deployment-confirm-footer button { padding: 10px 18px; border: 1px solid transparent; border-radius: 8px; font-size: 0.95rem; }
.deployment-confirm-footer .btn-danger { border-color: var(--theme-danger-border); }
</style>
