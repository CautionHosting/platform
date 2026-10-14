<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->
<script setup>
import { computed, ref, watch } from 'vue'
import CopyIconButton from './CopyIconButton.vue'
import { appHostname, candidateCountLabel, canDestroy, canSwitch, deploymentStateLabel, destroyCommand, destroyDeployment, orderDeployments, roleLabel, shortId, shortSha, switchCommand, switchDeployment, switchRequestBody, verifyCommand } from '../utils/deployments.js'

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
      <p class="app-detail-helper-text">{{ candidateCountLabel(app) }} candidates · Live first</p>
      <button type="button" class="text-button" @click="emit('changed')">Refresh</button>
    </header>
    <p v-if="outcome" :class="['deployment-outcome', `deployment-outcome--${outcome.kind}`]" role="status">{{ outcome.message }}</p>
    <div :class="['app-deployments-layout', { 'app-deployments-layout--inspecting': selected }]">
      <table class="apps-table deployments-table" aria-label="Deployments">
        <thead><tr><th scope="col">Deployment</th><th scope="col">Commit</th><th scope="col">Ref</th><th scope="col">Role</th><th scope="col">State</th><th scope="col">Created</th></tr></thead>
        <tbody>
          <tr v-if="rows.length === 0"><td colspan="6" class="apps-table-empty">No live deployment. Push to deploy.</td></tr>
          <tr v-for="deployment in rows" :key="deployment.id" :class="['apps-table-row', { 'is-selected': deployment.id === selectedId }]" @click="selectedId = deployment.id">
            <td><button type="button" class="app-name-text" :aria-label="`Inspect deployment ${shortId(deployment.id)}`" @click.stop="selectedId = deployment.id"><code>{{ shortId(deployment.id) }}</code></button></td>
            <td><code>{{ shortSha(deployment.commit_sha) }}</code><span v-if="deployment.commit_subject" class="deployment-subject">{{ deployment.commit_subject }}</span></td>
            <td>{{ deployment.pushed_ref || 'unknown' }}</td>
            <td>{{ roleOf(deployment) }}</td>
            <td><span :class="['app-status-badge', `status-${deployment.status}`]">{{ deploymentStateLabel(deployment) }}</span></td>
            <td>{{ formatTime(deployment.created_at) }}</td>
          </tr>
        </tbody>
      </table>
      <aside v-if="selected" class="deployment-inspector" :aria-label="`Deployment ${shortId(selected.id)}`">
        <header><h4>Deployment <code>{{ shortId(selected.id) }}</code></h4><button type="button" class="text-button" @click="selectedId = null">Close</button></header>
        <p v-if="selected.commit_subject" class="deployment-subject">{{ selected.commit_subject }}</p>
        <dl class="deployment-inspector-grid">
          <dt>ID</dt><dd><code>{{ selected.id }}</code> <CopyIconButton :value="selected.id" label="deployment ID" /></dd>
          <dt>Commit</dt><dd><code>{{ selected.commit_sha || 'unknown' }}</code></dd>
          <dt>Pushed ref</dt><dd>{{ selected.pushed_ref || 'unknown' }}</dd>
          <dt>Role</dt><dd>{{ roleOf(selected) }}</dd>
          <dt>State</dt><dd>{{ deploymentStateLabel(selected) }}</dd>
          <dt>Endpoint</dt><dd>{{ endpointOf(selected) }}</dd>
          <dt>Instance</dt><dd>{{ selected.instance_id || '—' }} · {{ selected.instance_type || 'unknown' }}</dd>
          <template v-if="selected.cleanup"><dt>Cleanup</dt><dd>{{ selected.cleanup === 'done' ? 'Done' : 'Pending' }}</dd></template>
          <dt>Created</dt><dd>{{ formatTime(selected.created_at) }}</dd>
          <dt>Running since</dt><dd>{{ formatTime(selected.running_at) }}</dd>
          <dt>Became live</dt><dd>{{ formatTime(selected.activated_at) }}</dd>
          <template v-if="selected.error"><dt>Error</dt><dd class="deployment-error">{{ selected.error }}</dd></template>
        </dl>
        <p v-if="selected.tls_after_switch" class="deployment-note">This deployment obtains its TLS certificate only while it is live. Verify TLS once it is live and the certificate is issued.</p>
        <div class="app-detail-command">
          <code>{{ verifyCommand(selected) }}</code>
          <CopyIconButton :value="verifyCommand(selected)" label="verification command" />
        </div>
        <p class="deployment-note">Running means the host and attestation respond. Verify, unlock and test the deployment yourself before switching.</p>
        <div v-if="!confirming" class="deployment-actions">
          <button v-if="canSwitch(app, selected)" type="button" class="btn-primary" :disabled="busy" @click="startConfirm('switch')">Switch live</button>
          <button v-if="canDestroy(app, selected)" type="button" class="btn-danger" :disabled="busy" @click="startConfirm('destroy')">Destroy deployment</button>
          <p v-if="selected.role === 'live'" class="deployment-note">The live deployment cannot be destroyed. Switch to another deployment first.</p>
        </div>
        <form v-if="confirming === 'switch'" class="deployment-confirm" @submit.prevent="confirmSwitch">
          <h5>Switch live to {{ shortId(selected.id) }}</h5>
          <ul>
            <li>App: {{ app.resource_name || app.id }} · {{ appHostname(app) }}</li>
            <li>Current live: <template v-if="pinnedLiveId">{{ shortId(pinnedLiveId) }}<template v-if="pinnedLive"> · {{ shortSha(pinnedLive.commit_sha) }}</template></template><template v-else>No live deployment</template></li>
            <li>Target: {{ shortId(selected.id) }} · {{ shortSha(selected.commit_sha) }}</li>
            <li>Stable IP: {{ app.public_ip || 'unassigned' }}</li>
            <li>The previous deployment stays running and billable. Connections may close during cutover.</li>
          </ul>
          <label><input v-model="acknowledged" type="checkbox" /> I verified and tested this deployment.</label>
          <label v-if="selected.tls_after_switch"><input v-model="tlsAcknowledged" type="checkbox" /> Application TLS verification is pending; I will verify after switching.</label>
          <p class="deployment-note">CLI: <code>{{ switchCommand(selected) }}</code></p>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" :disabled="busy" @click="cancelConfirm">Cancel</button>
            <button type="submit" class="btn-primary" :disabled="busy || !acknowledged || (selected.tls_after_switch && !tlsAcknowledged)">{{ busy ? 'Waiting for passkey…' : 'Approve with passkey' }}</button>
          </div>
        </form>
        <form v-if="confirming === 'destroy'" class="deployment-confirm" @submit.prevent="confirmDestroy">
          <h5>Destroy deployment {{ shortId(selected.id) }}</h5>
          <p>{{ app.resource_name || app.id }} · {{ appHostname(app) }}</p>
          <p>{{ shortId(selected.id) }} · {{ shortSha(selected.commit_sha) }} and its instance will be destroyed. <template v-if="live">Live deployment {{ shortId(live.id) }} keeps serving.</template><template v-else>No deployment is live; the app stays unavailable.</template></p>
          <p class="deployment-note">CLI: <code>{{ destroyCommand(selected) }}</code></p>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" :disabled="busy" @click="cancelConfirm">Cancel</button>
            <button type="submit" class="btn-danger" :disabled="busy">{{ busy ? 'Destroying…' : 'Destroy deployment' }}</button>
          </div>
        </form>
      </aside>
    </div>
  </section>
</template>

<style scoped>
.app-deployments-layout { display: grid; gap: 16px; }
@media (min-width: 1035px) { .app-deployments-layout--inspecting { grid-template-columns: minmax(0, 1fr) 360px; } }
.deployment-inspector { border: 1px solid var(--theme-border); border-radius: 8px; padding: 16px; background: var(--theme-surface); }
.deployment-inspector header { display: flex; justify-content: space-between; align-items: center; }
.deployment-inspector-grid { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 6px 12px; overflow-wrap: anywhere; }
.deployment-subject { display: block; color: var(--theme-text-secondary); }
.deployment-note { color: var(--theme-text-secondary); font-size: 0.875rem; }
.deployment-error { color: var(--theme-danger, #b42318); }
/* Without this the narrow column wraps badge text. */
.deployments-table .app-status-badge { white-space: nowrap; }
tr.is-selected { background: var(--theme-surface-subtle); }
.app-deployments-header { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.deployment-actions, .modal-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.deployment-confirm { border-top: 1px solid var(--theme-border); margin-top: 12px; padding-top: 12px; }
.deployment-outcome { color: var(--theme-danger); }
.deployment-outcome--success { color: var(--theme-success); }
.text-button { border: 0; background: none; padding: 0; color: var(--theme-accent); cursor: pointer; }
</style>
