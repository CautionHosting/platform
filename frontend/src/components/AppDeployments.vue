<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->
<script setup>
import { computed, ref, watch } from 'vue'
import CopyIconButton from './CopyIconButton.vue'
import { candidateCountLabel, deploymentStateLabel, orderDeployments, roleLabel, shortId, shortSha, verifyCommand } from '../utils/deployments.js'

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
</script>

<template>
  <section class="app-deployments" aria-labelledby="deployments-title">
    <header class="app-deployments-header">
      <h3 id="deployments-title" class="app-detail-section-title">Deployments</h3>
      <p class="app-detail-helper-text">{{ candidateCountLabel(app) }} candidates · Live first</p>
      <button type="button" class="text-button" @click="emit('changed')">Refresh</button>
    </header>
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
        <!-- Task 11: switch and destroy actions -->
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
.text-button { border: 0; background: none; padding: 0; color: var(--theme-accent); cursor: pointer; }
</style>
