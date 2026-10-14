<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->
<script setup>
import { ref, watch } from 'vue'
import { historyRowLabel } from '../utils/deployments.js'

const props = defineProps({ appId: { type: String, required: true }, fetch: { type: Function, required: true }, refreshKey: { type: Number, default: 0 } })
const open = ref(false)
const entries = ref([])
const next = ref(null) // { before_at, before_id } of the last entry shown
const error = ref('')
const loaded = ref(false) // the empty notice waits for a first answer

// Each request carries a token; a result is dropped once a newer load or an app change superseded it.
let token = 0
async function load(cursor = null) {
  const mine = ++token
  const appId = props.appId
  error.value = ''
  // The cursor is `{ before_at, before_id }`: both fields or neither (the API answers 400 to one alone).
  const query = new URLSearchParams({ limit: '20', ...(cursor || {}) })
  const response = await props.fetch(`/api/resources/${appId}/history?${query}`).catch(() => null)
  if (mine !== token) return
  if (!response?.ok) { error.value = 'History is unavailable.'; return }
  const page = await response.json().catch(() => null)
  if (mine !== token) return
  if (!page) { error.value = 'History is unavailable.'; return }
  entries.value = cursor ? [...entries.value, ...page.entries] : page.entries
  next.value = page.next
  loaded.value = true
}
watch(() => [props.appId, props.refreshKey, open.value], () => {
  // A new app or a refresh starts over: nothing of the old list or cursor may survive.
  token++
  entries.value = []
  next.value = null
  error.value = ''
  loaded.value = false
  if (open.value) load()
})
</script>

<template>
  <details class="app-history" @toggle="open = $event.target.open">
    <summary>History</summary>
    <p v-if="error" role="status">{{ error }}</p>
    <p v-else-if="loaded && entries.length === 0" class="app-detail-helper-text">No switches, destructions or failed attempts yet.</p>
    <ul>
      <li v-for="entry in entries" :key="entry.id">
        <details>
          <summary>{{ new Date(entry.at).toLocaleString() }} · {{ historyRowLabel(entry) }}</summary>
          <dl class="history-details">
            <template v-if="entry.actor || entry.auth_method"><dt>Actor</dt><dd>{{ entry.actor || 'deleted user' }} ({{ entry.auth_method || 'unknown' }})</dd></template>
            <template v-if="!entry.actor && !entry.auth_method && entry.kind === 'operation'"><dt>Observed by</dt><dd>Reconciliation</dd></template>
            <template v-if="entry.previous_deployment_id"><dt>Previous</dt><dd><code>{{ entry.previous_deployment_id }}</code></dd></template>
            <template v-if="entry.target_deployment_id"><dt>Target</dt><dd><code>{{ entry.target_deployment_id }}</code></dd></template>
            <template v-if="entry.commit_sha"><dt>Commit</dt><dd><code>{{ entry.commit_sha }}</code> {{ entry.commit_subject || '' }}</dd></template>
            <template v-if="entry.signed_request_id"><dt>Passkey proof</dt><dd><code>{{ entry.signed_request_id }}</code> · HTTP {{ entry.signed_request_status ?? 'pending' }}</dd></template>
            <template v-if="entry.error"><dt>Error</dt><dd>{{ entry.error }}</dd></template>
          </dl>
        </details>
      </li>
    </ul>
    <button v-if="next" type="button" class="text-button" @click="load(next)">Show older</button>
  </details>
</template>
