<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->
<script setup>
import { computed, ref, watch } from 'vue'
import CopyIconButton from './CopyIconButton.vue'
import { historyEvent, relativeTime, shortId, shortSha } from '../utils/deployments.js'

const props = defineProps({ appId: { type: String, required: true }, fetch: { type: Function, required: true }, refreshKey: { type: Number, default: 0 } })
const entries = ref([])
const next = ref(null) // { before_at, before_id } of the last entry shown
const error = ref('')
const loaded = ref(false) // the empty notice waits for a first answer
// The timeline shows the latest few; "Show older" reveals the rest of the page, then fetches the next one.
const FIRST = 5
const shown = ref(FIRST)
const visible = computed(() => entries.value.slice(0, shown.value))
const hasOlder = computed(() => entries.value.length > shown.value || Boolean(next.value))
async function showOlder() {
  if (entries.value.length <= shown.value && next.value) await load(next.value)
  shown.value += 10
}
const expanded = ref(null)
const toggle = (id) => { expanded.value = expanded.value === id ? null : id }
const ICONS = { switch: '⇄', attempt: '↑', destroy: '×' }
const actorLabel = (entry) => {
  if (entry.actor || entry.auth_method) return `${entry.actor || 'deleted user'} · ${entry.auth_method || 'unknown'}`
  return entry.kind === 'operation' ? 'reconciliation' : ''
}
const formatTime = (value) => (value ? new Date(value).toLocaleString() : '—')

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
watch(() => [props.appId, props.refreshKey], () => {
  // A new app or a refresh starts over: nothing of the old list or cursor may survive.
  token++
  entries.value = []
  next.value = null
  error.value = ''
  loaded.value = false
  shown.value = FIRST
  expanded.value = null
  load()
}, { immediate: true })
</script>

<template>
  <section class="app-history" aria-labelledby="history-title">
    <h4 id="history-title" class="app-detail-subsection-title">History</h4>
    <p v-if="error" role="status" class="app-detail-helper-text">{{ error }}</p>
    <p v-else-if="loaded && entries.length === 0" class="app-detail-helper-text">No switches, destructions or failed attempts yet.</p>
    <ol v-if="visible.length" class="history-timeline">
      <li v-for="entry in visible" :key="entry.id" :class="['history-event', `history-event--${historyEvent(entry).tone}`]">
        <span class="history-icon" aria-hidden="true">{{ ICONS[historyEvent(entry).kind] }}</span>
        <div class="history-body">
          <button type="button" class="history-row" :aria-expanded="expanded === entry.id ? 'true' : 'false'" @click="toggle(entry.id)">
            <span class="history-title">{{ historyEvent(entry).title }}</span>
            <span :class="['history-outcome', `history-outcome--${historyEvent(entry).tone}`]">{{ historyEvent(entry).outcome }}</span>
            <span v-if="entry.commit_subject" class="history-subject">{{ entry.commit_subject }}</span>
            <span class="history-actor">{{ actorLabel(entry) }}</span>
            <time class="history-time" :datetime="entry.at" :title="formatTime(entry.at)">{{ relativeTime(entry.at) }}</time>
          </button>
          <dl v-if="expanded === entry.id" class="history-details">
            <div><dt>When</dt><dd>{{ formatTime(entry.at) }}</dd></div>
            <div v-if="actorLabel(entry)"><dt>By</dt><dd>{{ actorLabel(entry) }}</dd></div>
            <div v-if="entry.previous_deployment_id"><dt>Previous</dt><dd>{{ shortId(entry.previous_deployment_id) }}<CopyIconButton :value="entry.previous_deployment_id" label="previous deployment ID" /></dd></div>
            <div v-if="entry.target_deployment_id"><dt>Target</dt><dd>{{ shortId(entry.target_deployment_id) }}<CopyIconButton :value="entry.target_deployment_id" label="target deployment ID" /></dd></div>
            <div v-if="entry.commit_sha"><dt>Commit</dt><dd>{{ shortSha(entry.commit_sha) }}<CopyIconButton :value="entry.commit_sha" label="commit" /></dd></div>
            <div v-if="entry.signed_request_id"><dt>Passkey proof</dt><dd>{{ shortId(entry.signed_request_id) }}<CopyIconButton :value="entry.signed_request_id" label="passkey proof ID" /> · HTTP {{ entry.signed_request_status ?? 'pending' }}</dd></div>
            <div v-if="entry.error" class="history-details-wide"><dt>Error</dt><dd class="history-error">{{ entry.error }}</dd></div>
          </dl>
        </div>
      </li>
    </ol>
    <button v-if="hasOlder" type="button" class="text-button history-older" @click="showOlder">Show older</button>
  </section>
</template>

<style scoped>
.app-history { margin: 28px 0 8px; }
.history-timeline { position: relative; margin: 10px 0 0; padding: 0; list-style: none; }
.history-event { position: relative; display: grid; grid-template-columns: 28px minmax(0, 1fr); gap: 12px; padding-bottom: 6px; }
.history-event:not(:last-child)::after { content: ''; position: absolute; top: 30px; bottom: 0; left: 13px; width: 1px; background: var(--theme-border); }
.history-icon { display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; margin-top: 6px; border-radius: 50%; background: var(--theme-surface-muted); color: var(--theme-text-secondary); font-size: 0.9rem; }
.history-event--success .history-icon { background: var(--theme-success-bg); color: var(--theme-success); }
.history-event--danger .history-icon { background: var(--theme-danger-bg); color: var(--theme-danger); }
.history-event--pending .history-icon { background: var(--theme-warning-bg); color: var(--theme-warning); }
.history-body { min-width: 0; }
.history-row { display: flex; align-items: baseline; flex-wrap: wrap; gap: 4px 10px; width: 100%; padding: 8px 10px; border: 0; border-radius: 8px; background: none; color: inherit; font: inherit; text-align: left; cursor: pointer; }
.history-row:hover, .history-row[aria-expanded='true'] { background: var(--theme-surface-subtle); }
.history-row:focus-visible { outline: 2px solid var(--theme-focus); }
.history-title { color: var(--theme-text-primary); font-weight: 500; font-variant-numeric: tabular-nums; }
.history-outcome { padding: 1px 8px; border-radius: 999px; background: var(--theme-surface-muted); color: var(--theme-text-secondary); font-size: 0.75rem; font-weight: 600; }
.history-outcome--success { background: var(--theme-success-bg); color: var(--theme-success); }
.history-outcome--danger { background: var(--theme-danger-bg); color: var(--theme-danger); }
.history-outcome--pending { background: var(--theme-warning-bg); color: var(--theme-warning); }
.history-subject { color: var(--theme-text-muted); }
.history-actor { margin-left: auto; color: var(--theme-text-muted); font-size: 0.85rem; }
.history-time { min-width: 5.5rem; color: var(--theme-text-muted); font-size: 0.85rem; text-align: right; }
.history-details { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px 20px; margin: 4px 10px 10px; padding: 12px 14px; border-radius: 8px; background: var(--theme-surface-subtle); }
.history-details dt { margin-bottom: 2px; color: var(--theme-text-muted); font-size: 0.72rem; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; }
.history-details dd { display: flex; align-items: center; gap: 6px; margin: 0; color: var(--theme-text-secondary); font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace; font-size: 0.85rem; overflow-wrap: anywhere; }
.history-details-wide { grid-column: 1 / -1; }
.history-error { color: var(--theme-danger); }
.history-older { margin: 8px 0 0 40px; }
.text-button { border: 0; background: none; padding: 0; color: var(--theme-accent); cursor: pointer; }
</style>
