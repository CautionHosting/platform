<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->
<template>
  <div class="policy-set" :data-set-index="set.index" :data-accepted="set.accepted">
    <p class="set-title"><strong>{{ set.accepted ? 'Accepted' : 'Approved' }} set {{ set.index + 1 }}</strong><span> · {{ cutoff }}</span></p>
    <table class="comparison"><caption class="sr-only">{{ purpose }} approved set {{ set.index + 1 }} comparison</caption>
      <thead><tr><th scope="col">PCR</th><th v-if="authenticated" scope="col">Observed</th><th scope="col">Allowed</th></tr></thead>
      <tbody><tr v-for="row in policyRows(set, measurements)" :key="row.index">
        <th scope="row">PCR{{ row.index }}<small v-if="authenticated" :class="{ invalid: row.comparison === 'Missing or invalid' || failed && row.comparison === 'Different value' }">{{ row.comparison }}</small></th>
        <td v-if="authenticated"><CopyValue :value="row.observed" :full="full" :label="`${serviceName} observed PCR${row.index}`" @copy="(value, label) => $emit('copy', value, label)" /></td>
        <td><CopyValue :value="row.allowed" :full="full" :label="`${serviceName} ${purpose} set ${set.index + 1} allowed PCR${row.index}`" @copy="(value, label) => $emit('copy', value, label)" /></td>
      </tr></tbody>
    </table>
  </div>
</template>
<script setup>
import { computed } from 'vue'
import CopyValue from './CopyValue.vue'
import { policyRows } from '../utils/components.js'
const props = defineProps({ set: { type: Object, required: true }, measurements: Object, serviceName: String, purpose: String, authenticated: Boolean, full: Boolean, failed: Boolean })
defineEmits(['copy'])
const cutoff = computed(() => {
  if (props.set.expires_at_unix_seconds == null) return 'No expiry'
  const date = new Date(props.set.expires_at_unix_seconds * 1000)
  return Number.isFinite(date.getTime()) ? `Cutoff ${date.toISOString()}` : 'Invalid expiry'
})
</script>
<style scoped>
.policy-set { margin-top: 16px; min-width: 0; }
.set-title { margin: 0 0 8px; font-size: .8rem; line-height: 1.5; overflow-wrap: anywhere; }
.set-title span, small { color: var(--theme-text-muted); }
table { width: 100%; border-collapse: collapse; table-layout: fixed; font-size: .78rem; }
th, td { text-align: left; padding: 10px 6px; vertical-align: top; border-bottom: 1px solid var(--theme-border); overflow-wrap: anywhere; }
thead th { color: var(--theme-text-muted); font-weight: 500; font-size: .72rem; }
th:first-child { width: 22%; }
small { display: block; font-size: .7rem; font-weight: 400; margin-top: 5px; }
.invalid { color: var(--theme-danger); }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
@media (max-width: 420px) { th, td { padding: 8px 3px; } }
</style>
