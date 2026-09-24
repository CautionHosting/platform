<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->
<template>
  <span class="copy-value">
    <code :title="value || undefined">{{ display }}</code>
    <button v-if="value" type="button" :aria-label="`Copy ${label}`" @click="$emit('copy', value, label)">Copy</button>
  <button v-if="expandable && value" type="button" :aria-expanded="expanded" @click="expanded = !expanded">{{ expanded ? 'Short' : 'Full' }}</button>
  </span>
</template>
<script setup>
import { computed, ref } from 'vue'
const props = defineProps({ value: String, label: { type: String, required: true }, full: Boolean, expandable: Boolean })
const expanded = ref(false)
defineEmits(['copy'])
const display = computed(() => !props.value ? 'Unavailable' : props.full || expanded.value || props.value.length <= 24 ? props.value : `${props.value.slice(0, 12)}…${props.value.slice(-8)}`)
</script>
<style scoped>
.copy-value { display: inline-flex; align-items: baseline; flex-wrap: wrap; gap: 5px; max-width: 100%; }
code { overflow-wrap: anywhere; min-width: 0; font-size: .78rem; }
button { color: var(--theme-text-secondary); background: transparent; border: 1px solid var(--theme-border); border-radius: 4px; padding: 2px 5px; font-size: .68rem; cursor: pointer; }
button:hover { color: var(--theme-text-primary); background: var(--theme-surface-subtle); }
button:focus-visible { outline: 2px solid var(--theme-focus); outline-offset: 3px; }
</style>
