<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->
<script setup>
import { onUnmounted, ref } from 'vue'

const props = defineProps({ value: { type: String, required: true }, label: { type: String, required: true } })
const copied = ref(false)
const announcement = ref('')
let timer

async function copy() {
  try {
    await navigator.clipboard.writeText(props.value)
    copied.value = true
    announcement.value = `${props.label} copied`
  } catch {
    announcement.value = `Could not copy ${props.label}`
  }
  clearTimeout(timer)
  timer = setTimeout(() => { copied.value = false; announcement.value = '' }, 2000)
}
onUnmounted(() => clearTimeout(timer))
</script>

<template>
  <span class="copy-icon">
    <button type="button" class="copy-inline-btn" :aria-label="copied ? `${label} copied` : `Copy ${label}`" :title="copied ? 'Copied' : 'Copy'" @click.stop="copy">
      <svg v-if="!copied" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
        <rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
      </svg>
      <svg v-else width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
        <polyline points="20 6 9 17 4 12" />
      </svg>
    </button>
    <span class="visually-hidden" role="status" aria-live="polite">{{ announcement }}</span>
  </span>
</template>

<style scoped>
.copy-icon { display: inline-flex; }
/* Dashboard.vue styles `.copy-inline-btn` in its scoped CSS, which does not reach this component. */
.copy-inline-btn { display: inline-flex; padding: 2px; border: 0; background: none; color: var(--theme-text-secondary); cursor: pointer; }
.copy-inline-btn:focus-visible { outline: 2px solid var(--theme-focus); }
.visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
</style>
