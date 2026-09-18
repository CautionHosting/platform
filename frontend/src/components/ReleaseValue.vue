<template><span class="value"><span class="text">{{ shown }}</span> <button v-if="shortened" type="button" :aria-label="`${revealed ? 'Hide' : 'Reveal'} ${label}`" @click="revealed = !revealed">{{ revealed ? 'Hide' : 'Reveal' }}</button><button v-if="available" type="button" :aria-label="`Copy ${label}`" @click="copy">{{ copied ? 'Copied' : 'Copy' }}</button><span v-if="failed" role="status">Copy unavailable; reveal and select the value.</span></span></template>
<script setup>
import { computed, ref } from 'vue'
import { displayValue } from '../composables/releaseDetails.js'
const props = defineProps({ value: [String, Number], label: { type: String, required: true } })
const copied = ref(false), failed = ref(false), revealed = ref(false)
const text = computed(() => displayValue(props.value))
const available = computed(() => text.value !== 'Unavailable')
const shortened = computed(() => /^[0-9a-f]{32,}$/i.test(text.value))
const shown = computed(() => shortened.value && !revealed.value ? `${text.value.slice(0, 8)}…${text.value.slice(-8)}` : text.value)
async function copy() { try { await navigator.clipboard.writeText(text.value); copied.value = true; failed.value = false } catch { failed.value = true } }
</script>
<style scoped>.value { overflow-wrap:anywhere; }.text { font-family:monospace; } button { color:#b8a5ff; background:transparent; border:0; text-decoration:underline; font-size:.8rem; padding:.2rem .3rem; cursor:pointer; } button:focus-visible { outline:2px solid #bcaaff; }</style>
