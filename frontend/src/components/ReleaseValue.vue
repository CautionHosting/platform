<template><span class="value">{{ text }} <button v-if="available" type="button" class="copy" :aria-label="`Copy ${label}`" @click="copy">{{ copied ? 'Copied' : 'Copy' }}</button><span v-if="failed" role="status">Copy unavailable; select the value.</span></span></template>
<script setup>
import { computed, ref } from 'vue'
import { displayValue } from '../composables/releaseDetails.js'
const props = defineProps({ value: [String, Number], label: { type: String, required: true } })
const copied = ref(false), failed = ref(false)
const text = computed(() => displayValue(props.value))
const available = computed(() => text.value !== 'Unavailable')
async function copy() { try { await navigator.clipboard.writeText(text.value); copied.value = true; failed.value = false } catch { failed.value = true } }
</script>
<style scoped>.value { overflow-wrap:anywhere; }.copy { color:#9baec6; background:transparent; border:0; text-decoration:underline; font-size:.75rem; padding:.2rem .4rem; cursor:pointer; }</style>
