<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial -->
<template>
  <main class="release-approval">
    <h1>Approve share recovery</h1>
    <p>Only approve an attempt you started. Compare these details with your CLI.</p>
    <dl v-if="request">
      <dt>Bundle</dt><dd>{{ bundleId }}</dd>
      <dt>Holder certificate</dt><dd>{{ request.context.holder }}</dd>
      <dt>Destination key</dt><dd>{{ destinationKey }}</dd>
      <dt>Release context hash</dt><dd>{{ request.context_hash }}</dd>
    </dl>
    <details v-if="request"><summary>Approved destination measurements</summary><pre>{{ request.context.destination_policy }}</pre></details>
    <p>Caution’s enclave holds the PGP private key. Your registered passkey authorizes re-encryption of your share to the verified application enclave. The private key is never released.</p>
    <p role="status">{{ status }}</p>
    <template v-if="request && !finished">
      <button :disabled="busy" @click="approve">Approve with passkey</button>
      <button @click="cancel">Cancel</button>
    </template>
  </main>
</template>
<script setup>
import { ref, computed, onMounted } from 'vue'
import { releaseOptions, releaseAssertion } from '../composables/releaseApproval.js'
const token = window.location.hash.slice(1)
const request = ref(null)
const status = ref('Loading release request…')
const busy = ref(false)
const finished = ref(false)
let controller
const hex = bytes => (bytes || []).map(b => b.toString(16).padStart(2, '0')).join('')
const bundleId = computed(() => hex(request.value?.context.bundle_id))
const destinationKey = computed(() => hex(request.value?.destination_key))
async function post(path, body) {
  const response = await fetch(`/auth/qr-release/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, ...body }) })
  if (!response.ok) throw new Error('Release request expired or was already consumed. Start a fresh attempt in the CLI.')
  return response.json()
}
onMounted(async () => {
  try {
    if (!token) throw new Error('Missing release request.')
    request.value = await post('read', {})
    status.value = 'Approval releases one share to this destination only.'
  } catch (error) { status.value = error.message; finished.value = true }
})
async function cancel() {
  finished.value = true
  controller?.abort()
  try { await post('finish', { assertion: null }) } catch { /* expired attempts are already unusable */ }
  status.value = 'Cancelled. Start a fresh attempt in the CLI to retry.'
}
async function approve() {
  busy.value = true
  controller = new AbortController()
  try {
    const credential = await navigator.credentials.get({ publicKey: releaseOptions(request.value.options), signal: controller.signal })
    await post('finish', { assertion: releaseAssertion(credential) })
    finished.value = true
    status.value = 'Assertion sent to the CLI. The custody enclave will verify it before releasing your share.'
  } catch (error) {
    await cancel()
    status.value = `${error.message} Start a fresh attempt in the CLI.`
  } finally { busy.value = false }
}
</script>
<style scoped>
.release-approval { max-width: 48rem; margin: 3rem auto; padding: 1.5rem; }
dt { font-weight: bold; margin-top: 1rem; }
dd { margin: .25rem 0; overflow-wrap: anywhere; font-family: monospace; }
button { margin: .5rem .5rem .5rem 0; padding: .75rem 1rem; }
</style>
