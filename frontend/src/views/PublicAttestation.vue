<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="public-attestation-page">
    <CompactPageHeader />

    <main class="public-attestation-main">
      <div class="public-attestation-intro">
        <p class="eyebrow">Public enclave verification</p>
        <h1>Verify a Caution application</h1>
        <p>
          This page requests fresh attestation evidence and verifies it in your browser.
          No Caution account or login is required.
        </p>
      </div>

      <section
        v-if="status !== 'idle'"
        :class="['verification-summary', `verification-summary--${status}`]"
        aria-live="polite"
      >
        <div class="verification-summary__header">
          <p class="verification-summary__label">Verification summary</p>
          <h2>{{ summaryHeadline }}</h2>
          <p v-if="statusMessage" class="verification-summary__message">{{ statusMessage }}</p>
        </div>
        <div class="verification-summary__checks">
          <div class="verification-summary__check">
            <span>AWS Nitro evidence</span>
            <strong :class="`check-status--${evidenceCheck.tone}`">{{ evidenceCheck.label }}</strong>
          </div>
          <div class="verification-summary__check">
            <span>Expected PCR0, PCR1, and PCR2</span>
            <strong :class="`check-status--${deploymentCheck.tone}`">
              {{ deploymentCheck.label }}
            </strong>
          </div>
        </div>
        <div v-if="verifiedAt" class="verification-summary__freshness">
          <span>
            Fresh nonce-bound evidence verified in this browser at
            {{ formattedVerificationTime }}
          </span>
          <button type="button" :disabled="status === 'loading'" @click="verifyAgain">
            Verify again
          </button>
        </div>
        <p v-if="attestationResult" class="verification-summary__boundary">
          This page does not reproduce source or test a STEVE encrypted session.
        </p>
      </section>

      <section v-if="target" class="metadata-card">
        <div class="metadata-card__item">
          <span class="metadata-card__label">Target</span>
          <strong class="metadata-card__hostname">{{ targetHostname }}</strong>
          <code class="metadata-card__endpoint">{{ target.attestationUrl }}</code>
        </div>
      </section>

      <section v-if="target" class="widget-card attestation-widget">
        <div ref="widgetContainer"></div>
        <details
          class="attestation-status attestation-status--expandable optional-pcr"
          :open="Boolean(pcrInput.trim() || activePcrProfile || pcrNotice)"
        >
          <summary class="attestation-status-header">
            <span class="attestation-status-text">Check expected deployment (recommended)</span>
          </summary>
          <div class="attestation-status-content">
            <div
              class="pcr-import"
              @dragover.prevent
              @drop.prevent="handlePcrDrop"
            >
              <input
                id="expected-pcr-file"
                type="file"
                accept=".pcrs,.json,text/plain,application/json"
                :disabled="!attestationResult || isDebugResult || status === 'loading'"
                :aria-describedby="pcrError ? 'expected-pcrs-error' : 'expected-pcrs-privacy'"
                @change="handlePcrSelection"
              />
              <label for="expected-pcr-file">
                <strong>{{ rememberedPcrs ? 'Replace saved PCRs' : 'Import expected PCRs' }}</strong>
                <span>
                  Choose or drop an enclave.pcrs or trusted_hashes.json file
                </span>
              </label>
            </div>
            <p id="expected-pcrs-privacy" class="optional-pcr__privacy">
              The file is read in this browser and is not uploaded.
            </p>
            <p v-if="activePcrProfile" class="optional-pcr__source">
              {{ activePcrSourceLabel }}
            </p>
            <p v-if="pcrError" id="expected-pcrs-error" class="optional-pcr__error" role="alert">
              {{ pcrError }}
            </p>

            <details class="manual-pcr" :open="Boolean(pcrInput.trim())">
              <summary>Advanced: paste PCRs manually</summary>
              <form @submit.prevent="checkExpectedPcrs">
                <label for="expected-pcrs">Expected Nitro PCR0, PCR1, and PCR2</label>
                <p>
                  Paste PCRs only after reviewing them through an independent trusted source.
                  <strong>Do not copy the attested values from this page into these fields.</strong>
                </p>
                <textarea
                  id="expected-pcrs"
                  v-model="pcrInput"
                  rows="6"
                  spellcheck="false"
                  placeholder="PCR0=…&#10;PCR1=…&#10;PCR2=…"
                  :aria-invalid="Boolean(pcrError)"
                  :aria-describedby="pcrError ? 'expected-pcrs-error' : undefined"
                ></textarea>
                <button
                  type="submit"
                  :disabled="!attestationResult || isDebugResult || !pcrInput.trim()"
                >
                  Compare expected hashes
                </button>
              </form>
            </details>

            <div v-if="pcrComparison?.checked" class="pcr-comparison" aria-live="polite">
              <div
                v-for="comparison in pcrComparison.comparisons"
                :key="comparison.name"
                class="pcr-comparison__row"
              >
                <div class="pcr-comparison__result">
                  <strong>{{ comparison.name }}</strong>
                  <span
                    :class="
                      comparison.matches
                        ? pcrComparison.matches
                          ? 'is-match'
                          : 'is-neutral-match'
                        : 'is-mismatch'
                    "
                  >
                    {{ comparison.matches ? 'Matched' : 'Mismatch' }}
                  </span>
                </div>
                <dl v-if="!comparison.matches">
                  <div>
                    <dt>Expected</dt>
                    <dd><code>{{ comparison.expected }}</code></dd>
                  </div>
                  <div>
                    <dt>Authenticated</dt>
                    <dd><code>{{ comparison.authenticated || 'Unavailable' }}</code></dd>
                  </div>
                </dl>
              </div>
            </div>
            <div v-if="rememberedPcrs" class="pcr-memory">
              <button type="button" class="secondary" @click="forgetExpectedPcrs">
                Forget saved PCRs
              </button>
            </div>
            <p v-if="pcrNotice" class="optional-pcr__notice" aria-live="polite">{{ pcrNotice }}</p>
          </div>
        </details>
      </section>

      <section v-if="target" class="verification-guide">
        <div>
          <span class="metadata-card__label">Verify independently</span>
          <h2>Reproduce and verify with the Caution CLI</h2>
          <p>
            From a reviewed application checkout, install the
            <a href="https://codeberg.org/caution/cli" target="_blank" rel="noopener noreferrer">
              Caution CLI
            </a>
            and run:
          </p>
        </div>
        <div class="verification-guide__command">
          <code>{{ cliVerifyCommand }}</code>
          <button type="button" aria-label="Copy CLI command" @click="copyCliCommand">Copy</button>
        </div>
        <span v-if="copyStatus" class="verification-guide__copy-status" aria-live="polite">
          {{ copyStatus }}
        </span>
        <p>
          The browser authenticates fresh Nitro evidence, but it does not authenticate the sibling
          manifest, reproduce source, or establish a STEVE encrypted session. The CLI reproduces
          the reviewed build and compares its PCR values. Read the
          <a
            href="https://docs.caution.co/guides/verify-an-app/"
            target="_blank"
            rel="noopener noreferrer"
          >
            verification guide
          </a>
          for the complete procedure.
        </p>
      </section>

      <section v-else class="usage-card">
        <h2>Choose an application to verify</h2>
        <p>Enter an HTTPS application domain or explicit HTTPS attestation endpoint.</p>
        <form class="target-form" @submit.prevent="submitTarget">
          <label for="attestation-target">Application or attestation URL</label>
          <div class="target-form__controls">
            <input
              id="attestation-target"
              v-model="targetInput"
              type="text"
              inputmode="url"
              autocomplete="url"
              placeholder="https://app.example.com"
            />
            <button type="submit">Verify application</button>
          </div>
          <p v-if="inputMessage" class="target-form__error" role="alert">{{ inputMessage }}</p>
        </form>
      </section>
    </main>
  </div>
</template>

<script>
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { renderInline } from 'attestation-widget'
import CompactPageHeader from '../components/CompactPageHeader.vue'
import {
  compareVerifiedPcrs,
  describeAttestationError,
  ensureUint8ArrayBase64,
  forgetRememberedPcrs,
  hasDebugPcrs,
  loadRememberedPcrs,
  normalizeAttestationInput,
  parseExpectedPcrs,
  quotePosixShellArgument,
  readExpectedPcrFile,
  resolveAttestationTarget,
  saveRememberedPcrs,
} from '../utils/publicAttestation.js'

export default {
  name: 'PublicAttestation',
  components: { CompactPageHeader },
  setup() {
    const widgetContainer = ref(null)
    const target = ref(null)
    const attestationResult = ref(null)
    const activePcrProfile = ref(null)
    const copyStatus = ref('')
    const inputMessage = ref('')
    const pcrComparison = ref(null)
    const pcrError = ref('')
    const pcrInput = ref('')
    const pcrNotice = ref('')
    const rememberedPcrs = ref(null)
    const status = ref('loading')
    const targetInput = ref('')
    const statusMessage = ref('')
    const verifiedAt = ref(null)
    let widget = null

    ensureUint8ArrayBase64()

    const isDebugResult = computed(() => hasDebugPcrs(attestationResult.value))

    const activePcrSourceLabel = computed(() => {
      if (activePcrProfile.value?.source === 'build') {
        return 'Local build output — unsigned; review the checkout and build independently.'
      }
      if (activePcrProfile.value?.source === 'cli') {
        return 'Caution CLI state — unsigned and editable.'
      }
      if (activePcrProfile.value?.source === 'manual') {
        return 'Manual entry — source not authenticated by this page.'
      }
      if (activePcrProfile.value?.source === 'remembered') {
        return 'Saved PCRs for this endpoint — browser continuity only.'
      }
      return ''
    })

    const summaryHeadline = computed(() => {
      if (status.value === 'evidence') {
        return 'Nitro evidence verified; compare expected PCRs below.'
      }
      if (status.value === 'matched') {
        return 'Nitro evidence verified; supplied expected PCRs match.'
      }
      if (status.value === 'mismatch') {
        return 'Expected deployment does not match authenticated PCRs.'
      }
      if (status.value === 'debug') {
        return 'Debug enclave authenticated; workload identity cannot be verified.'
      }
      if (status.value === 'failure') return 'Nitro attestation verification failed.'
      if (status.value === 'input-error') return 'Unable to verify this target.'
      return 'Verifying fresh Nitro evidence…'
    })

    const evidenceCheck = computed(() => {
      if (attestationResult.value?.verified) {
        return {
          label: 'Authenticated',
          tone: 'success',
        }
      }
      if (status.value === 'failure') return { label: 'Failed', tone: 'danger' }
      if (status.value === 'loading') return { label: 'Checking', tone: 'neutral' }
      return { label: 'Not checked', tone: 'neutral' }
    })

    const deploymentCheck = computed(() => {
      if (status.value === 'matched') return { label: 'Matched', tone: 'success' }
      if (status.value === 'mismatch') return { label: 'Mismatch', tone: 'danger' }
      if (status.value === 'debug') return { label: 'Unavailable', tone: 'danger' }
      if (status.value === 'evidence') return { label: 'Import PCRs below', tone: 'neutral' }
      if (status.value === 'loading') return { label: 'Pending', tone: 'neutral' }
      return { label: 'Not checked', tone: 'neutral' }
    })

    const cliVerifyCommand = computed(() =>
      target.value
        ? `caution verify --attestation-url ${quotePosixShellArgument(target.value.attestationUrl)}`
        : '',
    )

    const formattedVerificationTime = computed(() =>
      verifiedAt.value
        ? new Date(verifiedAt.value).toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          })
        : '',
    )

    const targetHostname = computed(() =>
      target.value ? new URL(target.value.attestationUrl).hostname : '',
    )

    const submitTarget = () => {
      try {
        const normalized = normalizeAttestationInput(targetInput.value)
        const search = new URLSearchParams()
        search.set('url', normalized)
        window.location.assign(`/verify?${search.toString()}`)
      } catch (error) {
        inputMessage.value = error.message
      }
    }

    const clearComparison = () => {
      pcrComparison.value = null
      pcrError.value = ''
      pcrNotice.value = ''
      if (attestationResult.value) {
        status.value = isDebugResult.value ? 'debug' : 'evidence'
      }
    }

    const compareActivePcrs = () => {
      if (!attestationResult.value || !activePcrProfile.value || isDebugResult.value) return

      pcrComparison.value = {
        checked: true,
        ...compareVerifiedPcrs(attestationResult.value, activePcrProfile.value.pcrs),
      }
      status.value = pcrComparison.value.matches ? 'matched' : 'mismatch'
      if (pcrComparison.value.matches && activePcrProfile.value.source !== 'remembered') {
        const replacing = Boolean(rememberedPcrs.value)
        try {
          rememberedPcrs.value = saveRememberedPcrs(
            window.localStorage,
            target.value.attestationUrl,
            activePcrProfile.value.pcrs,
          )
          pcrNotice.value = replacing
            ? 'Replaced saved PCRs for this endpoint.'
            : 'Saved PCRs for this endpoint.'
        } catch {
          pcrNotice.value = 'PCRs matched, but browser storage was unavailable.'
        }
      }
    }

    const checkExpectedPcrs = () => {
      if (!attestationResult.value || isDebugResult.value) return

      pcrError.value = ''
      pcrNotice.value = ''
      try {
        activePcrProfile.value = {
          pcrs: parseExpectedPcrs(pcrInput.value),
          source: 'manual',
        }
      } catch (error) {
        pcrError.value = error.message
        return
      }
      compareActivePcrs()
    }

    const importExpectedPcrFile = async (file) => {
      if (!attestationResult.value || isDebugResult.value) return

      activePcrProfile.value = null
      clearComparison()
      try {
        const profile = await readExpectedPcrFile(file)
        if (pcrInput.value) {
          pcrInput.value = ''
          await nextTick()
        }
        activePcrProfile.value = profile
        compareActivePcrs()
      } catch (error) {
        pcrError.value = error.message
      }
    }

    const handlePcrSelection = async (event) => {
      const file = event.target.files?.[0]
      if (file) await importExpectedPcrFile(file)
      event.target.value = ''
    }

    const handlePcrDrop = async (event) => {
      const file = event.dataTransfer?.files?.[0]
      if (file) await importExpectedPcrFile(file)
    }

    const forgetExpectedPcrs = () => {
      if (!target.value) return

      pcrNotice.value = ''
      try {
        forgetRememberedPcrs(window.localStorage, target.value.attestationUrl)
        rememberedPcrs.value = null
        pcrNotice.value = 'Forgot saved PCRs for this endpoint.'
        if (activePcrProfile.value?.source === 'remembered') {
          activePcrProfile.value = null
          clearComparison()
          pcrNotice.value = 'Forgot saved PCRs for this endpoint.'
        }
      } catch {
        pcrNotice.value = 'Could not use browser storage.'
      }
    }

    const handleVerificationError = (error) => {
      attestationResult.value = null
      pcrComparison.value = null
      pcrError.value = ''
      verifiedAt.value = null
      status.value = 'failure'
      statusMessage.value = describeAttestationError(
        error,
        target.value.attestationUrl,
        window.location.origin,
      )
    }

    const verifyAgain = async () => {
      if (!widget || status.value === 'loading') return

      attestationResult.value = null
      pcrComparison.value = null
      pcrError.value = ''
      status.value = 'loading'
      statusMessage.value = ''
      verifiedAt.value = null

      try {
        await widget.verify()
      } catch (error) {
        handleVerificationError(error)
      }
    }

    const copyCliCommand = async () => {
      copyStatus.value = ''
      try {
        await navigator.clipboard.writeText(cliVerifyCommand.value)
        copyStatus.value = 'Copied'
      } catch {
        copyStatus.value = 'Could not copy'
      }
    }

    watch(pcrInput, () => {
      activePcrProfile.value = null
      clearComparison()
    })

    onMounted(async () => {
      try {
        target.value = resolveAttestationTarget(window.location.search)
      } catch (error) {
        status.value = 'input-error'
        statusMessage.value = error.message
        return
      }

      if (!target.value) {
        status.value = 'idle'
        return
      }

      try {
        rememberedPcrs.value = loadRememberedPcrs(
          window.localStorage,
          target.value.attestationUrl,
        )
        if (rememberedPcrs.value) {
          activePcrProfile.value = {
            pcrs: rememberedPcrs.value.pcrs,
            source: 'remembered',
          }
        }
      } catch {
        pcrNotice.value = 'Could not use browser storage.'
      }

      await nextTick()
      widget = renderInline(widgetContainer.value, {
        attestationUrl: target.value.attestationUrl,
        autoVerify: true,
        showRaw: false,
        showVerifyButton: false,
        showChecks: true,
        showUserData: true,
        showPCRs: true,
        showSources: false,
        showConnectionStatus: false,
        onVerified: (result) => {
          attestationResult.value = result
          pcrComparison.value = null
          pcrError.value = ''
          status.value = hasDebugPcrs(result) ? 'debug' : 'evidence'
          statusMessage.value = ''
          verifiedAt.value = Date.now()
          compareActivePcrs()
        },
        onError: handleVerificationError,
      })
    })

    onUnmounted(() => {
      widget?.destroy()
    })

    return {
      activePcrProfile,
      activePcrSourceLabel,
      attestationResult,
      checkExpectedPcrs,
      cliVerifyCommand,
      copyCliCommand,
      copyStatus,
      deploymentCheck,
      evidenceCheck,
      formattedVerificationTime,
      forgetExpectedPcrs,
      handlePcrDrop,
      handlePcrSelection,
      inputMessage,
      isDebugResult,
      pcrComparison,
      pcrError,
      pcrInput,
      pcrNotice,
      rememberedPcrs,
      status,
      summaryHeadline,
      statusMessage,
      submitTarget,
      target,
      targetHostname,
      targetInput,
      verifiedAt,
      verifyAgain,
      widgetContainer,
    }
  },
}
</script>

<style scoped>
.public-attestation-page {
  min-height: 100vh;
  color: var(--theme-text-primary);
}

.public-attestation-main {
  width: min(860px, calc(100% - 40px));
  margin: 42px auto 80px;
}

.public-attestation-intro {
  max-width: 720px;
  margin-bottom: 32px;
}

.eyebrow,
.verification-summary__label,
.target-card span {
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.eyebrow {
  margin-bottom: 10px;
  color: var(--theme-text-muted);
}

h1 {
  margin-bottom: 14px;
  font-size: clamp(2.1rem, 6vw, 3.6rem);
  line-height: 1.08;
  letter-spacing: -0.04em;
}

.public-attestation-intro > p:last-child {
  color: var(--theme-text-muted);
  font-size: 1.08rem;
  line-height: 1.65;
}

.verification-summary,
.metadata-card,
.widget-card,
.verification-guide,
.usage-card {
  border: 1px solid var(--theme-border);
  border-radius: 16px;
  background: var(--theme-surface-translucent);
  box-shadow: var(--theme-shadow);
}

.verification-summary {
  display: grid;
  gap: 18px;
  padding: 22px 24px;
  margin-bottom: 18px;
}

.verification-summary--matched {
  border-color: var(--theme-success);
  background: var(--theme-success-bg);
}

.verification-summary--mismatch,
.verification-summary--debug,
.verification-summary--failure,
.verification-summary--input-error {
  border-color: var(--theme-danger);
  background: var(--theme-danger-bg);
}

.verification-summary__header {
  display: grid;
  gap: 5px;
}

.verification-summary__header h2 {
  font-size: 1.18rem;
  line-height: 1.35;
}

.verification-summary__label {
  color: var(--theme-text-muted);
}

.verification-summary__message,
.verification-summary__boundary,
.verification-summary__freshness {
  color: var(--theme-text-muted);
  line-height: 1.45;
}

.verification-summary--failure .verification-summary__message,
.verification-summary--input-error .verification-summary__message {
  color: var(--theme-danger);
}

.verification-summary__checks {
  overflow: hidden;
  border: 1px solid var(--theme-border);
  border-radius: 10px;
  background: var(--theme-surface-translucent);
}

.verification-summary__check {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding: 12px 14px;
}

.verification-summary__check + .verification-summary__check {
  border-top: 1px solid var(--theme-border);
}

.verification-summary__check strong {
  flex: 0 0 auto;
  border-radius: 999px;
  padding: 4px 9px;
  font-size: 0.78rem;
}

.check-status--neutral {
  color: var(--theme-text-secondary);
  background: var(--theme-surface-muted);
}

.check-status--success {
  color: #fff;
  background: var(--theme-success-strong);
}

.check-status--danger {
  color: #fff;
  background: var(--theme-danger-strong);
}

.verification-summary__freshness {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  font-size: 0.9rem;
}

.verification-summary__freshness button {
  border: 0;
  padding: 0;
  background: transparent;
  color: var(--theme-info);
  font: inherit;
  font-weight: 600;
  cursor: pointer;
}

.verification-summary__freshness button:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.verification-summary__boundary {
  padding-top: 14px;
  border-top: 1px solid var(--theme-border);
  font-size: 0.9rem;
}

.metadata-card,
.verification-guide,
.usage-card {
  padding: 22px 24px;
  margin-bottom: 18px;
}

.metadata-card,
.metadata-card__item,
.verification-guide {
  display: grid;
  gap: 10px;
}

.metadata-card__item + .metadata-card__item {
  margin-top: 8px;
  padding-top: 18px;
  border-top: 1px solid var(--theme-border);
}

.metadata-card__label {
  color: var(--theme-text-muted);
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.metadata-card__hostname {
  font-size: 1.2rem;
}

.metadata-card__endpoint {
  color: var(--theme-text-muted);
  font-size: 0.9rem;
}

.optional-pcr {
  margin-top: 12px;
}

.pcr-import {
  position: relative;
  overflow: hidden;
  border: 1px dashed var(--theme-border-strong);
  border-radius: 10px;
  background: var(--theme-surface-subtle);
}

.pcr-import:focus-within {
  outline: 3px solid var(--theme-focus-ring);
  border-color: var(--theme-focus);
}

.pcr-import input {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  opacity: 0;
  cursor: pointer;
}

.pcr-import input:disabled {
  cursor: not-allowed;
}

.pcr-import label {
  display: grid;
  gap: 3px;
  padding: 14px;
  cursor: pointer;
}

.pcr-import label span {
  color: var(--theme-text-muted);
  font-size: 0.86rem;
  font-weight: 400;
}

.pcr-import input:disabled + label {
  cursor: not-allowed;
  opacity: 0.5;
}

.optional-pcr form {
  display: grid;
  gap: 12px;
}

.optional-pcr label {
  font-size: 1rem;
  font-weight: 700;
}

.optional-pcr p {
  color: var(--theme-text-muted);
  line-height: 1.5;
}

.optional-pcr .optional-pcr__error {
  color: var(--theme-danger);
}

.optional-pcr__privacy,
.optional-pcr__source,
.optional-pcr__notice {
  margin-top: 8px;
  font-size: 0.86rem;
}

.optional-pcr__source {
  padding: 9px 11px;
  border-radius: 8px;
  background: var(--theme-surface-muted);
}

.manual-pcr {
  margin-top: 18px;
  padding-top: 16px;
  border-top: 1px solid var(--theme-border);
}

.manual-pcr summary {
  cursor: pointer;
  font-weight: 600;
}

.manual-pcr form {
  margin-top: 16px;
}

.optional-pcr textarea {
  width: 100%;
  resize: vertical;
  border: 1px solid var(--theme-border-strong);
  border-radius: 10px;
  padding: 14px;
  background: var(--theme-surface);
  color: var(--theme-text-primary);
  font: 0.88rem/1.5 'IBM Plex Mono', ui-monospace, SFMono-Regular, Consolas, monospace;
}

.optional-pcr textarea:focus {
  outline: 3px solid var(--theme-focus-ring);
  border-color: var(--theme-focus);
}

.optional-pcr button {
  justify-self: start;
  border: 0;
  border-radius: 999px;
  padding: 11px 20px;
  background: var(--theme-control);
  color: #fff;
  font: inherit;
  font-weight: 600;
  cursor: pointer;
}

.optional-pcr button:disabled {
  cursor: not-allowed;
  opacity: 0.45;
}

.pcr-comparison {
  margin-top: 20px;
  border: 1px solid var(--theme-border);
  border-radius: 10px;
}

.pcr-comparison__row {
  display: grid;
  gap: 12px;
  padding: 12px 14px;
}

.pcr-comparison__row + .pcr-comparison__row {
  border-top: 1px solid var(--theme-border);
}

.pcr-comparison__result {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.pcr-comparison__result span {
  border-radius: 999px;
  padding: 3px 8px;
  font-size: 0.76rem;
  font-weight: 700;
}

.pcr-comparison__result .is-match {
  color: var(--theme-success);
  background: var(--theme-success-bg);
}

.pcr-comparison__result .is-neutral-match {
  color: var(--theme-text-secondary);
  background: var(--theme-surface-muted);
}

.pcr-comparison__result .is-mismatch {
  color: var(--theme-danger);
  background: var(--theme-danger-bg);
}

.pcr-comparison dl,
.pcr-comparison dl > div {
  display: grid;
  gap: 5px;
}

.pcr-comparison dl {
  gap: 10px;
  margin: 0;
}

.pcr-comparison dt {
  color: var(--theme-text-muted);
  font-size: 0.78rem;
  font-weight: 600;
}

.pcr-comparison dd {
  min-width: 0;
  margin: 0;
}

.pcr-comparison code {
  overflow-wrap: anywhere;
  font-size: 0.78rem;
}

.pcr-memory {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 14px;
}

.pcr-memory button.secondary {
  border: 1px solid var(--theme-border-strong);
  background: transparent;
  color: var(--theme-text-primary);
}

.metadata-card code,
.verification-guide__command,
.usage-card code {
  overflow-wrap: anywhere;
  font-family: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Consolas, monospace;
}

.widget-card {
  padding: 16px;
  margin-bottom: 18px;
}

.widget-card :deep(.attestation-endpoint) {
  display: none;
}

.widget-card :deep(.attestation-body) {
  padding: 12px;
}

.widget-card :deep(.attestation-status--result) {
  margin-bottom: 0;
}

.widget-card :deep(.attestation-widget) {
  color: var(--theme-text-secondary);
}

.widget-card :deep(.attestation-inline) {
  border-color: var(--theme-border);
  background: transparent;
}

.widget-card :deep(.attestation-status-text),
.widget-card :deep(.attestation-check-message),
.widget-card :deep(.attestation-pcr-value),
.widget-card :deep(.attestation-source-value),
.widget-card :deep(.attestation-raw),
.widget-card :deep(.attestation-section summary) {
  color: var(--theme-text-secondary);
}

.widget-card :deep(.attestation-status-content),
.widget-card :deep(.attestation-pcr-label),
.widget-card :deep(.attestation-source-label),
.widget-card :deep(.attestation-endpoint-label),
.widget-card :deep(.attestation-loading),
.widget-card :deep(.attestation-status--expandable > summary::after) {
  color: var(--theme-text-muted);
}

.widget-card :deep(.attestation-check--pending .attestation-check-icon),
.widget-card :deep(.attestation-source-meta),
.widget-card :deep(.attestation-note) {
  color: var(--theme-text-faint);
}

.widget-card :deep(.attestation-diagram),
.widget-card :deep(.attestation-endpoint),
.widget-card :deep(.attestation-source),
.widget-card :deep(.attestation-raw),
.widget-card :deep(.attestation-section summary) {
  background: var(--theme-surface-subtle);
}

.widget-card :deep(.attestation-status--expandable > summary:hover),
.widget-card :deep(.attestation-section summary:hover) {
  background: var(--theme-surface-muted);
}

.widget-card :deep(.attestation-section),
.widget-card :deep(.attestation-section-content),
.widget-card :deep(.attestation-note) {
  border-color: var(--theme-border);
}

.widget-card :deep(.attestation-btn--secondary),
.widget-card :deep(.attestation-copy-btn) {
  border-color: var(--theme-border);
  background: var(--theme-surface-muted);
  color: var(--theme-text-muted);
}

.widget-card :deep(.attestation-check--success .attestation-check-icon) {
  color: var(--theme-success);
}

.widget-card :deep(.attestation-check--error .attestation-check-icon) {
  color: var(--theme-danger);
}

.verification-guide {
  gap: 16px;
}

.verification-guide h2 {
  margin-top: 4px;
  font-size: 1.2rem;
}

.verification-guide p {
  color: var(--theme-text-muted);
  line-height: 1.55;
}

.verification-guide a {
  color: var(--theme-info);
}

.verification-guide__command {
  display: flex;
  align-items: center;
  gap: 12px;
  overflow-x: auto;
  padding: 14px 16px;
  border-radius: 10px;
  background: var(--theme-code);
  color: var(--theme-code-text);
  white-space: nowrap;
}

.verification-guide__command code {
  min-width: 0;
  flex: 1;
}

.verification-guide__command button {
  flex: 0 0 auto;
  border: 1px solid rgba(255, 255, 255, 0.35);
  border-radius: 7px;
  padding: 6px 10px;
  background: transparent;
  color: #fff;
  font: inherit;
  font-weight: 600;
  cursor: pointer;
}

.verification-guide__copy-status {
  color: var(--theme-text-muted);
  font-size: 0.88rem;
}

.usage-card h2 {
  margin-bottom: 10px;
}

.usage-card p {
  margin-bottom: 12px;
  color: var(--theme-text-muted);
}

.target-form {
  display: grid;
  gap: 10px;
  margin-top: 20px;
}

.target-form label {
  font-weight: 700;
}

.target-form__controls {
  display: flex;
  gap: 10px;
}

.target-form input {
  min-width: 0;
  flex: 1;
  border: 1px solid var(--theme-border-strong);
  border-radius: 10px;
  padding: 12px 14px;
  background: var(--theme-surface);
  color: var(--theme-text-primary);
  font: inherit;
}

.target-form input:focus {
  outline: 3px solid var(--theme-focus-ring);
  border-color: var(--theme-focus);
}

.target-form button {
  border: 0;
  border-radius: 999px;
  padding: 11px 20px;
  background: var(--theme-control);
  color: #fff;
  font: inherit;
  font-weight: 600;
  cursor: pointer;
}

.target-form .target-form__error {
  margin: 0;
  color: var(--theme-danger);
}

@media (max-width: 600px) {
  .public-attestation-main {
    width: min(100% - 24px, 860px);
  }

  .public-attestation-main {
    margin-top: 24px;
  }

  .verification-summary,
  .metadata-card,
  .verification-guide,
  .usage-card {
    padding: 18px;
  }

  .target-form__controls {
    align-items: stretch;
    flex-direction: column;
  }

  .verification-summary__check,
  .verification-summary__freshness {
    align-items: flex-start;
    flex-direction: column;
  }

  .verification-guide__command {
    align-items: stretch;
    flex-direction: column;
  }

  .verification-guide__command button {
    align-self: flex-start;
  }
}
</style>
