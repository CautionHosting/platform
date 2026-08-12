<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="public-attestation-page">
    <header class="public-attestation-header">
      <a href="https://caution.co" aria-label="Caution home">
        <img src="/assets/caution-logo-black.svg" alt="Caution" />
      </a>
    </header>

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
        :class="['verification-result', `verification-result--${status}`]"
        aria-live="polite"
      >
        <div class="verification-result__icon" aria-hidden="true">
          {{ statusIcon }}
        </div>
        <div>
          <p class="verification-result__label">{{ statusLabel }}</p>
          <p v-if="statusMessage" class="verification-result__message">{{ statusMessage }}</p>
        </div>
      </section>

      <section v-if="target" class="metadata-card">
        <div class="metadata-card__item">
          <span class="metadata-card__label">Attestation endpoint</span>
          <code>{{ target.attestationUrl }}</code>
        </div>
      </section>

      <section v-if="target" class="widget-card attestation-widget">
        <div ref="widgetContainer"></div>
        <details
          class="attestation-status attestation-status--expandable optional-pcr"
          :open="Boolean(pcrInput.trim())"
        >
          <summary class="attestation-status-header">
            <span class="attestation-status-text">Optional: compare expected PCR hashes</span>
          </summary>
          <div class="attestation-status-content">
            <form @submit.prevent="checkExpectedPcrs">
              <label for="expected-pcrs">Expected Nitro PCR0, PCR1, and PCR2</label>
              <p>
                This browser verifier does not pin expected PCRs automatically. Paste hashes only
                after reviewing them through an independent trusted source.
              </p>
              <textarea
                id="expected-pcrs"
                v-model="pcrInput"
                rows="6"
                spellcheck="false"
                placeholder="PCR0=…&#10;PCR1=…&#10;PCR2=…"
              ></textarea>
              <button type="submit" :disabled="!attestationResult || !pcrInput.trim()">
                Compare expected hashes
              </button>
            </form>
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
        <code class="verification-guide__command">{{ cliVerifyCommand }}</code>
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
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { renderInline } from 'attestation-widget'
import {
  compareOptionalExpectedPcrs,
  describeAttestationError,
  ensureUint8ArrayBase64,
  normalizeAttestationInput,
  quotePosixShellArgument,
  resolveAttestationTarget,
} from '../utils/publicAttestation.js'

export default {
  name: 'PublicAttestation',
  setup() {
    const widgetContainer = ref(null)
    const target = ref(null)
    const attestationResult = ref(null)
    const inputMessage = ref('')
    const pcrInput = ref('')
    const status = ref('loading')
    const targetInput = ref('')
    const statusMessage = ref('')
    let widget = null

    ensureUint8ArrayBase64()

    const statusLabel = computed(() => {
      if (status.value === 'success') return 'Fresh Nitro attestation authenticated'
      if (status.value === 'failure') return 'Failed verification'
      if (status.value === 'input-error') return 'Unable to verify'
      return 'Verifying application…'
    })

    const statusIcon = computed(() => {
      if (status.value === 'success') return '✓'
      if (status.value === 'failure' || status.value === 'input-error') return '×'
      return '···'
    })

    const cliVerifyCommand = computed(() =>
      target.value
        ? `caution verify --attestation-url ${quotePosixShellArgument(target.value.attestationUrl)}`
        : '',
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

    const checkExpectedPcrs = () => {
      let comparison
      try {
        comparison = compareOptionalExpectedPcrs(attestationResult.value, pcrInput.value)
      } catch (error) {
        status.value = 'input-error'
        statusMessage.value = error.message
        return
      }

      if (!attestationResult.value) {
        status.value = 'loading'
        statusMessage.value = 'Waiting for cryptographic attestation verification.'
        return
      }

      if (!comparison.matches) {
        status.value = 'failure'
        statusMessage.value = `${comparison.mismatches.join(', ')} did not match the attested values.`
        return
      }

      status.value = 'success'
      statusMessage.value =
        'The supplied PCR0, PCR1, and PCR2 matched the authenticated values. This does not establish a STEVE encrypted session.'
    }

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
          status.value = 'success'
          statusMessage.value =
            'Fresh nonce-bound Nitro evidence is authenticated. PCR0, PCR1, and PCR2 have not been compared with independently reviewed values. This does not establish a STEVE encrypted session.'
        },
        onError: (error) => {
          attestationResult.value = null
          status.value = 'failure'
          statusMessage.value = describeAttestationError(
            error,
            target.value.attestationUrl,
            window.location.origin,
          )
        },
      })
    })

    onUnmounted(() => {
      widget?.destroy()
    })

    return {
      attestationResult,
      checkExpectedPcrs,
      cliVerifyCommand,
      inputMessage,
      pcrInput,
      status,
      statusIcon,
      statusLabel,
      statusMessage,
      submitTarget,
      target,
      targetInput,
      widgetContainer,
    }
  },
}
</script>

<style scoped>
.public-attestation-page {
  min-height: 100vh;
  color: #0f0f0f;
}

.public-attestation-header {
  width: min(1120px, calc(100% - 40px));
  margin: 0 auto;
  padding: 28px 0;
}

.public-attestation-header img {
  display: block;
  width: 140px;
  height: auto;
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
.verification-result__label,
.target-card span {
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.eyebrow {
  margin-bottom: 10px;
  color: #56636f;
}

h1 {
  margin-bottom: 14px;
  font-size: clamp(2.1rem, 6vw, 3.6rem);
  line-height: 1.08;
  letter-spacing: -0.04em;
}

.public-attestation-intro > p:last-child {
  color: #56636f;
  font-size: 1.08rem;
  line-height: 1.65;
}

.verification-result,
.metadata-card,
.widget-card,
.verification-guide,
.usage-card {
  border: 1px solid rgba(15, 15, 15, 0.12);
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.86);
  box-shadow: 0 12px 36px rgba(46, 106, 234, 0.08);
}

.verification-result {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 22px 24px;
  margin-bottom: 18px;
}

.verification-result--success {
  border-color: #2e7d32;
  background: #f0f9f1;
}

.verification-result--failure,
.verification-result--input-error {
  border-color: #c62828;
  background: #fff3f3;
}

.verification-result__icon {
  display: grid;
  place-items: center;
  width: 42px;
  height: 42px;
  flex: 0 0 42px;
  border-radius: 50%;
  background: #edf1f7;
  font-size: 1.35rem;
  font-weight: 700;
}

.verification-result--success .verification-result__icon {
  color: #fff;
  background: #2e7d32;
}

.verification-result--failure .verification-result__icon,
.verification-result--input-error .verification-result__icon {
  color: #fff;
  background: #c62828;
}

.verification-result__message {
  margin-top: 5px;
  color: #56636f;
  line-height: 1.45;
}

.verification-result--failure .verification-result__message,
.verification-result--input-error .verification-result__message {
  color: #6e2020;
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
  border-top: 1px solid rgba(15, 15, 15, 0.1);
}

.metadata-card__label {
  color: #56636f;
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.optional-pcr {
  margin-top: 12px;
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
  color: #56636f;
  line-height: 1.5;
}

.optional-pcr textarea {
  width: 100%;
  resize: vertical;
  border: 1px solid #b8c2cc;
  border-radius: 10px;
  padding: 14px;
  background: #fff;
  color: #0f0f0f;
  font: 0.88rem/1.5 'IBM Plex Mono', ui-monospace, SFMono-Regular, Consolas, monospace;
}

.optional-pcr textarea:focus {
  outline: 3px solid rgba(46, 106, 234, 0.22);
  border-color: #2e6aea;
}

.optional-pcr button {
  justify-self: start;
  border: 0;
  border-radius: 999px;
  padding: 11px 20px;
  background: #0f0f0f;
  color: #fff;
  font: inherit;
  font-weight: 600;
  cursor: pointer;
}

.optional-pcr button:disabled {
  cursor: not-allowed;
  opacity: 0.45;
}

.metadata-card code,
.verification-guide__command,
.usage-card code {
  overflow-wrap: anywhere;
  font-family: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Consolas, monospace;
}

.widget-card {
  padding: 16px;
}

.verification-guide {
  gap: 16px;
}

.verification-guide h2 {
  margin-top: 4px;
  font-size: 1.2rem;
}

.verification-guide p {
  color: #56636f;
  line-height: 1.55;
}

.verification-guide a {
  color: #1559a6;
}

.verification-guide__command {
  display: block;
  overflow-x: auto;
  padding: 14px 16px;
  border-radius: 10px;
  background: #111827;
  color: #f8fafc;
  white-space: nowrap;
}

.usage-card h2 {
  margin-bottom: 10px;
}

.usage-card p {
  margin-bottom: 12px;
  color: #56636f;
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
  border: 1px solid #b8c2cc;
  border-radius: 10px;
  padding: 12px 14px;
  background: #fff;
  color: #0f0f0f;
  font: inherit;
}

.target-form input:focus {
  outline: 3px solid rgba(46, 106, 234, 0.22);
  border-color: #2e6aea;
}

.target-form button {
  border: 0;
  border-radius: 999px;
  padding: 11px 20px;
  background: #0f0f0f;
  color: #fff;
  font: inherit;
  font-weight: 600;
  cursor: pointer;
}

.target-form .target-form__error {
  margin: 0;
  color: #a51d1d;
}

@media (max-width: 600px) {
  .public-attestation-header,
  .public-attestation-main {
    width: min(100% - 24px, 860px);
  }

  .public-attestation-main {
    margin-top: 24px;
  }

  .verification-result,
  .metadata-card,
  .verification-guide,
  .usage-card {
    padding: 18px;
  }

  .target-form__controls {
    align-items: stretch;
    flex-direction: column;
  }
}
</style>
