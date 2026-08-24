<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="public-e2ee-page">
    <CompactPageHeader />

    <main class="public-e2ee-main">
      <div class="public-e2ee-intro">
        <p class="eyebrow">Public encrypted-session tester</p>
        <h1>Test a STEVE E2EE session</h1>
        <p>Establish, inspect, and exercise an attested STEVE v2 channel entirely in your browser.</p>
      </div>

      <section v-if="mode === 'error'" class="card error-card">
        <p class="metadata-label">Tester error</p>
        <h2>Unable to open this tester</h2>
        <p class="form-error" role="alert">{{ pageError }}</p>
        <a class="text-link" href="/verify-e2ee/">Choose another target</a>
      </section>

      <section v-else-if="mode === 'chooser'" class="card chooser-card">
        <div class="section-heading">
          <h2>Connect to a STEVE deployment</h2>
          <p>Enter its public HTTPS origin and deployment-fixed key-establishment suite.</p>
        </div>
        <form class="target-form" @submit.prevent="submitTarget">
          <label for="steve-target">STEVE origin</label>
          <input
            id="steve-target"
            v-model="targetInput"
            type="text"
            inputmode="url"
            autocomplete="url"
            placeholder="https://secure.example.com"
          />
          <fieldset class="suite-picker">
            <legend>Key establishment</legend>
            <div class="suite-picker__options">
              <label v-for="suite in suites" :key="suite" class="suite-option">
                <input
                  v-model="selectedSuite"
                  class="visually-hidden"
                  type="radio"
                  name="steve-suite"
                  :value="suite"
                />
                <span>
                  <b>{{ suite }}</b>
                  <small>{{ suite === 'X25519' ? 'Classical' : 'Hybrid post-quantum' }}</small>
                </span>
              </label>
            </div>
          </fieldset>
          <p class="small-note">Must match <code>caution.hcl</code>. No negotiation or fallback.</p>
          <fieldset class="trust-picker">
            <legend>Trust policy</legend>
            <div class="trust-picker__options">
              <label v-for="option in trustOptions" :key="option.value" class="trust-option">
                <input
                  v-model="trustIntent"
                  class="visually-hidden"
                  type="radio"
                  name="trust-policy"
                  :value="option.value"
                />
                <span>
                  <b>{{ option.label }}</b>
                  <small>{{ option.description }}</small>
                </span>
              </label>
            </div>
          </fieldset>
          <div class="chooser-setup">
            <p class="metadata-label">Required CORS configuration</p>
            <p>Allow this page’s exact origin in <code>caution.hcl</code>, then redeploy the target.</p>
            <pre><code>{{ chooserCorsExample }}</code></pre>
          </div>
          <p v-if="inputError" class="form-error" role="alert">{{ inputError }}</p>
          <button type="submit" :disabled="targetBusy">
            {{ targetBusy ? 'Opening tester…' : 'Open tester' }}
          </button>
        </form>
      </section>

      <template v-else-if="mode === 'tester' && target">
        <section class="card control-center">
          <div class="target-heading">
            <div>
              <p class="metadata-label">Target</p>
              <h2>{{ targetHostname }}</h2>
              <code>{{ target.origin }}</code>
            </div>
            <div class="target-heading__actions">
              <span class="suite-pill">{{ target.suite }}</span>
              <a class="text-link" :href="changeTargetHref">Change</a>
            </div>
          </div>

          <div :class="['status-line', `status-line--${trustSummary.tone}`]" aria-live="polite">
            <span class="status-dot" aria-hidden="true"></span>
            <div class="status-line__copy">
              <p class="metadata-label">Channel status</p>
              <h3>{{ trustSummary.title }}</h3>
              <p>{{ trustSummary.message }}</p>
              <p v-if="sessionErrorMessage" class="form-error" role="alert">{{ sessionErrorMessage }}</p>
            </div>
            <span :class="['status-pill', `status-pill--${trustSummary.tone}`]">{{ trustSummary.badge }}</span>
          </div>

          <dl v-if="sessionStatus?.session" class="evidence-strip">
            <div><dt>Protocol</dt><dd>{{ protocolName }}</dd></div>
            <div><dt>Suite</dt><dd>{{ sessionStatus.protocol?.keyEstablishment }}</dd></div>
            <div><dt>Established</dt><dd>{{ formatTimestamp(sessionStatus.session.establishedAt) }}</dd></div>
            <div><dt>Rotates</dt><dd>{{ formatTimestamp(sessionStatus.session.rotatesAt) }}</dd></div>
          </dl>

          <div class="control-center__toolbar">
            <div class="disclosure-actions">
              <button
                v-if="sessionStatus?.session"
                type="button"
                class="text-button"
                :aria-expanded="evidenceOpen"
                @click="evidenceOpen = !evidenceOpen"
              >
                {{ evidenceOpen ? 'Hide evidence' : 'View evidence' }}
              </button>
              <button
                type="button"
                class="text-button"
                :aria-expanded="trustPolicyOpen"
                @click="trustPolicyOpen = !trustPolicyOpen"
              >
                Trust: {{ activeTrustLabel }} <span v-if="pcrProfiles.length">({{ pcrProfiles.length }})</span>
              </button>
            </div>
            <div class="session-controls">
              <button
                v-if="primarySessionAction"
                type="button"
                :disabled="!sdkReady || sessionBusy"
                @click="runSessionAction(primarySessionAction.action)"
              >
                {{ sessionBusy ? 'Working…' : primarySessionAction.label }}
              </button>
              <details v-if="sessionAuthenticated || sessionStatus?.initialized" class="action-menu">
                <summary>Session actions</summary>
                <div>
                  <button type="button" :disabled="!sessionAuthenticated || sessionBusy" @click="runSessionAction('rotate')">Rotate session</button>
                  <button type="button" :disabled="!sdkReady || sessionBusy" @click="runSessionAction('reconnect')">Reconnect</button>
                  <button type="button" :disabled="!sessionStatus?.initialized || sessionBusy" @click="runSessionAction('reset')">Reset</button>
                </div>
              </details>
            </div>
          </div>

          <section v-if="evidenceOpen" class="embedded-panel" aria-label="Session evidence">
            <div class="embedded-panel__heading">
              <div>
                <p class="metadata-label">Evidence</p>
                <h3>Session and Nitro details</h3>
              </div>
              <span :class="['status-pill', `status-pill--${sessionCheck.tone}`]">{{ sessionCheck.label }}</span>
            </div>
            <template v-if="sessionStatus?.session">
              <details class="diagnostic" open>
                <summary>Session and protocol</summary>
                <dl class="diagnostic-list">
                  <div><dt>Session ID</dt><dd><code>{{ sessionStatus.session.id }}</code></dd></div>
                  <div><dt>Transcript hash</dt><dd><code>{{ sessionStatus.session.transcriptHash }}</code></dd></div>
                  <div><dt>Trigger</dt><dd>{{ sessionStatus.session.trigger || 'Unavailable' }}</dd></div>
                  <div><dt>Key confirmation</dt><dd>{{ sessionStatus.session.confirmation }}</dd></div>
                  <div><dt>Key derivation</dt><dd>{{ sessionStatus.protocol?.keyDerivation }}</dd></div>
                  <div><dt>Record protection</dt><dd>{{ sessionStatus.protocol?.recordProtection }}</dd></div>
                </dl>
              </details>
              <details class="diagnostic">
                <summary>Nitro authentication checks</summary>
                <dl class="diagnostic-list">
                  <div><dt>Verifier</dt><dd>{{ sessionStatus.attestationVerifier?.id }}</dd></div>
                  <div><dt>Trust anchor</dt><dd>{{ sessionStatus.attestationVerifier?.trustAnchor }}</dd></div>
                  <div><dt>Module ID</dt><dd><code>{{ sessionStatus.attestation?.moduleId }}</code></dd></div>
                  <div><dt>Certificate chain</dt><dd>{{ sessionStatus.attestation?.checks?.certificateChain }}</dd></div>
                  <div><dt>Fresh nonce binding</dt><dd>{{ sessionStatus.attestation?.checks?.nonceBinding }}</dd></div>
                  <div><dt>Transcript binding</dt><dd>{{ sessionStatus.attestation?.checks?.sessionBinding }}</dd></div>
                  <div><dt>Key confirmation</dt><dd>{{ sessionStatus.attestation?.checks?.keyConfirmation }}</dd></div>
                  <div><dt>PCR trust</dt><dd>{{ sessionStatus.attestation?.pcrTrust || 'not-checked' }}</dd></div>
                </dl>
              </details>
              <details class="diagnostic">
                <summary>Authenticated Nitro PCRs</summary>
                <dl class="pcr-value-list">
                  <div v-for="name in authenticatedPcrNames" :key="name">
                    <dt>{{ name }}</dt>
                    <dd><code>{{ sessionStatus.attestation?.pcrs?.[name] }}</code></dd>
                  </div>
                </dl>
                <details v-if="authenticatedZeroPcrNames.length" class="pcr-classification">
                  <summary>
                    <span>Zero PCRs — not pinnable</span>
                    <span class="pcr-classification__count">{{ authenticatedZeroPcrNames.length }}</span>
                  </summary>
                  <div class="pcr-classification__content">
                    <code>{{ authenticatedZeroPcrNames.join(', ') }}</code>
                    <p>Zero measurements are shown for completeness and cannot be included in a pinned profile.</p>
                  </div>
                </details>
                <details v-if="authenticatedMalformedPcrNames.length" class="pcr-classification">
                  <summary>
                    <span>Malformed PCR values</span>
                    <span class="pcr-classification__count">{{ authenticatedMalformedPcrNames.length }}</span>
                  </summary>
                  <div class="pcr-classification__content">
                    <code>{{ authenticatedMalformedPcrNames.join(', ') }}</code>
                    <p>Malformed values are ignored by this display and cannot be pinned.</p>
                  </div>
                </details>
              </details>
            </template>
            <p v-else class="small-note">Establish a session to inspect authenticated evidence.</p>
          </section>

          <section v-if="trustPolicyOpen" class="embedded-panel" aria-label="Browser PCR policy">
            <div class="embedded-panel__heading">
              <div>
                <p class="metadata-label">Trust policy</p>
                <h3>Browser PCR profiles</h3>
              </div>
            </div>
            <p class="small-note">
              Each profile is one indivisible alternative. The SDK accepts one whole match and never mixes PCR values.
              Optional nonzero PCR3–PCR255 can narrow a profile; every included value must be nonzero.
            </p>

            <div v-if="reviewSnapshot" class="review-card">
              <div>
                <p class="metadata-label">First-use review</p>
                <h4>Pin the current authenticated profile</h4>
                <p>First-use trust provides browser continuity, not independent deployment identity.</p>
              </div>
              <div class="review-pcrs">
                <div v-for="name in reviewPcrNames" :key="name" class="review-pcr-row">
                  <div>
                    <span>{{ name }}</span>
                    <code>{{ reviewSnapshot.pcrs[name] }}</code>
                  </div>
                  <span v-if="requiredPcrNames.includes(name)" class="selection-pill selection-pill--fixed">Required</span>
                  <button
                    v-else
                    type="button"
                    class="selection-pill"
                    :class="{ 'selection-pill--selected': selectedAdditionalPcrs.includes(name) }"
                    :disabled="!isSelectableReviewPcr(name)"
                    :aria-pressed="selectedAdditionalPcrs.includes(name)"
                    @click="toggleReviewPcr(name)"
                  >
                    {{ selectedAdditionalPcrs.includes(name) ? 'Pinned' : isSelectableReviewPcr(name) ? 'Not pinned' : 'Unavailable' }}
                  </button>
                </div>
              </div>
              <details v-if="reviewZeroPcrNames.length" class="pcr-classification">
                <summary>
                  <span>Zero PCRs — not pinnable</span>
                  <span class="pcr-classification__count">{{ reviewZeroPcrNames.length }}</span>
                </summary>
                <div class="pcr-classification__content">
                  <code>{{ reviewZeroPcrNames.join(', ') }}</code>
                  <p>These authenticated zero measurements will not be added to the profile.</p>
                </div>
              </details>
              <details v-if="reviewMalformedPcrNames.length" class="pcr-classification">
                <summary>
                  <span>Malformed PCR values</span>
                  <span class="pcr-classification__count">{{ reviewMalformedPcrNames.length }}</span>
                </summary>
                <div class="pcr-classification__content">
                  <code>{{ reviewMalformedPcrNames.join(', ') }}</code>
                  <p>These values cannot be added to the profile.</p>
                </div>
              </details>
              <div class="button-row">
                <button type="button" class="secondary" :disabled="profileBusy" @click="cancelPcrReview">Cancel</button>
                <button type="button" :disabled="profileBusy" @click="pinReviewedProfile">
                  {{ profileBusy ? 'Applying…' : 'Pin this profile' }}
                </button>
              </div>
            </div>

            <div v-else-if="showFirstUseCallout" class="first-use-callout">
              <div>
                <h4>Trust this first use</h4>
                <p>Review the authenticated values before creating the first browser profile.</p>
              </div>
              <button type="button" class="secondary" :disabled="profileBusy" @click="beginPcrReview">Review PCRs</button>
            </div>

            <div v-if="pcrProfiles.length" class="profile-list">
              <div v-for="(profile, index) in pcrProfiles" :key="profile.fingerprint" class="profile-row">
                <details>
                  <summary>
                    <span class="profile-chevron" aria-hidden="true">›</span>
                    <span class="profile-summary-copy">
                      <b>Profile {{ index + 1 }}</b>
                      <small>{{ profileSourceLabel(profile) }} · {{ formatTimestamp(profile.addedAt) }}</small>
                    </span>
                    <span v-if="profile.fingerprint === matchedProfileFingerprint" class="status-pill status-pill--success">Matched</span>
                  </summary>
                  <p class="profile-fingerprint"><span>Fingerprint</span><code>{{ profile.fingerprint }}</code></p>
                  <dl class="pcr-value-list">
                    <div v-for="name in profilePcrNames(profile)" :key="name">
                      <dt>{{ name }}</dt><dd><code>{{ profile.pcrs[name] }}</code></dd>
                    </div>
                  </dl>
                </details>
                <div class="profile-actions">
                  <template v-if="pendingRemovalFingerprint === profile.fingerprint">
                    <span>Remove?</span>
                    <button type="button" class="secondary compact-button" :disabled="profileBusy" @click="cancelProfileRemoval">Cancel</button>
                    <button type="button" class="remove-button" :disabled="profileBusy" @click="removeProfile(profile, index)">Confirm</button>
                  </template>
                  <button v-else type="button" class="remove-button" :disabled="profileBusy" @click="requestProfileRemoval(profile.fingerprint)">Remove</button>
                </div>
              </div>
            </div>
            <p v-else-if="!reviewSnapshot" class="empty-state">No browser PCR profiles are pinned.</p>

            <details
              class="profile-additions"
              :open="profileAdditionsOpen"
              @toggle="profileAdditionsOpen = $event.currentTarget.open"
            >
              <summary>{{ profileAdditionsLabel }}</summary>
              <div class="profile-additions__content">
                <div class="pcr-import" @dragover.prevent @drop.prevent="handlePcrDrop">
                  <input
                    id="expected-e2ee-pcr-file"
                    type="file"
                    accept=".pcrs,.json,text/plain,application/json"
                    @change="handlePcrSelection"
                  />
                  <label for="expected-e2ee-pcr-file">
                    <b>Import a profile</b>
                    <span>Choose or drop an enclave.pcrs or trusted_hashes.json file</span>
                  </label>
                </div>
                <details class="manual-pcr" :open="Boolean(pcrInput)">
                  <summary>Advanced: paste a profile manually</summary>
                  <form @submit.prevent="addManualProfile">
                    <textarea
                      v-model="pcrInput"
                      rows="6"
                      spellcheck="false"
                      placeholder="PCR0=…&#10;PCR1=…&#10;PCR2=…"
                    ></textarea>
                    <button type="submit" :disabled="!pcrInput.trim() || profileBusy">Add profile</button>
                  </form>
                </details>
              </div>
            </details>
            <p v-if="profileError" class="form-error" role="alert">{{ profileError }}</p>
            <p v-if="profileWarning" class="form-error" role="alert">{{ profileWarning }}</p>
            <p v-if="profileNotice" class="small-note" aria-live="polite">{{ profileNotice }}</p>
          </section>
        </section>

        <section class="card request-card">
          <div class="section-heading">
            <p class="metadata-label">Protected request</p>
            <h2>Send a request through STEVE</h2>
          </div>
          <form class="request-form" @submit.prevent="sendRequest">
            <div class="request-command">
              <label>
                <span>Method</span>
                <select v-model="requestMethod">
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                </select>
              </label>
              <label class="request-path">
                <span>Origin-relative path</span>
                <input v-model="requestPath" type="text" spellcheck="false" placeholder="/v1/health" />
              </label>
              <button type="submit" :disabled="sessionBusy || requestBusy || !requestGate.allowed">
                {{ requestBusy ? 'Sending…' : 'Send' }}
              </button>
            </div>
            <template v-if="requestMethod === 'POST'">
              <div class="request-body-heading">
                <span>Request body <small>64 KiB maximum</small></span>
                <fieldset class="segmented-control">
                  <legend class="visually-hidden">Body format</legend>
                  <label>
                    <input v-model="requestBodyType" class="visually-hidden" type="radio" name="request-body-type" value="json" />
                    <span>JSON</span>
                  </label>
                  <label>
                    <input v-model="requestBodyType" class="visually-hidden" type="radio" name="request-body-type" value="text" />
                    <span>Text</span>
                  </label>
                </fieldset>
              </div>
              <textarea v-model="requestBody" rows="4" spellcheck="false" aria-label="Request body"></textarea>
            </template>
            <div v-if="showTestDataModeWarning" class="request-warning">
              <div>
                <h3>Deployment identity is not checked</h3>
                <p>Send only non-sensitive test data until a browser PCR profile is pinned.</p>
              </div>
              <button
                type="button"
                class="secondary"
                :aria-pressed="nonSensitiveAcknowledged"
                @click="nonSensitiveAcknowledged = !nonSensitiveAcknowledged"
              >
                {{ nonSensitiveAcknowledged ? 'Test-data mode enabled' : 'Enable test-data mode' }}
              </button>
            </div>
            <p v-if="!requestGate.allowed && !showTestDataModeWarning" class="gate-message">{{ requestGate.reason }}</p>
            <p v-if="requestError" class="form-error" role="alert">{{ requestError }}</p>
          </form>

          <div v-if="requestResult" class="response-card" aria-live="polite">
            <div class="response-summary">
              <span class="status-pill status-pill--success">STEVE protected</span>
              <span>HTTP {{ requestResult.status }}</span>
              <span>Round trip {{ Math.round(requestResult.durationMs) }} ms</span>
              <span>{{ requestResult.contentType }}</span>
            </div>
            <details
              v-if="requestResult.exchange"
              class="response-exchange"
              :open="responseExchangeOpen"
              @toggle="responseExchangeOpen = $event.currentTarget.open"
            >
              <summary>Exchange details</summary>
              <div class="response-exchange__content">
                <dl class="exchange-list">
                  <div>
                    <dt>Inner request</dt>
                    <dd>{{ requestResult.method }} {{ requestResult.path }}</dd>
                  </div>
                  <div>
                    <dt>Outer exchange</dt>
                    <dd>POST /e2p/v2/request · application/cbor · HTTP {{ requestResult.exchange.outerStatus }}</dd>
                  </div>
                  <div>
                    <dt>Protection</dt>
                    <dd>
                      {{ requestResult.exchange.protocolName }} · {{ requestResult.exchange.protection }} ·
                      {{ requestResult.exchange.keyExchange }} · {{ pcrTrustLabel(requestResult.exchange.pcrTrust) }}
                    </dd>
                  </div>
                  <div>
                    <dt>Binding</dt>
                    <dd>session {{ requestResult.exchange.sessionId }} · sequence {{ requestResult.exchange.sequence }} authenticated</dd>
                  </div>
                  <div>
                    <dt>Request sizes</dt>
                    <dd>
                      body {{ formatByteCount(requestResult.requestBodyBytes) }} ·
                      CBOR {{ formatByteCount(requestResult.exchange.requestPlaintextBytes) }} ·
                      ciphertext {{ formatByteCount(requestResult.exchange.requestCiphertextBytes) }} ·
                      envelope {{ formatByteCount(requestResult.exchange.requestEnvelopeBytes) }}
                    </dd>
                  </div>
                  <div>
                    <dt>Response sizes</dt>
                    <dd>
                      body {{ formatByteCount(requestResult.responseBodyBytes) }} ·
                      CBOR {{ formatByteCount(requestResult.exchange.responsePlaintextBytes) }} ·
                      ciphertext {{ formatByteCount(requestResult.exchange.responseCiphertextBytes) }} ·
                      envelope {{ formatByteCount(requestResult.exchange.responseEnvelopeBytes) }}
                    </dd>
                  </div>
                </dl>
                <details
                  class="response-headers"
                  :open="responseHeadersOpen"
                  @toggle="responseHeadersOpen = $event.currentTarget.open"
                >
                  <summary>Response headers ({{ requestResult.responseHeaders.length }})</summary>
                  <pre>{{ formatResponseHeaders(requestResult.responseHeaders) }}</pre>
                </details>
              </div>
            </details>
            <details
              class="response-preview"
              :open="responseBodyOpen"
              @toggle="responseBodyOpen = $event.currentTarget.open"
            >
              <summary>Response body{{ requestResult.truncated ? ' (truncated)' : '' }}</summary>
              <pre>{{ requestResult.preview || '(empty body)' }}</pre>
            </details>
            <p v-if="!requestResult.ok" class="small-note">
              This is an authenticated application HTTP error, not a STEVE transport failure.
            </p>
          </div>
        </section>

        <details class="card setup-card" :open="corsTroubleshootingNeeded">
          <summary>
            <span><small>Setup</small><b>CORS and target configuration</b></span>
            <span class="status-pill status-pill--neutral">Exact origin</span>
          </summary>
          <div class="setup-content">
            <p>Configure this page’s exact origin and the same deployment-fixed suite, then redeploy.</p>
            <pre><code>{{ corsExample }}</code></pre>
            <p>STEVE must allow POST and OPTIONS on <code>/e2p/v2/</code> from <code>{{ pageOrigin }}</code>. Wildcards are rejected.</p>
          </div>
        </details>
      </template>
    </main>
  </div>
</template>

<script>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import CompactPageHeader from '../components/CompactPageHeader.vue'
import { readExpectedPcrFile } from '../utils/publicAttestation.js'
import {
  REQUIRED_PCRS,
  STEVE_SUITES,
  buildE2eeChooserUrl,
  buildControlledTesterTarget,
  buildSteveCorsExample,
  classifyE2eePcrs,
  compareSessionPcrProfiles,
  connectSteveSession,
  createE2eePcrProfile,
  describeSteveError,
  describeSteveTrustState,
  externalSteveOrigin,
  hasDebugPcrs,
  isAuthenticatedSteveStatus,
  isPcrPolicyMismatch,
  loadE2eePcrProfiles,
  normalizeE2eePcrProfiles,
  normalizeE2eePcrs,
  parseE2eePcrProfile,
  parseE2eeChooserDefaults,
  protectedRequestGate,
  reconcileE2eePcrProfiles,
  resolveControlledTesterTarget,
  saveE2eePcrProfiles,
  sendProtectedRequest,
} from '../utils/publicE2ee.js'

function sortedPcrNames(pcrs) {
  return Object.keys(pcrs || {})
    .filter((name) => /^PCR\d+$/u.test(name))
    .sort((left, right) => Number(left.slice(3)) - Number(right.slice(3)))
}

function formatByteCount(value) {
  const bytes = Number(value)
  return Number.isSafeInteger(bytes) && bytes >= 0
    ? `${bytes.toLocaleString()} B`
    : 'Unavailable'
}

function formatResponseHeaders(headers) {
  if (!headers?.length) return '(none)'
  return headers.map(([name, value]) => `${name}: ${value}`).join('\n')
}

function pcrTrustLabel(value) {
  return {
    pinned: 'Pinned matched',
    'not-checked': 'Not checked',
    'tofu-enrolled': 'TOFU enrolled',
    'tofu-matched': 'TOFU matched',
  }[value] || 'Unavailable'
}

export default {
  name: 'PublicE2ee',
  components: { CompactPageHeader },
  setup() {
    const mode = ref('loading')
    const pageError = ref('')
    const pageOrigin = window.location.origin
    const suites = STEVE_SUITES
    const trustOptions = [
      { value: 'tofu', label: 'TOFU', description: 'Review the first authenticated PCRs, then pin them.' },
      { value: 'pinned', label: 'Pinned', description: 'Load approved release measurements before connecting.' },
      { value: 'none', label: 'None', description: 'Test the channel with non-sensitive data only.' },
    ]
    const requiredPcrNames = REQUIRED_PCRS
    const target = ref(null)
    const targetInput = ref('')
    const selectedSuite = ref('X25519')
    const trustIntent = ref('tofu')
    const targetBusy = ref(false)
    const inputError = ref('')

    const sdkReady = ref(false)
    const sessionBusy = ref(false)
    const sessionError = ref(null)
    const sessionStatus = ref(null)
    let adapter = null
    let stopAdapterEvents = null
    let profileNoticeTimer = null

    const evidenceOpen = ref(false)
    const trustPolicyOpen = ref(false)
    const pcrProfiles = ref([])
    const profileBusy = ref(false)
    const profileError = ref('')
    const profileWarning = ref('')
    const profileNotice = ref('')
    const profileAdditionsOpen = ref(false)
    const pendingRemovalFingerprint = ref('')
    const pcrInput = ref('')
    const reviewSnapshot = ref(null)
    const selectedAdditionalPcrs = ref([])
    const nonSensitiveAcknowledged = ref(false)

    const requestMethod = ref('GET')
    const requestPath = ref('/')
    const requestBodyType = ref('json')
    const requestBody = ref('{}')
    const requestBusy = ref(false)
    const requestError = ref('')
    const requestResult = ref(null)
    const responseExchangeOpen = ref(false)
    const responseHeadersOpen = ref(false)
    const responseBodyOpen = ref(false)
    let responseDisclosuresInitialized = false

    const targetHostname = computed(() => new URL(target.value.origin).hostname)
    const sessionAuthenticated = computed(() => isAuthenticatedSteveStatus(sessionStatus.value))
    const isDebugSession = computed(() => hasDebugPcrs(sessionStatus.value?.attestation?.pcrs))
    const pcrPolicyMismatch = computed(() => isPcrPolicyMismatch(sessionError.value))
    const pcrComparison = computed(() => compareSessionPcrProfiles(sessionStatus.value, pcrProfiles.value))
    const matchedProfileFingerprint = computed(() => pcrComparison.value?.profileFingerprint || '')
    const authenticatedPcrs = computed(() => classifyE2eePcrs(sessionStatus.value?.attestation?.pcrs))
    const authenticatedPcrNames = computed(() =>
      [...authenticatedPcrs.value.required, ...authenticatedPcrs.value.optional].map(({ name }) => name),
    )
    const authenticatedZeroPcrNames = computed(() => authenticatedPcrs.value.zero.map(({ name }) => name))
    const authenticatedMalformedPcrNames = computed(() => authenticatedPcrs.value.malformed.map(({ name }) => name))
    const reviewPcrs = computed(() => classifyE2eePcrs(reviewSnapshot.value?.pcrs))
    const reviewPcrNames = computed(() =>
      [...reviewPcrs.value.required, ...reviewPcrs.value.optional].map(({ name }) => name),
    )
    const reviewZeroPcrNames = computed(() => reviewPcrs.value.zero.map(({ name }) => name))
    const reviewMalformedPcrNames = computed(() => reviewPcrs.value.malformed.map(({ name }) => name))
    const canReviewCurrent = computed(() => sessionAuthenticated.value && !isDebugSession.value)
    const changeTargetHref = computed(() =>
      target.value ? buildE2eeChooserUrl(target.value.origin, target.value.suite, activeTrustLabel.value.toLowerCase()) : '/verify-e2ee/',
    )
    const showFirstUseCallout = computed(() =>
      trustIntent.value === 'tofu' && canReviewCurrent.value && pcrProfiles.value.length === 0,
    )
    const requestGate = computed(() => {
      if (trustIntent.value !== 'none' && pcrProfiles.value.length === 0) {
        return {
          allowed: false,
          reason: trustIntent.value === 'pinned'
            ? 'Add an approved PCR profile before sending a request.'
            : 'Review and accept the first authenticated PCR profile before sending a request.',
        }
      }
      return protectedRequestGate(
        sessionStatus.value,
        pcrProfiles.value.length,
        nonSensitiveAcknowledged.value,
        sessionError.value,
      )
    })
    const showTestDataModeWarning = computed(() =>
      trustIntent.value === 'none' &&
        sessionAuthenticated.value &&
        pcrProfiles.value.length === 0 &&
        !isDebugSession.value,
    )
    const primarySessionAction = computed(() => {
      if (sessionAuthenticated.value) return null
      if (pcrPolicyMismatch.value) return null
      if (trustIntent.value === 'pinned' && pcrProfiles.value.length === 0) return null
      return sessionStatus.value?.state === 'error' || sessionStatus.value?.initialized
        ? { action: 'reconnect', label: 'Reconnect' }
        : { action: 'establish', label: 'Establish session' }
    })
    const sessionCheck = computed(() => {
      if (sessionBusy.value) return { label: 'Checking', tone: 'neutral' }
      if (sessionAuthenticated.value) return { label: 'Authenticated', tone: 'success' }
      if (sessionError.value || sessionStatus.value?.state === 'error') return { label: 'Failed', tone: 'danger' }
      return { label: 'Not established', tone: 'neutral' }
    })
    const trustSummary = computed(() => {
      if (
        sdkReady.value &&
        trustIntent.value === 'pinned' &&
        pcrProfiles.value.length === 0 &&
        !sessionError.value
      ) {
        return {
          badge: 'Policy needed',
          tone: 'warning',
          title: 'Add an approved PCR profile',
          message: 'The tester will connect after a complete profile is loaded.',
        }
      }
      return describeSteveTrustState(
        sessionStatus.value,
        pcrProfiles.value.length,
        { busy: sessionBusy.value || profileBusy.value, error: sessionError.value, sdkReady: sdkReady.value },
      )
    })
    const activeTrustLabel = computed(() => {
      if (pcrProfiles.value.length) return 'Pinned'
      return { tofu: 'TOFU', pinned: 'Pinned', none: 'None' }[trustIntent.value]
    })
    const profileAdditionsLabel = computed(() => {
      if (pcrPolicyMismatch.value) return 'Add an independently approved profile'
      if (pcrProfiles.value.length) return 'Add another profile'
      return trustIntent.value === 'pinned' ? 'Add an approved profile' : 'Use an existing profile instead'
    })
    const sessionErrorMessage = computed(() =>
      sessionError.value && !pcrPolicyMismatch.value ? describeSteveError(sessionError.value, pageOrigin) : '',
    )
    const protocolName = computed(() => {
      const protocol = sessionStatus.value?.protocol
      if (!protocol) return 'Unavailable'
      return `${protocol.id || 'STEVE-E2P'} v${protocol.version || sessionStatus.value.protocolVersion}`
    })
    const corsTroubleshootingNeeded = computed(() =>
      ['TRANSPORT', 'TIMEOUT', 'HTTP_STATUS'].includes(sessionError.value?.code),
    )
    const corsExample = computed(() => buildSteveCorsExample(pageOrigin, target.value.suite))
    const chooserCorsExample = computed(() => buildSteveCorsExample(pageOrigin, selectedSuite.value))

    function formatTimestamp(value) {
      if (!value) return 'Unavailable'
      return new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
    }

    function profileSourceLabel(profile) {
      return {
        'first-use': 'Reviewed first use',
        build: 'Build output',
        cli: 'Caution CLI state',
        manual: 'Manual entry',
        remembered: 'Migrated browser profile',
        worker: 'Worker policy',
      }[profile.source] || 'Imported profile'
    }

    function profilePcrNames(profile) {
      return sortedPcrNames(profile.pcrs)
    }

    function showProfileNotice(message) {
      window.clearTimeout(profileNoticeTimer)
      profileNotice.value = message
      profileNoticeTimer = window.setTimeout(() => { profileNotice.value = '' }, 5_000)
    }

    function canonicalizeTrustMode() {
      if (!target.value) return
      const current = new URL(window.location.href)
      if (current.searchParams.get('trust') === trustIntent.value) return
      current.searchParams.set('trust', trustIntent.value)
      window.history.replaceState(window.history.state, '', `${current.pathname}${current.search}`)
    }

    function acceptSessionError(error) {
      sessionError.value = error
      if (isPcrPolicyMismatch(error)) {
        trustPolicyOpen.value = true
        profileAdditionsOpen.value = true
      }
    }

    async function submitTarget() {
      inputError.value = ''
      targetBusy.value = true
      try {
        const origin = externalSteveOrigin(targetInput.value, pageOrigin)
        const destination = new URL(
          (await buildControlledTesterTarget(origin, selectedSuite.value)).url,
          window.location.origin,
        )
        destination.searchParams.set('trust', trustIntent.value)
        window.location.assign(`${destination.pathname}${destination.search}`)
      } catch (error) {
        inputError.value = error.message
        targetBusy.value = false
      }
    }

    function resetRequestState({ preserveDisclosures = false } = {}) {
      requestResult.value = null
      requestError.value = ''
      nonSensitiveAcknowledged.value = false
      if (!preserveDisclosures) {
        responseExchangeOpen.value = false
        responseHeadersOpen.value = false
        responseBodyOpen.value = false
        responseDisclosuresInitialized = false
      }
    }

    function acceptStatus(status, preserveDisclosures = requestBusy.value) {
      const previousSessionId = sessionStatus.value?.session?.id
      sessionStatus.value = status
      if (previousSessionId && previousSessionId !== status?.session?.id) {
        resetRequestState({ preserveDisclosures })
      }
      if (status?.state !== 'error') sessionError.value = null
    }

    async function runSessionAction(action) {
      if (!adapter || sessionBusy.value) return
      sessionBusy.value = true
      sessionError.value = null
      resetRequestState()
      try {
        acceptStatus(await adapter[action]())
      } catch (error) {
        acceptSessionError(error)
        try { sessionStatus.value = await adapter.status() } catch { /* operation error is displayed */ }
      } finally {
        sessionBusy.value = false
      }
    }

    async function persistProfiles() {
      try {
        pcrProfiles.value = await saveE2eePcrProfiles(
          window.localStorage,
          target.value.origin,
          target.value.suite,
          pcrProfiles.value,
        )
      } catch {
        profileWarning.value = 'The SDK policy is active, but profile metadata could not be saved locally.'
      }
    }

    async function applyProfiles(nextProfiles, notice) {
      if (!adapter || profileBusy.value) return
      profileBusy.value = true
      profileError.value = ''
      profileWarning.value = ''
      profileNotice.value = ''
      window.clearTimeout(profileNoticeTimer)
      const reestablish = Boolean(sessionStatus.value?.initialized || sessionStatus.value?.session)
      try {
        const normalized = await normalizeE2eePcrProfiles(nextProfiles)
        const { status } = await adapter.replacePcrProfiles(normalized)
        pcrProfiles.value = normalized
        acceptStatus(status)
        await persistProfiles()
        showProfileNotice(notice)
        reviewSnapshot.value = null
        selectedAdditionalPcrs.value = []
        pendingRemovalFingerprint.value = ''
        resetRequestState()
        if (reestablish) acceptStatus(await adapter.establish())
        return true
      } catch (error) {
        profileError.value = describeSteveError(error, pageOrigin)
        if (error?.code?.startsWith('PCR_')) acceptSessionError(error)
        return false
      } finally {
        profileBusy.value = false
      }
    }

    async function addProfile(pcrs, source) {
      const profile = await createE2eePcrProfile(pcrs, source)
      if (pcrProfiles.value.some((existing) => existing.fingerprint === profile.fingerprint)) {
        showProfileNotice('That complete profile is already pinned.')
        return false
      }
      const notice = source === 'first-use'
        ? 'Pinned the reviewed first-use profile.'
        : source === 'manual'
          ? 'Added the manually entered profile.'
          : 'Imported an approved PCR profile.'
      if (await applyProfiles([...pcrProfiles.value, profile], notice)) {
        trustIntent.value = 'pinned'
        canonicalizeTrustMode()
        return true
      }
      return false
    }

    async function importExpectedPcrFile(file) {
      profileError.value = ''
      try {
        const profile = await readExpectedPcrFile(file)
        await addProfile(profile.pcrs, profile.source || 'file')
      } catch (error) {
        profileError.value = error.message
      }
    }

    async function handlePcrSelection(event) {
      const file = event.target.files?.[0]
      if (file) await importExpectedPcrFile(file)
      event.target.value = ''
    }

    async function handlePcrDrop(event) {
      const file = event.dataTransfer?.files?.[0]
      if (file) await importExpectedPcrFile(file)
    }

    async function addManualProfile() {
      profileError.value = ''
      try {
        await addProfile(parseE2eePcrProfile(pcrInput.value), 'manual')
        pcrInput.value = ''
      } catch (error) {
        profileError.value = error.message
      }
    }

    async function beginPcrReview() {
      profileError.value = ''
      try {
        const status = await adapter.status()
        if (!isAuthenticatedSteveStatus(status)) throw new Error('Establish an authenticated session first.')
        const required = Object.fromEntries(REQUIRED_PCRS.map((name) => [name, status.attestation.pcrs?.[name]]))
        normalizeE2eePcrs(required)
        const reviewPcrs = Object.fromEntries(
          sortedPcrNames(status.attestation.pcrs).map((name) => [name, status.attestation.pcrs[name]]),
        )
        reviewSnapshot.value = { sessionId: status.session.id, pcrs: reviewPcrs }
        selectedAdditionalPcrs.value = []
        trustPolicyOpen.value = true
      } catch (error) {
        profileError.value = error.message
      }
    }

    function isSelectableReviewPcr(name) {
      const value = String(reviewSnapshot.value?.pcrs?.[name] || '').toLowerCase()
      return /^[0-9a-f]{96}$/u.test(value) && value !== '0'.repeat(96)
    }

    function toggleReviewPcr(name) {
      if (!isSelectableReviewPcr(name)) return
      selectedAdditionalPcrs.value = selectedAdditionalPcrs.value.includes(name)
        ? selectedAdditionalPcrs.value.filter((candidate) => candidate !== name)
        : [...selectedAdditionalPcrs.value, name]
    }

    function cancelPcrReview() {
      reviewSnapshot.value = null
      selectedAdditionalPcrs.value = []
    }

    async function pinReviewedProfile() {
      profileError.value = ''
      try {
        const current = await adapter.status()
        if (current?.session?.id !== reviewSnapshot.value?.sessionId) {
          throw new Error('The session changed. Review the current PCRs again.')
        }
        const names = [...REQUIRED_PCRS, ...selectedAdditionalPcrs.value]
        const pcrs = Object.fromEntries(names.map((name) => [name, reviewSnapshot.value.pcrs[name]]))
        for (const name of names) {
          if (current.attestation?.pcrs?.[name] !== pcrs[name]) {
            throw new Error('The authenticated PCRs changed. Review the current session again.')
          }
        }
        await addProfile(normalizeE2eePcrs(pcrs), 'first-use')
      } catch (error) {
        profileError.value = error.message
      }
    }

    function requestProfileRemoval(fingerprint) {
      pendingRemovalFingerprint.value = fingerprint
    }

    function cancelProfileRemoval() {
      pendingRemovalFingerprint.value = ''
    }

    async function removeProfile(profile, index) {
      await applyProfiles(
        pcrProfiles.value.filter((candidate) => candidate.fingerprint !== profile.fingerprint),
        `Removed Profile ${index + 1}.`,
      )
    }

    async function sendRequest() {
      if (!adapter || sessionBusy.value || !requestGate.value.allowed || requestBusy.value) return
      requestBusy.value = true
      requestError.value = ''
      requestResult.value = null
      try {
        const { status, result } = await sendProtectedRequest(
          adapter,
          sessionStatus.value,
          pcrProfiles.value.length,
          nonSensitiveAcknowledged.value,
          {
            method: requestMethod.value,
            path: requestPath.value,
            bodyType: requestBodyType.value,
            body: requestBody.value,
          },
        )
        if (!responseDisclosuresInitialized) {
          responseBodyOpen.value = !result.truncated && result.preview.length <= 2048
          responseDisclosuresInitialized = true
        }
        acceptStatus(status, true)
        requestResult.value = result
      } catch (error) {
        requestResult.value = null
        requestError.value = describeSteveError(error, pageOrigin)
      } finally {
        requestBusy.value = false
      }
    }

    onMounted(async () => {
      try {
        target.value = await resolveControlledTesterTarget(window.location.pathname, window.location.search)
        if (target.value) externalSteveOrigin(target.value.origin, pageOrigin)
      } catch (error) {
        pageError.value = error.message
        mode.value = 'error'
        return
      }
      if (!target.value) {
        try {
          const defaults = parseE2eeChooserDefaults(window.location.search, pageOrigin)
          if (defaults) {
            targetInput.value = defaults.origin
            selectedSuite.value = defaults.suite
            trustIntent.value = defaults.trust
          }
        } catch (error) {
          inputError.value = error.message
        }
        mode.value = 'chooser'
        return
      }

      mode.value = 'tester'
      targetInput.value = target.value.origin
      selectedSuite.value = target.value.suite
      const requestedTrust = new URLSearchParams(window.location.search).get('trust')
      trustIntent.value = ['none', 'pinned', 'tofu'].includes(requestedTrust) ? requestedTrust : 'tofu'
      trustPolicyOpen.value = trustIntent.value !== 'none'
      profileAdditionsOpen.value = trustIntent.value === 'pinned'
      let storedProfiles = []
      try {
        storedProfiles = await loadE2eePcrProfiles(window.localStorage, target.value.origin, target.value.suite)
      } catch {
        profileWarning.value = 'Browser profile metadata is unavailable.'
      }

      try {
        adapter = await connectSteveSession(target.value)
        const reconciliation = await reconcileE2eePcrProfiles(await adapter.getPcrPolicy(), storedProfiles)
        pcrProfiles.value = reconciliation.profiles
        if (pcrProfiles.value.length) {
          trustIntent.value = 'pinned'
          trustPolicyOpen.value = false
          canonicalizeTrustMode()
        }
        if (reconciliation.replaceWorkerPolicy) {
          acceptStatus((await adapter.replacePcrProfiles(pcrProfiles.value)).status)
        }
        if (pcrProfiles.value.length) await persistProfiles()
        stopAdapterEvents = adapter.onChange(acceptStatus, acceptSessionError)
        acceptStatus(await adapter.status())
        sdkReady.value = true
      } catch (error) {
        acceptSessionError(error)
      }
    })

    onUnmounted(() => {
      stopAdapterEvents?.()
      window.clearTimeout(profileNoticeTimer)
    })

    return {
      addManualProfile,
      activeTrustLabel,
      authenticatedMalformedPcrNames,
      authenticatedPcrNames,
      authenticatedZeroPcrNames,
      beginPcrReview,
      cancelPcrReview,
      cancelProfileRemoval,
      changeTargetHref,
      chooserCorsExample,
      corsExample,
      corsTroubleshootingNeeded,
      evidenceOpen,
      formatByteCount,
      formatResponseHeaders,
      formatTimestamp,
      handlePcrDrop,
      handlePcrSelection,
      inputError,
      isSelectableReviewPcr,
      matchedProfileFingerprint,
      mode,
      nonSensitiveAcknowledged,
      pageError,
      pageOrigin,
      pcrInput,
      pcrProfiles,
      pendingRemovalFingerprint,
      pinReviewedProfile,
      primarySessionAction,
      profileBusy,
      profileAdditionsLabel,
      profileAdditionsOpen,
      profileError,
      profileNotice,
      profileWarning,
      profilePcrNames,
      profileSourceLabel,
      pcrTrustLabel,
      protocolName,
      removeProfile,
      requestBody,
      requestBodyType,
      requestBusy,
      requestError,
      requestGate,
      requestMethod,
      requestPath,
      requestResult,
      requestProfileRemoval,
      requiredPcrNames,
      responseBodyOpen,
      responseExchangeOpen,
      responseHeadersOpen,
      reviewPcrNames,
      reviewMalformedPcrNames,
      reviewSnapshot,
      reviewZeroPcrNames,
      runSessionAction,
      sdkReady,
      selectedAdditionalPcrs,
      selectedSuite,
      sendRequest,
      sessionAuthenticated,
      sessionBusy,
      sessionCheck,
      sessionErrorMessage,
      sessionStatus,
      showFirstUseCallout,
      showTestDataModeWarning,
      submitTarget,
      suites,
      target,
      targetBusy,
      targetHostname,
      targetInput,
      toggleReviewPcr,
      trustIntent,
      trustOptions,
      trustPolicyOpen,
      trustSummary,
    }
  },
}
</script>

<style scoped>
.public-e2ee-page {
  --e2ee-text: var(--theme-text-primary, #0f0f0f);
  --e2ee-muted: var(--theme-text-secondary, #56636f);
  --e2ee-card: var(--theme-surface-translucent, rgba(255, 255, 255, 0.88));
  --e2ee-surface: var(--theme-surface, #fff);
  --e2ee-subtle: var(--theme-surface-subtle, #f8fafc);
  --e2ee-muted-surface: var(--theme-surface-muted, #e8edf3);
  --e2ee-border: var(--theme-border, rgba(15, 15, 15, 0.12));
  --e2ee-border-strong: var(--theme-border-strong, #b8c2cc);
  --e2ee-control: var(--theme-control, #0f0f0f);
  --e2ee-control-hover: var(--theme-control-hover, #333);
  --e2ee-control-text: var(--theme-control-text, #fff);
  --e2ee-code: var(--theme-code, #111827);
  --e2ee-code-text: var(--theme-code-text, #f8fafc);
  --e2ee-focus: var(--theme-focus, #2e6aea);
  --e2ee-focus-ring: var(--theme-focus-ring, rgba(46, 106, 234, 0.22));
  --e2ee-link: var(--theme-info, #1559a6);
  --e2ee-success: var(--theme-success-strong, #2e7d32);
  --e2ee-success-bg: var(--theme-success-bg, #f0f9f1);
  --e2ee-success-border: var(--theme-success-border, #a5d6a7);
  --e2ee-warning: var(--theme-warning, #92400e);
  --e2ee-warning-bg: var(--theme-warning-bg, #fef3c7);
  --e2ee-warning-border: var(--theme-warning-border, #fde68a);
  --e2ee-danger: var(--theme-danger-strong, #c62828);
  --e2ee-danger-bg: var(--theme-danger-bg, #fff3f3);
  --e2ee-danger-border: var(--theme-danger-border, #ef9a9a);
  --e2ee-shadow: var(--theme-shadow, 0 12px 36px rgba(46, 106, 234, 0.08));
  min-height: 100vh;
  color: var(--e2ee-text);
}

.public-e2ee-main {
  width: min(860px, calc(100% - 40px));
  margin: 42px auto 80px;
}

.public-e2ee-intro {
  max-width: 720px;
  margin-bottom: 32px;
}

.eyebrow,
.metadata-label {
  margin: 0;
  color: var(--e2ee-muted);
  font-size: 0.76rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

h1 {
  margin: 10px 0 14px;
  font-size: clamp(2.1rem, 6vw, 3.55rem);
  line-height: 1.08;
  letter-spacing: -0.04em;
}

.public-e2ee-intro > p:last-child,
.section-heading > p,
.status-line__copy > p:last-child,
.review-card p,
.first-use-callout p,
.setup-content p {
  color: var(--e2ee-muted);
  line-height: 1.55;
}

.card {
  margin-bottom: 18px;
  border: 1px solid var(--e2ee-border);
  border-radius: 16px;
  background: var(--e2ee-card);
  box-shadow: var(--e2ee-shadow);
}

.chooser-card,
.error-card,
.request-card,
.control-center {
  padding: 24px;
}

.section-heading {
  display: grid;
  gap: 5px;
  margin-bottom: 20px;
}

.section-heading h2,
.section-heading p,
.target-heading h2,
.embedded-panel h3,
.review-card h4,
.first-use-callout h4,
.request-warning h3,
.error-card h2 {
  margin: 0;
}

.target-form,
.request-form {
  display: grid;
  gap: 14px;
}

label,
legend,
.request-body-heading > span {
  font-weight: 600;
}

input,
select,
textarea,
button,
.action-menu summary {
  font: inherit;
}

input,
select,
textarea {
  width: 100%;
  border: 1px solid var(--e2ee-border-strong);
  border-radius: 10px;
  padding: 11px 13px;
  color: var(--e2ee-text);
  background: var(--e2ee-surface);
}

textarea {
  resize: vertical;
  font-family: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Consolas, monospace;
}

input:focus,
select:focus,
textarea:focus,
button:focus-visible,
summary:focus-visible,
a:focus-visible {
  outline: 2px solid var(--e2ee-focus);
  outline-offset: 2px;
  box-shadow: 0 0 0 4px var(--e2ee-focus-ring);
}

button,
.action-menu summary {
  width: fit-content;
  border: 1px solid var(--e2ee-control);
  border-radius: 999px;
  padding: 9px 16px;
  color: var(--e2ee-control-text);
  background: var(--e2ee-control);
  font-weight: 650;
  cursor: pointer;
}

button:hover:not(:disabled),
.action-menu summary:hover {
  background: var(--e2ee-control-hover);
}

button:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

button.secondary,
.action-menu summary,
.remove-button {
  color: var(--e2ee-text);
  background: transparent;
  border-color: var(--e2ee-border-strong);
}

.text-link,
.text-button {
  color: var(--e2ee-link);
  font-weight: 600;
}

.text-button {
  border: 0;
  border-radius: 4px;
  padding: 2px 0;
  background: transparent;
  text-decoration: underline;
  text-underline-offset: 3px;
}

.text-button:hover:not(:disabled) {
  background: transparent;
}

code {
  overflow-wrap: anywhere;
  font-family: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Consolas, monospace;
  font-weight: 400;
}

.small-note,
.gate-message,
.empty-state {
  margin: 0;
  color: var(--e2ee-muted);
  font-size: 0.87rem;
  line-height: 1.5;
}

.form-error {
  margin: 5px 0 0;
  color: var(--e2ee-danger);
  line-height: 1.45;
}

.suite-picker,
.trust-picker {
  margin: 0;
  padding: 0;
  border: 0;
}

.suite-picker__options,
.trust-picker__options {
  display: grid;
  gap: 10px;
  margin-top: 8px;
}

.suite-picker__options {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.trust-picker__options {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.suite-option > span,
.trust-option > span {
  display: grid;
  gap: 2px;
  border: 1px solid var(--e2ee-border-strong);
  border-radius: 10px;
  padding: 12px 14px;
  cursor: pointer;
}

.suite-option small,
.trust-option small {
  color: var(--e2ee-muted);
  font-size: 0.78rem;
  font-weight: 400;
  line-height: 1.35;
}

.suite-option input:checked + span,
.trust-option input:checked + span {
  border-color: var(--e2ee-focus);
  box-shadow: inset 0 0 0 1px var(--e2ee-focus);
}

.chooser-setup {
  display: grid;
  gap: 7px;
  border: 1px solid var(--e2ee-border);
  border-radius: 10px;
  padding: 13px 14px;
  background: var(--e2ee-subtle);
}

.chooser-setup p {
  margin: 0;
}

.chooser-setup pre {
  overflow: auto;
  margin: 2px 0 0;
  border-radius: 8px;
  padding: 12px;
  color: var(--e2ee-code-text);
  background: var(--e2ee-code);
  white-space: pre-wrap;
}

.control-center {
  display: grid;
  gap: 18px;
}

.target-heading,
.control-center__toolbar,
.embedded-panel__heading,
.first-use-callout,
.request-body-heading,
.response-summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.target-heading {
  align-items: flex-start;
}

.target-heading h2 {
  margin-top: 5px;
  font-size: 1.3rem;
}

.target-heading > div:first-child > code {
  display: block;
  margin-top: 4px;
  color: var(--e2ee-muted);
}

.target-heading__actions,
.disclosure-actions,
.session-controls,
.button-row {
  display: flex;
  align-items: center;
  gap: 12px;
}

.suite-pill,
.status-pill,
.selection-pill {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  padding: 5px 10px;
  font-size: 0.77rem;
  font-weight: 650;
  white-space: nowrap;
}

.suite-pill {
  border: 1px solid var(--e2ee-border-strong);
  color: var(--e2ee-muted);
}

.status-pill--neutral {
  color: var(--e2ee-muted);
  background: var(--e2ee-muted-surface);
}

.status-pill--success {
  color: var(--e2ee-control-text);
  background: var(--e2ee-success);
}

.status-pill--warning {
  color: var(--e2ee-warning);
  background: var(--e2ee-warning-bg);
}

.status-pill--danger {
  color: var(--e2ee-control-text);
  background: var(--e2ee-danger);
}

.status-line {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 12px;
  border: 1px solid var(--e2ee-border);
  border-radius: 12px;
  padding: 15px 16px;
  background: var(--e2ee-subtle);
}

.status-line--success { border-color: var(--e2ee-success-border); }
.status-line--warning { border-color: var(--e2ee-warning-border); }
.status-line--danger { border-color: var(--e2ee-danger-border); }

.status-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--e2ee-muted);
}

.status-line--success .status-dot { background: var(--e2ee-success); }
.status-line--warning .status-dot { background: var(--e2ee-warning); }
.status-line--danger .status-dot { background: var(--e2ee-danger); }

.status-line__copy h3 {
  margin: 3px 0 2px;
  font-size: 1.02rem;
}

.status-line__copy > p:last-child {
  margin: 0;
  font-size: 0.9rem;
}

.evidence-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin: 0;
  overflow: hidden;
  border: 1px solid var(--e2ee-border);
  border-radius: 10px;
  background: var(--e2ee-subtle);
}

.evidence-strip > div {
  min-width: 0;
  padding: 12px;
}

.evidence-strip > div + div {
  border-left: 1px solid var(--e2ee-border);
}

.evidence-strip dt,
.diagnostic-list dt,
.pcr-value-list dt {
  color: var(--e2ee-muted);
  font-size: 0.75rem;
}

.evidence-strip dd {
  margin: 5px 0 0;
  overflow-wrap: anywhere;
  font-family: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 0.79rem;
  font-weight: 400;
}

.action-menu {
  position: relative;
}

.action-menu summary {
  list-style: none;
}

.action-menu summary::-webkit-details-marker { display: none; }

.action-menu > div {
  position: absolute;
  z-index: 5;
  top: calc(100% + 7px);
  right: 0;
  display: grid;
  min-width: 170px;
  padding: 6px;
  border: 1px solid var(--e2ee-border);
  border-radius: 12px;
  background: var(--e2ee-surface);
  box-shadow: var(--e2ee-shadow);
}

.action-menu > div button {
  width: 100%;
  border: 0;
  border-radius: 7px;
  padding: 9px 10px;
  color: var(--e2ee-text);
  background: transparent;
  text-align: left;
}

.action-menu > div button:hover:not(:disabled) { background: var(--e2ee-subtle); }

.embedded-panel {
  display: grid;
  gap: 15px;
  padding: 18px;
  border: 1px solid var(--e2ee-border);
  border-radius: 12px;
  background: var(--e2ee-subtle);
}

.diagnostic {
  border-top: 1px solid var(--e2ee-border);
  padding-top: 12px;
}

.diagnostic summary,
.manual-pcr summary,
.profile-row summary {
  cursor: pointer;
  font-weight: 600;
}

.diagnostic-list,
.pcr-value-list {
  display: grid;
  gap: 0;
  margin: 10px 0 0;
}

.diagnostic-list > div,
.pcr-value-list > div {
  display: grid;
  grid-template-columns: minmax(120px, 0.32fr) minmax(0, 1fr);
  gap: 12px;
  padding: 8px 0;
  border-top: 1px solid var(--e2ee-border);
}

.diagnostic-list dd,
.pcr-value-list dd {
  margin: 0;
  overflow-wrap: anywhere;
  font-weight: 400;
}

.pcr-classification {
  margin-top: 10px;
  border-top: 1px solid var(--e2ee-border);
  padding-top: 10px;
  color: var(--e2ee-muted);
  font-size: 0.82rem;
}

.pcr-classification summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  cursor: pointer;
  font-weight: 600;
}

.pcr-classification__count {
  min-width: 24px;
  border-radius: 999px;
  padding: 2px 7px;
  background: var(--e2ee-muted-surface);
  text-align: center;
  font-size: 0.72rem;
  font-weight: 650;
}

.pcr-classification__content {
  display: grid;
  gap: 6px;
  margin-top: 9px;
}

.pcr-classification__content code {
  color: var(--e2ee-muted);
  font-size: 0.76rem;
}

.pcr-classification__content p { margin: 0; }

.review-card {
  display: grid;
  gap: 14px;
  padding: 16px;
  border: 1px solid var(--e2ee-warning-border);
  border-radius: 10px;
  background: var(--e2ee-warning-bg);
}

.review-card p,
.first-use-callout p {
  margin: 4px 0 0;
  font-size: 0.88rem;
}

.review-pcrs {
  overflow: hidden;
  border: 1px solid var(--e2ee-border);
  border-radius: 9px;
  background: var(--e2ee-surface);
}

.review-pcr-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 14px;
  padding: 10px 12px;
}

.review-pcr-row + .review-pcr-row { border-top: 1px solid var(--e2ee-border); }

.review-pcr-row > div {
  display: grid;
  grid-template-columns: 45px minmax(0, 1fr);
  gap: 8px;
  min-width: 0;
}

.review-pcr-row code {
  color: var(--e2ee-muted);
  font-size: 0.76rem;
}

.selection-pill {
  border: 1px solid var(--e2ee-border-strong);
  color: var(--e2ee-muted);
  background: transparent;
}

button.selection-pill {
  padding: 5px 10px;
}

.selection-pill--selected,
.selection-pill--fixed {
  border-color: var(--e2ee-success-border);
  color: var(--e2ee-success);
  background: var(--e2ee-success-bg);
}

.first-use-callout,
.request-warning {
  padding: 14px 15px;
  border: 1px solid var(--e2ee-warning-border);
  border-radius: 10px;
  background: var(--e2ee-warning-bg);
}

.first-use-callout button {
  flex: 0 0 auto;
  white-space: nowrap;
}

.profile-list {
  display: grid;
  gap: 8px;
}

.profile-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 10px;
  border: 1px solid var(--e2ee-border);
  border-radius: 10px;
  padding: 11px 12px;
  background: var(--e2ee-surface);
}

.profile-row details {
  min-width: 0;
}

.profile-row:has(details[open]) .profile-actions {
  align-self: start;
  margin-top: 10px;
}

.profile-row summary {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 9px;
  min-height: 34px;
  list-style: none;
}

.profile-row summary::-webkit-details-marker { display: none; }

.profile-summary-copy {
  display: grid;
  gap: 2px;
}

.profile-row summary small {
  color: var(--e2ee-muted);
  font-weight: 400;
}

.profile-chevron {
  color: var(--e2ee-muted);
  font-size: 1.2rem;
  line-height: 1;
  transition: transform 120ms ease;
}

.profile-row details[open] .profile-chevron { transform: rotate(90deg); }

.profile-fingerprint {
  display: grid;
  gap: 3px;
  margin: 10px 0 0 21px;
  color: var(--e2ee-muted);
  font-size: 0.76rem;
}

.profile-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  min-height: 34px;
  color: var(--e2ee-muted);
  font-size: 0.78rem;
}

.remove-button {
  padding: 6px 10px;
  color: var(--e2ee-danger);
  font-size: 0.78rem;
}

.compact-button {
  padding: 6px 10px;
  font-size: 0.78rem;
}

.profile-additions {
  border-top: 1px solid var(--e2ee-border);
  padding-top: 12px;
  color: var(--e2ee-muted);
}

.profile-additions > summary {
  width: fit-content;
  color: var(--e2ee-link);
  cursor: pointer;
  font-weight: 600;
}

.profile-additions__content {
  display: grid;
  gap: 12px;
  margin-top: 12px;
}

.pcr-import {
  position: relative;
}

.pcr-import input {
  position: absolute;
  width: 1px;
  height: 1px;
  opacity: 0;
}

.pcr-import label {
  display: grid;
  gap: 3px;
  border: 1px dashed var(--e2ee-border-strong);
  border-radius: 10px;
  padding: 13px 15px;
  cursor: pointer;
}

.pcr-import label span {
  color: var(--e2ee-muted);
  font-size: 0.84rem;
  font-weight: 400;
}

.manual-pcr form {
  display: grid;
  gap: 10px;
  margin-top: 10px;
}

.request-command {
  display: grid;
  grid-template-columns: 115px minmax(0, 1fr) auto;
  align-items: end;
  gap: 10px;
}

.request-command label {
  display: grid;
  gap: 6px;
}

.request-body-heading small {
  color: var(--e2ee-muted);
  font-weight: 400;
}

.segmented-control {
  display: inline-flex;
  margin: 0;
  padding: 3px;
  border: 1px solid var(--e2ee-border);
  border-radius: 999px;
  background: var(--e2ee-subtle);
}

.segmented-control span {
  display: block;
  border-radius: 999px;
  padding: 5px 11px;
  color: var(--e2ee-muted);
  cursor: pointer;
}

.segmented-control input:checked + span {
  color: var(--e2ee-text);
  background: var(--e2ee-surface);
  box-shadow: 0 1px 3px var(--e2ee-border);
}

.request-warning {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.response-card {
  margin-top: 18px;
  overflow: hidden;
  border: 1px solid var(--e2ee-border);
  border-radius: 11px;
  background: var(--e2ee-subtle);
}

.response-summary,
.response-preview,
.response-card > .small-note {
  padding: 12px 14px;
}

.response-summary {
  justify-content: flex-start;
  flex-wrap: wrap;
  border-bottom: 1px solid var(--e2ee-border);
}

.response-exchange {
  border-bottom: 1px solid var(--e2ee-border);
}

.response-exchange > summary,
.response-preview summary,
.response-headers summary {
  cursor: pointer;
}

.response-exchange > summary {
  padding: 12px 14px;
  font-weight: 600;
}

.response-exchange__content {
  padding: 0 14px 14px;
}

.exchange-list {
  display: grid;
  margin: 0;
}

.exchange-list > div {
  display: grid;
  grid-template-columns: 125px minmax(0, 1fr);
  gap: 12px;
  padding: 8px 0;
  border-top: 1px solid var(--e2ee-border);
}

.exchange-list dt {
  color: var(--e2ee-muted);
  font-size: 0.75rem;
}

.exchange-list dd {
  min-width: 0;
  margin: 0;
  overflow-wrap: anywhere;
  font-family: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 0.79rem;
  font-weight: 400;
}

.response-headers {
  margin-top: 12px;
  border-top: 1px solid var(--e2ee-border);
  padding-top: 12px;
}

.response-preview pre,
.response-headers pre,
.setup-content pre {
  overflow: auto;
  margin: 10px 0 0;
  border-radius: 8px;
  padding: 12px;
  color: var(--e2ee-code-text);
  background: var(--e2ee-code);
  font-family: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Consolas, monospace;
  white-space: pre-wrap;
}

.setup-card > summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 18px 22px;
  cursor: pointer;
  list-style: none;
}

.setup-card > summary::-webkit-details-marker { display: none; }

.setup-card > summary > span:first-child {
  display: grid;
  gap: 3px;
}

.setup-card > summary small {
  color: var(--e2ee-muted);
  font-size: 0.74rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.setup-content {
  padding: 0 22px 20px;
  border-top: 1px solid var(--e2ee-border);
}

.setup-content pre code { color: inherit; }

.visually-hidden {
  position: absolute !important;
  width: 1px !important;
  height: 1px !important;
  padding: 0 !important;
  margin: -1px !important;
  overflow: hidden !important;
  clip: rect(0, 0, 0, 0) !important;
  white-space: nowrap !important;
  border: 0 !important;
}

@media (max-width: 720px) {
  .public-e2ee-main {
    width: min(100% - 28px, 860px);
    margin-top: 24px;
  }

  .chooser-card,
  .error-card,
  .request-card,
  .control-center {
    padding: 18px;
  }

  .target-heading,
  .control-center__toolbar,
  .embedded-panel__heading,
  .first-use-callout,
  .request-warning {
    align-items: flex-start;
    flex-direction: column;
  }

  .evidence-strip {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .evidence-strip > div:nth-child(3) {
    border-left: 0;
  }

  .evidence-strip > div:nth-child(n + 3) {
    border-top: 1px solid var(--e2ee-border);
  }

  .request-command {
    grid-template-columns: 100px minmax(0, 1fr);
  }

  .request-command button {
    grid-column: 1 / -1;
    width: 100%;
  }
}

@media (max-width: 500px) {
  .target-heading__actions,
  .control-center__toolbar,
  .session-controls,
  .disclosure-actions,
  .button-row {
    width: 100%;
    flex-wrap: wrap;
  }

  .status-line {
    grid-template-columns: auto minmax(0, 1fr);
    align-items: start;
  }

  .status-line > .status-pill {
    grid-column: 2;
    justify-self: start;
  }

  .suite-picker__options,
  .trust-picker__options,
  .evidence-strip,
  .request-command {
    grid-template-columns: 1fr;
  }

  .evidence-strip > div + div,
  .evidence-strip > div:nth-child(3) {
    border-left: 0;
    border-top: 1px solid var(--e2ee-border);
  }

  .request-command button { grid-column: auto; }

  .diagnostic-list > div,
  .pcr-value-list > div,
  .review-pcr-row > div,
  .exchange-list > div {
    grid-template-columns: 1fr;
  }

  .profile-row {
    grid-template-columns: 1fr;
  }

  .profile-actions { margin-left: 21px; }
}
</style>
