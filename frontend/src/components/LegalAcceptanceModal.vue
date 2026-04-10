<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="legal-modal-overlay">
    <div class="legal-modal">
      <template v-if="step === 'review'">
        <div class="legal-modal-review">
          <h2
            class="legal-modal-title"
            :class="{ 'legal-modal-title--single-document': pendingDocuments.length === 1 }"
          >
            {{ reviewTitle }}
          </h2>
          <p class="legal-modal-copy">
            Please review the updated document(s). To continue using Caution, click
            “Accept and continue.”
          </p>

          <div v-if="error" class="legal-modal-error">
            {{ error }}
          </div>

          <div class="legal-document-list">
            <section
              v-for="doc in pendingDocuments"
              :key="doc.type"
              class="legal-document-card"
            >
              <div class="legal-document-header">
                <div>
                  <h3 class="legal-document-title">{{ doc.title }}</h3>
                  <p v-if="doc.effectiveDateLabel" class="legal-document-meta">
                    Effective {{ doc.effectiveDateLabel }}
                  </p>
                </div>
                <a
                  :href="doc.url"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="legal-document-link"
                >
                  <span>Review</span>
                  <svg
                    class="legal-document-link-icon"
                    xmlns="http://www.w3.org/2000/svg"
                    width="15"
                    height="15"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    aria-hidden="true"
                  >
                    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                    <polyline points="15 3 21 3 21 9"/>
                    <line x1="10" y1="14" x2="21" y2="3"/>
                  </svg>
                </a>
              </div>
            </section>
          </div>

          <div class="legal-modal-actions">
            <button
              type="button"
              class="legal-document-button legal-document-button--primary"
              :disabled="isLoading"
              @click="$emit('accept-all')"
            >
              {{ isLoading ? "Saving your acceptance..." : primaryButtonLabel }}
            </button>

            <button
              type="button"
              class="legal-document-button legal-document-button--quiet"
              :disabled="isLoading"
              @click="step = 'decline'"
            >
              Do not accept
            </button>
          </div>
        </div>
      </template>

      <template v-else>
        <div class="legal-modal-decline">
          <svg
            class="legal-modal-decline-icon"
            xmlns="http://www.w3.org/2000/svg"
            width="64"
            height="64"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
          >
            <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/>
            <path d="M12 9v4"/>
            <path d="M12 17h.01"/>
          </svg>
          <h2 class="legal-modal-title legal-modal-title--single-document">You’ll need to accept to continue</h2>
          <p class="legal-modal-copy legal-modal-copy--centered">
            To continue using Caution, you need to accept the current legal documents.
            If you do not accept them, you will need to log out.
          </p>

          <div class="legal-modal-actions">
            <button
              type="button"
              class="legal-document-button legal-document-button--primary"
              :disabled="isLoading"
              @click="step = 'review'"
            >
              Back to review
            </button>

            <button
              type="button"
              class="legal-document-button legal-document-button--quiet legal-document-button--quiet-danger"
              :disabled="isLoading"
              @click="$emit('logout')"
            >
              Log out
            </button>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>

<script>
import { computed, ref } from "vue";

const DOCUMENT_META = {
  terms_of_service: {
    title: "Terms of Service",
    url: "https://caution.co/terms.html",
  },
  privacy_notice: {
    title: "Privacy Notice",
    url: "https://caution.co/privacy.html",
  },
};

export default {
  name: "LegalAcceptanceModal",
  props: {
    legal: {
      type: Object,
      required: true,
    },
    loadingDocumentType: {
      type: String,
      default: null,
    },
    error: {
      type: String,
      default: "",
    },
  },
  emits: ["accept-all", "logout"],
  setup(props) {
    const step = ref("review");

    const formatEffectiveDate = (value) => {
      if (!value) return null;
      const parsed = new Date(`${value}T00:00:00`);
      if (Number.isNaN(parsed.getTime())) return value;
      return new Intl.DateTimeFormat("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
      }).format(parsed);
    };

    const pendingDocuments = computed(() =>
      Object.entries(DOCUMENT_META)
        .filter(([type]) => props.legal?.[type]?.requires_action)
        .map(([type, meta]) => ({
          type,
          ...meta,
          effectiveDateLabel: formatEffectiveDate(props.legal?.[type]?.active_version),
        }))
    );

    const isLoading = computed(() => Boolean(props.loadingDocumentType));

    const reviewTitle = computed(() => {
      if (pendingDocuments.value.length > 1) {
        return "We've updated our Terms of Service and Privacy Notice";
      }

      return `We've updated our ${pendingDocuments.value[0]?.title || "legal documents"}`;
    });

    const primaryButtonLabel = computed(() => "Accept and continue");

    return {
      step,
      pendingDocuments,
      isLoading,
      reviewTitle,
      primaryButtonLabel,
    };
  },
};
</script>

<style scoped>
.legal-modal-overlay {
  position: fixed;
  inset: 0;
  z-index: 2000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background:
    radial-gradient(circle at top, rgba(199, 232, 255, 0.35), transparent 45%),
    rgba(7, 11, 16, 0.62);
  backdrop-filter: blur(5px);
}

.legal-modal {
  width: min(580px, 100%);
  min-height: 420px;
  max-height: calc(100vh - 48px);
  overflow-y: auto;
  padding: 42px 36px 24px 36px;
  border: 1px solid rgba(15, 15, 15, 0.08);
  border-radius: 20px;
  background: #ffffff;
  box-shadow: 0 30px 80px rgba(8, 17, 28, 0.22);
}

.legal-modal-title {
  margin: 0;
  color: #0f0f0f;
  font-size: clamp(1.5rem, 3vw, 1.95rem);
  line-height: 1.3;
  text-align: center;
}

.legal-modal-title--single-document {
  max-width: 350px;
}

.legal-modal-copy {
  margin: 20px 0 0;
  color: #56636f;
  font-size: clamp(1rem, 2vw, 1.05rem);
  line-height: 1.6;
  text-align: start;
}

.legal-modal-copy--centered {
  margin: 20px 0 0;
  text-align: start;
}

.legal-modal-review,
.legal-modal-decline {
  display: flex;
  min-height: calc(420px - 72px);
  flex-direction: column;
  align-items: center;
  justify-content: end;
}

.legal-modal-review {
  width: 100%;
}

.legal-modal-decline-icon {
  margin-bottom: 36px;
  color: var(--color-slate-muted);
  opacity: 0.8;
}

.legal-modal-error {
  margin-top: 20px;
  padding: 14px 16px;
  border: 1px solid #f3b8bf;
  border-radius: 14px;
  background: #fff4f5;
  color: #a23240;
  font-size: 0.92rem;
}

.legal-document-card {
  width: 100%;
  padding: 18px;
  border: 1px solid #ececec;
  border-radius: 12px;
  background: #fafafa;
}

.legal-document-list {
  display: flex;
  width: 100%;
  flex-direction: column;
  gap: 12px;
  margin-top: 24px;
}

.legal-document-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.legal-document-title {
  margin: 0;
  color: #232b2b;
  font-size: 1.05rem;
  font-weight: 600;
}

.legal-document-meta {
  margin: 0;
  color: #56636f;
  font-size: 0.9rem;
}

.legal-document-link {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  color: #0f0f0f;
  font-size: 1.05rem;
  font-weight: 600;
  text-decoration: none;
  white-space: nowrap;
  transition: color 0.2s ease;
}

.legal-document-link-icon {
  flex-shrink: 0;
}

.legal-document-link:hover {
  color: var(--color-pink);
}

.legal-modal-actions {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  margin: 0;
}

.legal-document-button {
  padding: 12px 18px;
  border: none;
  border-radius: 999px;
  background: transparent;
  color: #ffffff;
  font-size: 0.94rem;
  font-weight: 500;
  font-family: inherit;
  cursor: pointer;
  transition: all 0.3s ease;
}

.legal-document-button:disabled {
  opacity: 0.6;
  cursor: wait;
}

.legal-document-button--primary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  position: relative;
  margin-top: 24px;
  padding: 9px 36px 10px 36px;
  font-size: clamp(1rem, 1.8vw, 1.035rem);
  font-weight: 400;
  color: #ffffff;
  letter-spacing: 0.02em;
  background: linear-gradient(
    180deg,
    rgba(55, 55, 55, 1) 0%,
    rgba(35, 35, 35, 1) 40%,
    rgba(25, 25, 25, 1) 100%
  );
  border: 1.5px solid rgba(80, 80, 80, 0.6);
  outline: 1px solid rgba(0, 0, 0, 0.8);
  box-shadow:
    inset 0 1px 0 0 rgba(255, 255, 255, 0.08),
    inset 0 0 20px 0 rgba(255, 255, 255, 0.03);
}

.legal-document-button--primary::before {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: 999px;
  background: radial-gradient(
    ellipse 75% 35% at center bottom,
    rgba(255, 255, 255, 0.2) 0%,
    rgba(255, 255, 255, 0.08) 25%,
    rgba(255, 255, 255, 0.02) 50%,
    transparent 70%
  );
  pointer-events: none;
}

.legal-document-button--primary:hover:not(:disabled) {
  color: var(--color-pink, #f048b5);
  box-shadow:
    inset 0 1px 0 0 rgba(255, 255, 255, 0.12),
    inset 0 0 20px 0 rgba(255, 255, 255, 0.05);
}

.legal-document-button--quiet {
  padding: 0;
  border-radius: 0;
  background: transparent;
  color: #778390;
  font-size: clamp(1rem, 1.8vw, 1.035rem);
  font-weight: 400;
  text-align: left;
}

.legal-document-button--quiet:hover:not(:disabled) {
  transform: none;
  background: transparent;
  color: #394552;
}

.legal-document-button--quiet-danger {
  color: #b15c68;
}

.legal-document-button--quiet-danger:hover:not(:disabled) {
  color: #b53a4b;
}

@media (max-width: 640px) {
  .legal-modal {
    padding: 24px;
    border-radius: 20px;
    min-width: 0;
    min-height: 0;
  }

  .legal-modal-title {
    font-size: 1.55rem;
  }

  .legal-document-header {
    flex-direction: column;
  }

  .legal-document-link {
    white-space: normal;
  }

  .legal-document-button--primary {
    width: 100%;
  }

  .legal-document-button--quiet {
    width: auto;
  }
}
</style>
