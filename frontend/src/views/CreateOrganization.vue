<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="organization-page">
    <CompactPageHeader />
    <main class="organization-container">
      <div class="organization-card">
        <h1>Create an organization</h1>
        <p>
          Your account is not part of an organization, so applications, secrets and users
          are unavailable. Create one to continue.
        </p>

        <form @submit.prevent="createOrganization">
          <label for="organizationName">Organization name</label>
          <input
            id="organizationName"
            v-model="organizationName"
            type="text"
            placeholder="Organization name"
            autocomplete="organization"
            data-testid="organization-name"
            :disabled="creating"
            @input="clearMessages"
          />

          <button
            type="submit"
            class="btn-primary"
            data-testid="create-organization"
            :disabled="creating"
          >
            {{ creating ? 'Creating organization...' : 'Create organization' }}
          </button>
        </form>

        <div class="messages-container">
          <div v-if="usernameRequired" class="info-message">
            Set a username before creating an organization.
            <a href="/#account" @click.prevent="goToUsernameClaim">Claim a username</a>.
          </div>
          <div v-if="error" class="error-message">{{ error }}</div>
          <button type="button" class="link-button" :disabled="creating" @click="logout">
            Log out
          </button>
        </div>
      </div>
    </main>
  </div>
</template>

<script>
import { ref } from 'vue'
import CompactPageHeader from '../components/CompactPageHeader.vue'
import { authFetch } from '../composables/useWebAuthn.js'
import {
  DEFAULT_ORGANIZATION_NAME,
  ORGANIZATION_CREATION_OUTCOME,
  organizationCreationErrorMessage,
  organizationCreationOutcome,
  parseResponseBody,
  validateOrganizationName,
} from '../utils/organizations.js'

export default {
  name: 'CreateOrganization',
  components: { CompactPageHeader },
  setup() {
    const organizationName = ref(DEFAULT_ORGANIZATION_NAME)
    const creating = ref(false)
    const error = ref('')
    const usernameRequired = ref(false)

    const clearMessages = () => {
      error.value = ''
      usernameRequired.value = false
    }

    const goToUsernameClaim = () => {
      window.location.href = '/#account'
    }

    const logout = async () => {
      try {
        const response = await authFetch('/auth/logout', { method: 'POST' })
        if (!response.ok) {
          error.value = 'Logout failed. Please try again.'
          return
        }
        window.location.href = '/login'
      } catch {
        error.value = 'Could not reach the server. Please try again.'
      }
    }

    const createOrganization = async () => {
      clearMessages()

      const name = organizationName.value.trim()
      const validationError = validateOrganizationName(name)
      if (validationError) {
        error.value = validationError
        return
      }

      creating.value = true

      try {
        // The gateway's username gate and the API's legal middleware both refuse
        // before the handler runs, so each outcome is reported here instead of
        // being left to authFetch's default handler, which would redirect
        // straight back to this page with nothing explaining why.
        const response = await authFetch('/api/organizations', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name }),
          suppressGateRedirect: true,
        })

        const text = await response.text().catch(() => '')
        const body = parseResponseBody(text)

        switch (organizationCreationOutcome(response.status, body)) {
          // `already_member` means the account belongs to an organization
          // already: the status this page was built from was stale, or a
          // concurrent submission won. Either way there is nothing left to
          // create, so continue to the dashboard.
          case ORGANIZATION_CREATION_OUTCOME.created:
          case ORGANIZATION_CREATION_OUTCOME.already_member:
            window.location.href = '/'
            return
          case ORGANIZATION_CREATION_OUTCOME.unauthenticated:
            window.location.href = '/login'
            return
          case ORGANIZATION_CREATION_OUTCOME.username_required:
            usernameRequired.value = true
            return
          case ORGANIZATION_CREATION_OUTCOME.legal_required:
            error.value = 'Accept the updated legal documents before creating an organization.'
            return
          default:
            error.value = organizationCreationErrorMessage(
              body,
              text,
              'Failed to create organization',
            )
        }
      } catch {
        error.value = 'Could not reach the server. Please try again.'
      } finally {
        creating.value = false
      }
    }

    return {
      organizationName,
      creating,
      error,
      usernameRequired,
      clearMessages,
      createOrganization,
      goToUsernameClaim,
      logout,
    }
  },
}
</script>

<style scoped>
.organization-page {
  min-height: 100vh;
  color: var(--theme-text-primary);
}

.organization-container {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: calc(100vh - 92px);
  padding: 2rem;
}

.organization-card {
  background: var(--theme-surface);
  border-radius: 12px;
  padding: 3rem;
  max-width: 440px;
  width: 100%;
  border: 1px solid var(--theme-border);
  box-shadow: var(--theme-shadow);
}

h1 {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--theme-text-primary);
  margin-bottom: 0.5rem;
}

p {
  color: var(--theme-text-muted);
  font-size: 0.9rem;
  line-height: 1.5;
  margin-bottom: 1.5rem;
}

label {
  display: block;
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--theme-text-primary);
  margin-bottom: 0.4rem;
}

input {
  width: 100%;
  padding: 0.7rem 0.85rem;
  border: 1px solid var(--theme-border-strong);
  border-radius: 8px;
  background: var(--theme-surface);
  color: var(--theme-text-primary);
  font-size: 0.9rem;
  font-family: inherit;
  margin-bottom: 1rem;
  box-sizing: border-box;
  transition: border-color 0.15s ease;
}

input:focus {
  outline: 3px solid var(--theme-focus-ring);
  border-color: var(--theme-focus);
}

input:disabled {
  background: var(--theme-surface-muted);
  cursor: not-allowed;
}

input::placeholder {
  color: var(--theme-text-faint);
}

.btn-primary {
  width: 100%;
  padding: 0.7rem 1.5rem;
  background: var(--theme-control);
  color: var(--theme-control-text);
  border: none;
  border-radius: 8px;
  font-family: inherit;
  font-size: 0.95rem;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.15s ease;
}

.btn-primary:hover:not(:disabled) {
  background: var(--theme-control-hover);
}

.btn-primary:focus-visible {
  outline: 3px solid var(--theme-focus-ring);
  outline-offset: 2px;
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.messages-container {
  margin-top: 1rem;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
}

.error-message {
  width: 100%;
  background: var(--theme-danger-bg);
  border: 1px solid var(--theme-danger-border);
  border-radius: 8px;
  padding: 0.7rem 1rem;
  color: var(--theme-danger);
  font-size: 0.85rem;
}

.info-message {
  width: 100%;
  background: var(--theme-info-bg);
  border-radius: 8px;
  padding: 0.7rem 1rem;
  color: var(--theme-info);
  font-size: 0.85rem;
}

.info-message a {
  color: inherit;
  text-decoration: underline;
}

.link-button {
  background: none;
  border: none;
  padding: 0;
  color: var(--theme-text-muted);
  font-family: inherit;
  font-size: 0.85rem;
  text-decoration: underline;
  cursor: pointer;
}

.link-button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

@media (max-width: 600px) {
  .organization-container {
    min-height: calc(100vh - 76px);
    padding: 12px;
  }

  .organization-card {
    padding: 2rem 1.5rem;
  }
}
</style>
