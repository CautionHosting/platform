<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <button
    type="button"
    class="theme-toggle"
    :aria-label="`Switch to ${nextTheme} mode`"
    :title="`Switch to ${nextTheme} mode`"
    @click="changeTheme"
  >
    <svg v-if="theme === 'dark'" viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.42-1.42M17.66 6.34l1.41-1.41" />
    </svg>
    <svg v-else viewBox="0 0 24 24" aria-hidden="true">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79Z" />
    </svg>
  </button>
</template>

<script>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { THEME_CHANGE_EVENT, getCurrentTheme, toggleTheme } from '../utils/theme.js'

export default {
  name: 'ThemeToggle',
  setup() {
    const theme = ref(getCurrentTheme())
    const nextTheme = computed(() => (theme.value === 'dark' ? 'light' : 'dark'))
    const syncTheme = (event) => {
      theme.value = event.detail?.theme || getCurrentTheme()
    }
    const changeTheme = () => {
      theme.value = toggleTheme()
    }

    onMounted(() => window.addEventListener(THEME_CHANGE_EVENT, syncTheme))
    onUnmounted(() => window.removeEventListener(THEME_CHANGE_EVENT, syncTheme))

    return { changeTheme, nextTheme, theme }
  },
}
</script>

<style scoped>
.theme-toggle {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  flex: 0 0 36px;
  padding: 0;
  border: 1px solid var(--theme-border-strong);
  border-radius: 999px;
  background: var(--theme-surface-translucent);
  color: var(--theme-text-muted);
  cursor: pointer;
  transition: border-color 0.15s ease, color 0.15s ease, transform 0.15s ease;
}

.theme-toggle:hover {
  border-color: var(--theme-brand-hover);
  color: var(--theme-brand-hover);
  transform: translateY(-1px);
}

.theme-toggle:focus-visible {
  outline: 3px solid var(--theme-focus-ring);
  outline-offset: 2px;
}

.theme-toggle svg {
  width: 17px;
  height: 17px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-linejoin: round;
}
</style>
