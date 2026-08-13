<!-- SPDX-FileCopyrightText: 2026 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <header class="compact-page-header">
    <a :href="homeHref" class="compact-page-header__brand" aria-label="Caution home">
      <img src="/assets/caution-logo-black.svg" alt="Caution" />
    </a>
    <ThemeToggle />
  </header>
</template>

<script>
import ThemeToggle from './ThemeToggle.vue'

export default {
  name: 'CompactPageHeader',
  components: { ThemeToggle },
  props: {
    homeHref: {
      type: String,
      default: 'https://caution.co',
    },
  },
}
</script>

<style scoped>
.compact-page-header {
  width: min(100%, 1120px);
  margin: 0 auto;
  padding: 28px 24px 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.compact-page-header__brand {
  display: inline-flex;
  align-items: center;
}

.compact-page-header__brand img {
  height: clamp(1.55rem, 3.5vw, 2rem);
  width: auto;
}

@media (max-width: 640px) {
  .compact-page-header {
    padding: 20px 18px 0;
  }
}
</style>
