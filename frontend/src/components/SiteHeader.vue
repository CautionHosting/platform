<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <header
    class="header-navbar"
    :class="{
      'mobile-menu-open': mobileMenuOpen,
      'navbar--hidden': navbarHidden,
      'navbar--scrolled': navbarScrolled,
      'navbar--on-dark': navbarOnDark,
    }"
  >
    <div class="nav-top-bar">
      <a href="https://caution.co" class="nav-logo">
        <img src="/assets/caution-logo-white.svg" alt="Caution logo" />
      </a>

      <nav class="nav-desktop">
        <div class="nav-container">
          <a href="https://caution.co/about.html" class="nav-link">About</a>
          <a href="https://caution.co/blog.html" class="nav-link">Blog</a>
          <a href="/login" @click.prevent="$emit('login')" class="nav-link"
            >Log in</a
          >
          <a href="/" class="btn-dark nav-cta"> Get started </a>
        </div>
      </nav>

      <button
        class="mobile-menu-button"
        @click="$emit('toggle-menu')"
        :aria-expanded="mobileMenuOpen"
        aria-label="Toggle menu"
      >
        <span class="hamburger">
          <span class="hamburger-line"></span>
          <span class="hamburger-line"></span>
          <span class="hamburger-line"></span>
        </span>
      </button>
    </div>

    <!-- Mobile menu -->
    <div class="mobile-menu" :class="{ active: mobileMenuOpen }">
      <div class="mobile-menu-content">
        <a href="https://caution.co/about.html" class="mobile-menu-link"
          >About</a
        >
        <a href="https://caution.co/blog.html" class="mobile-menu-link">Blog</a>
        <a href="https://caution.co/contact.html" class="mobile-menu-link"
          >Contact</a
        >
        <a
          href="/login"
          @click.prevent="$emit('login')"
          class="mobile-menu-link"
          >Log in</a
        >
        <a href="/" class="btn-dark mobile-menu-cta"> Get started </a>
      </div>
    </div>
  </header>
</template>

<script>
export default {
  name: "SiteHeader",
  props: {
    mobileMenuOpen: {
      type: Boolean,
      default: false,
    },
    navbarHidden: {
      type: Boolean,
      default: false,
    },
    navbarScrolled: {
      type: Boolean,
      default: false,
    },
    navbarOnDark: {
      type: Boolean,
      default: false,
    },
  },
  emits: ["login", "toggle-menu"],
};
</script>
