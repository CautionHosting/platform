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
          <div class="nav-dropdown" :class="{ 'is-open': dropdownOpen }">
            <button
              class="nav-link nav-dropdown__trigger"
              :aria-expanded="dropdownOpen"
              aria-haspopup="true"
              @click.stop="toggleDropdown"
            >
              Platform
              <svg
                class="nav-dropdown__chevron"
                width="12"
                height="12"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              >
                <path d="m6 9 6 6 6-6" />
              </svg>
            </button>
            <div class="nav-dropdown__menu">
              <a href="https://caution.co/about.html" class="nav-dropdown__item">
                <span class="nav-dropdown__icon">
                  <img
                    src="/assets/favicons/caution-icon.svg"
                    alt=""
                    class="nav-dropdown__icon-img"
                  />
                </span>
                About
              </a>
              <a href="https://caution.co/platform-tour.html" class="nav-dropdown__item">
                <svg
                  class="nav-dropdown__icon"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <path d="M9 9.003a1 1 0 0 1 1.517-.859l4.997 2.997a1 1 0 0 1 0 1.718l-4.997 2.997A1 1 0 0 1 9 14.996z" />
                  <circle cx="12" cy="12" r="10" />
                </svg>
                Platform demo
              </a>
              <a href="https://caution.co/pricing.html" class="nav-dropdown__item">
                <svg
                  class="nav-dropdown__icon"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <rect width="18" height="18" x="3" y="3" rx="2" />
                  <path d="M3 9a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2" />
                  <path
                    d="M3 11h3c.8 0 1.6.3 2.1.9l1.1.9c1.6 1.6 4.1 1.6 5.7 0l1.1-.9c.5-.5 1.3-.9 2.1-.9H21"
                  />
                </svg>
                Pricing
              </a>
              <a href="https://caution.co/blog.html" class="nav-dropdown__item">
                <svg
                  class="nav-dropdown__icon"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <path d="M12 7v14" />
                  <path d="M16 12h2" />
                  <path d="M16 8h2" />
                  <path
                    d="M3 18a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h5a4 4 0 0 1 4 4 4 4 0 0 1 4-4h5a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1h-6a3 3 0 0 0-3 3 3 3 0 0 0-3-3z"
                  />
                  <path d="M6 12h2" />
                  <path d="M6 8h2" />
                </svg>
                Blog
              </a>
            </div>
          </div>
          <a href="https://docs.caution.co/" target="_blank" rel="noopener noreferrer" class="nav-link">Docs</a>
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
        <div class="mobile-menu-nav">
          <div class="mobile-menu-section">
            <button
              class="mobile-menu-label"
              :aria-expanded="platformAccordionOpen"
              @click="togglePlatformAccordion"
            >
              Platform
              <img
                src="/assets/icons/arrow-right.svg"
                alt=""
                class="mobile-menu-label__arrow"
                width="32"
                height="32"
              />
            </button>
            <div class="mobile-menu-section__content" :class="{ 'is-expanded': platformAccordionOpen }">
              <div class="mobile-menu-section__inner">
                <a href="https://caution.co/about.html" class="mobile-menu-link">About</a>
                <a href="https://caution.co/platform-tour.html" class="mobile-menu-link">Platform demo</a>
                <a href="https://alpha.caution.co/" class="mobile-menu-link">Early access</a>
              </div>
            </div>
          </div>
          <a href="https://docs.caution.co/" target="_blank" rel="noopener noreferrer" class="mobile-menu-link">Docs</a>
          <a href="https://caution.co/blog.html" class="mobile-menu-link">Blog</a>
          <a href="https://caution.co/pricing.html" class="mobile-menu-link">Pricing</a>
        </div>
        <div class="mobile-menu-footer">
          <a href="/" class="mobile-menu-cta">Get started</a>
          <a href="https://caution.co/platform-tour.html" class="cta-link">
            Watch demo
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            >
              <path d="M5 12h14" />
              <path d="m12 5 7 7-7 7" />
            </svg>
          </a>
        </div>
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
  data() {
    return {
      dropdownOpen: false,
      platformAccordionOpen: false,
    };
  },
  mounted() {
    document.addEventListener("click", this.handleClickOutside);
    document.addEventListener("keydown", this.handleEscape);
  },
  beforeUnmount() {
    document.removeEventListener("click", this.handleClickOutside);
    document.removeEventListener("keydown", this.handleEscape);
  },
  methods: {
    toggleDropdown() {
      this.dropdownOpen = !this.dropdownOpen;
    },
    togglePlatformAccordion() {
      this.platformAccordionOpen = !this.platformAccordionOpen;
    },
    handleClickOutside(e) {
      if (!e.target.closest(".nav-dropdown")) {
        this.dropdownOpen = false;
      }
    },
    handleEscape(e) {
      if (e.key === "Escape") {
        this.dropdownOpen = false;
      }
    },
  },
};
</script>
