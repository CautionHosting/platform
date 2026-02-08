<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="dashboard-page">
    <!-- Alpha Banner (dismissible) -->
    <div v-if="showAlphaBanner" class="alpha-banner">
      <span class="alpha-banner-text">
        The software is currently in early alpha and is not production ready. You
        may encounter breaking changes and evolving features.
      </span>
      <button class="alpha-banner-close" @click="dismissBanner" aria-label="Close banner">
        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M18 6 6 18"/>
          <path d="m6 6 12 12"/>
        </svg>
      </button>
    </div>

    <!-- Top Header Row -->
    <div class="dashboard-header">
      <button class="sidebar-logo" @click="$emit('tab-change', 'apps')">
        <img src="/assets/caution-logo-black.svg" alt="Caution" />
      </button>
      <h2 v-if="showTitle" class="page-title">{{ title }}</h2>
      <div class="header-nav">
        <span class="alpha-label">SOFTWARE IN ALPHA</span>
        <span class="alpha-label alpha-label-warning">NOT PRODUCTION READY</span>
      </div>
    </div>

    <!-- Desktop Required Message (mobile/tablet only) -->
    <div class="desktop-required-message">
      <div class="desktop-required-content">
        <h2 class="desktop-required-title">Desktop recommended</h2>
        <p class="desktop-required-text">Caution is currently optimized for desktop. Mobile and tablet support is coming soon.</p>
      </div>
    </div>

    <div class="dashboard-layout">
      <!-- Sidebar -->
      <aside class="sidebar">
        <nav class="sidebar-nav">
          <button
            :class="['nav-item', { active: activeTab === 'apps' }]"
            @click="$emit('tab-change', 'apps')"
          >
            <img
              :src="activeTab === 'apps' ? '/assets/icons/apps--act.svg' : '/assets/icons/apps--inact.svg'"
              alt=""
              class="nav-icon"
            />
            <span>Applications</span>
          </button>

          <button
            :class="['nav-item', { active: activeTab === 'ssh' }]"
            @click="$emit('tab-change', 'ssh')"
          >
            <img
              :src="activeTab === 'ssh' ? '/assets/icons/ssh--act.svg' : '/assets/icons/ssh--inact.svg'"
              alt=""
              class="nav-icon"
            />
            <span>SSH keys</span>
          </button>

          <button
            :class="['nav-item', { active: activeTab === 'security' }]"
            @click="$emit('tab-change', 'security')"
          >
            <svg
              class="nav-icon"
              :style="{ opacity: activeTab === 'security' ? 1 : 0.5, width: '30px', height: '30px', minWidth: '30px', minHeight: '30px' }"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="1.5"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <span>Security</span>
          </button>

          <!-- Hidden for now - docs site covers this
          <button
            :class="['nav-item', { active: activeTab === 'guide' }]"
            @click="$emit('tab-change', 'guide')"
          >
            <img
              :src="activeTab === 'guide' ? '/assets/icons/guide--act.svg' : '/assets/icons/guide--inact.svg'"
              alt=""
              class="nav-icon"
            />
            <span>Quick start guide</span>
          </button>
          -->

          <button class="nav-item nav-item--logout" @click="$emit('logout')">
            <img
              src="/assets/icons/log_out--inact.svg"
              alt=""
              class="nav-icon"
            />
            <span>Log out</span>
          </button>
        </nav>
      </aside>

      <!-- Main Content -->
      <main class="main-content">
        <div class="main-content-primary">
          <slot></slot>
        </div>
        <aside class="main-content-aside">
          <slot name="aside"></slot>
        </aside>
      </main>
    </div>

    <!-- Footer -->
    <footer class="dashboard-footer">
      <div class="footer-left">
        &copy; 2025 Caution SEZC. All rights reserved.
      </div>
      <div class="footer-right">
        <a
          href="https://docs.caution.co/"
          target="_blank"
          rel="noopener noreferrer"
          >Docs</a
        >
        <a
          href="https://codeberg.org/caution"
          target="_blank"
          rel="noopener noreferrer"
          >Source code</a
        >
        <a
          href="mailto:info@caution.co?subject=Caution%20Platform%20Inquiry&body=Hello%20Caution%20team%2C%0A%0AI%20am%20reaching%20out%20regarding%20the%20Caution%20platform.%0A%0A"
          >Contact</a
        >
      </div>
    </footer>
  </div>
</template>

<script>
import { ref } from "vue";

export default {
  name: "DashboardLayout",
  props: {
    title: {
      type: String,
      default: "Welcome to Caution Alpha!",
    },
    activeTab: {
      type: String,
      default: "apps",
    },
    showTitle: {
      type: Boolean,
      default: false,
    },
  },
  emits: ["tab-change", "logout"],
  setup() {
    const showAlphaBanner = ref(true);

    const dismissBanner = () => {
      showAlphaBanner.value = false;
    };

    const openAlphaNotes = () => {
      window.open("https://caution.co/alpha-notes.html", "_blank");
    };

    return {
      showAlphaBanner,
      dismissBanner,
      openAlphaNotes,
    };
  },
};
</script>

<style src="../styles/dashboard-layout.css"></style>
