<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="dashboard-page">
    <div v-if="showDevelopmentWarning" class="development-banner">
      <div class="development-banner-content">
        <span>
          <strong>Development mode:</strong> PIN verification is disabled.
          <button class="development-banner-link" @click="$emit('tab-change', 'security')">
            Enable PIN requirement
          </button>
          for production use.
        </span>
      </div>
    </div>

    <!-- Top Header Row -->
    <div class="dashboard-header">
      <button class="sidebar-logo" @click="$emit('tab-change', 'apps')">
        <img src="/assets/caution-logo-black.svg" alt="Caution" />
      </button>
      <h2 v-if="showTitle" class="page-title">{{ title }}</h2>
      <div class="header-actions">
        <button class="header-logout-button" @click="$emit('logout')">
          <svg
            class="header-logout-icon"
            xmlns="http://www.w3.org/2000/svg"
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
          >
            <path d="M12 2v10" />
            <path d="M18.4 6.6a9 9 0 1 1-12.77.04" />
          </svg>
          <span>Log out</span>
        </button>
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
            :class="['nav-item', { active: activeTab === 'credentials' }]"
            @click="$emit('tab-change', 'credentials')"
          >
            <svg
              class="nav-icon"
              width="30"
              height="30"
              viewBox="0 0 30 30"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
              aria-hidden="true"
            >
              <rect v-if="activeTab === 'credentials'" width="30" height="30" rx="15" fill="white"/>
              <g
                transform="translate(5,5) scale(0.833)"
                :stroke="activeTab === 'credentials' ? '#0F0F0F' : '#535455'"
                stroke-width="1.8"
                stroke-linecap="round"
                stroke-linejoin="round"
              >
                <path d="m10.852 19.772-.383.924"/>
                <path d="m13.148 14.228.383-.923"/>
                <path d="M13.148 19.772a3 3 0 1 0-2.296-5.544l-.383-.923"/>
                <path d="m13.53 20.696-.382-.924a3 3 0 1 1-2.296-5.544"/>
                <path d="m14.772 15.852.923-.383"/>
                <path d="m14.772 18.148.923.383"/>
                <path d="M4.2 15.1a7 7 0 1 1 9.93-9.858A7 7 0 0 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.2"/>
                <path d="m9.228 15.852-.923-.383"/>
                <path d="m9.228 18.148-.923.383"/>
              </g>
            </svg>
            <span>Cloud credentials</span>
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
            :class="['nav-item', { active: activeTab === 'keys' }]"
            @click="$emit('tab-change', 'keys')"
          >
            <svg
              class="nav-icon"
              width="30" height="30" viewBox="0 0 30 30"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <rect v-if="activeTab === 'keys'" width="30" height="30" rx="15" fill="white"/>
              <g transform="translate(5,5) scale(0.833)">
                <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"
                  :stroke="activeTab === 'keys' ? '#0F0F0F' : '#535455'"
                />
              </g>
            </svg>
            <span>Key services</span>
          </button>

          <button
            :class="['nav-item', { active: activeTab === 'security' }]"
            @click="$emit('tab-change', 'security')"
          >
            <svg
              class="nav-icon"
              width="30" height="30" viewBox="0 0 30 30"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <rect v-if="activeTab === 'security'" width="30" height="30" rx="15" fill="white"/>
              <g transform="translate(5,5) scale(0.833)">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"
                  :stroke="activeTab === 'security' ? '#0F0F0F' : '#535455'"
                />
              </g>
            </svg>
            <span>Security</span>
          </button>

          <button
            :class="['nav-item', { active: activeTab === 'settings' }]"
            @click="$emit('tab-change', 'settings')"
          >
            <img
              :src="activeTab === 'settings' ? '/assets/icons/settings--act.svg' : '/assets/icons/settings--inact.svg'"
              alt=""
              class="nav-icon"
            />
            <span>Settings</span>
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
        {{ copyrightLabel }}
      </div>
      <div class="footer-right">
        <a
          href="https://caution.co/terms.html"
          target="_blank"
          rel="noopener noreferrer"
          >Terms</a
        >
        <a
          href="https://caution.co/privacy.html"
          target="_blank"
          rel="noopener noreferrer"
          >Privacy</a
        >
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
import { computed } from "vue";

export default {
  name: "DashboardLayout",
  props: {
    title: {
      type: String,
      default: "Welcome to Caution",
    },
    activeTab: {
      type: String,
      default: "apps",
    },
    showTitle: {
      type: Boolean,
      default: false,
    },
    showDevelopmentWarning: {
      type: Boolean,
      default: false,
    },
  },
  emits: ["tab-change", "logout"],
  setup() {
    const copyrightLabel = computed(() => {
      return `© ${new Date().getFullYear()} Caution SEZC. All rights reserved.`;
    });

    return {
      copyrightLabel,
    };
  },
};
</script>

<style src="../styles/dashboard-layout.css"></style>
