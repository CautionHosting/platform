<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="dashboard-page">
    <div v-if="showDevelopmentBanner" class="development-banner">
      <div class="development-banner-content">
        <span>
          <strong>Development mode:</strong> PIN verification is disabled.
          <button class="development-banner-link" @click="$emit('tab-change', 'security')">
            Enable PIN requirement
          </button>
          for production use.
        </span>
        <button
          type="button"
          class="development-banner-dismiss"
          aria-label="Dismiss development mode banner"
          title="Dismiss"
          @click="dismissDevelopmentBanner"
        >
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
          >
            <path d="M18 6 6 18" />
            <path d="m6 6 12 12" />
          </svg>
        </button>
      </div>
    </div>

    <!-- Top Header Row -->
    <div class="dashboard-header">
      <button class="sidebar-logo" @click="$emit('tab-change', 'apps')">
        <img src="/assets/caution-logo-black.svg" alt="Caution" />
      </button>
      <h2 v-if="showTitle" class="page-title">{{ title }}</h2>
      <div class="header-actions">
        <button
          :class="['header-action-button', { active: activeTab === 'account' }]"
          :aria-current="activeTab === 'account' ? 'page' : undefined"
          @click="$emit('tab-change', 'account')"
        >
          <svg
            class="header-action-icon lucide lucide-circle-user-round-icon lucide-circle-user-round"
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
            <path d="M17.925 20.056a6 6 0 0 0-11.851.001" />
            <circle cx="12" cy="11" r="4" />
            <circle cx="12" cy="12" r="10" />
          </svg>
          <span>Account</span>
        </button>
        <button class="header-action-button header-logout-button" @click="$emit('logout')">
          <svg
            class="header-action-icon header-logout-icon"
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

          <div class="nav-group" :class="{ 'is-open': securityNavOpen }">
            <button
              :class="['nav-item', 'nav-item--parent', { active: isSecurityNavActive }]"
              :aria-expanded="securityNavOpen ? 'true' : 'false'"
              aria-controls="security-nav-submenu"
              @click="toggleSecurityNav"
            >
              <svg
                class="nav-icon"
                width="30" height="30" viewBox="0 0 30 30"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <rect v-if="isSecurityNavActive" width="30" height="30" rx="15" fill="white"/>
                <g transform="translate(5,5) scale(0.833)">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"
                    :stroke="isSecurityNavActive ? '#0F0F0F' : '#535455'"
                  />
                </g>
              </svg>
              <span>Security</span>
              <svg
                class="nav-chevron"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
              >
                <path d="m6 9 6 6 6-6" />
              </svg>
            </button>

            <div
              v-show="securityNavOpen"
              id="security-nav-submenu"
              class="nav-submenu"
            >
              <button
                :class="['nav-subitem', { active: activeTab === 'ssh' }]"
                :aria-current="activeTab === 'ssh' ? 'page' : undefined"
                @click="$emit('tab-change', 'ssh')"
              >
                SSH keys
              </button>
              <button
                :class="['nav-subitem', { active: activeTab === 'security' }]"
                :aria-current="activeTab === 'security' ? 'page' : undefined"
                @click="$emit('tab-change', 'security')"
              >
                Authentication
              </button>
            </div>
          </div>

          <button
            :class="['nav-item', { active: activeTab === 'credentials' }]"
            @click="$emit('tab-change', 'credentials')"
          >
            <svg
              class="nav-icon"
              width="30" height="30" viewBox="0 0 30 30"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <rect v-if="activeTab === 'credentials'" width="30" height="30" rx="15" fill="white"/>
              <g transform="translate(4,5) scale(0.9)">
                <path
                  d="M18 18h1.2a4.15 4.15 0 0 0 .72-8.24A7 7 0 0 0 6.7 7.85 5.35 5.35 0 0 0 7 18h1.15"
                  stroke-width="1.8"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  :stroke="activeTab === 'credentials' ? '#0F0F0F' : '#535455'"
                />
                <circle
                  cx="13"
                  cy="18"
                  r="2"
                  stroke-width="1.8"
                  :stroke="activeTab === 'credentials' ? '#0F0F0F' : '#535455'"
                />
                <path
                  d="M13 14.4v-1.1M13 22.7v-1.1M16.1 16.2l.95-.55M8.95 20.35l.95-.55M16.1 19.8l.95.55M8.95 15.65l.95.55"
                  stroke-width="1.8"
                  stroke-linecap="round"
                  :stroke="activeTab === 'credentials' ? '#0F0F0F' : '#535455'"
                />
              </g>
            </svg>
            <span>Cloud credentials</span>
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
            <span>Secrets</span>
          </button>

          <button
            :class="['nav-item', { active: activeTab === 'billing' }]"
            @click="$emit('tab-change', 'billing')"
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
              <rect v-if="activeTab === 'billing'" width="30" height="30" rx="15" fill="white"/>
              <g transform="translate(5,5) scale(0.85)">
                <rect
                  width="20"
                  height="14"
                  x="2"
                  y="5"
                  rx="2"
                  :stroke="activeTab === 'billing' ? '#0F0F0F' : '#535455'"
                  stroke-width="1.8"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <line
                  x1="2"
                  x2="22"
                  y1="10"
                  y2="10"
                  :stroke="activeTab === 'billing' ? '#0F0F0F' : '#535455'"
                  stroke-width="1.8"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </g>
            </svg>
            <span>Billing</span>
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
      <div class="footer-center">
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
import { computed, ref, watch } from "vue";
import {
  dismissDevelopmentBannerForSession,
  isDevelopmentBannerDismissed,
} from "../utils/developmentBanner.js";

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
  setup(props) {
    const securityTabs = ["ssh", "security"];
    const isSecurityNavActive = computed(() => securityTabs.includes(props.activeTab));
    const securityNavOpen = ref(isSecurityNavActive.value);
    const developmentBannerDismissed = ref(isDevelopmentBannerDismissed());
    const showDevelopmentBanner = computed(() => {
      return props.showDevelopmentWarning && !developmentBannerDismissed.value;
    });

    const toggleSecurityNav = () => {
      securityNavOpen.value = !securityNavOpen.value;
    };

    const dismissDevelopmentBanner = () => {
      developmentBannerDismissed.value = true;
      dismissDevelopmentBannerForSession();
    };

    const copyrightLabel = computed(() => {
      return `© ${new Date().getFullYear()} Caution SEZC. All rights reserved.`;
    });

    watch(
      () => props.activeTab,
      (activeTab) => {
        if (securityTabs.includes(activeTab)) {
          securityNavOpen.value = true;
        }
      }
    );

    return {
      copyrightLabel,
      dismissDevelopmentBanner,
      isSecurityNavActive,
      securityNavOpen,
      showDevelopmentBanner,
      toggleSecurityNav,
    };
  },
};
</script>

<style src="../styles/dashboard-layout.css"></style>
