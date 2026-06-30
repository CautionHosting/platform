<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="dashboard-page">
    <div v-if="showDevelopmentBanner" class="development-banner">
      <div class="development-banner-content">
        <span>
          <strong>Development mode:</strong> PIN verification is disabled.
          <button class="development-banner-link" @click="selectTab('security')">
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
      <button class="sidebar-logo" @click="selectTab('apps')">
        <img src="/assets/caution-logo-black.svg" alt="Caution" />
      </button>
      <h2 v-if="showTitle" class="page-title">{{ title }}</h2>
      <div class="header-actions">
        <button
          :class="['header-action-button', { active: activeTab === 'account' }]"
          :aria-current="activeTab === 'account' ? 'page' : undefined"
          @click="selectTab('account')"
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
            @click="selectTab('apps')"
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
              @click="selectTab('ssh')"
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
                @click="selectTab('ssh')"
              >
                SSH keys
              </button>
              <button
                :class="['nav-subitem', { active: activeTab === 'security' }]"
                :aria-current="activeTab === 'security' ? 'page' : undefined"
                @click="selectTab('security')"
              >
                Authentication
              </button>
            </div>
          </div>

          <button
            :class="['nav-item', { active: activeTab === 'keys' }]"
            @click="selectTab('keys')"
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
            @click="selectTab('billing')"
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
      <div
        v-if="buildInputs.length"
        class="footer-build-inputs"
        title="Commits the platform builds new enclaves with. Build inputs, not attested measurements — verify a running enclave with `caution verify`."
      >
        <span class="footer-build-inputs-label">Build inputs:</span>
        <template v-for="(input, i) in buildInputs" :key="input.name">
          <a
            :href="input.url"
            target="_blank"
            rel="noopener noreferrer"
            :title="input.commit"
            >{{ input.name }}@{{ input.short }}</a
          ><span v-if="i < buildInputs.length - 1" class="footer-build-inputs-sep">·</span>
        </template>
      </div>
    </footer>
  </div>
</template>

<script>
import { computed, onMounted, ref, watch } from "vue";
import {
  dismissDevelopmentBannerForSession,
  isDevelopmentBannerDismissed,
} from "../utils/developmentBanner.js";

const TOOL_ORDER = ["platform", "enclaveos", "bootproof", "steve", "locksmith"];

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
  setup(props, { emit }) {
    const securityTabs = ["ssh", "security"];
    const isSecurityNavActive = computed(() => securityTabs.includes(props.activeTab));
    const securityNavOpen = ref(isSecurityNavActive.value);
    const developmentBannerDismissed = ref(isDevelopmentBannerDismissed());
    const showDevelopmentBanner = computed(() => {
      return props.showDevelopmentWarning && !developmentBannerDismissed.value;
    });

    const selectTab = (tab) => {
      securityNavOpen.value = securityTabs.includes(tab);
      emit("tab-change", tab);
    };

    const dismissDevelopmentBanner = () => {
      developmentBannerDismissed.value = true;
      dismissDevelopmentBannerForSession();
    };

    const copyrightLabel = computed(() => {
      return `© ${new Date().getFullYear()} Caution SEZC. All rights reserved.`;
    });

    // Tool commits the platform currently builds new enclaves with. Sourced from
    // the same resolver the builder uses, so the footer can't drift from reality.
    const buildInputsData = ref(null);
    const buildInputs = computed(() => {
      const data = buildInputsData.value;
      if (!data) return [];
      return TOOL_ORDER.flatMap((name) => {
        const commit = data[name]?.commit;
        const repo = data[name]?.repo;
        if (!commit || !repo) return [];
        const base = repo.replace(/\.git$/, "");
        return [{ name, commit, short: commit.slice(0, 7), url: `${base}/commit/${commit}` }];
      });
    });

    onMounted(async () => {
      try {
        const res = await fetch("/.well-known/caution/build-inputs");
        if (res.ok) buildInputsData.value = await res.json();
      } catch {
        // Footer detail is non-critical; stay silent if it can't be fetched.
      }
    });

    watch(
      () => props.activeTab,
      (activeTab) => {
        securityNavOpen.value = securityTabs.includes(activeTab);
      }
    );

    return {
      buildInputs,
      copyrightLabel,
      dismissDevelopmentBanner,
      isSecurityNavActive,
      securityNavOpen,
      showDevelopmentBanner,
      selectTab,
    };
  },
};
</script>

<style src="../styles/dashboard-layout.css"></style>
