<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="dashboard-page">
    <!-- Alpha Banner -->
    <div class="alpha-banner">
      The software is currently in early alpha and is not production ready. You
      may encounter breaking changes and evolving features.
    </div>

    <!-- Top Header Row -->
    <div class="dashboard-header">
      <a href="/" class="sidebar-logo">
        <img src="/assets/caution-logo-black.svg" alt="Caution" />
      </a>
      <h1 class="page-title">{{ title }}</h1>
    </div>

    <div class="dashboard-layout">
      <!-- Sidebar -->
      <aside class="sidebar">
        <nav class="sidebar-nav">
          <button
            :class="['nav-item', { active: activeTab === 'apps' }]"
            @click="$emit('tab-change', 'apps')"
          >
            <svg
              class="nav-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
            >
              <rect x="3" y="3" width="7" height="7" rx="1" />
              <rect x="14" y="3" width="7" height="7" rx="1" />
              <rect x="3" y="14" width="7" height="7" rx="1" />
              <rect x="14" y="14" width="7" height="7" rx="1" />
            </svg>
            <span>Applications</span>
          </button>

          <button
            :class="['nav-item', { active: activeTab === 'ssh' }]"
            @click="$emit('tab-change', 'ssh')"
          >
            <svg
              class="nav-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"
              />
            </svg>
            <span>SSH Keys</span>
          </button>

          <button
            :class="['nav-item', { active: activeTab === 'credentials' }]"
            @click="$emit('tab-change', 'credentials')"
          >
            <svg
              class="nav-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                d="M19 11H5a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2Z"
              />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
            <span>Cloud Credentials</span>
          </button>

          <button class="nav-item" @click="openAlphaNotes">
            <svg
              class="nav-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
            >
              <path d="m22 2-7 20-4-9-9-4 20-7Z" />
              <path d="M22 2 11 13" />
            </svg>
            <span>Alpha notes</span>
          </button>

          <button class="nav-item nav-item--logout" @click="$emit('logout')">
            <svg
              class="nav-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
            >
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <polyline points="16,17 21,12 16,7" />
              <line x1="21" y1="12" x2="9" y2="12" />
            </svg>
            <span>Log out</span>
          </button>
        </nav>
      </aside>

      <!-- Main Content -->
      <main class="main-content">
        <slot></slot>
      </main>
    </div>

    <!-- Footer -->
    <footer class="dashboard-footer">
      <div class="footer-left">
        &copy; 2025 Caution SEZC. All rights reserved.
      </div>
      <div class="footer-right">
        <a
          href="https://codeberg.org/caution/platform"
          target="_blank"
          rel="noopener noreferrer"
          >Source code</a
        >
        <a
          href="https://caution.co/blog.html"
          target="_blank"
          rel="noopener noreferrer"
          >Blog</a
        >
        <a
          href="https://caution.co/contact.html"
          target="_blank"
          rel="noopener noreferrer"
          >Contact</a
        >
      </div>
    </footer>
  </div>
</template>

<script>
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
  },
  emits: ["tab-change", "logout"],
  setup() {
    const openAlphaNotes = () => {
      window.open("https://caution.co/alpha-notes.html", "_blank");
    };

    return {
      openAlphaNotes,
    };
  },
};
</script>

<style src="../styles/dashboard-layout.css"></style>
