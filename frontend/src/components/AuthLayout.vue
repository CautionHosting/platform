<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div class="auth-page" :class="{ 'login-in-progress': loginLoading }">
    <SiteHeader
      :mobile-menu-open="mobileMenuOpen"
      :navbar-hidden="navbarHidden"
      :navbar-scrolled="navbarScrolled"
      :navbar-on-dark="navbarOnDark"
      @login="$emit('login')"
      @toggle-menu="toggleMobileMenu"
    />

    <div
      class="mobile-menu-overlay"
      :class="{ active: mobileMenuOpen }"
      @click="closeMobileMenu"
    ></div>

    <div class="auth-split">
      <!-- Left Panel - Dark -->
      <div class="left-panel">
        <div class="left-content">
          <slot name="left-panel">
            <h1 class="info-title">Caution Alpha</h1>
            <p class="info">
              Caution is in closed alpha for teams testing and deploying
              reproducible enclaves. Early users get access to new capabilities,
              help validate workflows, and shape the platform during development.
            </p>
            <h2 class="info">Overview</h2>
            <ul class="feature-list">
              <li>
                <a href="https://caution.co/platform-tour.html" target="_blank" rel="noopener noreferrer">
                  Platform walkthrough video
                </a>
              </li>
              <li>Verified enclave deployments</li>
              <li>Self-guided onboarding</li>
              <li>
                <span class="platform-item"
                  >AWS Nitro supported today
                  <span
                    class="tooltip-trigger"
                    @click="toggleTooltipCloud"
                    @mouseenter="showTooltipCloud"
                    @mouseleave="hideTooltipCloud"
                  >
                    <InfoIcon />
                    <span
                      class="tooltip"
                      :class="{ visible: tooltipCloudVisible }"
                    >
                      <strong>COMING SOON:</strong> <br />
                      Intel TDX<br />
                      AMD SEV-SNP<br />
                      TPM 2.0 attestations<br />
                    </span> </span
                ></span>
              </li>
              <li>
                <span class="platform-item"
                  >{{ platformText }}
                  <span
                    class="tooltip-trigger"
                    @click="toggleTooltipPlatform"
                    @mouseenter="showTooltipPlatform"
                    @mouseleave="hideTooltipPlatform"
                  >
                    <InfoIcon />
                    <span
                      class="tooltip"
                      :class="{ visible: tooltipPlatformVisible }"
                    >
                      <strong>COMING SOON:</strong> <br />
                      Windows and macOS<br />
                    </span> </span
                ></span>
              </li>
              <slot name="extra-features"></slot>
            </ul>

            <h2 class="info">Access</h2>
            <p class="info">
              <slot name="access-text">
                Enter your alpha code on the right to continue. If you don't have a
                code, request one at
                <a
                  href="mailto:info@caution.co?subject=Caution%20Early%20Access%20Inquiry&body=Hi%20Caution%20Team%2C%0A%0AI%20am%20interested%20in%20getting%20early%20access%20to%20Caution's%20managed%20services..."
                  >info@caution.co</a
                >.
              </slot>
            </p>
          </slot>
        </div>
      </div>

      <!-- Right Panel - Light -->
      <div class="right-panel">
        <div class="right-content">
          <!-- Show desktop required message on mobile -->
          <div v-if="isMobile" class="mobile-blocked">
            <h2 class="form-title">Desktop required</h2>
            <p class="mobile-blocked-text">
              Registration and login require a desktop browser. Please visit this page on a desktop computer to continue.
            </p>
          </div>
          <!-- Show normal content on desktop -->
          <slot v-else name="right-panel"></slot>
        </div>
      </div>
    </div>

    <SiteFooter @login="$emit('login')" />
  </div>
</template>

<script>
import { ref, onMounted, onUnmounted } from "vue";
import SiteHeader from "./SiteHeader.vue";
import SiteFooter from "./SiteFooter.vue";
import InfoIcon from "./InfoIcon.vue";
import { useNavbar } from "../composables/useNavbar.js";

export default {
  name: "AuthLayout",
  components: {
    SiteHeader,
    SiteFooter,
    InfoIcon,
  },
  props: {
    loginLoading: {
      type: Boolean,
      default: false,
    },
    platformText: {
      type: String,
      default: "CLI available for Linux x86_64 today",
    },
  },
  emits: ["login"],
  setup() {
    const tooltipPlatformVisible = ref(false);
    const tooltipCloudVisible = ref(false);
    const isMobile = ref(false);

    const checkMobile = () => {
      isMobile.value = window.innerWidth <= 960;
    };

    const {
      mobileMenuOpen,
      navbarHidden,
      navbarScrolled,
      navbarOnDark,
      closeMobileMenu,
      toggleMobileMenu,
      setupScrollListeners,
      cleanupScrollListeners,
    } = useNavbar();

    const showTooltipPlatform = () => {
      tooltipPlatformVisible.value = true;
    };

    const hideTooltipPlatform = () => {
      tooltipPlatformVisible.value = false;
    };

    const toggleTooltipPlatform = () => {
      tooltipPlatformVisible.value = !tooltipPlatformVisible.value;
    };

    const showTooltipCloud = () => {
      tooltipCloudVisible.value = true;
    };

    const hideTooltipCloud = () => {
      tooltipCloudVisible.value = false;
    };

    const toggleTooltipCloud = () => {
      tooltipCloudVisible.value = !tooltipCloudVisible.value;
    };

    const closeAllTooltips = () => {
      tooltipPlatformVisible.value = false;
      tooltipCloudVisible.value = false;
    };

    const handleClickOutside = (event) => {
      const isTooltipTrigger = event.target.closest('.tooltip-trigger');
      if (!isTooltipTrigger) {
        closeAllTooltips();
      }
    };

    onMounted(() => {
      setupScrollListeners();
      document.addEventListener('click', handleClickOutside);
      checkMobile();
      window.addEventListener('resize', checkMobile);
    });

    onUnmounted(() => {
      cleanupScrollListeners();
      document.removeEventListener('click', handleClickOutside);
      window.removeEventListener('resize', checkMobile);
    });

    return {
      mobileMenuOpen,
      navbarHidden,
      navbarScrolled,
      navbarOnDark,
      tooltipPlatformVisible,
      tooltipCloudVisible,
      isMobile,
      closeMobileMenu,
      toggleMobileMenu,
      showTooltipPlatform,
      hideTooltipPlatform,
      toggleTooltipPlatform,
      showTooltipCloud,
      hideTooltipCloud,
      toggleTooltipCloud,
    };
  },
};
</script>

<style src="../styles/auth-layout.css"></style>
