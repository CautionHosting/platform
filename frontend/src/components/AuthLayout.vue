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
            <h1 class="info-title">Enclaves you can verify</h1>
            <p class="info">
              Confidential compute platform for teams deploying verifiable enclaves.
              <a href="https://caution.co/platform-tour.html" target="_blank" rel="noopener noreferrer">
                Watch the platform demo.
              </a>
            </p>
            <h2 class="info">What you get</h2>
            <ul class="feature-list">
              <li>
                <span class="platform-item"
                  >Verifiable AWS Nitro enclave deployments
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
                  >CLI-first deployment workflow for Linux and macOS
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
                      CLI support for Windows<br />
                    </span> </span
                ></span>
              </li>
              <li>
                <span class="platform-item"
                  >Passkey-based account security
                  <span
                    class="tooltip-trigger"
                    @click="toggleTooltipPasskey"
                    @mouseenter="showTooltipPasskey"
                    @mouseleave="hideTooltipPasskey"
                  >
                    <InfoIcon />
                    <span
                      class="tooltip"
                      :class="{ visible: tooltipPasskeyVisible }"
                    >
                      <strong>SUPPORTED:</strong> <br />
                      Browser or platform passkeys<br />
                      Password manager passkeys<br />
                      Security keys and smart cards<br />
                      YubiKey, NitroKey, or LibremKey<br />
                    </span> </span
                ></span>
              </li>
              <slot name="extra-features"></slot>
            </ul>

            <h2 class="info">Get access</h2>
            <p class="info">
              <slot name="access-text">
                Email
                <a
                  href="mailto:info@caution.co?subject=Caution%20Early%20Access%20Inquiry&body=Hi%20Caution%20Team%2C%0A%0AI%20am%20interested%20in%20getting%20early%20access%20to%20Caution's%20managed%20services..."
                  >info@caution.co</a
                > to request an access code.
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
  },
  emits: ["login"],
  setup() {
    const tooltipPlatformVisible = ref(false);
    const tooltipCloudVisible = ref(false);
    const tooltipPasskeyVisible = ref(false);
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

    const showTooltipPasskey = () => {
      tooltipPasskeyVisible.value = true;
    };

    const hideTooltipPasskey = () => {
      tooltipPasskeyVisible.value = false;
    };

    const toggleTooltipPasskey = () => {
      tooltipPasskeyVisible.value = !tooltipPasskeyVisible.value;
    };

    const closeAllTooltips = () => {
      tooltipPlatformVisible.value = false;
      tooltipCloudVisible.value = false;
      tooltipPasskeyVisible.value = false;
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
      tooltipPasskeyVisible,
      isMobile,
      closeMobileMenu,
      toggleMobileMenu,
      showTooltipPlatform,
      hideTooltipPlatform,
      toggleTooltipPlatform,
      showTooltipCloud,
      hideTooltipCloud,
      toggleTooltipCloud,
      showTooltipPasskey,
      hideTooltipPasskey,
      toggleTooltipPasskey,
    };
  },
};
</script>

<style src="../styles/auth-layout.css"></style>
