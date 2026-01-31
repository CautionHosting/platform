// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import { ref, onMounted, onUnmounted } from "vue";

export function useNavbar() {
  const mobileMenuOpen = ref(false);
  const navbarHidden = ref(false);
  const navbarScrolled = ref(false);
  const navbarOnDark = ref(false);

  // Scroll behavior state
  let lastScrollY = 0;
  let ticking = false;
  const SCROLL_THRESHOLD = 5;
  const SHOW_THRESHOLD = 10;
  const TOP_THRESHOLD = 100;

  const updateNavbarVisibility = () => {
    const currentScrollY = window.scrollY;
    const scrollDelta = currentScrollY - lastScrollY;

    // Toggle scrolled state for blur effect
    navbarScrolled.value = currentScrollY > 50;

    // Check if navbar is over dark background (for stacked layout 960px and below)
    // In stacked layout, right panel (light) comes first, then left panel (dark)
    const rightPanel = document.querySelector(".right-panel");
    if (rightPanel && window.innerWidth <= 960) {
      const rightPanelBottom = rightPanel.offsetTop + rightPanel.offsetHeight;
      // Navbar is over dark when scrolled past the light panel
      navbarOnDark.value = currentScrollY > rightPanelBottom - 80;
    } else {
      navbarOnDark.value = false;
    }

    // Always show navbar when near the top
    if (currentScrollY < TOP_THRESHOLD) {
      navbarHidden.value = false;
      lastScrollY = currentScrollY;
      return;
    }

    // Check scroll direction and apply threshold to prevent jitter
    if (Math.abs(scrollDelta) > SCROLL_THRESHOLD) {
      if (scrollDelta > 0) {
        // Scrolling down - hide navbar
        navbarHidden.value = true;
      } else if (Math.abs(scrollDelta) > SHOW_THRESHOLD) {
        // Scrolling up with intent - show navbar
        navbarHidden.value = false;
      }
    }

    lastScrollY = currentScrollY;
  };

  const handleScroll = () => {
    if (!ticking) {
      window.requestAnimationFrame(() => {
        updateNavbarVisibility();
        ticking = false;
      });
      ticking = true;
    }
  };

  const handleResize = () => {
    // Re-check navbar dark state on resize
    updateNavbarVisibility();
  };

  const closeMobileMenu = () => {
    mobileMenuOpen.value = false;
    document.documentElement.classList.remove("mobile-menu-active");
    document.body.classList.remove("mobile-menu-active");
  };

  const toggleMobileMenu = () => {
    mobileMenuOpen.value = !mobileMenuOpen.value;
    document.documentElement.classList.toggle("mobile-menu-active", mobileMenuOpen.value);
    document.body.classList.toggle("mobile-menu-active", mobileMenuOpen.value);
  };

  const setupScrollListeners = () => {
    window.addEventListener("scroll", handleScroll, { passive: true });
    window.addEventListener("resize", handleResize, { passive: true });
  };

  const cleanupScrollListeners = () => {
    window.removeEventListener("scroll", handleScroll);
    window.removeEventListener("resize", handleResize);
  };

  return {
    mobileMenuOpen,
    navbarHidden,
    navbarScrolled,
    navbarOnDark,
    closeMobileMenu,
    toggleMobileMenu,
    setupScrollListeners,
    cleanupScrollListeners,
  };
}
