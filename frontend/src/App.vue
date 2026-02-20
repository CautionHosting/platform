<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div id="app">
    <component :is="currentView" />
  </div>
</template>

<script>
import { ref, computed, onMounted } from 'vue'
import Onboarding from './views/Onboarding.vue'
import Register from './views/Login.vue'
import AuthLogin from './views/AuthLogin.vue'
import Dashboard from './views/Dashboard.vue'
import QrLogin from './views/QrLogin.vue'
import { getCsrfToken } from './composables/useWebAuthn.js'

export default {
  name: 'App',
  components: {
    Onboarding,
    Register,
    AuthLogin,
    Dashboard,
    QrLogin
  },
  setup() {
    // Session is now stored in HTTP-only cookie, not URL
    // We track authentication state here, but actual auth is via cookie
    const isAuthenticated = ref(false)
    const authChecked = ref(false)

    const currentRoute = ref(window.location.pathname)

    // Page metadata by route
    const pageMeta = {
      '/': {
        title: 'Alpha access • Caution',
        description: 'Enter your alpha code to access Caution. Closed alpha with support for verified enclave deployments on AWS Nitro.'
      },
      '/login': {
        title: 'Log in to Caution',
        description: 'Log in to your Caution account to manage applications and verified enclave deployments.'
      },
      '/onboarding': {
        title: 'Onboarding • Caution',
        description: 'Complete your Caution account setup.'
      },
      '/dashboard': {
        title: 'Dashboard • Caution',
        description: 'Manage your applications and verified enclave deployments.'
      },
      '/qr-login': {
        title: 'CLI Login • Caution',
        description: 'Authenticate your CLI session using a security key.'
      }
    }

    // Update page title and meta description
    const updatePageMeta = (path) => {
      const meta = pageMeta[path] || pageMeta['/']
      document.title = meta.title
      const metaDesc = document.querySelector('meta[name="description"]')
      if (metaDesc) {
        metaDesc.setAttribute('content', meta.description)
      }
    }

    // Check authentication status via API call (session in HTTP-only cookie)
    const checkAuth = async () => {
      try {
        const response = await fetch('/api/user/status', {
          credentials: 'include',
        })
        isAuthenticated.value = response.ok
      } catch {
        isAuthenticated.value = false
      }
      authChecked.value = true
    }

    // Simple client-side routing
    const currentView = computed(() => {
      const path = currentRoute.value || window.location.pathname

      // Update page metadata
      updatePageMeta(path)

      if (path === '/') {
        // Register page (alpha code entry)
        return 'Register'
      } else if (path === '/login') {
        // Login page (WebAuthn authentication)
        return 'AuthLogin'
      } else if (path === '/onboarding') {
        // Protected route - redirect to home if not authenticated
        if (authChecked.value && !isAuthenticated.value) {
          window.location.href = '/'
          return 'Register'
        }
        return 'Onboarding'
      } else if (path === '/dashboard') {
        // Protected route - redirect to home if not authenticated
        if (authChecked.value && !isAuthenticated.value) {
          window.location.href = '/'
          return 'Register'
        }
        return 'Dashboard'
      } else if (path === '/qr-login') {
        // Public route - QR code CLI login (no auth required)
        return 'QrLogin'
      }

      // Unknown path - redirect to home
      window.location.href = '/'
      return 'Register'
    })

    onMounted(() => {
      // Check authentication on mount
      checkAuth()

      // Handle browser back/forward buttons
      window.addEventListener('popstate', () => {
        currentRoute.value = window.location.pathname
      })
    })

    return {
      currentView,
      isAuthenticated,
      getCsrfToken
    }
  }
}
</script>

<style>
/* Plus Jakarta Sans */
@font-face {
  font-family: 'Plus Jakarta Sans';
  src: url('./assets/fonts/PlusJakartaSans-ExtraLight.otf') format('opentype');
  font-weight: 200;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: 'Plus Jakarta Sans';
  src: url('./assets/fonts/PlusJakartaSans-Light.otf') format('opentype');
  font-weight: 300;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: 'Plus Jakarta Sans';
  src: url('./assets/fonts/PlusJakartaSans-Regular.otf') format('opentype');
  font-weight: 400;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: 'Plus Jakarta Sans';
  src: url('./assets/fonts/PlusJakartaSans-Medium.otf') format('opentype');
  font-weight: 500;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: 'Plus Jakarta Sans';
  src: url('./assets/fonts/PlusJakartaSans-SemiBold.otf') format('opentype');
  font-weight: 600;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: 'Plus Jakarta Sans';
  src: url('./assets/fonts/PlusJakartaSans-Bold.otf') format('opentype');
  font-weight: 700;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: 'Plus Jakarta Sans';
  src: url('./assets/fonts/PlusJakartaSans-ExtraBold.otf') format('opentype');
  font-weight: 800;
  font-style: normal;
  font-display: swap;
}

/* IBM Plex Sans */
@font-face {
  font-family: 'IBM Plex Sans';
  src: url('./assets/fonts/IBMPlexSans-Light.woff2') format('woff2');
  font-weight: 300;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: 'IBM Plex Sans';
  src: url('./assets/fonts/IBMPlexSans-Regular.woff2') format('woff2');
  font-weight: 400;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: 'IBM Plex Sans';
  src: url('./assets/fonts/IBMPlexSans-Medium.woff2') format('woff2');
  font-weight: 500;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: 'IBM Plex Sans';
  src: url('./assets/fonts/IBMPlexSans-SemiBold.woff2') format('woff2');
  font-weight: 600;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: 'IBM Plex Sans';
  src: url('./assets/fonts/IBMPlexSans-Bold.woff2') format('woff2');
  font-weight: 700;
  font-style: normal;
  font-display: swap;
}

:root {
  /* Colors - Brand */
  --color-dark: #0f0f0f;
  --color-grey: #666666;
  --color-grey-dark: #232b2b;
  --color-grey-mid: #ccc;
  --color-grey-med: #858585;
  --color-grey-light: #edf1f7;
  --color-slate-muted: oklch(70.4% 0.04 256.788);
  --color-slate: #56636f;
  --color-blue-base: #ecf6fd;
  --color-blue-light: #e7f1ff;
  --color-blue-mid: #c7e8ff;
  --color-pink: #f048b5;
  --color-accent-green: oklch(79.2% 0.209 151.711);

  /* HSL Color System */
  --bg-dark: hsl(205 79% 85%);
  --bg: hsl(205 80% 90%);
  --bg-light: hsl(204 77% 95%);
  --text: hsl(0 0% 5%);
  --text-muted: hsl(0 0% 30%);
  --highlight: hsl(300 50% 100%);
  --border: hsl(300 0% 50%);
  --border-muted: hsl(340 0% 62%);
  --accent-pink: hsl(322 87% 62%);

  /* Spacing scale */
  --spacing1: 4px;
  --spacing2: 8px;
  --spacing3: 16px;
  --spacing4: 20px;
  --spacing5: 40px;
  --spacing6: 80px;
  --spacing6-5: 120px;
  --spacing7: 160px;
  --spacing8: 240px;

  /* Border radius */
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 20px;
  --radius-xl: 30px;
  --radius-full: 9999px;

  /* Shadows */
  --shadow-sm: 0 2px 6px rgba(0, 0, 0, 0.15);
  --shadow-md: 0 6px 24px rgba(46, 106, 234, 0.1), 0 2px 6px rgba(0, 0, 0, 0.06);
  --shadow-lg: 0 10px 34px rgba(46, 106, 234, 0.15), 0 6px 16px rgba(0, 0, 0, 0.08);

  /* Layout */
  --site-width: 95%;
  --site-max-width: 1450px;

  /* Transitions */
  --transition-fast: 0.15s ease;
  --transition-base: 0.2s ease;
  --transition-slow: 0.3s ease;

  /* Typography - Heading 1 */
  --heading1-font-size: clamp(2.5rem, 5vw, 3.25rem);
  --heading1-font-weight: 700;
  --heading1-line-height: 1.2;
  --heading1-letter-spacing: -0.02em;

  /* Typography - Heading 2 */
  --heading2-font-size: clamp(2rem, 4vw, 2.6rem);
  --heading2-font-weight: 600;
  --heading2-line-height: 1.25;
  --heading2-letter-spacing: -0.01em;

  /* Typography - Heading 3 */
  --heading3-font-size: clamp(1.5rem, 3vw, 2rem);
  --heading3-font-weight: 600;
  --heading3-line-height: 1.33;
  --heading3-letter-spacing: -0.005em;

  /* Typography - Subtitle */
  --subtitle-font-size: clamp(1.15rem, 2vw, 1.3rem);
  --subtitle-font-weight: 500;
  --subtitle-line-height: 1.5;
  --subtitle-letter-spacing: 0em;

  /* Typography - Body */
  --body-font-size: clamp(1.15rem, 2vw, 1.3rem);
  --body-font-weight: 300;
  --body-line-height: 1.5;
  --body-letter-spacing: 0em;

  /* Typography - Button */
  --button-font-size: clamp(1.05rem, 2vw, 1.2rem);
  --button-font-weight: 400;
  --button-line-height: 1.5;
  --button-letter-spacing: 0em;

  /* Typography - List */
  --list-font-size: clamp(1.5rem, 3vw, 2rem);
  --list-font-weight: 300;
  --list-line-height: 1.33;
  --list-letter-spacing: -0.005em;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: radial-gradient(circle at 50% 25%, white 0%, transparent 60%) no-repeat, #E8F4FC;
  min-height: 100vh;
}

#app {
  min-height: 100vh;
}
</style>
