<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <div id="app">
    <component :is="currentView" :session="session" @update-session="handleSessionUpdate" />
  </div>
</template>

<script>
import { ref, computed, onMounted } from 'vue'
import Onboarding from './views/Onboarding.vue'
import Login from './views/Login.vue'
import Dashboard from './views/Dashboard.vue'

export default {
  name: 'App',
  components: {
    Onboarding,
    Login,
    Dashboard
  },
  setup() {
    // Extract session from URL params immediately in setup (before child components mount)
    const params = new URLSearchParams(window.location.search)
    const sessionParam = params.get('session')
    const session = ref(sessionParam || null)

    const currentRoute = ref(window.location.pathname)

    // Simple client-side routing
    const currentView = computed(() => {
      const path = currentRoute.value || window.location.pathname

      if (path === '/' || path === '/login') {
        return 'Login'
      } else if (path === '/onboarding') {
        return 'Onboarding'
      } else if (path === '/dashboard') {
        return 'Dashboard'
      }

      return 'Login'
    })

    const handleSessionUpdate = (newSession) => {
      session.value = newSession
    }

    onMounted(() => {
      // Handle browser back/forward buttons
      window.addEventListener('popstate', () => {
        currentRoute.value = window.location.pathname
      })
    })

    return {
      currentView,
      session,
      handleSessionUpdate
    }
  }
}
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  min-height: 100vh;
}

#app {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
</style>
