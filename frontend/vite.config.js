// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import { dashboardPreviewPlugin, isDashboardPreviewEnabled } from './dev/dashboardPreview.js'

export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const proxyTarget = env.VITE_PROXY_TARGET || 'http://localhost:8000'
  const dashboardPreviewEnabled = isDashboardPreviewEnabled({ command, env })
  const allowedHosts = env.VITE_ALLOWED_HOSTS
    ? env.VITE_ALLOWED_HOSTS.split(',').map((host) => host.trim()).filter(Boolean)
    : []
  const proxyOptions = {
    target: proxyTarget,
    changeOrigin: true,
    secure: false,
    cookieDomainRewrite: ''
  }
  const proxy = Object.fromEntries(
    ['/api', '/auth', '/user', '/ssh-keys', '/pgp-keys', '/passkeys', '/health', '/.well-known'].map((path) => [
      path,
      { ...proxyOptions },
    ]),
  )

  return {
    plugins: [vue(), dashboardPreviewPlugin(dashboardPreviewEnabled)],
    define: {
      __CAUTION_DASHBOARD_PREVIEW__: JSON.stringify(dashboardPreviewEnabled),
    },
    server: {
      host: dashboardPreviewEnabled ? '127.0.0.1' : '0.0.0.0',
      port: 3000,
      allowedHosts,
      hmr: {
        overlay: false,
      },
      proxy: dashboardPreviewEnabled ? undefined : proxy,
    },
    build: {
      outDir: 'dist',
      assetsDir: 'assets'
    }
  }
})
