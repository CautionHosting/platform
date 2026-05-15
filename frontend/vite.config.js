// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const proxyTarget = env.VITE_PROXY_TARGET || 'http://localhost:8000'
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
    ['/api', '/auth', '/ssh-keys', '/passkeys', '/health'].map((path) => [
      path,
      { ...proxyOptions },
    ]),
  )

  return {
    plugins: [vue()],
    server: {
      host: '0.0.0.0',
      port: 3000,
      allowedHosts,
      hmr: {
        overlay: false,
      },
      proxy,
    },
    build: {
      outDir: 'dist',
      assetsDir: 'assets'
    }
  }
})
