// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const proxyTarget = process.env.VITE_PROXY_TARGET || 'http://localhost:8000';

export default defineConfig({
  plugins: [vue()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/api': {
        target: proxyTarget,
        changeOrigin: true,
        secure: false,
        cookieDomainRewrite: ''
      },
      '/auth': {
        target: proxyTarget,
        changeOrigin: true,
        secure: false,
        cookieDomainRewrite: ''
      },
      '/ssh-keys': {
        target: proxyTarget,
        changeOrigin: true,
        secure: false,
        cookieDomainRewrite: ''
      },
      '/health': {
        target: proxyTarget,
        changeOrigin: true,
        secure: false,
        cookieDomainRewrite: ''
      }
    }
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets'
  }
})
