// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import { createApp } from 'vue'
import './styles/theme.css'
import App from './App.vue'
import { initializeTheme } from './utils/theme.js'

initializeTheme()
createApp(App).mount('#app')
