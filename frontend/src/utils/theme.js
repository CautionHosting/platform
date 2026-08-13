// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

export const THEME_STORAGE_KEY = 'caution-theme'
export const THEME_CHANGE_EVENT = 'caution:theme-change'
export const DEFAULT_THEME = 'light'
export const SYSTEM_THEME_QUERY = '(prefers-color-scheme: dark)'
export const THEME_META_COLORS = {
  light: '#e8f4fc',
  dark: '#090d12',
}

const VALID_THEMES = new Set(['light', 'dark'])
let storageListenerWindow = null
let systemListenerWindow = null

export const resolveTheme = (storedTheme, systemTheme = DEFAULT_THEME) => {
  if (VALID_THEMES.has(storedTheme)) return storedTheme
  if (VALID_THEMES.has(systemTheme)) return systemTheme
  return DEFAULT_THEME
}

export const getSystemTheme = (windowRef = window) => {
  try {
    if (typeof windowRef.matchMedia !== 'function') return DEFAULT_THEME
    return windowRef.matchMedia(SYSTEM_THEME_QUERY).matches ? 'dark' : 'light'
  } catch {
    return DEFAULT_THEME
  }
}

export const readStoredTheme = (windowRef = window) => {
  try {
    return windowRef.localStorage.getItem(THEME_STORAGE_KEY)
  } catch {
    return null
  }
}

export const updateMetaColor = (theme, documentRef = document) => {
  const color = THEME_META_COLORS[theme] || THEME_META_COLORS[DEFAULT_THEME]
  for (const selector of ['meta[name="theme-color"]', 'meta[name="msapplication-TileColor"]']) {
    const element = documentRef.querySelector(selector)
    if (element) {
      element.setAttribute('content', color)
    }
  }
}

export const setDocumentTheme = (theme, documentRef = document) => {
  documentRef.documentElement.dataset.theme = theme
  documentRef.documentElement.style.colorScheme = theme
  updateMetaColor(theme, documentRef)
}

const emitThemeChange = (theme, source, windowRef = window) => {
  windowRef.dispatchEvent(new CustomEvent(THEME_CHANGE_EVENT, { detail: { theme, source } }))
}

export const applyTheme = (
  theme,
  { persist = false, emit = true, source = 'local', windowRef = window, documentRef = document } = {},
) => {
  const nextTheme = resolveTheme(theme)
  setDocumentTheme(nextTheme, documentRef)

  if (persist) {
    try {
      windowRef.localStorage.setItem(THEME_STORAGE_KEY, nextTheme)
    } catch {
      // The selected theme still applies when browser storage is unavailable.
    }
  }

  if (emit) {
    emitThemeChange(nextTheme, source, windowRef)
  }

  return nextTheme
}

export const handleStorageChange = (event, { windowRef = window, documentRef = document } = {}) => {
  if (event.key && event.key !== THEME_STORAGE_KEY) return
  if (event.storageArea) {
    try {
      if (event.storageArea !== windowRef.localStorage) return
    } catch {
      return
    }
  }
  applyTheme(resolveTheme(event.newValue, getSystemTheme(windowRef)), {
    source: 'storage',
    windowRef,
    documentRef,
  })
}

export const handleSystemThemeChange = (
  event,
  { windowRef = window, documentRef = document } = {},
) => {
  if (VALID_THEMES.has(readStoredTheme(windowRef))) return
  applyTheme(event.matches ? 'dark' : 'light', { source: 'system', windowRef, documentRef })
}

const listenForSystemThemeChanges = (windowRef, documentRef) => {
  if (systemListenerWindow === windowRef) return

  let mediaQuery
  try {
    if (typeof windowRef.matchMedia !== 'function') return
    mediaQuery = windowRef.matchMedia(SYSTEM_THEME_QUERY)
  } catch {
    return
  }

  const listener = (event) => handleSystemThemeChange(event, { windowRef, documentRef })
  if (typeof mediaQuery.addEventListener === 'function') {
    mediaQuery.addEventListener('change', listener)
  } else if (typeof mediaQuery.addListener === 'function') {
    mediaQuery.addListener(listener)
  } else {
    return
  }
  systemListenerWindow = windowRef
}

export const initializeTheme = ({ windowRef = window, documentRef = document } = {}) => {
  const theme = applyTheme(resolveTheme(readStoredTheme(windowRef), getSystemTheme(windowRef)), {
    emit: false,
    windowRef,
    documentRef,
  })

  if (storageListenerWindow !== windowRef) {
    windowRef.addEventListener('storage', (event) => handleStorageChange(event, { windowRef, documentRef }))
    storageListenerWindow = windowRef
  }
  listenForSystemThemeChanges(windowRef, documentRef)

  return theme
}

export const getCurrentTheme = (documentRef = document) =>
  resolveTheme(documentRef.documentElement.dataset.theme)

export const toggleTheme = ({ windowRef = window, documentRef = document } = {}) => {
  const nextTheme = getCurrentTheme(documentRef) === 'dark' ? 'light' : 'dark'
  return applyTheme(nextTheme, { persist: true, windowRef, documentRef })
}
