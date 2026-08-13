// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

export const THEME_STORAGE_KEY = 'caution-theme'
export const THEME_CHANGE_EVENT = 'caution:theme-change'
export const DEFAULT_THEME = 'light'
export const THEME_META_COLORS = {
  light: '#e8f4fc',
  dark: '#090d12',
}

const VALID_THEMES = new Set(['light', 'dark'])
let storageListenerWindow = null

export const resolveTheme = (storedTheme) => {
  if (VALID_THEMES.has(storedTheme)) return storedTheme
  return DEFAULT_THEME
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
  applyTheme(resolveTheme(event.newValue), { source: 'storage', windowRef, documentRef })
}

export const initializeTheme = ({ windowRef = window, documentRef = document } = {}) => {
  const theme = applyTheme(resolveTheme(readStoredTheme(windowRef)), {
    emit: false,
    windowRef,
    documentRef,
  })

  if (storageListenerWindow !== windowRef) {
    windowRef.addEventListener('storage', (event) => handleStorageChange(event, { windowRef, documentRef }))
    storageListenerWindow = windowRef
  }

  return theme
}

export const getCurrentTheme = (documentRef = document) =>
  resolveTheme(documentRef.documentElement.dataset.theme)

export const toggleTheme = ({ windowRef = window, documentRef = document } = {}) => {
  const nextTheme = getCurrentTheme(documentRef) === 'dark' ? 'light' : 'dark'
  return applyTheme(nextTheme, { persist: true, windowRef, documentRef })
}
