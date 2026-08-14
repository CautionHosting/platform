// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import test from 'node:test'
import {
  THEME_CHANGE_EVENT,
  THEME_META_COLORS,
  applyTheme,
  handleStorageChange,
  initializeTheme,
  resolveTheme,
  toggleTheme,
} from '../src/utils/theme.js'

class CustomEventStub {
  constructor(type, init = {}) {
    this.type = type
    this.detail = init.detail
  }
}

const createEnvironment = ({
  storedTheme = null,
  storageThrows = false,
  systemDark = false,
  matchMediaUnavailable = false,
} = {}) => {
  const listeners = new Map()
  const mediaListeners = []
  const metaElements = new Map([
    ['meta[name="theme-color"]', { content: '', setAttribute(name, value) { this[name] = value } }],
    ['meta[name="msapplication-TileColor"]', { content: '', setAttribute(name, value) { this[name] = value } }],
  ])
  const storage = new Map(storedTheme == null ? [] : [['caution-theme', storedTheme]])

  const localStorage = {
    getItem(key) {
      if (storageThrows) throw new Error('storage unavailable')
      return storage.has(key) ? storage.get(key) : null
    },
    setItem(key, value) {
      if (storageThrows) throw new Error('storage unavailable')
      storage.set(key, value)
    },
  }

  const windowRef = {
    localStorage,
    addEventListener(type, listener) {
      const queue = listeners.get(type) || []
      queue.push(listener)
      listeners.set(type, queue)
    },
    removeEventListener(type, listener) {
      const queue = listeners.get(type) || []
      listeners.set(
        type,
        queue.filter((entry) => entry !== listener),
      )
    },
    dispatchEvent(event) {
      for (const listener of listeners.get(event.type) || []) {
        listener(event)
      }
    },
  }
  const mediaQuery = {
    matches: systemDark,
    addEventListener(type, listener) {
      if (type === 'change') mediaListeners.push(listener)
    },
  }
  if (!matchMediaUnavailable) {
    windowRef.matchMedia = () => mediaQuery
  }

  const documentRef = {
    documentElement: {
      dataset: {},
      style: {},
    },
    querySelector(selector) {
      return metaElements.get(selector) || null
    },
  }

  globalThis.CustomEvent = CustomEventStub

  const setSystemDark = (matches) => {
    mediaQuery.matches = matches
    for (const listener of mediaListeners) listener({ matches })
  }

  return { documentRef, metaElements, setSystemDark, storage, windowRef }
}

test('stored valid theme is restored', () => {
  assert.equal(resolveTheme('light'), 'light')
  assert.equal(resolveTheme('dark'), 'dark')
})

test('system theme is the default without a valid stored theme', () => {
  assert.equal(resolveTheme(null), 'light')
  assert.equal(resolveTheme(null, 'dark'), 'dark')
  assert.equal(resolveTheme('invalid', 'dark'), 'dark')
})

test('initializeTheme follows the system when storage is unavailable', () => {
  const { documentRef, windowRef } = createEnvironment({ storageThrows: true, systemDark: true })

  const theme = initializeTheme({ windowRef, documentRef })

  assert.equal(theme, 'dark')
  assert.equal(documentRef.documentElement.dataset.theme, 'dark')
})

test('initializeTheme ignores an invalid stored value and follows the system', () => {
  const { documentRef, windowRef } = createEnvironment({ storedTheme: 'invalid', systemDark: true })

  const theme = initializeTheme({ windowRef, documentRef })

  assert.equal(theme, 'dark')
  assert.equal(documentRef.documentElement.dataset.theme, 'dark')
})

test('initializeTheme falls back to light when matchMedia is unavailable', () => {
  const { documentRef, windowRef } = createEnvironment({ matchMediaUnavailable: true })

  const theme = initializeTheme({ windowRef, documentRef })

  assert.equal(theme, 'light')
  assert.equal(documentRef.documentElement.dataset.theme, 'light')
})

test('initializeTheme applies the stored theme before mount state', () => {
  const { documentRef, metaElements, windowRef } = createEnvironment({ storedTheme: 'dark' })

  const theme = initializeTheme({ windowRef, documentRef })

  assert.equal(theme, 'dark')
  assert.equal(documentRef.documentElement.dataset.theme, 'dark')
  assert.equal(documentRef.documentElement.style.colorScheme, 'dark')
  assert.equal(metaElements.get('meta[name="theme-color"]').content, THEME_META_COLORS.dark)
})

test('toggleTheme persists the opposite of the system-resolved theme and emits it', () => {
  const { documentRef, storage, windowRef } = createEnvironment({ systemDark: true })
  initializeTheme({ windowRef, documentRef })

  let emittedTheme = null
  windowRef.addEventListener(THEME_CHANGE_EVENT, (event) => {
    emittedTheme = event.detail.theme
  })

  const nextTheme = toggleTheme({ windowRef, documentRef })

  assert.equal(nextTheme, 'light')
  assert.equal(storage.get('caution-theme'), 'light')
  assert.equal(emittedTheme, 'light')
})

test('applyTheme still works when storage is unavailable', () => {
  const { documentRef, windowRef } = createEnvironment({ storageThrows: true })

  const theme = applyTheme('dark', { persist: true, windowRef, documentRef })

  assert.equal(theme, 'dark')
  assert.equal(documentRef.documentElement.dataset.theme, 'dark')
})

test('storage events synchronize theme changes across tabs', () => {
  const { documentRef, metaElements, windowRef } = createEnvironment({ storedTheme: 'light' })

  initializeTheme({ windowRef, documentRef })
  handleStorageChange(
    { key: 'caution-theme', newValue: 'dark' },
    { windowRef, documentRef },
  )

  assert.equal(documentRef.documentElement.dataset.theme, 'dark')
  assert.equal(metaElements.get('meta[name="theme-color"]').content, THEME_META_COLORS.dark)
})

test('cleared or invalid storage values return to the system theme', () => {
  const { documentRef, windowRef } = createEnvironment({ storedTheme: 'light', systemDark: true })

  initializeTheme({ windowRef, documentRef })
  handleStorageChange(
    { key: 'caution-theme', newValue: null },
    { windowRef, documentRef },
  )

  assert.equal(documentRef.documentElement.dataset.theme, 'dark')

  handleStorageChange(
    { key: 'caution-theme', newValue: 'bogus' },
    { windowRef, documentRef },
  )

  assert.equal(documentRef.documentElement.dataset.theme, 'dark')
})

test('system changes update automatic mode', () => {
  const { documentRef, setSystemDark, windowRef } = createEnvironment()

  initializeTheme({ windowRef, documentRef })
  setSystemDark(true)

  assert.equal(documentRef.documentElement.dataset.theme, 'dark')
})

test('system changes do not override an explicit theme', () => {
  const { documentRef, setSystemDark, windowRef } = createEnvironment({ storedTheme: 'light' })

  initializeTheme({ windowRef, documentRef })
  setSystemDark(true)

  assert.equal(documentRef.documentElement.dataset.theme, 'light')
})

test('storage events ignore unrelated keys and other storage areas', () => {
  const { documentRef, windowRef } = createEnvironment({ storedTheme: 'light' })

  initializeTheme({ windowRef, documentRef })
  handleStorageChange(
    { key: 'something-else', newValue: 'dark' },
    { windowRef, documentRef },
  )
  assert.equal(documentRef.documentElement.dataset.theme, 'light')

  handleStorageChange(
    {
      key: 'caution-theme',
      newValue: 'dark',
      storageArea: {
        getItem() {
          return 'dark'
        },
      },
    },
    { windowRef, documentRef },
  )
  assert.equal(documentRef.documentElement.dataset.theme, 'light')
})
