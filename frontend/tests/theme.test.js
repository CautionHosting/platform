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

const createEnvironment = ({ storedTheme = null, storageThrows = false } = {}) => {
  const listeners = new Map()
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

  return { documentRef, metaElements, storage, windowRef }
}

test('stored valid theme is restored', () => {
  assert.equal(resolveTheme('light'), 'light')
  assert.equal(resolveTheme('dark'), 'dark')
})

test('light is the default without a valid stored theme', () => {
  assert.equal(resolveTheme(null), 'light')
  assert.equal(resolveTheme('invalid'), 'light')
})

test('initializeTheme falls back to light when storage is unavailable', () => {
  const { documentRef, windowRef } = createEnvironment({ storageThrows: true })

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

test('toggleTheme persists and emits the selected theme', () => {
  const { documentRef, storage, windowRef } = createEnvironment({ storedTheme: 'light' })
  initializeTheme({ windowRef, documentRef })

  let emittedTheme = null
  windowRef.addEventListener(THEME_CHANGE_EVENT, (event) => {
    emittedTheme = event.detail.theme
  })

  const nextTheme = toggleTheme({ windowRef, documentRef })

  assert.equal(nextTheme, 'dark')
  assert.equal(storage.get('caution-theme'), 'dark')
  assert.equal(emittedTheme, 'dark')
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

test('invalid storage event values safely fall back to light', () => {
  const { documentRef, windowRef } = createEnvironment({ storedTheme: 'dark' })

  initializeTheme({ windowRef, documentRef })
  handleStorageChange(
    { key: 'caution-theme', newValue: 'bogus' },
    { windowRef, documentRef },
  )

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
