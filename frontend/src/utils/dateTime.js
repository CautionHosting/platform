// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

export function getUserLocale() {
  if (typeof navigator === "undefined") {
    return undefined;
  }

  return navigator.languages?.[0] || navigator.language || undefined;
}

export function formatLocalDate(date, options) {
  return date.toLocaleDateString(getUserLocale(), options);
}

export function formatLocalTime(date, options) {
  return date.toLocaleTimeString(getUserLocale(), options);
}

export function formatLocalDateTime(date, options) {
  return new Intl.DateTimeFormat(getUserLocale(), options).format(date);
}
