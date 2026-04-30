// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

const DEVELOPMENT_BANNER_DISMISSED_KEY = "caution:development-banner-dismissed";

export function isDevelopmentBannerDismissed() {
  try {
    return window.sessionStorage.getItem(DEVELOPMENT_BANNER_DISMISSED_KEY) === "true";
  } catch {
    return false;
  }
}

export function dismissDevelopmentBannerForSession() {
  try {
    window.sessionStorage.setItem(DEVELOPMENT_BANNER_DISMISSED_KEY, "true");
  } catch {
    // Ignore storage failures; the in-memory dismissed state still applies.
  }
}

export function resetDevelopmentBannerDismissal() {
  try {
    window.sessionStorage.removeItem(DEVELOPMENT_BANNER_DISMISSED_KEY);
  } catch {
    // Ignore storage failures.
  }
}
