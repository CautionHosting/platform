// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

export function getSubscriptionPlanAction(subscription) {
  if (subscription) {
    return {
      endpoint: '/api/billing/subscription/change-tier',
      buttonLabel: 'Change plan',
      successMessage: 'Plan changed!',
    }
  }

  return {
    endpoint: '/api/billing/subscription/subscribe',
    buttonLabel: 'Subscribe now',
    successMessage: 'Subscription activated!',
  }
}
