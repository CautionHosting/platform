// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict'
import test from 'node:test'
import { getSubscriptionPlanAction } from '../src/utils/subscriptionPlan.js'

test('existing subscriptions change tier instead of starting a second subscription', () => {
  assert.deepEqual(getSubscriptionPlanAction({ source: 'paddle' }), {
    endpoint: '/api/billing/subscription/change-tier',
    buttonLabel: 'Change plan',
    successMessage: 'Plan changed!',
  })
})

test('organizations without a subscription keep the subscribe flow', () => {
  assert.deepEqual(getSubscriptionPlanAction(null), {
    endpoint: '/api/billing/subscription/subscribe',
    buttonLabel: 'Subscribe now',
    successMessage: 'Subscription activated!',
  })
})
