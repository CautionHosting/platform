// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import { sentryBuildConfig, validateSentryArtifacts } from '../build/sentry.js'

try {
  if (process.argv.length !== 4) throw new Error('Usage: node frontend/scripts/validate-sentry-artifacts.js <dist-directory> <sentry-artifacts-directory>')
  await validateSentryArtifacts({
    dist: process.argv[2],
    artifacts: process.argv[3],
    expectedConfig: sentryBuildConfig(process.env),
  })
} catch (error) {
  console.error(error.message)
  process.exitCode = 1
}
