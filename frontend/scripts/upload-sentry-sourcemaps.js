// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import { spawnSync } from 'node:child_process'
import { SentryCli } from '@sentry/cli'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { validateSentryArtifacts } from '../build/sentry.js'

export async function uploadSourceMaps({ dist, artifacts, env = process.env, run = spawnSync }) {
  for (const key of ['SENTRY_AUTH_TOKEN', 'SENTRY_ORG', 'SENTRY_PROJECT', 'SENTRY_RELEASE']) {
    if (!env[key]?.trim()) throw new Error(`Set ${key} in the upload process environment`)
  }
  dist = resolve(dist)
  artifacts = resolve(artifacts)
  const manifest = await validateSentryArtifacts({ dist, artifacts, expectedConfig: { enabled: true, release: env.SENTRY_RELEASE } })
  const args = [
    'sourcemaps', 'upload', '--org', env.SENTRY_ORG, '--project', env.SENTRY_PROJECT,
    '--release', manifest.release, '--url-prefix', '~/assets',
    '--no-rewrite', '--validate', '--strict', '--wait', join(artifacts, 'assets'),
  ]
  const childEnv = { SENTRY_AUTH_TOKEN: env.SENTRY_AUTH_TOKEN, SENTRY_LOAD_DOTENV: '0' }
  for (const key of ['PATH', 'HOME', 'SENTRY_URL', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY']) {
    if (env[key] !== undefined) childEnv[key] = env[key]
  }
  const result = run(SentryCli.getPath(), args, { env: childEnv, stdio: 'inherit' })
  if (result.error) throw result.error
  if (result.status !== 0) throw new Error(`Sentry upload failed (exit ${result.status}, signal ${result.signal || 'none'})`)
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 4) throw new Error('Usage: node frontend/scripts/upload-sentry-sourcemaps.js <dist-directory> <sentry-artifacts-directory>')
    await uploadSourceMaps({ dist: process.argv[2], artifacts: process.argv[3] })
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
