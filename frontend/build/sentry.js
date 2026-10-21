// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import { createHash } from 'node:crypto'
import { copyFile, lstat, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises'
import { basename, dirname, join, resolve } from 'node:path'
import { isDeepStrictEqual } from 'node:util'

export async function fileHashes(root) {
  root = resolve(root)
  if (!(await lstat(root)).isDirectory()) throw new Error(`Unsupported artifact root: ${root}`)
  const hashes = new Map()
  async function visit(directory, prefix = '') {
    for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
      const name = prefix + entry.name
      const path = join(directory, entry.name)
      if (entry.isDirectory()) await visit(path, `${name}/`)
      else if (entry.isFile()) hashes.set(name, createHash('sha256').update(await readFile(path)).digest('hex'))
      else throw new Error(`Unsupported artifact entry: ${name}`)
    }
  }
  await visit(root)
  return Object.fromEntries(hashes)
}

export async function validateSentryArtifacts({ dist, artifacts, expectedConfig }) {
  const distHashes = await fileHashes(dist)
  const artifactHashes = await fileHashes(artifacts)
  const manifest = JSON.parse(await readFile(join(artifacts, 'manifest.json')))
  if (!manifest || manifest.version !== 1 || ![undefined, true, false].includes(manifest.enabled) || !/^[a-f0-9]{64}$/.test(manifest.buildConfigSha256)) {
    throw new Error('Invalid retained frontend manifest version or enabled state')
  }
  const enabled = manifest.enabled !== false
  if (enabled) {
    sentryBuildConfig({ VITE_SENTRY_DSN: 'enabled', VITE_SENTRY_RELEASE: manifest.release, VITE_SENTRY_ENVIRONMENT: manifest.environment })
  }
  if (expectedConfig) {
    if (expectedConfig.enabled !== enabled) throw new Error('Sentry enabled state must match the retained build manifest')
    for (const key of ['release', 'environment', 'buildConfigSha256']) {
      if (expectedConfig[key] !== undefined && expectedConfig[key] !== manifest[key]) {
        throw new Error(`Sentry ${key} must match the retained build manifest`)
      }
    }
  }
  if (!isDeepStrictEqual(distHashes, manifest.dist) || Object.keys(distHashes).some((name) => name.endsWith('.map'))) {
    throw new Error('dist bytes do not match the retained build manifest, or contain public source maps')
  }
  delete artifactHashes['manifest.json']
  if (!isDeepStrictEqual(artifactHashes, manifest.artifacts)) {
    throw new Error('Source-map artifact bytes do not match the retained build manifest')
  }
  if (!enabled) {
    if (Object.keys(artifactHashes).length || manifest.release !== undefined || manifest.environment !== undefined) {
      throw new Error('Disabled Sentry exports must not retain source-map artifacts or release settings')
    }
    return manifest
  }
  const scripts = Object.keys(distHashes).filter((name) => /^assets\/[^/]+\.js$/.test(name))
  const expectedFiles = scripts.flatMap((name) => [name, `${name}.map`]).sort()
  if (!scripts.length || !isDeepStrictEqual(Object.keys(artifactHashes).sort(), expectedFiles)) {
    throw new Error('Source-map artifacts require exactly one JS/map pair per built script')
  }
  for (const name of scripts) {
    if (artifactHashes[name] !== distHashes[name]) {
      throw new Error('Source-map JS pair must match the deployed assets filename and bytes')
    }
    const map = JSON.parse(await readFile(join(artifacts, `${name}.map`)))
    if (map.version !== 3 || map.file !== basename(name) || !Array.isArray(map.sourcesContent) || !map.sourcesContent.length) {
      throw new Error('Source-map filename or embedded sources do not match the JS pair')
    }
  }
  return manifest
}

export function sentryArtifactsPlugin(config) {
  let dist
  let artifacts
  return {
    name: 'private-sentry-artifacts',
    apply: 'build',
    enforce: 'post',
    configResolved(vite) {
      dist = resolve(vite.root, vite.build.outDir)
      artifacts = join(dirname(dist), 'sentry-artifacts')
      if (dist === artifacts) throw new Error('Sentry artifacts must be outside dist')
    },
    async buildStart() {
      await rm(artifacts, { recursive: true, force: true })
      await mkdir(artifacts, { recursive: true })
    },
    async closeBundle() {
      const files = await fileHashes(dist)
      for (const name of Object.keys(files).filter((name) => name.endsWith('.map'))) {
        const destination = join(artifacts, name)
        await mkdir(dirname(destination), { recursive: true })
        await rename(join(dist, name), destination)
      }
      if (!config.enabled) {
        await rm(artifacts, { recursive: true, force: true })
        await mkdir(artifacts, { recursive: true })
      } else {
        for (const name of Object.keys(files).filter((name) => /^assets\/[^/]+\.js$/.test(name))) {
          await readFile(join(artifacts, `${name}.map`))
          await copyFile(join(dist, name), join(artifacts, name))
        }
      }
      await writeFile(join(artifacts, 'manifest.json'), JSON.stringify({
        version: 1,
        enabled: config.enabled,
        release: config.release,
        environment: config.environment,
        buildConfigSha256: config.buildConfigSha256,
        dist: await fileHashes(dist),
        artifacts: await fileHashes(artifacts),
      }, null, 2) + '\n')
    },
  }
}

export function sentryBuildConfig(env) {
  const buildConfigSha256 = createHash('sha256').update(JSON.stringify([
    env.VITE_SENTRY_DSN || '', env.VITE_SENTRY_ENVIRONMENT || '',
    env.VITE_SENTRY_RELEASE || '', env.VITE_PADDLE_SANDBOX || '',
  ])).digest('hex')
  if (!env.VITE_SENTRY_DSN?.trim()) return { enabled: false, buildConfigSha256 }
  const environment = env.VITE_SENTRY_ENVIRONMENT || ''
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(environment) || environment === 'None') {
    throw new Error('Enabled frontend Sentry requires an explicit VITE_SENTRY_ENVIRONMENT (1–64 letters, digits, underscores or hyphens; not None)')
  }
  const release = env.VITE_SENTRY_RELEASE || ''
  if (!/^[a-f0-9]{40}$/.test(release)) {
    throw new Error('Enabled frontend Sentry requires VITE_SENTRY_RELEASE to be the full lowercase Git commit SHA')
  }
  return { enabled: true, environment, release, buildConfigSha256 }
}
