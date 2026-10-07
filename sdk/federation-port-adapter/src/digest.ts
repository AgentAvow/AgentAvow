// Manifest and artifact digests, federation-port/v0 contract section 3.
// Re-implemented from federation-port src/runtime/canonical.ts (commit 92d5078, Apache-2.0) so this
// package can seal and verify its own manifest without importing src/runtime. The adapter itself does
// not use this file; test/manifest.test.ts checks it against the upstream implementation when a
// federation-port checkout is available (FEDERATION_PORT_DIR).
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

/** Sorted-key JSON. Refuses values JSON cannot represent exactly. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('canonical_json_non_finite_number')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']'
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort()
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}'
  }
  throw new Error(`canonical_json_unsupported_type:${typeof value}`)
}

export const sha256 = (data: string | Uint8Array): string =>
  'sha256:' + createHash('sha256').update(data).digest('hex')

export const digestJson = (value: unknown): string => sha256(canonicalJson(value))

/** Artifact digest: files sorted by relative path, each framed as path, byte length, bytes. */
export function artifactDigest(baseDir: string, files: string[]): string {
  const h = createHash('sha256')
  for (const f of [...files].sort()) {
    const bytes = readFileSync(join(baseDir, f))
    h.update(`${f}\n${bytes.byteLength}\n`)
    h.update(bytes)
  }
  return 'sha256:' + h.digest('hex')
}
