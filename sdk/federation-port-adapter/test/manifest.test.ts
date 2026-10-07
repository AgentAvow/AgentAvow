// Manifest and artifact digests per contract section 3, and the pin values a customer policy would hold.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import type { Manifest } from '../src/contract/types.ts'
import { artifactDigest, canonicalJson, digestJson, sha256 } from '../src/digest.ts'
import { PINNED_JWK, createAdapter } from '../adapters/agentavow-mcp-admission/adapter.ts'
import { ADAPTER_DIR, COMPONENT, FIXTURE_PATH, ROOT, vectors } from './fixture.ts'

const manifest: Manifest = JSON.parse(readFileSync(join(ADAPTER_DIR, 'manifest.json'), 'utf8'))
const FP = process.env.FEDERATION_PORT_DIR

test('manifest: every required field of contract section 2, role tool_admission, three claims each with establishes and limits', () => {
  assert.equal(manifest.contract, 'federation-port/v0')
  assert.equal(manifest.id, COMPONENT)
  assert.equal(manifest.role, 'tool_admission')
  for (const k of ['publisher', 'maintainer', 'artifact', 'schemas', 'claims', 'profiles', 'privileges_requested', 'data_destinations', 'keys', 'license'] as const) assert.ok(k in manifest, k)
  assert.ok(manifest.artifact.files.includes(manifest.artifact.entry))
  assert.deepEqual(manifest.claims.map(c => c.id), ['agentavow.grade', 'agentavow.tool_definition_binds', 'agentavow.fresh'])
  for (const c of manifest.claims) { assert.ok(c.establishes.endsWith('.'), c.id); assert.ok(c.limits.length >= 2, c.id) }
  assert.deepEqual(manifest.profiles.map(p => p.id), ['agentavow.mcp-tool-definition.v1'])
  assert.deepEqual(manifest.data_destinations, ['https://agentavow.com'])
  assert.deepEqual(manifest.privileges_requested, [])
  assert.equal(manifest.keys.length, 1)
  assert.equal(manifest.keys[0].id, PINNED_JWK.kid)
  assert.equal(manifest.keys[0].held_by, 'publisher')
  assert.equal(manifest.license.spdx, 'Apache-2.0')
  assert.ok(manifest.schemas.check_evidence && manifest.schemas.output_evidence)
})

test('artifact digest: SHA-256 over the files sorted by path, framed path\\nbyteLength\\nbytes, equals manifest.artifact.digest', () => {
  assert.equal(artifactDigest(ADAPTER_DIR, manifest.artifact.files), manifest.artifact.digest)
  assert.match(manifest.artifact.digest, /^sha256:[0-9a-f]{64}$/)
})

test('describe() returns the pinned manifest: same canonical JSON, same manifest digest', () => {
  const a = createAdapter({ config: {}, secrets: Object.freeze({}), fetch })
  assert.equal(canonicalJson(a.describe()), canonicalJson(manifest))
  assert.equal(digestJson(a.describe()), digestJson(manifest))
})

test('the pinned JWK in the adapter is the issuer key the vectors file pins (kid agentgraph-security-v1)', () => {
  assert.deepEqual({ kty: PINNED_JWK.kty, crv: PINNED_JWK.crv, x: PINNED_JWK.x, kid: PINNED_JWK.kid },
    { kty: vectors.issuer.jwk.kty, crv: vectors.issuer.jwk.crv, x: vectors.issuer.jwk.x, kid: vectors.issuer.jwk.kid })
})

test('the fixture copy equals docs/standards/tool-manifest-digest-vectors-v1 when the repository is present', () => {
  const canonical = join(ROOT, '../../docs/standards/tool-manifest-digest-vectors-v1/tool-manifest-digest-v1-vectors.json')
  if (!existsSync(canonical)) return
  assert.equal(sha256(readFileSync(FIXTURE_PATH)), sha256(readFileSync(canonical)))
})

test('digest re-implementation matches federation-port src/runtime/canonical.ts (needs FEDERATION_PORT_DIR)', { skip: !FP }, async () => {
  const up = await import(pathToFileURL(join(FP!, 'src/runtime/canonical.ts')).href)
  assert.equal(up.artifactDigest(ADAPTER_DIR, manifest.artifact.files), manifest.artifact.digest)
  assert.equal(up.digestJson(manifest), digestJson(manifest))
  assert.equal(up.canonicalJson(manifest), canonicalJson(manifest))
  const types = readFileSync(join(FP!, 'src/contract/types.ts'), 'utf8')
  const copy = readFileSync(join(ROOT, 'src/contract/types.ts'), 'utf8')
  assert.ok(copy.endsWith(types), 'src/contract/types.ts is the upstream file plus a provenance header')
})
