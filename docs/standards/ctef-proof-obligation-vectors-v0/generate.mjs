// SPDX-License-Identifier: Apache-2.0
// Deterministically rebuild VECTORS.json from source.json. Node.js built-ins only.
// Usage: node generate.mjs [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { CANONICALIZATION, HASH_ALGORITHM, PROFILE, evaluateVector, sha256Hex, validateVectorSuite } from './profile.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const sourcePath = join(here, 'source.json');
const outputPath = join(here, 'VECTORS.json');
const source = JSON.parse(readFileSync(sourcePath, 'utf8'));

if (!Array.isArray(source.vectors) || source.vectors.length !== 16) {
  throw new Error(`source.json must contain exactly 16 vectors; found ${source.vectors?.length ?? 'none'}`);
}
if (new Set(source.vectors.map((vector) => vector.id)).size !== 16) {
  throw new Error('source.json vector ids must be unique');
}

const output = {
  suite: source.suite,
  version: source.version,
  license: source.license,
  spdx_license_identifier: source.spdx_license_identifier,
  attribution: source.attribution,
  fixture_key_provenance: source.fixture_key_provenance,
  profile: { ...PROFILE },
  canonicalization: {
    id: CANONICALIZATION,
    digest_algorithm: HASH_ALGORITHM,
    signature_algorithm: 'Ed25519',
    input_encoding: 'UTF-8',
    object_key_order: 'ECMAScript UTF-16 code-unit order',
    numeric_domain: 'finite safe integers only',
  },
  vectors: source.vectors.map((fixture) => {
    const vector = {
      id: fixture.id,
      title: fixture.title,
      coverage: structuredClone(fixture.coverage),
      profile: { ...PROFILE },
      trust_roots: structuredClone(source.trust_roots),
      input: structuredClone(fixture.input),
      input_commitment: {
        algorithm: HASH_ALGORITHM,
        canonicalization: CANONICALIZATION,
        domain: 'CTEF-PO-RESULTS/1/input',
        digest: sha256Hex({ domain: 'CTEF-PO-RESULTS/1/input', input: fixture.input }),
      },
    };
    vector.expected_results = evaluateVector(vector);
    return vector;
  }),
};

const errors = validateVectorSuite(output);
if (errors.length) throw new Error(`generated suite failed validation:\n${errors.join('\n')}`);
const bytes = `${JSON.stringify(output, null, 2)}\n`;
if (process.argv.includes('--check')) {
  let current;
  try { current = readFileSync(outputPath, 'utf8'); } catch { current = null; }
  if (current !== bytes) {
    console.error('VECTORS.json differs from deterministic generation');
    process.exit(1);
  }
  console.log('generator check passed: VECTORS.json is byte-identical to source.json generation');
} else {
  writeFileSync(outputPath, bytes, 'utf8');
  console.log(`generated ${output.vectors.length} vectors (${bytes.length} UTF-8 bytes)`);
}
