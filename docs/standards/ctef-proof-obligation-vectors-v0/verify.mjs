// SPDX-License-Identifier: Apache-2.0
// Verify all vectors offline with Node.js built-ins only.
// Usage: node verify.mjs [VECTORS.json] [--id vector-id]
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { diffValues, evaluateVector, validateResultSchema, validateStandaloneVector, validateVectorSuite } from './profile.mjs';

const here = dirname(fileURLToPath(import.meta.url));
let file = resolve(here, 'VECTORS.json');
let vectorId;
let single = false;
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i] === '--id') vectorId = process.argv[++i];
  else if (process.argv[i] === '--single') { single = true; file = resolve(process.argv[++i]); }
  else if (process.argv[i].startsWith('--')) throw new Error(`unknown option ${process.argv[i]}`);
  else file = resolve(process.argv[i]);
}
const set = JSON.parse(readFileSync(file, 'utf8'));
const suiteErrors = single ? validateStandaloneVector(set) : validateVectorSuite(set);
if (suiteErrors.length) {
  console.error('suite/schema validation failed:');
  for (const error of suiteErrors) console.error(`  FAIL  ${error}`);
  process.exit(1);
}

const selected = single ? [set] : vectorId ? set.vectors.filter((vector) => vector.id === vectorId) : set.vectors;
if (vectorId && selected.length !== 1) {
  console.error(`vector id not found or not unique: ${vectorId}`);
  process.exit(1);
}

let failures = 0;
for (const vector of selected) {
  const actual = evaluateVector(vector);
  const errors = [];
  if (actual.length !== vector.expected_results.length) errors.push(`expected ${vector.expected_results.length} result objects, got ${actual.length}`);
  for (let i = 0; i < Math.min(actual.length, vector.expected_results.length); i++) {
    const schemaErrors = validateResultSchema(vector.expected_results[i], `${vector.id}.expected_results[${i}]`);
    errors.push(...schemaErrors);
    errors.push(...diffValues(vector.expected_results[i], actual[i], `${vector.id}.expected_results[${i}]`));
  }
  if (errors.length) {
    failures++;
    console.error(`FAIL ${vector.id}`);
    for (const error of errors) console.error(`  ${error}`);
  } else {
    console.log(`PASS ${vector.id} (${actual.length}/${actual.length} obligation results)`);
    for (const result of actual) {
      console.log(`  ${result.obligation_id} ${result.layer} ${result.completion}/${result.verdict} ${result.diagnostic_reason}; promotion=${result.promotion.status}`);
    }
  }
}
console.log(failures ? `FAIL ${failures}/${selected.length} vector(s)` : `all checks passed (${selected.length} vectors, ${selected.length * 8} results)`);
process.exit(failures ? 1 : 0);
