// Zero-dependency verifier. Node 18+. Exits non-zero on any failure.
//   node verify.mjs [path-to-vectors.json]
//
// For each vector it recomputes the four axes a correct consumer reports
// separately, and checks them against the vector's declared expectation. None
// of the four is derived from another: a valid signature does not make coverage
// consistent, and neither makes execution established.
import { createPublicKey, verify as edVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const file = process.argv[2] ?? new URL('./execution-coverage-v0-vectors.json', import.meta.url);
const set = JSON.parse(readFileSync(file, 'utf8'));

function jcs(v) {
  if (v === null || typeof v !== 'object' || v.toJSON != null) return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}

const pub = createPublicKey({
  key: Buffer.from(set.public_key_spki_b64, 'base64'), format: 'der', type: 'spki',
});

function computeAxes(vec) {
  const { signature, ...bodyWithObserved } = vec.report;
  // the signed body is the report without its signature field
  const body = bodyWithObserved;
  const sigOk = edVerify(null, Buffer.from(jcs(body), 'utf8'), pub,
    Buffer.from(signature.value, 'base64'));

  const req = body.checks.filter(c => c.required);
  const reqPassed = req.filter(c => c.state === 'pass');
  const passedAll = body.checks.filter(c => c.state === 'pass');
  const coverage_consistent =
    body.aggregate.required === req.length &&
    body.aggregate.passed === passedAll.length &&
    body.aggregate.required_passed === reqPassed.length;

  const digest_binds = body.subject_digest === vec.observed_digest;

  let execution_state;
  if (reqPassed.some(c => c.execution === 'unavailable')) execution_state = 'unavailable';
  else if (reqPassed.every(c => c.execution === 'receipt' || c.execution === 'reproduced'))
    execution_state = 'established';
  else execution_state = 'unestablished';

  return { signature_valid: sigOk, coverage_consistent, digest_binds, execution_state };
}

let failures = 0;
const check = (label, got, want) => {
  if (String(got) === String(want)) { console.log(`  ok    ${label}`); return; }
  failures++;
  console.log(`  FAIL  ${label}\n        want ${want}\n        got  ${got}`);
};

console.log(`${set.suite}\n${set.author_set}\n`);
const byName = {};
for (const v of set.vectors) {
  const got = computeAxes(v);
  byName[v.name] = got;
  for (const axis of ['signature_valid', 'coverage_consistent', 'digest_binds', 'execution_state']) {
    check(`${v.name}: ${axis}`, got[axis], v.expect[axis]);
  }
}

console.log('\nproperties under test');
const ctrl = byName['completion-without-execution-evidence'];
check('distinguishing control: signature + coverage + digest pass, execution unestablished',
  ctrl.signature_valid && ctrl.coverage_consistent && ctrl.digest_binds && ctrl.execution_state === 'unestablished',
  'true');
check('coverage-reading catches the skipped required check',
  byName['skipped-required-check'].coverage_consistent, 'false');
check('unavailable is distinct from unestablished',
  byName['reproduction-unavailable'].execution_state !== byName['completion-without-execution-evidence'].execution_state,
  'true');
check('a valid, evidenced report for the wrong digest does not bind',
  byName['digest-mismatch'].digest_binds, 'false');

console.log(failures ? `\n${failures} failure(s)` : '\nall checks passed');
process.exit(failures ? 1 : 0);
