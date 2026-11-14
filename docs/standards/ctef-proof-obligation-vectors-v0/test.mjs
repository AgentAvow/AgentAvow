// SPDX-License-Identifier: Apache-2.0
// Schema, graph, semantic, and mutation regression tests. Node.js built-ins only.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  OBLIGATIONS, PROFILE, canonicalJSON, evaluateVector, sha256Hex,
  validateDependencyGraph, validateResultSchema, validateStandaloneVector, validateVectorSuite,
} from './profile.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, 'VECTORS.json');
const suite = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const schema = JSON.parse(readFileSync(join(here, 'result.schema.json'), 'utf8'));
const byId = new Map(suite.vectors.map((vector) => [vector.id, vector]));
let checks = 0;
function check(label, fn) {
  fn();
  checks++;
  console.log('PASS ' + label);
}
function vector(id) {
  assert.ok(byId.has(id), 'fixture exists: ' + id);
  return structuredClone(byId.get(id));
}
function refreshInputCommitment(item) {
  item.input_commitment.digest = sha256Hex({ domain: 'CTEF-PO-RESULTS/1/input', input: item.input });
}
function suiteRejectsAfterMutation(label, id, mutate, expectedResultPattern) {
  const altered = structuredClone(suite);
  const item = altered.vectors.find((candidate) => candidate.id === id);
  mutate(item);
  refreshInputCommitment(item);
  const errors = validateVectorSuite(altered);
  assert.ok(errors.length > 0, label + ': verifier accepted mutation');
  if (expectedResultPattern) {
    assert.ok(errors.some((error) => error.includes(id) && error.includes('result mismatch') && error.includes(expectedResultPattern)),
      label + ': rejection did not identify the affected result: ' + errors.join(' | '));
  }
}

check('exactly 16 unique vectors and eight explicit result objects per vector', () => {
  assert.equal(suite.vectors.length, 16);
  assert.equal(new Set(suite.vectors.map((item) => item.id)).size, 16);
  assert.ok(suite.vectors.every((item) => item.expected_results.length === 8));
  assert.deepEqual(validateVectorSuite(suite), []);
});

check('one extracted vector is independently schema-checked and runnable', () => {
  const extracted = vector('case-09-completed-binding-mismatch');
  assert.deepEqual(validateStandaloneVector(extracted), []);
  const temp = mkdtempSync(join(tmpdir(), 'ctef-po-single-'));
  const file = join(temp, 'one-vector.json');
  try {
    writeFileSync(file, JSON.stringify(extracted));
    const run = spawnSync(process.execPath, [resolve(here, 'verify.mjs'), '--single', file], { encoding: 'utf8', timeout: 10000 });
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.match(run.stdout, /PASS case-09-completed-binding-mismatch/);
    assert.match(run.stdout, /all checks passed \(1 vectors, 8 results\)/);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

check('JSON Schema required fields match the emitted result object', () => {
  assert.equal(schema['x-spdx-license-identifier'], 'Apache-2.0');
  assert.deepEqual([...schema.required].sort(), Object.keys(suite.vectors[0].expected_results[0]).sort());
  for (const item of suite.vectors) for (const result of item.expected_results) {
    assert.deepEqual(validateResultSchema(result), []);
  }
});

check('result schema rejects nested extra fields and inconsistent state combinations', () => {
  const template = vector('case-02-authenticated-and-authorized').expected_results.find((r) => r.obligation_id === 'AUTHORIZED');
  const mutations = [
    (item) => { item.evidence_commitment.unexpected = true; },
    (item) => { item.trust_basis.unexpected = true; },
    (item) => { item.dependencies[0].unexpected = true; },
    (item) => { item.promotion.unexpected = true; },
    (item) => { item.promotion.status = 'eligible'; item.promotion.blocked_by = ['ACTION_BOUND']; },
    (item) => { item.completion = 'incomplete'; },
    (item) => { item.diagnostic_reason = 'binding_mismatch'; },
  ];
  for (const mutate of mutations) {
    const item = structuredClone(template);
    mutate(item);
    assert.ok(validateResultSchema(item).length > 0, 'schema accepted a nested or semantic mutation');
  }
  const unavailable = structuredClone(template);
  unavailable.evidence_commitment.status = 'unavailable';
  unavailable.evidence_commitment.digest = 'f'.repeat(64);
  assert.ok(validateResultSchema(unavailable).some((error) => error.includes('evidence_commitment')));
});

check('every result has explicit layer, exact proposition, profile, commitment, trust, dependencies, terminality, and promotion', () => {
  for (const item of suite.vectors) for (const result of item.expected_results) {
    assert.ok(['L1_evidence', 'L2_governance'].includes(result.layer));
    assert.ok(result.proposition.length > 30);
    assert.deepEqual(result.verification_profile, PROFILE);
    assert.ok(result.evidence_commitment.algorithm === 'SHA-256');
    assert.ok(Array.isArray(result.trust_basis.assumptions));
    assert.ok(Array.isArray(result.dependencies));
    assert.ok(Array.isArray(result.dependent_claims));
    assert.ok(typeof result.terminal === 'boolean');
    assert.ok(result.promotion && result.promotion.claim_id === result.claim_id);
  }
});

check('negative vectors each have one targeted local root and positive twins pass', () => {
  for (const item of suite.vectors) {
    const results = item.expected_results;
    const unsatisfied = results.filter((result) => result.verdict !== 'satisfied');
    if (item.coverage.polarity === 'negative') {
      assert.equal(unsatisfied.length, 1, item.id);
      assert.equal(unsatisfied[0].obligation_id, item.coverage.targeted_root_obligation_id, item.id);
    } else assert.equal(unsatisfied.length, 0, item.id);
  }
});

check('positive twins change only their named boundary evidence for simple pairs', () => {
  const pairs = [
    ['case-01-authenticated-without-authorization', 'case-02-authenticated-and-authorized', ['authorization_evidence']],
    ['case-03-authorized-without-enforcement-witness', 'case-04-authorized-with-enforcement-witness', ['enforcement_evidence']],
    ['case-05-recorded-outcome-without-finality-witness', 'case-06-recorded-outcome-with-finality-witness', ['finality_evidence']],
    ['case-09-completed-binding-mismatch', 'case-10-matched-binding-control', ['binding']],
    ['case-11-missing-binding-evidence', 'case-10-matched-binding-control', ['binding']],
    ['case-12-authentication-procedure-unavailable', 'case-08-intact-authentication-control', ['procedure']],
    ['case-15-independent-finality-outcome-divergence', 'case-06-recorded-outcome-with-finality-witness', ['finality_evidence']],
  ];
  for (const [negativeId, positiveId, allowedKeys] of pairs) {
    const left = vector(negativeId).input;
    const right = vector(positiveId).input;
    for (const key of Object.keys(left)) {
      if (allowedKeys.includes(key)) continue;
      assert.equal(canonicalJSON(left[key]), canonicalJSON(right[key]), negativeId + ' changed unrelated input ' + key);
    }
    for (const key of Object.keys(right)) {
      if (allowedKeys.includes(key)) continue;
      assert.equal(canonicalJSON(left[key]), canonicalJSON(right[key]), positiveId + ' changed unrelated input ' + key);
    }
  }
});

check('completed indeterminate and incomplete indeterminate remain distinct', () => {
  const authz = byId.get('case-01-authenticated-without-authorization').expected_results.find((r) => r.obligation_id === 'AUTHORIZED');
  const unavailable = byId.get('case-12-authentication-procedure-unavailable').expected_results.find((r) => r.obligation_id === 'AUTHENTICATED');
  assert.equal(authz.completion, 'completed');
  assert.equal(authz.verdict, 'indeterminate');
  assert.equal(unavailable.completion, 'incomplete');
  assert.equal(unavailable.verdict, 'indeterminate');
  assert.equal(unavailable.terminal, false);
});

check('procedure-unavailable state applies to any declared obligation and blocks its dependents', () => {
  const altered = vector('case-08-intact-authentication-control');
  altered.input.procedure = { unavailable_obligation_ids: ['ACTION_BOUND'] };
  const results = evaluateVector(altered);
  const binding = results.find((r) => r.obligation_id === 'ACTION_BOUND');
  assert.equal(binding.completion, 'incomplete');
  assert.equal(binding.verdict, 'indeterminate');
  assert.equal(binding.diagnostic_reason, 'procedure_unavailable');
  assert.equal(binding.terminal, false);
  assert.equal(results.find((r) => r.obligation_id === 'AUTHORIZED').promotion.status, 'blocked');
});

check('authentication does not promote authorization; authorization does not promote enforcement; enforcement does not promote finality', () => {
  const authOnly = byId.get('case-01-authenticated-without-authorization').expected_results;
  assert.equal(authOnly.find((r) => r.obligation_id === 'AUTHENTICATED').verdict, 'satisfied');
  assert.equal(authOnly.find((r) => r.obligation_id === 'AUTHORIZED').verdict, 'indeterminate');
  const noEnforcement = byId.get('case-03-authorized-without-enforcement-witness').expected_results;
  assert.equal(noEnforcement.find((r) => r.obligation_id === 'AUTHORIZED').promotion.status, 'eligible');
  assert.equal(noEnforcement.find((r) => r.obligation_id === 'ENFORCED').verdict, 'indeterminate');
  const noFinality = byId.get('case-05-recorded-outcome-without-finality-witness').expected_results;
  assert.equal(noFinality.find((r) => r.obligation_id === 'ENFORCED').verdict, 'satisfied');
  assert.equal(noFinality.find((r) => r.obligation_id === 'FINALITY_WITNESSED').verdict, 'indeterminate');
});

check('binding mismatch is terminal only for the defined proposition and blocks descendants', () => {
  const results = byId.get('case-09-completed-binding-mismatch').expected_results;
  const bound = results.find((r) => r.obligation_id === 'ACTION_BOUND');
  assert.equal(bound.verdict, 'refuted');
  assert.equal(bound.terminal, true);
  assert.equal(bound.terminal_scope, 'specific_proposition_only');
  assert.equal(results.find((r) => r.obligation_id === 'AUTHORIZED').promotion.status, 'blocked');
  assert.equal(results.find((r) => r.obligation_id === 'OUTCOME_RECORDED').promotion.status, 'eligible');
});

check('invalid authentication does not refute the recorded outcome or imply that execution never occurred', () => {
  const results = byId.get('case-07-tampered-authentication-material').expected_results;
  assert.equal(results.find((r) => r.obligation_id === 'AUTHENTICATED').verdict, 'refuted');
  assert.equal(results.find((r) => r.obligation_id === 'OUTCOME_RECORDED').verdict, 'satisfied');
  assert.equal(results.find((r) => r.obligation_id === 'OUTCOME_CONSISTENT').verdict, 'satisfied');
});

check('guardrail rewrite fails only enforcement binding; corrected action rebind passes', () => {
  const stale = byId.get('case-13-rewritten-action-with-stale-authorization-binding').expected_results;
  assert.equal(stale.find((r) => r.obligation_id === 'AUTHORIZED').verdict, 'satisfied');
  assert.equal(stale.find((r) => r.obligation_id === 'ENFORCED').diagnostic_reason, 'binding_mismatch');
  assert.equal(byId.get('case-14-rebound-effective-action-control').expected_results.find((r) => r.obligation_id === 'ENFORCED').verdict, 'satisfied');
});

check('independent finality divergence refutes only finality matching', () => {
  const results = byId.get('case-15-independent-finality-outcome-divergence').expected_results;
  assert.equal(results.find((r) => r.obligation_id === 'FINALITY_WITNESSED').verdict, 'refuted');
  assert.equal(results.find((r) => r.obligation_id === 'OUTCOME_RECORDED').verdict, 'satisfied');
  assert.equal(results.find((r) => r.obligation_id === 'OUTCOME_CONSISTENT').verdict, 'satisfied');
});

check('dependency failure propagates across multiple hops and preserves unrelated eligibility', () => {
  const results = byId.get('case-16-refuted-authentication-isolation').expected_results;
  assert.equal(results.find((r) => r.obligation_id === 'AUTHENTICATED').promotion.status, 'refuted');
  assert.equal(results.find((r) => r.obligation_id === 'AUTHORIZED').promotion.status, 'blocked');
  assert.equal(results.find((r) => r.obligation_id === 'ENFORCED').promotion.status, 'blocked');
  assert.equal(results.find((r) => r.obligation_id === 'FINALITY_WITNESSED').promotion.status, 'blocked');
  assert.equal(results.find((r) => r.obligation_id === 'OUTCOME_RECORDED').promotion.status, 'eligible');
});

check('dependency graph rejects unknown ids and cycles', () => {
  const unknown = structuredClone(OBLIGATIONS);
  unknown[1].dependencies.push('NOT_DECLARED');
  assert.throws(() => validateDependencyGraph(unknown), /unknown dependency/);
  const cyclic = structuredClone(OBLIGATIONS);
  cyclic[0].dependencies.push('FINALITY_WITNESSED');
  assert.throws(() => validateDependencyGraph(cyclic), /dependency cycle/);
  assert.throws(() => validateDependencyGraph([...OBLIGATIONS].reverse()), /dependency ordering/);
});

check('message-tampering mutation is rejected against the positive expected output', () => {
  suiteRejectsAfterMutation('message tampering', 'case-08-intact-authentication-control', (item) => {
    item.input.authentication.message.subject = 'did:example:mutated-subject';
  }, 'AUTHENTICATED');
});

check('signature-tampering mutation is rejected against the positive expected output', () => {
  suiteRejectsAfterMutation('signature tampering', 'case-08-intact-authentication-control', (item) => {
    const value = item.input.authentication.signature.value;
    item.input.authentication.signature.value = (value[0] === 'A' ? 'B' : 'A') + value.slice(1);
  }, 'AUTHENTICATED');
});

check('hash-mismatch mutation is rejected against the positive expected output', () => {
  suiteRejectsAfterMutation('hash mismatch', 'case-08-intact-authentication-control', (item) => {
    item.input.outcome_record.output_commitment = 'f'.repeat(64);
  }, 'OUTCOME_CONSISTENT');
});

check('stale-binding mutation is rejected against the positive expected output', () => {
  suiteRejectsAfterMutation('stale binding', 'case-10-matched-binding-control', (item) => {
    item.input.binding.action_commitment = 'e'.repeat(64);
  }, 'ACTION_BOUND');
});

check('omitted mandatory enforcement evidence is rejected against the positive expected output', () => {
  suiteRejectsAfterMutation('omitted enforcement evidence', 'case-04-authorized-with-enforcement-witness', (item) => {
    item.input.enforcement_evidence = null;
  }, 'ENFORCED');
});

check('unexpected result promotion is rejected by expected-versus-actual comparison', () => {
  const altered = structuredClone(suite);
  const target = altered.vectors.find((item) => item.id === 'case-01-authenticated-without-authorization');
  target.expected_results.find((result) => result.obligation_id === 'AUTHORIZED').promotion.status = 'eligible';
  const errors = validateVectorSuite(altered);
  assert.ok(errors.some((error) => error.includes('case-01-authenticated-without-authorization') && error.includes('result mismatch') && error.includes('promotion.status')));
});

check('dependency refutation blocks descendants without rewriting their local results', () => {
  const altered = vector('case-08-intact-authentication-control');
  const value = altered.input.authentication.signature.value;
  altered.input.authentication.signature.value = (value[0] === 'A' ? 'B' : 'A') + value.slice(1);
  const results = evaluateVector(altered);
  assert.equal(results.find((result) => result.obligation_id === 'AUTHENTICATED').verdict, 'refuted');
  assert.equal(results.find((result) => result.obligation_id === 'AUTHORIZED').verdict, 'satisfied');
  assert.equal(results.find((result) => result.obligation_id === 'AUTHORIZED').promotion.status, 'blocked');
  assert.equal(results.find((result) => result.obligation_id === 'OUTCOME_RECORDED').promotion.status, 'eligible');
});

check('CLI rejects a mutated positive vector and names the exact failed result', () => {
  const altered = structuredClone(suite);
  const item = altered.vectors.find((candidate) => candidate.id === 'case-08-intact-authentication-control');
  item.input.authentication.message.subject = 'did:example:cli-mutated-subject';
  refreshInputCommitment(item);
  const temp = mkdtempSync(join(tmpdir(), 'ctef-po-v1-'));
  const file = join(temp, 'mutated.json');
  try {
    writeFileSync(file, JSON.stringify(altered));
    const run = spawnSync(process.execPath, [resolve(here, 'verify.mjs'), file], { encoding: 'utf8', timeout: 10000 });
    assert.equal(run.status, 1, run.stdout + run.stderr);
    assert.match(run.stderr, /AUTHENTICATED/);
    assert.match(run.stderr, /result mismatch/);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

console.log('all checks passed (' + checks + ' regression and mutation checks)');
