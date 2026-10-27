// SPDX-License-Identifier: Apache-2.0
// Separate reproduction of the vector semantics; imports no profile code.
// Node.js built-ins only.
import { createHash, createPublicKey, verify as verifyEd25519 } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const suite = JSON.parse(readFileSync(join(here, 'VECTORS.json'), 'utf8'));
const profile = { id: 'ctef-proof-obligation-results-v1', version: '1.0.0' };
const canonicalization = 'CTEF-JCS-subset-v1';
const provenance = 'Synthetic public-only conformance roots; private components and seeds are not included in the repository or required for regeneration.';
const defs = [
  ['INPUT_PRESENT', 'claim.input_present', 'The self-contained input document contains a profile-conforming action record.', 'L1_evidence', 'input_presence', [], [], ['The verifier received the exact input bytes it parses.']],
  ['AUTHENTICATED', 'claim.authenticated_action', 'The pinned synthetic subject key signed this exact action commitment for this profile and result identifier.', 'L1_evidence', 'authentication', ['INPUT_PRESENT'], ['subject'], ['The pinned public fixture key is the profile test identity; this does not establish real-world identity or authority.']],
  ['ACTION_BOUND', 'claim.action_binding', 'The supplied action-binding commitment equals the SHA-256 commitment recomputed from the exact action record.', 'L1_evidence', 'binding', ['INPUT_PRESENT'], [], ['SHA-256 collision resistance is assumed for this bounded fixture profile.']],
  ['AUTHORIZED', 'claim.authorized_action', 'A distinct pinned synthetic governance key signed an allow decision whose checked policy permits this exact action commitment.', 'L2_governance', 'authorization_decision', ['AUTHENTICATED', 'ACTION_BOUND'], ['governance'], ['The pinned governance fixture key and the decision policy are trusted only inside this synthetic profile.']],
  ['ENFORCED', 'claim.enforced_action', 'A distinct pinned synthetic observer signed that the effective action was applied and its observer-recorded authorization commitment matches the effective action commitment.', 'L1_evidence', 'enforcement_observation', ['AUTHORIZED', 'ACTION_BOUND'], ['enforcement_observer'], ['The pinned observer fixture key is independent of the subject and governance fixture keys.']],
  ['OUTCOME_RECORDED', 'claim.outcome_recorded', 'The input contains a self-reported outcome record with this profile result identifier.', 'L1_evidence', 'outcome_record', ['INPUT_PRESENT'], [], ['A self-reported record establishes only that this input contains the report.']],
  ['OUTCOME_CONSISTENT', 'claim.outcome_commitment_consistency', 'The recorded output hash recomputes from the recorded output and the record action commitment matches the recomputed action commitment.', 'L1_evidence', 'outcome_consistency', ['ACTION_BOUND', 'OUTCOME_RECORDED'], [], ['Hash consistency does not independently witness execution or finality.']],
  ['FINALITY_WITNESSED', 'claim.synthetic_finality_commitment_match', 'A pinned synthetic finality witness signed a statement bound to this obligation, claim, action, result, and witness profile, with an observed commitment matching the recorded output commitment.', 'L1_evidence', 'finality_witness', ['ENFORCED', 'OUTCOME_CONSISTENT'], ['finality_witness'], ['The synthetic witness trust root is explicitly pinned and proves only this fixture-defined commitment match, not production or distributed finality.']],
].map(([id, claim, proposition, layer, kind, dependencies, roles, assumptions]) => ({ id, claim, proposition, layer, kind, dependencies, roles, assumptions }));
const defById = new Map(defs.map((item) => [item.id, item]));
const errors = [];
function expect(ok, text) { if (!ok) errors.push(text); }
function canon(value) {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new TypeError('unsupported numeric value');
  if (typeof value === 'string' && /[\uD800-\uDFFF]/u.test(value)) throw new TypeError('unsupported surrogate');
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canon).join(',') + ']';
  return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canon(value[key])).join(',') + '}';
}
function hash(value) {
  const bytes = typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(canon(value), 'utf8');
  return createHash('sha256').update(bytes).digest('hex');
}
function actionHash(action) { return hash({ domain: 'CTEF-PO-RESULTS/1/action', action }); }
function decodeBase64Exact(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null;
  const decoded = Buffer.from(value, 'base64');
  return decoded.toString('base64') === value ? decoded : null;
}
function signed(role, kind, evidence, roots) {
  try {
    const root = roots[role];
    if (!evidence || !root || root.algorithm !== 'Ed25519' || root.public_key_format !== 'DER-SPKI-base64' ||
        evidence.signature?.algorithm !== 'Ed25519' || evidence.signature.key_id !== root.key_id) return false;
    const keyBytes = decodeBase64Exact(root.public_key);
    const signature = decodeBase64Exact(evidence.signature.value);
    if (!keyBytes || !signature) return false;
    const key = createPublicKey({ key: keyBytes, format: 'der', type: 'spki' });
    const msg = Buffer.concat([Buffer.from('CTEF-PO-RESULTS/1\0' + kind + '\0', 'utf8'), Buffer.from(canon(evidence.message), 'utf8')]);
    return verifyEd25519(null, msg, key, signature);
  } catch { return false; }
}
function evidenceFor(input, id) {
  if (id === 'INPUT_PRESENT') return input;
  if (id === 'AUTHENTICATED') return input.authentication ?? null;
  if (id === 'ACTION_BOUND') return { action: input.action, binding: input.binding ?? null };
  if (id === 'AUTHORIZED') return input.authorization_evidence ?? null;
  if (id === 'ENFORCED') return input.enforcement_evidence ?? null;
  if (id === 'OUTCOME_RECORDED' || id === 'OUTCOME_CONSISTENT') return input.outcome_record ?? null;
  if (id === 'FINALITY_WITNESSED') return input.finality_evidence ?? null;
  throw new Error('unknown obligation ' + id);
}
function resultCommitment(id, evidence) {
  const domain = 'CTEF-PO-RESULTS/1/evidence/' + id;
  if (evidence === null || evidence === undefined) return { algorithm: 'SHA-256', canonicalization, domain, status: 'unavailable', digest: null };
  return { algorithm: 'SHA-256', canonicalization, domain, status: 'committed', digest: hash({ domain, evidence }) };
}
function local(vector, def, actionDigest) {
  const input = vector.input;
  const roots = vector.trust_roots;
  const id = def.id;
  const unavailable = input.procedure?.unavailable_obligation_ids?.includes(id) === true;
  const state = (completion, verdict, reason) => ({ completion, verdict, reason });
  if (id === 'INPUT_PRESENT') return input && input.profile?.id === profile.id && input.profile?.version === profile.version && input.action
    ? state('completed', 'satisfied', 'none') : state('completed', 'refuted', 'verification_failed');
  if (id === 'AUTHENTICATED') {
    const e = input.authentication;
    if (unavailable) return state('incomplete', 'indeterminate', 'procedure_unavailable');
    if (!e) return state('completed', 'indeterminate', 'evidence_unavailable');
    const m = e.message;
    const fields = m.profile_id === profile.id && m.profile_version === profile.version && m.obligation_id === id &&
      m.claim_id === def.claim && m.result_id === input.result_id && m.subject === input.action.subject && m.action_commitment === actionDigest;
    return signed('subject', 'authentication-v1', e, roots) && fields
      ? state('completed', 'satisfied', 'none') : state('completed', 'refuted', 'verification_failed');
  }
  if (id === 'ACTION_BOUND') {
    if (input.binding?.action_commitment === null || input.binding?.action_commitment === undefined)
      return state('completed', 'indeterminate', 'binding_unresolved');
    return input.binding.action_commitment === actionDigest
      ? state('completed', 'satisfied', 'none') : state('completed', 'refuted', 'binding_mismatch');
  }
  if (id === 'AUTHORIZED') {
    const e = input.authorization_evidence;
    if (!e) return state('completed', 'indeterminate', 'evidence_unavailable');
    const m = e.message;
    const fields = m.profile_id === profile.id && m.profile_version === profile.version && m.obligation_id === id &&
      m.claim_id === def.claim && m.result_id === input.result_id;
    if (!signed('governance', 'authorization-v1', e, roots)) return state('completed', 'refuted', 'verification_failed');
    if (!fields || m.action_commitment !== actionDigest) return state('completed', 'refuted', 'binding_mismatch');
    const allows = m.decision === 'allow' && m.policy?.id === 'synthetic-payment-policy-v1' && m.policy?.version === '1' &&
      typeof m.decision_id === 'string' && m.decision_id.length > 0 &&
      m.policy?.action_types?.includes(input.action.action_type) === true &&
      typeof m.policy.scope_prefix === 'string' && input.action.scope.startsWith(m.policy.scope_prefix);
    return allows ? state('completed', 'satisfied', 'none') : state('completed', 'refuted', 'policy_denied');
  }
  if (id === 'ENFORCED') {
    const e = input.enforcement_evidence;
    if (!e) return state('completed', 'indeterminate', 'enforcement_evidence_missing');
    const m = e.message;
    const effective = actionHash(m.effective_action);
    const auth = input.authorization_evidence?.message?.action_commitment;
    const fields = m.profile_id === profile.id && m.profile_version === profile.version && m.obligation_id === id &&
      m.claim_id === def.claim && m.result_id === input.result_id && m.state === 'applied' &&
      m.action_commitment === actionDigest && m.effective_action_commitment === effective &&
      m.policy_profile === 'synthetic-payment-policy-v1';
    if (!signed('enforcement_observer', 'enforcement-v1', e, roots)) return state('completed', 'refuted', 'verification_failed');
    if (!fields || m.authorization_action_commitment !== effective || (auth !== undefined && m.authorization_action_commitment !== auth))
      return state('completed', 'refuted', 'binding_mismatch');
    return state('completed', 'satisfied', 'none');
  }
  if (id === 'OUTCOME_RECORDED') {
    const o = input.outcome_record;
    if (!o) return state('completed', 'indeterminate', 'evidence_unavailable');
    return o.result_id === input.result_id && typeof o.status === 'string' && o.output !== undefined
      ? state('completed', 'satisfied', 'none') : state('completed', 'refuted', 'verification_failed');
  }
  if (id === 'OUTCOME_CONSISTENT') {
    const o = input.outcome_record;
    if (!o) return state('completed', 'indeterminate', 'evidence_unavailable');
    const outHash = hash({ domain: profile.id + '/output', output: o.output });
    return o.output_commitment === outHash && o.action_commitment === actionDigest && o.result_id === input.result_id
      ? state('completed', 'satisfied', 'none') : state('completed', 'refuted', 'binding_mismatch');
  }
  if (id === 'FINALITY_WITNESSED') {
    const e = input.finality_evidence;
    if (!e) return state('completed', 'indeterminate', 'outcome_unwitnessed');
    if (!signed('finality_witness', 'finality-v1', e, roots)) return state('completed', 'refuted', 'verification_failed');
    const m = e.message;
    const o = input.outcome_record;
    const fields = m.profile_id === profile.id && m.profile_version === profile.version && m.obligation_id === id &&
      m.claim_id === def.claim && m.result_id === input.result_id && m.action_commitment === actionDigest &&
      m.witness_profile === 'synthetic-finality-witness-v1';
    return fields && o && m.output_commitment === o.output_commitment && m.observed_commitment === o.output_commitment
      ? state('completed', 'satisfied', 'none') : state('completed', 'refuted', 'binding_mismatch');
  }
  throw new Error('no independent evaluator for ' + id);
}
function dependents(id) {
  const found = new Set();
  function visit(parent) {
    for (const item of defs) if (item.dependencies.includes(parent) && !found.has(item.claim)) {
      found.add(item.claim);
      visit(item.id);
    }
  }
  visit(id);
  return [...found].sort();
}
function checkGraph() {
  const done = new Set();
  const active = new Set();
  function visit(id) {
    if (active.has(id)) throw new Error('graph cycle at ' + id);
    if (done.has(id)) return;
    active.add(id);
    for (const dep of defById.get(id).dependencies) {
      if (!defById.has(dep)) throw new Error('unknown graph dependency ' + dep);
      visit(dep);
    }
    active.delete(id);
    done.add(id);
  }
  for (const def of defs) visit(def.id);
}
checkGraph();
expect(suite.vectors.length === 16, 'vector count must equal 16');
expect(new Set(suite.vectors.map((item) => item.id)).size === 16, 'vector ids must be unique');
expect(suite.profile?.id === profile.id && suite.profile?.version === profile.version, 'suite profile mismatch');
const schema = JSON.parse(readFileSync(join(here, 'result.schema.json'), 'utf8'));
const resultKeys = ['obligation_id','claim_id','proposition','verification_profile','evidence_commitment','trust_basis','layer','obligation_kind','completion','verdict','diagnostic_reason','dependencies','dependent_claims','terminal','terminal_scope','promotion'].sort();
expect(JSON.stringify([...schema.required].sort()) === JSON.stringify(resultKeys), 'schema required fields differ');

for (const vector of suite.vectors) {
  const prefix = 'vector ' + vector.id;
  expect(vector.input_commitment.digest === hash({ domain: 'CTEF-PO-RESULTS/1/input', input: vector.input }), prefix + ': input commitment mismatch');
  expect(vector.expected_results.length === defs.length, prefix + ': result count mismatch');
  const actionDigest = actionHash(vector.input.action);
  const localResults = defs.map((def) => ({ def, ...local(vector, def, actionDigest), evidence: evidenceFor(vector.input, def.id) }));
  const promotions = new Map();
  for (let index = 0; index < localResults.length; index++) {
    const item = localResults[index];
    const result = vector.expected_results[index];
    const label = prefix + ' ' + item.def.id;
    expect(result?.obligation_id === item.def.id && result?.claim_id === item.def.claim, label + ': obligation/claim identity mismatch');
    expect(result?.proposition === item.def.proposition, label + ': proposition mismatch');
    expect(result?.layer === item.def.layer && result?.obligation_kind === item.def.kind, label + ': classification mismatch');
    expect(JSON.stringify(result?.verification_profile) === JSON.stringify(profile), label + ': profile mismatch');
    expect(result?.completion === item.completion && result?.verdict === item.verdict && result?.diagnostic_reason === item.reason, label + ': expected local output mismatch');
    expect(JSON.stringify(result?.evidence_commitment) === JSON.stringify(resultCommitment(item.def.id, item.evidence)), label + ': evidence commitment mismatch');
    expect(JSON.stringify(result?.dependencies) === JSON.stringify(item.def.dependencies.map((obligation_id) => ({obligation_id,mandatory:true}))), label + ': dependency edges mismatch');
    expect(JSON.stringify(result?.dependent_claims) === JSON.stringify(dependents(item.def.id)), label + ': dependent claims mismatch');
    const blocked = item.def.dependencies.filter((dep) => promotions.get(dep) !== 'eligible');
    let promotion = 'eligible';
    if (item.verdict === 'refuted') promotion = 'refuted';
    else if (item.verdict === 'indeterminate' || item.completion !== 'completed') promotion = 'indeterminate';
    else if (blocked.length) promotion = 'blocked';
    promotions.set(item.def.id, promotion);
    expect(result?.promotion?.status === promotion && result?.promotion?.claim_id === item.def.claim, label + ': claim promotion mismatch');
    expect(result?.promotion?.mandatory_dependencies_satisfied === (blocked.length === 0), label + ': dependency eligibility mismatch');
    expect(JSON.stringify(result?.promotion?.blocked_by) === JSON.stringify(blocked), label + ': propagated blockers mismatch');
    expect(result?.terminal === (item.completion === 'completed' && item.verdict === 'refuted'), label + ': terminal flag mismatch');
    expect(result?.terminal_scope === (result?.terminal ? 'specific_proposition_only' : 'none'), label + ': terminal scope mismatch');
    expect(Object.keys(result ?? {}).sort().join('|') === resultKeys.join('|'), label + ': schema object fields mismatch');
    expect(result?.trust_basis?.fixture_key_provenance === provenance, label + ': fixture key provenance missing');
    expect(JSON.stringify(result?.trust_basis?.assumptions) === JSON.stringify(item.def.assumptions), label + ': trust assumptions mismatch');
    expect(JSON.stringify(result?.trust_basis?.signer_roles) === JSON.stringify(item.def.roles), label + ': signer roles mismatch');
    const expectedKeyIds = item.evidence === null || item.evidence === undefined
      ? [] : item.def.roles.map((role) => vector.trust_roots[role]?.key_id).filter(Boolean);
    expect(JSON.stringify(result?.trust_basis?.key_ids) === JSON.stringify(expectedKeyIds), label + ': public key ids mismatch');
  }
  const unsatisfied = localResults.filter((item) => item.verdict !== 'satisfied');
  if (vector.coverage.polarity === 'negative') {
    expect(unsatisfied.length === 1 && unsatisfied[0]?.def.id === vector.coverage.targeted_root_obligation_id, prefix + ': negative root isolation failed');
  } else expect(unsatisfied.length === 0, prefix + ': positive vector contains non-satisfied result');
}
function get(vectorId, obligationId) {
  return suite.vectors.find((item) => item.id === vectorId).expected_results.find((item) => item.obligation_id === obligationId);
}
expect(get('case-01-authenticated-without-authorization','AUTHENTICATED').verdict === 'satisfied' &&
  get('case-01-authenticated-without-authorization','AUTHORIZED').completion === 'completed' &&
  get('case-01-authenticated-without-authorization','AUTHORIZED').verdict === 'indeterminate', 'authentication must not imply authorization');
expect(get('case-03-authorized-without-enforcement-witness','AUTHORIZED').verdict === 'satisfied' &&
  get('case-03-authorized-without-enforcement-witness','ENFORCED').verdict === 'indeterminate', 'authorization must not imply enforcement');
expect(get('case-05-recorded-outcome-without-finality-witness','ENFORCED').verdict === 'satisfied' &&
  get('case-05-recorded-outcome-without-finality-witness','FINALITY_WITNESSED').verdict === 'indeterminate', 'enforcement must not imply finality');
expect(get('case-16-refuted-authentication-isolation','OUTCOME_RECORDED').verdict === 'satisfied' &&
  get('case-16-refuted-authentication-isolation','OUTCOME_RECORDED').promotion.status === 'eligible', 'unrelated outcome branch must remain eligible');
expect(get('case-15-independent-finality-outcome-divergence','OUTCOME_RECORDED').verdict === 'satisfied' &&
  get('case-15-independent-finality-outcome-divergence','FINALITY_WITNESSED').verdict === 'refuted', 'finality divergence must not refute outcome record');

if (errors.length) {
  console.error('independent verifier failures:');
  for (const item of errors) console.error('  FAIL ' + item);
  process.exit(1);
}
console.log('independent reproduction passed: 16 vectors, 128 result objects, commitments, Ed25519 evidence, graph propagation, and claim boundaries');
