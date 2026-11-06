// SPDX-License-Identifier: Apache-2.0
// CTEF proof-obligation result profile v1. Zero runtime dependencies; Node.js built-ins only.
import { createHash, createPublicKey, verify as ed25519Verify } from 'node:crypto';

export const PROFILE = Object.freeze({
  id: 'ctef-proof-obligation-results-v1',
  version: '1.0.0',
});

export const CANONICALIZATION = 'CTEF-JCS-subset-v1';
export const HASH_ALGORITHM = 'SHA-256';
export const SIGNATURE_ALGORITHM = 'Ed25519';

export const OBLIGATIONS = Object.freeze([
  {
    obligation_id: 'INPUT_PRESENT',
    claim_id: 'claim.input_present',
    proposition: 'The self-contained input document contains a profile-conforming action record.',
    layer: 'L1_evidence',
    obligation_kind: 'input_presence',
    dependencies: [],
    signer_roles: [],
    trust_assumptions: ['The verifier received the exact input bytes it parses.'],
  },
  {
    obligation_id: 'AUTHENTICATED',
    claim_id: 'claim.authenticated_action',
    proposition: 'The pinned synthetic subject key signed this exact action commitment for this profile and result identifier.',
    layer: 'L1_evidence',
    obligation_kind: 'authentication',
    dependencies: ['INPUT_PRESENT'],
    signer_roles: ['subject'],
    trust_assumptions: ['The pinned public fixture key is the profile test identity; this does not establish real-world identity or authority.'],
  },
  {
    obligation_id: 'ACTION_BOUND',
    claim_id: 'claim.action_binding',
    proposition: 'The supplied action-binding commitment equals the SHA-256 commitment recomputed from the exact action record.',
    layer: 'L1_evidence',
    obligation_kind: 'binding',
    dependencies: ['INPUT_PRESENT'],
    signer_roles: [],
    trust_assumptions: ['SHA-256 collision resistance is assumed for this bounded fixture profile.'],
  },
  {
    obligation_id: 'AUTHORIZED',
    claim_id: 'claim.authorized_action',
    proposition: 'A distinct pinned synthetic governance key signed an allow decision whose checked policy permits this exact action commitment.',
    layer: 'L2_governance',
    obligation_kind: 'authorization_decision',
    dependencies: ['AUTHENTICATED', 'ACTION_BOUND'],
    signer_roles: ['governance'],
    trust_assumptions: ['The pinned governance fixture key and the decision policy are trusted only inside this synthetic profile.'],
  },
  {
    obligation_id: 'ENFORCED',
    claim_id: 'claim.enforced_action',
    proposition: 'A distinct pinned synthetic observer signed that the effective action was applied and its observer-recorded authorization commitment matches the effective action commitment.',
    layer: 'L1_evidence',
    obligation_kind: 'enforcement_observation',
    dependencies: ['AUTHORIZED', 'ACTION_BOUND'],
    signer_roles: ['enforcement_observer'],
    trust_assumptions: ['The pinned observer fixture key is independent of the subject and governance fixture keys.'],
  },
  {
    obligation_id: 'OUTCOME_RECORDED',
    claim_id: 'claim.outcome_recorded',
    proposition: 'The input contains a self-reported outcome record with this profile result identifier.',
    layer: 'L1_evidence',
    obligation_kind: 'outcome_record',
    dependencies: ['INPUT_PRESENT'],
    signer_roles: [],
    trust_assumptions: ['A self-reported record establishes only that this input contains the report.'],
  },
  {
    obligation_id: 'OUTCOME_CONSISTENT',
    claim_id: 'claim.outcome_commitment_consistency',
    proposition: 'The recorded output hash recomputes from the recorded output and the record action commitment matches the recomputed action commitment.',
    layer: 'L1_evidence',
    obligation_kind: 'outcome_consistency',
    dependencies: ['ACTION_BOUND', 'OUTCOME_RECORDED'],
    signer_roles: [],
    trust_assumptions: ['Hash consistency does not independently witness execution or finality.'],
  },
  {
    obligation_id: 'FINALITY_WITNESSED',
    claim_id: 'claim.synthetic_finality_commitment_match',
    proposition: 'A pinned synthetic finality witness signed a statement bound to this obligation, claim, action, result, and witness profile, with an observed commitment matching the recorded output commitment.',
    layer: 'L1_evidence',
    obligation_kind: 'finality_witness',
    dependencies: ['ENFORCED', 'OUTCOME_CONSISTENT'],
    signer_roles: ['finality_witness'],
    trust_assumptions: ['The synthetic witness trust root is explicitly pinned and proves only this fixture-defined commitment match, not production or distributed finality.'],
  },
]);

export const DIAGNOSTIC_REASONS = Object.freeze([
  'none',
  'binding_mismatch',
  'binding_unresolved',
  'evidence_unavailable',
  'verification_failed',
  'enforcement_evidence_missing',
  'outcome_unwitnessed',
  'procedure_unavailable',
  'policy_denied',
]);

const PROMOTION_RULE = 'eligible iff completion is completed, verdict is satisfied, and every mandatory dependency is eligible';
const DIAGNOSTIC_STATES = Object.freeze({
  none: [['completed', 'satisfied']],
  binding_mismatch: [['completed', 'refuted']],
  binding_unresolved: [['completed', 'indeterminate']],
  evidence_unavailable: [['completed', 'indeterminate']],
  verification_failed: [['completed', 'refuted']],
  enforcement_evidence_missing: [['completed', 'indeterminate']],
  outcome_unwitnessed: [['completed', 'indeterminate']],
  procedure_unavailable: [['incomplete', 'indeterminate'], ['not_evaluated', 'indeterminate']],
  policy_denied: [['completed', 'refuted']],
});

const PROFILE_DOMAIN = 'CTEF-PO-RESULTS/1';

function assertSupported(value, path = '$', seen = new Set()) {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) {
    throw new TypeError(`${path}: only finite safe integers are supported`);
  }
  if (typeof value === 'string' && /[\uD800-\uDFFF]/u.test(value)) {
    throw new TypeError(`${path}: lone UTF-16 surrogate is unsupported`);
  }
  if (value === undefined || typeof value === 'function' || typeof value === 'symbol' || typeof value === 'bigint') {
    throw new TypeError(`${path}: unsupported JSON value`);
  }
  if (value && typeof value === 'object') {
    if (seen.has(value)) throw new TypeError(`${path}: cyclic value`);
    if (Object.getPrototypeOf(value) !== Object.prototype && !Array.isArray(value)) {
      throw new TypeError(`${path}: only plain objects and arrays are supported`);
    }
    seen.add(value);
    if (Array.isArray(value)) value.forEach((item, index) => assertSupported(item, `${path}[${index}]`, seen));
    else Object.entries(value).forEach(([key, item]) => {
      assertSupported(key, `${path}.<key>`, seen);
      assertSupported(item, `${path}.${key}`, seen);
    });
    seen.delete(value);
  }
}

export function canonicalJSON(value) {
  assertSupported(value);
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(',')}}`;
}

export function sha256Hex(value) {
  const bytes = typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(canonicalJSON(value), 'utf8');
  return createHash('sha256').update(bytes).digest('hex');
}

export function actionCommitment(action) {
  return sha256Hex({ domain: `${PROFILE_DOMAIN}/action`, action });
}

function evidenceCommitment(obligationId, evidence) {
  const domain = `${PROFILE_DOMAIN}/evidence/${obligationId}`;
  if (evidence === null || evidence === undefined) {
    return { algorithm: HASH_ALGORITHM, canonicalization: CANONICALIZATION, domain, status: 'unavailable', digest: null };
  }
  return {
    algorithm: HASH_ALGORITHM,
    canonicalization: CANONICALIZATION,
    domain,
    status: 'committed',
    digest: sha256Hex({ domain, evidence }),
  };
}

export function signedMessageBytes(kind, message) {
  const prefix = Buffer.from(`${PROFILE_DOMAIN}\0${kind}\0`, 'utf8');
  return Buffer.concat([prefix, Buffer.from(canonicalJSON(message), 'utf8')]);
}

function decodeBase64Exact(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null;
  const decoded = Buffer.from(value, 'base64');
  return decoded.toString('base64') === value ? decoded : null;
}

function validSignedEvidence(evidence, role, roots, kind) {
  try {
    if (!evidence || typeof evidence !== 'object' || !evidence.message || !evidence.signature) return false;
    const root = roots?.[role];
    if (!root || root.algorithm !== SIGNATURE_ALGORITHM || root.public_key_format !== 'DER-SPKI-base64') return false;
    if (evidence.signature.algorithm !== SIGNATURE_ALGORITHM || evidence.signature.key_id !== root.key_id) return false;
    const publicKeyBytes = decodeBase64Exact(root.public_key);
    const signature = decodeBase64Exact(evidence.signature.value);
    if (!publicKeyBytes || !signature) return false;
    const key = createPublicKey({ key: publicKeyBytes, format: 'der', type: 'spki' });
    return ed25519Verify(null, signedMessageBytes(kind, evidence.message), key, signature);
  } catch {
    return false;
  }
}

function same(actual, expected) {
  return canonicalJSON(actual) === canonicalJSON(expected);
}

function obligationById(id) {
  return OBLIGATIONS.find((item) => item.obligation_id === id);
}

function allDependentClaims(id) {
  const found = new Set();
  const visit = (parent) => {
    for (const item of OBLIGATIONS) {
      if (item.dependencies.includes(parent) && !found.has(item.claim_id)) {
        found.add(item.claim_id);
        visit(item.obligation_id);
      }
    }
  };
  visit(id);
  return [...found].sort();
}

export function validateDependencyGraph(definitions = OBLIGATIONS) {
  const byId = new Map(definitions.map((item) => [item.obligation_id, item]));
  if (byId.size !== definitions.length) throw new Error('duplicate obligation_id in dependency graph');
  for (const item of definitions) {
    for (const dependency of item.dependencies) {
      if (!byId.has(dependency)) throw new Error(`${item.obligation_id}: unknown dependency ${dependency}`);
    }
  }
  const visiting = new Set();
  const visited = new Set();
  const visit = (id) => {
    if (visiting.has(id)) throw new Error(`dependency cycle includes ${id}`);
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dependency of byId.get(id).dependencies) visit(dependency);
    visiting.delete(id);
    visited.add(id);
  };
  for (const item of definitions) visit(item.obligation_id);
  const position = new Map(definitions.map((item, index) => [item.obligation_id, index]));
  for (const item of definitions) {
    for (const dependency of item.dependencies) {
      if (position.get(dependency) >= position.get(item.obligation_id)) {
        throw new Error(`${item.obligation_id}: dependency ordering is not topological (${dependency} must appear first)`);
      }
    }
  }
  return true;
}

function baseStatus(definition, input, evidence, procedureUnavailable = false) {
  if (procedureUnavailable) return { completion: 'incomplete', verdict: 'indeterminate', diagnostic_reason: 'procedure_unavailable' };
  if (evidence === null || evidence === undefined) return { completion: 'completed', verdict: 'indeterminate', diagnostic_reason: 'evidence_unavailable' };
  return { completion: 'completed', verdict: 'satisfied', diagnostic_reason: 'none' };
}

function evidenceForObligation(input, id) {
  switch (id) {
    case 'INPUT_PRESENT': return input;
    case 'AUTHENTICATED': return input.authentication ?? null;
    case 'ACTION_BOUND': return { action: input.action, binding: input.binding ?? null };
    case 'AUTHORIZED': return input.authorization_evidence ?? null;
    case 'ENFORCED': return input.enforcement_evidence ?? null;
    case 'OUTCOME_RECORDED':
    case 'OUTCOME_CONSISTENT': return input.outcome_record ?? null;
    case 'FINALITY_WITNESSED': return input.finality_evidence ?? null;
    default: throw new Error(`No evidence selector for obligation ${id}`);
  }
}

function evaluateOne(definition, vector, computedActionCommitment) {
  const { input, trust_roots: roots } = vector;
  const id = definition.obligation_id;
  const unavailable = input.procedure?.unavailable_obligation_ids?.includes(id) === true;
  const action = input.action;
  let evidence;
  let status;
  let keyIds = [];

  if (unavailable) {
    evidence = evidenceForObligation(input, id);
    keyIds = evidence ? definition.signer_roles.map((role) => roots[role]?.key_id).filter(Boolean) : [];
    status = { completion: 'incomplete', verdict: 'indeterminate', diagnostic_reason: 'procedure_unavailable' };
  } else switch (id) {
    case 'INPUT_PRESENT':
      evidence = input;
      status = input && input.profile?.id === PROFILE.id && input.profile?.version === PROFILE.version && action
        ? { completion: 'completed', verdict: 'satisfied', diagnostic_reason: 'none' }
        : { completion: 'completed', verdict: 'refuted', diagnostic_reason: 'verification_failed' };
      break;
    case 'AUTHENTICATED':
      evidence = input.authentication ?? null;
      keyIds = evidence ? [roots.subject?.key_id].filter(Boolean) : [];
      status = baseStatus(definition, input, evidence, unavailable);
      if (status.verdict === 'satisfied') {
        const message = evidence.message;
        const fieldsMatch = message.profile_id === PROFILE.id && message.profile_version === PROFILE.version &&
          message.obligation_id === id && message.claim_id === definition.claim_id &&
          message.result_id === input.result_id && message.subject === action.subject &&
          message.action_commitment === computedActionCommitment;
        if (!validSignedEvidence(evidence, 'subject', roots, 'authentication-v1') || !fieldsMatch) {
          status = { completion: 'completed', verdict: 'refuted', diagnostic_reason: 'verification_failed' };
        }
      }
      break;
    case 'ACTION_BOUND': {
      evidence = { action, binding: input.binding ?? null };
      if (input.binding?.action_commitment === null || input.binding?.action_commitment === undefined) {
        status = { completion: 'completed', verdict: 'indeterminate', diagnostic_reason: 'binding_unresolved' };
      } else if (input.binding.action_commitment === computedActionCommitment) {
        status = { completion: 'completed', verdict: 'satisfied', diagnostic_reason: 'none' };
      } else {
        status = { completion: 'completed', verdict: 'refuted', diagnostic_reason: 'binding_mismatch' };
      }
      break;
    }
    case 'AUTHORIZED':
      evidence = input.authorization_evidence ?? null;
      keyIds = evidence ? [roots.governance?.key_id].filter(Boolean) : [];
      status = baseStatus(definition, input, evidence);
      if (status.verdict === 'satisfied') {
        const message = evidence.message;
        const messageMatches = message.profile_id === PROFILE.id && message.profile_version === PROFILE.version &&
          message.obligation_id === id && message.claim_id === definition.claim_id &&
          message.result_id === input.result_id;
        if (!validSignedEvidence(evidence, 'governance', roots, 'authorization-v1')) {
          status = { completion: 'completed', verdict: 'refuted', diagnostic_reason: 'verification_failed' };
        } else if (!messageMatches || message.action_commitment !== computedActionCommitment) {
          status = { completion: 'completed', verdict: 'refuted', diagnostic_reason: 'binding_mismatch' };
        } else {
          const { decision, policy } = message;
          const allowed = decision === 'allow' && policy?.id === 'synthetic-payment-policy-v1' && policy?.version === '1' &&
            typeof message.decision_id === 'string' && message.decision_id.length > 0 &&
            policy?.action_types?.includes(action.action_type) === true &&
            typeof policy.scope_prefix === 'string' && action.scope.startsWith(policy.scope_prefix);
          if (!allowed) status = { completion: 'completed', verdict: 'refuted', diagnostic_reason: 'policy_denied' };
        }
      }
      break;
    case 'ENFORCED':
      evidence = input.enforcement_evidence ?? null;
      keyIds = evidence ? [roots.enforcement_observer?.key_id].filter(Boolean) : [];
      status = baseStatus(definition, input, evidence);
      if (evidence === null || evidence === undefined) {
        status = { completion: 'completed', verdict: 'indeterminate', diagnostic_reason: 'enforcement_evidence_missing' };
      } else if (status.verdict === 'satisfied') {
        const message = evidence.message;
        const signed = validSignedEvidence(evidence, 'enforcement_observer', roots, 'enforcement-v1');
        const effectiveCommitment = actionCommitment(message.effective_action);
        const authEvidence = input.authorization_evidence;
        const authCommitment = authEvidence?.message?.action_commitment;
        const fieldsMatch = message.profile_id === PROFILE.id && message.profile_version === PROFILE.version &&
          message.obligation_id === id && message.claim_id === definition.claim_id &&
          message.result_id === input.result_id && message.state === 'applied' &&
          message.action_commitment === computedActionCommitment &&
          message.effective_action_commitment === effectiveCommitment &&
          message.policy_profile === 'synthetic-payment-policy-v1';
        if (!signed) status = { completion: 'completed', verdict: 'refuted', diagnostic_reason: 'verification_failed' };
        else if (!fieldsMatch || message.authorization_action_commitment !== effectiveCommitment ||
            (authCommitment !== undefined && message.authorization_action_commitment !== authCommitment)) {
          status = { completion: 'completed', verdict: 'refuted', diagnostic_reason: 'binding_mismatch' };
        }
      }
      break;
    case 'OUTCOME_RECORDED':
      evidence = input.outcome_record ?? null;
      if (!evidence) status = { completion: 'completed', verdict: 'indeterminate', diagnostic_reason: 'evidence_unavailable' };
      else if (evidence.result_id === input.result_id && typeof evidence.status === 'string' && evidence.output !== undefined) {
        status = { completion: 'completed', verdict: 'satisfied', diagnostic_reason: 'none' };
      } else status = { completion: 'completed', verdict: 'refuted', diagnostic_reason: 'verification_failed' };
      break;
    case 'OUTCOME_CONSISTENT':
      evidence = input.outcome_record ?? null;
      if (!evidence) status = { completion: 'completed', verdict: 'indeterminate', diagnostic_reason: 'evidence_unavailable' };
      else if (evidence.output_commitment !== sha256Hex({ domain: `${PROFILE.id}/output`, output: evidence.output }) ||
          evidence.action_commitment !== computedActionCommitment || evidence.result_id !== input.result_id) {
        status = { completion: 'completed', verdict: 'refuted', diagnostic_reason: 'binding_mismatch' };
      } else status = { completion: 'completed', verdict: 'satisfied', diagnostic_reason: 'none' };
      break;
    case 'FINALITY_WITNESSED':
      evidence = input.finality_evidence ?? null;
      keyIds = evidence ? [roots.finality_witness?.key_id].filter(Boolean) : [];
      if (!evidence) status = { completion: 'completed', verdict: 'indeterminate', diagnostic_reason: 'outcome_unwitnessed' };
      else {
        const message = evidence.message;
        if (!validSignedEvidence(evidence, 'finality_witness', roots, 'finality-v1')) {
          status = { completion: 'completed', verdict: 'refuted', diagnostic_reason: 'verification_failed' };
        } else {
          const record = input.outcome_record;
          const fieldsMatch = message.profile_id === PROFILE.id && message.profile_version === PROFILE.version &&
            message.obligation_id === id && message.claim_id === definition.claim_id &&
            message.result_id === input.result_id && message.action_commitment === computedActionCommitment &&
            message.witness_profile === 'synthetic-finality-witness-v1';
          if (!fieldsMatch || !record || message.output_commitment !== record.output_commitment) {
            status = { completion: 'completed', verdict: 'refuted', diagnostic_reason: 'binding_mismatch' };
          } else if (message.observed_commitment !== record.output_commitment) {
            status = { completion: 'completed', verdict: 'refuted', diagnostic_reason: 'binding_mismatch' };
          } else {
            status = { completion: 'completed', verdict: 'satisfied', diagnostic_reason: 'none' };
          }
        }
      }
      break;
    default:
      throw new Error(`No evaluator for obligation ${id}`);
  }

  return {
    obligation_id: id,
    claim_id: definition.claim_id,
    proposition: definition.proposition,
    verification_profile: { ...PROFILE },
    evidence_commitment: evidenceCommitment(id, evidence),
    trust_basis: {
      assumptions: [...definition.trust_assumptions],
      signer_roles: [...definition.signer_roles],
      key_ids: keyIds,
      fixture_key_provenance: 'Synthetic public-only conformance roots; private components and seeds are not included in the repository or required for regeneration.',
    },
    layer: definition.layer,
    obligation_kind: definition.obligation_kind,
    completion: status.completion,
    verdict: status.verdict,
    diagnostic_reason: status.diagnostic_reason,
    dependencies: definition.dependencies.map((obligation_id) => ({ obligation_id, mandatory: true })),
    dependent_claims: allDependentClaims(id),
    terminal: status.completion === 'completed' && status.verdict === 'refuted',
    terminal_scope: status.completion === 'completed' && status.verdict === 'refuted' ? 'specific_proposition_only' : 'none',
    promotion: null,
  };
}

export function evaluateVector(vector) {
  validateDependencyGraph();
  const input = vector.input;
  const computedActionCommitment = actionCommitment(input.action);
  const results = OBLIGATIONS.map((definition) => evaluateOne(definition, vector, computedActionCommitment));
  const byId = new Map(results.map((result) => [result.obligation_id, result]));

  for (const result of results) {
    const definition = obligationById(result.obligation_id);
    const blockedBy = definition.dependencies.filter((dependency) => byId.get(dependency).promotion?.status !== 'eligible');
    let promotionStatus;
    if (result.verdict === 'refuted') promotionStatus = 'refuted';
    else if (result.verdict === 'indeterminate' || result.completion !== 'completed') promotionStatus = 'indeterminate';
    else if (blockedBy.length > 0) promotionStatus = 'blocked';
    else promotionStatus = 'eligible';
    result.promotion = {
      claim_id: result.claim_id,
      status: promotionStatus,
      mandatory_dependencies_satisfied: blockedBy.length === 0,
      blocked_by: blockedBy,
      rule: PROMOTION_RULE,
    };
  }
  return results;
}

const RESULT_KEYS = [
  'obligation_id', 'claim_id', 'proposition', 'verification_profile', 'evidence_commitment', 'trust_basis',
  'layer', 'obligation_kind', 'completion', 'verdict', 'diagnostic_reason', 'dependencies', 'dependent_claims',
  'terminal', 'terminal_scope', 'promotion',
];

function exactObject(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    same(Object.keys(value).sort(), [...keys].sort());
}

function stringArray(value, { nonEmpty = false, unique = false } = {}) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string' && (!nonEmpty || item.length > 0)) &&
    (!unique || new Set(value).size === value.length);
}

function expect(condition, message, errors) {
  if (!condition) errors.push(message);
}

export function validateResultSchema(result, path = '$result') {
  const errors = [];
  expect(result && typeof result === 'object' && !Array.isArray(result), `${path}: expected object`, errors);
  if (!result || typeof result !== 'object' || Array.isArray(result)) return errors;
  expect(same(Object.keys(result).sort(), [...RESULT_KEYS].sort()), `${path}: fields differ from the stable result schema`, errors);
  expect(typeof result.obligation_id === 'string' && result.obligation_id.length > 0, `${path}.obligation_id: expected non-empty string`, errors);
  expect(typeof result.claim_id === 'string' && result.claim_id.length > 0, `${path}.claim_id: expected non-empty string`, errors);
  expect(typeof result.proposition === 'string' && result.proposition.length > 0, `${path}.proposition: expected exact proposition string`, errors);
  expect(exactObject(result.verification_profile, ['id', 'version']) && same(result.verification_profile, PROFILE), `${path}.verification_profile: unexpected id/version or fields`, errors);
  const commitment = result.evidence_commitment;
  expect(exactObject(commitment, ['algorithm', 'canonicalization', 'domain', 'status', 'digest']) &&
    commitment.algorithm === HASH_ALGORITHM && commitment.canonicalization === CANONICALIZATION &&
    typeof commitment.domain === 'string' && commitment.domain.length > 0 && ['committed', 'unavailable'].includes(commitment.status) &&
    (commitment.status === 'committed' ? /^[0-9a-f]{64}$/.test(commitment.digest ?? '') : commitment.digest === null),
  `${path}.evidence_commitment: invalid shape or null semantics`, errors);
  const trust = result.trust_basis;
  expect(exactObject(trust, ['assumptions', 'signer_roles', 'key_ids', 'fixture_key_provenance']) &&
    stringArray(trust.assumptions, { nonEmpty: true }) && stringArray(trust.signer_roles, { nonEmpty: true, unique: true }) &&
    stringArray(trust.key_ids, { nonEmpty: true, unique: true }) &&
    typeof trust.fixture_key_provenance === 'string' && trust.fixture_key_provenance.length > 0,
  `${path}.trust_basis: invalid shape or fields`, errors);
  expect(['L1_evidence', 'L2_governance'].includes(result.layer), `${path}.layer: invalid classification`, errors);
  expect(typeof result.obligation_kind === 'string' && result.obligation_kind.length > 0, `${path}.obligation_kind: expected string`, errors);
  expect(['completed', 'incomplete', 'not_evaluated'].includes(result.completion), `${path}.completion: invalid value`, errors);
  expect(['satisfied', 'refuted', 'indeterminate'].includes(result.verdict), `${path}.verdict: invalid value`, errors);
  expect(DIAGNOSTIC_REASONS.includes(result.diagnostic_reason), `${path}.diagnostic_reason: unknown stable reason code`, errors);
  const stateMatchesReason = DIAGNOSTIC_STATES[result.diagnostic_reason]?.some(([completion, verdict]) =>
    result.completion === completion && result.verdict === verdict) === true;
  expect(stateMatchesReason, `${path}: diagnostic_reason is inconsistent with completion/verdict`, errors);
  expect(Array.isArray(result.dependencies) && result.dependencies.every((item) =>
    exactObject(item, ['obligation_id', 'mandatory']) && typeof item.obligation_id === 'string' && item.obligation_id.length > 0 && item.mandatory === true) &&
    new Set((result.dependencies ?? []).map((item) => item?.obligation_id)).size === (result.dependencies ?? []).length,
  `${path}.dependencies: invalid shape or fields`, errors);
  expect(stringArray(result.dependent_claims, { nonEmpty: true, unique: true }) &&
    same(result.dependent_claims, [...result.dependent_claims].sort()), `${path}.dependent_claims: invalid, duplicate, or unstable order`, errors);
  expect(typeof result.terminal === 'boolean' && ['none', 'specific_proposition_only'].includes(result.terminal_scope), `${path}.terminal: invalid shape`, errors);
  expect(result.terminal === (result.completion === 'completed' && result.verdict === 'refuted') &&
    result.terminal_scope === (result.terminal ? 'specific_proposition_only' : 'none'), `${path}.terminal: inconsistent terminal semantics`, errors);
  const promotion = result.promotion;
  const promotionShape = exactObject(promotion, ['claim_id', 'status', 'mandatory_dependencies_satisfied', 'blocked_by', 'rule']);
  expect(promotionShape && promotion.claim_id === result.claim_id && ['eligible', 'blocked', 'refuted', 'indeterminate'].includes(promotion.status) &&
    typeof promotion.mandatory_dependencies_satisfied === 'boolean' && stringArray(promotion.blocked_by, { nonEmpty: true, unique: true }) &&
    typeof promotion.rule === 'string' && promotion.rule === PROMOTION_RULE, `${path}.promotion: invalid shape or fields`, errors);
  if (promotionShape && Array.isArray(result.dependencies) && Array.isArray(promotion.blocked_by)) {
    const dependencyIds = result.dependencies.map((item) => item?.obligation_id);
    const blockedIds = promotion.blocked_by;
    expect(blockedIds.every((id) => dependencyIds.includes(id)), `${path}.promotion.blocked_by: unknown direct dependency`, errors);
    expect(same(blockedIds, dependencyIds.filter((id) => blockedIds.includes(id))), `${path}.promotion.blocked_by: unstable dependency order`, errors);
    expect(promotion.mandatory_dependencies_satisfied === (blockedIds.length === 0), `${path}.promotion: dependency flag disagrees with blocked_by`, errors);
    if (promotion.status === 'eligible') expect(result.completion === 'completed' && result.verdict === 'satisfied' && blockedIds.length === 0,
      `${path}.promotion: ineligible result marked eligible`, errors);
    if (promotion.status === 'blocked') expect(result.completion === 'completed' && result.verdict === 'satisfied' && blockedIds.length > 0,
      `${path}.promotion: blocked status requires a locally satisfied claim and blocked dependency`, errors);
    if (promotion.status === 'refuted') expect(result.completion === 'completed' && result.verdict === 'refuted',
      `${path}.promotion: refuted status requires a completed refutation`, errors);
    if (promotion.status === 'indeterminate') expect(result.verdict === 'indeterminate',
      `${path}.promotion: indeterminate status requires an indeterminate local result`, errors);
  }
  if (result.completion === 'incomplete' || result.completion === 'not_evaluated') {
    expect(result.verdict === 'indeterminate' && !result.terminal, `${path}: incomplete/not-evaluated must be indeterminate and non-terminal`, errors);
  }
  return errors;
}

export function diffValues(expected, actual, path = '$') {
  if (same(expected, actual)) return [];
  if (expected && actual && typeof expected === 'object' && typeof actual === 'object' &&
      !Array.isArray(expected) && !Array.isArray(actual)) {
    const keys = [...new Set([...Object.keys(expected), ...Object.keys(actual)])].sort();
    return keys.flatMap((key) => {
      if (!(key in expected)) return [`${path}.${key}: unexpected ${JSON.stringify(actual[key])}`];
      if (!(key in actual)) return [`${path}.${key}: missing; expected ${JSON.stringify(expected[key])}`];
      return diffValues(expected[key], actual[key], `${path}.${key}`);
    });
  }
  return [`${path}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`];
}

export function validateVectorSuite(set) {
  const errors = [];
  expect(set && typeof set === 'object' && !Array.isArray(set), '$: expected suite object', errors);
  if (!set || typeof set !== 'object' || Array.isArray(set)) return errors;
  expect(set && set.profile?.id === PROFILE.id && set.profile?.version === PROFILE.version, '$.profile: unsupported profile', errors);
  expect(Array.isArray(set?.vectors) && set.vectors.length === 16, '$.vectors: expected exactly 16 vectors', errors);
  if (!Array.isArray(set?.vectors)) return errors;
  const ids = set.vectors.map((vector) => vector?.id);
  expect(new Set(ids).size === ids.length, '$.vectors: duplicate vector id', errors);
  const positive = new Set(set.vectors.filter((v) => v.coverage?.polarity === 'positive').map((v) => v.id));
  const requiredCases = [
    ['case-01-authenticated-without-authorization', 'negative', 'AUTHORIZED', 'case-02-authenticated-and-authorized'],
    ['case-02-authenticated-and-authorized', 'positive', null, null],
    ['case-03-authorized-without-enforcement-witness', 'negative', 'ENFORCED', 'case-04-authorized-with-enforcement-witness'],
    ['case-04-authorized-with-enforcement-witness', 'positive', null, null],
    ['case-05-recorded-outcome-without-finality-witness', 'negative', 'FINALITY_WITNESSED', 'case-06-recorded-outcome-with-finality-witness'],
    ['case-06-recorded-outcome-with-finality-witness', 'positive', null, null],
    ['case-07-tampered-authentication-material', 'negative', 'AUTHENTICATED', 'case-08-intact-authentication-control'],
    ['case-08-intact-authentication-control', 'positive', null, null],
    ['case-09-completed-binding-mismatch', 'negative', 'ACTION_BOUND', 'case-10-matched-binding-control'],
    ['case-10-matched-binding-control', 'positive', null, null],
    ['case-11-missing-binding-evidence', 'negative', 'ACTION_BOUND', 'case-10-matched-binding-control'],
    ['case-12-authentication-procedure-unavailable', 'negative', 'AUTHENTICATED', 'case-08-intact-authentication-control'],
    ['case-13-rewritten-action-with-stale-authorization-binding', 'negative', 'ENFORCED', 'case-14-rebound-effective-action-control'],
    ['case-14-rebound-effective-action-control', 'positive', null, null],
    ['case-15-independent-finality-outcome-divergence', 'negative', 'FINALITY_WITNESSED', 'case-06-recorded-outcome-with-finality-witness'],
    ['case-16-refuted-authentication-isolation', 'negative', 'AUTHENTICATED', 'case-08-intact-authentication-control'],
  ];
  expect(set.vectors.length === requiredCases.length && set.vectors.every((vector, index) =>
    vector?.id === requiredCases[index][0] && vector?.coverage?.case_number === index + 1 &&
    vector?.coverage?.polarity === requiredCases[index][1] &&
    (vector?.coverage?.targeted_root_obligation_id ?? null) === requiredCases[index][2] &&
    (vector?.coverage?.positive_control_id ?? null) === requiredCases[index][3]),
  '$.vectors: required sixteen-case coverage order or root/control mapping differs', errors);
  for (const vector of set.vectors) {
    if (!vector || typeof vector !== 'object' || Array.isArray(vector)) {
      errors.push('vector entry: expected object');
      continue;
    }
    const label = `vector ${vector.id}`;
    expect(/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(vector.id), `${label}: invalid stable id`, errors);
    expect(vector.profile?.id === PROFILE.id && vector.profile?.version === PROFILE.version, `${label}: profile mismatch`, errors);
    expect(vector.input && typeof vector.input === 'object' && !Array.isArray(vector.input) &&
      vector.input.profile?.id === PROFILE.id && vector.input.profile?.version === PROFILE.version &&
      typeof vector.input.result_id === 'string' && vector.input.result_id.length > 0 &&
      vector.input.action && typeof vector.input.action === 'object' && !Array.isArray(vector.input.action),
    `${label}: missing self-contained profile, result identifier, or action input`, errors);
    expect(vector.coverage && Number.isInteger(vector.coverage.case_number) && ['positive', 'negative'].includes(vector.coverage.polarity), `${label}: missing coverage metadata`, errors);
    let inputCommitmentMatches = false;
    try {
      inputCommitmentMatches = vector.input_commitment?.algorithm === HASH_ALGORITHM && vector.input_commitment?.canonicalization === CANONICALIZATION &&
        vector.input_commitment?.digest === sha256Hex({ domain: `${PROFILE_DOMAIN}/input`, input: vector.input });
    } catch { /* malformed inputs are reported by the explicit shape/evaluation errors */ }
    expect(inputCommitmentMatches, `${label}: input commitment mismatch or unsupported canonical input`, errors);
    expect(Array.isArray(vector.expected_results) && vector.expected_results.length === OBLIGATIONS.length, `${label}: expected one result per obligation`, errors);
    if (!Array.isArray(vector.expected_results)) continue;
    let actual;
    try { actual = evaluateVector(vector); }
    catch (error) {
      errors.push(`${label}: evaluation failed: ${error.message}`);
      continue;
    }
    const expectedIds = OBLIGATIONS.map((item) => item.obligation_id);
    expect(same(vector.expected_results.map((r) => r?.obligation_id), expectedIds), `${label}: expected results are not in stable obligation order`, errors);
    for (let i = 0; i < Math.min(actual.length, vector.expected_results.length); i++) {
      const resultPath = `${label}.expected_results[${i}]`;
      for (const schemaError of validateResultSchema(vector.expected_results[i], resultPath)) errors.push(schemaError);
      expect(same(actual[i], vector.expected_results[i]), `${label}: result mismatch ${diffValues(vector.expected_results[i], actual[i], resultPath).join('; ')}`, errors);
    }
    const unsatisfied = actual.filter((result) => result.verdict !== 'satisfied');
    if (vector.coverage?.polarity === 'negative') {
      const root = vector.coverage.targeted_root_obligation_id;
      expect(typeof root === 'string', `${label}: negative vector has no targeted root`, errors);
      expect(unsatisfied.length === 1 && unsatisfied[0]?.obligation_id === root, `${label}: expected exactly one targeted root result, got ${unsatisfied.map((x) => `${x.obligation_id}:${x.verdict}`).join(', ')}`, errors);
      if (root) expect(actual.find((x) => x.obligation_id === root)?.terminal === false || actual.find((x) => x.obligation_id === root)?.terminal === true,
        `${label}: missing root result`, errors);
    } else if (vector.coverage?.polarity === 'positive') {
      expect(unsatisfied.length === 0, `${label}: positive vector has non-satisfied local results: ${unsatisfied.map((x) => x.obligation_id).join(', ')}`, errors);
    }
    if (vector.coverage?.positive_control_id) expect(positive.has(vector.coverage.positive_control_id), `${label}: positive control id is absent or not positive`, errors);
  }
  return errors;
}

export function validateStandaloneVector(vector) {
  const errors = [];
  expect(vector && typeof vector === 'object' && !Array.isArray(vector), '$vector: expected one vector object', errors);
  if (!vector || typeof vector !== 'object' || Array.isArray(vector)) return errors;
  expect(typeof vector.id === 'string' && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(vector.id), '$vector.id: invalid stable id', errors);
  expect(vector.profile?.id === PROFILE.id && vector.profile?.version === PROFILE.version, '$vector.profile: unsupported profile', errors);
  expect(vector.input && typeof vector.input === 'object' && !Array.isArray(vector.input) &&
    vector.input.profile?.id === PROFILE.id && vector.input.profile?.version === PROFILE.version &&
    typeof vector.input.result_id === 'string' && vector.input.result_id.length > 0 &&
    vector.input.action && typeof vector.input.action === 'object' && !Array.isArray(vector.input.action),
  '$vector.input: missing self-contained profile, result identifier, or action', errors);
  let inputCommitmentMatches = false;
  try {
    inputCommitmentMatches = vector.input_commitment?.algorithm === HASH_ALGORITHM && vector.input_commitment?.canonicalization === CANONICALIZATION &&
      vector.input_commitment?.digest === sha256Hex({ domain: `${PROFILE_DOMAIN}/input`, input: vector.input });
  } catch { /* the validator below reports invalid input shape without throwing */ }
  expect(inputCommitmentMatches, '$vector.input_commitment: mismatch or unsupported canonical input', errors);
  expect(Array.isArray(vector.expected_results) && vector.expected_results.length === OBLIGATIONS.length, '$vector.expected_results: expected eight obligation objects', errors);
  if (!Array.isArray(vector.expected_results)) return errors;
  let actual;
  try { actual = evaluateVector(vector); }
  catch (error) {
    errors.push(`$vector: evaluation failed: ${error.message}`);
    return errors;
  }
  const expectedIds = OBLIGATIONS.map((item) => item.obligation_id);
  expect(same(vector.expected_results.map((item) => item?.obligation_id), expectedIds), '$vector.expected_results: stable obligation order/id mismatch', errors);
  for (let index = 0; index < Math.min(actual.length, vector.expected_results.length); index++) {
    const path = `${vector.id}.expected_results[${index}]`;
    for (const schemaError of validateResultSchema(vector.expected_results[index], path)) errors.push(schemaError);
    expect(same(actual[index], vector.expected_results[index]), `${vector.id}: result mismatch ${diffValues(vector.expected_results[index], actual[index], path).join('; ')}`, errors);
  }
  const unsatisfied = actual.filter((result) => result.verdict !== 'satisfied');
  if (vector.coverage?.polarity === 'negative') {
    expect(unsatisfied.length === 1 && unsatisfied[0]?.obligation_id === vector.coverage.targeted_root_obligation_id,
      `${vector.id}: negative vector does not isolate its declared root`, errors);
  } else if (vector.coverage?.polarity === 'positive') {
    expect(unsatisfied.length === 0, `${vector.id}: positive vector contains a non-satisfied result`, errors);
  } else expect(false, `${vector.id}: invalid coverage polarity`, errors);
  return errors;
}
