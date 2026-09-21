// Generates the execution-coverage vector set for OpenSecureAIAlliance/RFCs#6.
//
// The property: signing a coverage block binds the signer to the coverage
// assertion; it does not establish that the checks ran. A consumer reports three
// axes separately and none inherits another's result:
//   signature_valid   — the report's signature verifies under the trust policy
//   coverage_consistent — declared coverage/aggregation is internally consistent
//   execution_state   — established | unestablished | unavailable, from receipts
//                        or independent reproduction (never from the signature)
// digest_binds is a fourth axis: the report is about the definition admission
// observes, not a different one. Whether a consumer proceeds is a separately
// versioned admission policy, not a change to any of these verdicts.
import { createHash, generateKeyPairSync, sign as edSign, verify as edVerify } from 'node:crypto';
import { writeFileSync } from 'node:fs';

function jcs(v) {
  if (v === null || typeof v !== 'object' || v.toJSON != null) return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}
const sha256 = s => createHash('sha256').update(s, 'utf8').digest('hex');

// one deterministic-enough keypair for the set (ed25519, RFC 8032)
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pubDer = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const signReport = report => edSign(null, Buffer.from(jcs(report), 'utf8'), privateKey).toString('base64');

// A check: id, whether it is required, its declared state, and what execution
// evidence the report carries for it.
//   state:     pass | skipped | error
//   execution: receipt | reproduced | none | unavailable
const chk = (id, required, state, execution) => ({ id, required, state, execution });

const DIGEST_A = sha256('tool-definition:acme/fs-mcp@1.4.0#A');
const DIGEST_B = sha256('tool-definition:acme/fs-mcp@1.4.0#B'); // a different build

// Build a report body (no signature yet) from checks + the subject it is about.
const body = (report_id, subject_digest, checks) => {
  const required = checks.filter(c => c.required);
  return {
    report_id,
    subject_digest,
    checks,
    aggregate: {
      required: required.length,
      passed: checks.filter(c => c.state === 'pass').length,
      required_passed: required.filter(c => c.state === 'pass').length,
    },
  };
};

// Each vector: a signed report, the digest admission observes, and the four
// verdicts a correct consumer computes. mode names the property it exercises.
const V = (name, mode, note, report, observed_digest, expect) => {
  const signed = { ...report, signature: { alg: 'EdDSA', value: signReport(report) } };
  return { name, mode, note, observed_digest, report: signed, expect };
};

const vectors = [
  V('skipped-required-check', 'coverage-inconsistent',
    'Valid signature over a report whose aggregate claims all required checks passed, while a required check is declared skipped. The coverage-reading consumer catches the contradiction; the signature does not.',
    (() => { const b = body('r-skip', DIGEST_A,
      [chk('secret-scan', true, 'pass', 'receipt'), chk('exec-sandbox', true, 'skipped', 'none')]);
      b.aggregate.required_passed = 2; // the false claim: says both required passed
      return b; })(),
    DIGEST_A,
    // the passed required check IS evidenced; the skip is caught on coverage, not execution
    { signature_valid: true, coverage_consistent: false, digest_binds: true, execution_state: 'established' }),

  V('completion-without-execution-evidence', 'distinguishing-control',
    'THE control. Valid signature, internally consistent coverage, correct arithmetic, and it binds the observed digest — but no required check carries a receipt or reproduction. Signature and arithmetic pass while execution is unestablished. A coverage-only reader passes this false-green.',
    body('r-noev', DIGEST_A,
      [chk('secret-scan', true, 'pass', 'none'), chk('exec-sandbox', true, 'pass', 'none')]),
    DIGEST_A,
    { signature_valid: true, coverage_consistent: true, digest_binds: true, execution_state: 'unestablished' }),

  V('digest-mismatch', 'wrong-subject',
    'A valid, fully-evidenced report for definition digest A, presented when admission observes digest B. Every other axis passes; the report is simply not about the artefact being admitted.',
    body('r-mismatch', DIGEST_A,
      [chk('secret-scan', true, 'pass', 'receipt'), chk('exec-sandbox', true, 'pass', 'reproduced')]),
    DIGEST_B,
    { signature_valid: true, coverage_consistent: true, digest_binds: false, execution_state: 'established' }),

  V('reproduction-unavailable', 'unavailable-not-false',
    'A required check whose inputs or dependencies cannot be disclosed, so it can be neither receipted nor independently reproduced. Execution is unavailable, which is a distinct state from unestablished: nothing claims it ran, and nothing can check that it did.',
    body('r-unavail', DIGEST_A,
      [chk('secret-scan', true, 'pass', 'receipt'), chk('license-audit', true, 'pass', 'unavailable')]),
    DIGEST_A,
    { signature_valid: true, coverage_consistent: true, digest_binds: true, execution_state: 'unavailable' }),

  V('positive-continuation', 'admissible',
    'Matching definitions, every required check passed and evidenced by a receipt or independent reproduction, and the report binds the observed digest. All four axes hold; whether to proceed is then the admission policy, versioned separately from this verdict.',
    body('r-ok', DIGEST_A,
      [chk('secret-scan', true, 'pass', 'receipt'), chk('exec-sandbox', true, 'pass', 'reproduced')]),
    DIGEST_A,
    { signature_valid: true, coverage_consistent: true, digest_binds: true, execution_state: 'established' }),
];

const out = {
  suite: 'execution-coverage-v0',
  spec: 'OpenSecureAIAlliance/RFCs#6 — pre-connection tool-trust attestation',
  status: 'proposed — a report shape for the RFC to refine, not a finalized schema',
  derivation: 'signature = Ed25519 (RFC 8032) over jcs(report) minus the signature field; RFC 8785 JCS. digests are sha-256.',
  author_set: 'agentgraph (AgentAvow attestation layer, did:web:agentgraph.co).',
  axes: {
    signature_valid: "the report's signature verifies; binds the signer to what it signed and no further",
    coverage_consistent: 'declared coverage and aggregation are internally consistent; a required check is not both skipped and counted as passed',
    digest_binds: 'the report is about the definition admission observes (subject_digest == observed_digest)',
    execution_state: 'established (every required check receipted or reproduced) | unestablished (no such evidence) | unavailable (cannot be receipted or reproduced); never inferred from the signature',
  },
  public_key_spki_b64: pubDer,
  vectors,
};
writeFileSync(new URL('./execution-coverage-v0-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${vectors.length} vectors`);
