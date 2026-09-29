// Rebuilds tool-manifest-digest-v0-vectors.json from source.json. Node 18+, zero deps.
//   node generate.mjs
// Everything derived here is derived, not transcribed: the tampered JWS is re-encoded
// from the real payload, the drifted digest is a sha-256 of a fixed string, and the
// evaluation times are offsets from the attestation's own issuedAt / expiresAt.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const src = JSON.parse(readFileSync(new URL('./source.json', import.meta.url), 'utf8'));
const [h, p, s] = src.jws.split('.');
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));

function jcs(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}
if (jcs(payload) !== Buffer.from(p, 'base64url').toString('utf8'))
  throw new Error('source payload is not JCS-canonical; refusing to build');

const subject = payload.subject.id;
const digest = payload.scan.toolManifestDigest;
const issuedAt = new Date(payload.issuedAt);
const expiresAt = new Date(payload.expiresAt);
const plusH = (d, hrs) => new Date(d.getTime() + hrs * 3600_000).toISOString();

// A tampered copy: score raised, payload re-canonicalized, original signature kept.
const tampered = structuredClone(payload);
tampered.scan.trustScore = 99;
tampered.scan.trustTier = 'verified';
const tamperedJws = [h, b64u(jcs(tampered)), s].join('.');

const drifted = 'sha256:' + createHash('sha256').update('drifted tool definition').digest('hex');

const expectAll = (o) => ({ signature_valid: true, canonical_bytes: true, subject_binds: true,
  digest_binds: true, fresh: true, rely: true, ...o });

const vectors = [
  { name: 'digest-match', note: 'The positive case. The gate authorizes the same subject, observes the same tool manifest digest the scan graded, and evaluates inside the validity window. Every axis passes, so the grade may be relied on, within its stated ceiling.',
    gate: { subject_id: subject, observed_manifest_digest: digest, evaluation_time: plusH(issuedAt, 1) },
    jws: 'reference', expect: expectAll({}) },
  { name: 'digest-mismatch', note: 'The tool definitions the gate observes differ from the ones the scan graded (the rug-pull). Signature, subject and freshness all pass; the attestation is simply not about this definition. Do not rely.',
    gate: { subject_id: subject, observed_manifest_digest: drifted, evaluation_time: plusH(issuedAt, 1) },
    jws: 'reference', expect: expectAll({ digest_binds: false, rely: false }) },
  { name: 'past-expiry', note: 'Same attestation, evaluated after expiresAt. A signed verdict does not verify forever; a grade issued before a tool was trojaned must stop being relied on. Treated as unsigned.',
    gate: { subject_id: subject, observed_manifest_digest: digest, evaluation_time: plusH(expiresAt, 1) },
    jws: 'reference', expect: expectAll({ fresh: false, rely: false }) },
  { name: 'wrong-subject', note: 'The gate is authorizing a different tool than the one the attestation names. A valid grade for one tool re-attached to another. Do not rely.',
    gate: { subject_id: 'github:microsoft/playwright-mcp', observed_manifest_digest: digest, evaluation_time: plusH(issuedAt, 1) },
    jws: 'reference', expect: expectAll({ subject_binds: false, rely: false }) },
  { name: 'tampered-payload', note: 'Payload edited after signing (trustScore raised to 99), re-canonicalized, original signature kept. Canonical bytes still check, which is the point: canonical form is not authenticity. Signature fails. Do not rely.',
    gate: { subject_id: subject, observed_manifest_digest: digest, evaluation_time: plusH(issuedAt, 1) },
    jws: tamperedJws, expect: expectAll({ signature_valid: false, rely: false }) },
];

const out = {
  suite: 'tool-manifest-digest-v0',
  spec: 'aeoess/agent-governance-vocabulary#177 — tool-safety evidence consumed by a pre-execution gate, bound by tool_manifest_digest',
  status: 'proposed — a consumer-input shape (gate) and five expected outcomes for the boundary to refine; not a finalized schema',
  claim_ceiling: 'rely=true establishes exactly this: at evaluation_time, the named issuer had signed a static-analysis grade for this subject over this tool-definition digest, and the signature, subject, digest and validity window all check. It establishes nothing about runtime behavior, nothing about what the tool does when invoked, and nothing about definitions the scan did not observe. Whether a gate proceeds on rely=true is a separately versioned admission policy.',
  derivation: 'attestation = compact JWS (RFC 7515), alg EdDSA (Ed25519), payload = RFC 8785 JCS canonical bytes of the verdict. signature is over ASCII(BASE64URL(header) || "." || BASE64URL(payload)). tool_manifest_digest = sha-256 folded over the per-file tool-definition digests the scan observed (scan.toolDigests).',
  author_set: 'agentgraph (AgentAvow attestation layer, did:web:agentgraph.co).',
  axes: {
    signature_valid: 'Ed25519 verifies under the pinned JWK whose kid matches the JWS header. Binds the signer to what it signed, and no further.',
    canonical_bytes: 'jcs(JSON.parse(payload)) equals the payload bytes. Recomputability check; independent of the signature.',
    subject_binds: 'payload.subject.id equals gate.subject_id.',
    digest_binds: 'payload.scan.toolManifestDigest equals gate.observed_manifest_digest.',
    fresh: 'gate.evaluation_time is within [issuedAt, expiresAt).',
    rely: 'all five axes true. None of the five is derived from another.',
  },
  issuer: { id: payload.issuer.id, jwks_url: src.jwks_url, jwk: src.jwk },
  attestation: {
    source_url: src.attestation_url,
    subject: payload.subject, issuedAt: payload.issuedAt, expiresAt: payload.expiresAt,
    trustScore: payload.scan.trustScore, toolManifestDigest: digest, toolDigests: payload.scan.toolDigests,
    payload_sha256: createHash('sha256').update(Buffer.from(p, 'base64url')).digest('hex'),
    jws: src.jws,
  },
  vectors,
};
writeFileSync(new URL('./tool-manifest-digest-v0-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${vectors.length} vectors for ${subject} @ ${digest}`);
