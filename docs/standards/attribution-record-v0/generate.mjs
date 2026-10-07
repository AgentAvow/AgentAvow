// Rebuilds consumed-artifact-record-v0-vectors.json from source.json and pins/. Node 18+, zero deps.
//   node generate.mjs
// Everything derived here is derived, not transcribed: every digest is sha256 over the
// pinned bytes; the build refuses to run if the APS manifest or the PriorSeal report does
// not hash to the value the thread agreed on; the negatives are the positive record with
// exactly one thing changed; the test keys are derived from public labels, so two runs
// produce the same bytes. No production key is involved anywhere.
import { createHash, createPrivateKey, createPublicKey, sign as edSign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const here = (p) => new URL(p, import.meta.url);
const src = JSON.parse(readFileSync(here('./source.json'), 'utf8'));
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const b64u = (buf) => Buffer.from(buf).toString('base64url');

function jcs(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}

// ── the byte store: ref -> retained bytes, digests computed, never copied ──────
const store = {};
const byteStore = src.byte_store.map(({ ref, path }) => {
  const bytes = readFileSync(here('./' + path));
  store[ref] = bytes;
  return { ref, path, sha256: sha256(bytes), bytes: bytes.length };
});
const digestOf = (ref) => 'sha256:' + sha256(store[ref]);
const refFor = (suffix) => Object.keys(store).find(r => r.endsWith(suffix));

// The pinned bytes must be the ones the thread agreed on, or the fixture teaches nothing.
const manifestRef = refFor('/MANIFEST.sha256');
if (sha256(store[manifestRef]) !== src.pins.aps.manifest_sha256)
  throw new Error('APS MANIFEST.sha256 does not hash to the pinned manifest digest; refusing to build');
const manifest = Object.fromEntries(store[manifestRef].toString('utf8').trim().split('\n')
  .map(line => line.trim().split(/\s+/)).map(([hex, path]) => [path, hex]));
for (const [path, hex] of Object.entries(manifest)) {
  const ref = refFor('/' + src.pins.aps.dir + '/' + path);
  if (ref && sha256(store[ref]) !== hex) throw new Error(`${path} does not match its manifest line; refusing to build`);
}
const reportRef = refFor('/PAYMENT-LIMIT-REPORT.json');
if (sha256(store[reportRef]) !== src.pins.priorseal.report_sha256)
  throw new Error('PriorSeal PAYMENT-LIMIT-REPORT.json does not hash to the pinned report digest; refusing to build');

// ── test keys derived from public labels (Ed25519 seed = sha256(label)) ────────
// A fixed seed makes the signatures reproducible: Ed25519 signing is deterministic.
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
function testKey(label) {
  const seed = createHash('sha256').update(label, 'utf8').digest();
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const jwk = createPublicKey(priv).export({ format: 'jwk' });
  return { priv, jwk };
}
const keys = {};
const attesters = src.attesters.map(a => {
  const { priv, jwk } = testKey(a.label);
  keys[a.kid] = priv;
  return { id: a.id, kid: a.kid, jwk: { ...jwk, kid: a.kid, use: 'sig', alg: 'EdDSA' },
    valid_from: a.valid_from, valid_until: a.valid_until, derived_from_label: a.label, note: a.note };
});
const attesterById = Object.fromEntries(attesters.map(a => [a.id, a]));

function signRecord(record, kid) {
  const header = b64u(JSON.stringify({ alg: 'EdDSA', kid }));
  const payload = b64u(jcs(record));
  const sig = edSign(null, Buffer.from(`${header}.${payload}`, 'ascii'), keys[kid]);
  return `${header}.${payload}.${b64u(sig)}`;
}

// ── the positive record ───────────────────────────────────────────────────────
const attester = attesters[0];
const other = attesters[1];
const claims = src.claims.map(c => ({
  artifact: { ref: c.artifact_ref, digest: digestOf(c.artifact_ref) },
  role: c.role,
  evidence: c.evidence.map(e => ({ ref: e.ref, digest: digestOf(e.ref), binding: e.binding })),
}));
const record = {
  profile: src.profile,
  action: { ref: src.action.ref },
  consumed: claims,
  attester: { id: attester.id, kid: attester.kid },
  attested_at: src.attested_at,
};

// Every binding in the positive record must hold against the pinned bytes, or the
// fixture would be attesting something the evidence does not say.
function pointer(doc, ptr) {
  if (ptr === '') return doc;
  let cur = doc;
  for (const raw of ptr.split('/').slice(1)) {
    const key = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = Array.isArray(cur) ? cur[Number(key)] : cur[key];
  }
  return cur;
}
const normHex = (v) => typeof v === 'string' ? v.toLowerCase().replace(/^(0x|sha256:)/, '') : undefined;
for (const c of claims) {
  const art = JSON.parse(store[c.artifact.ref].toString('utf8'));
  for (const e of c.evidence) {
    const ev = JSON.parse(store[e.ref].toString('utf8'));
    const b = e.binding;
    const ok = b.kind === 'value_equals'
      ? normHex(pointer(art, b.artifact_pointer)) !== undefined
        && normHex(pointer(art, b.artifact_pointer)) === normHex(pointer(ev, b.evidence_pointer))
      : b.kind === 'digest_cited'
        ? normHex(pointer(ev, b.evidence_pointer)) === sha256(store[c.artifact.ref])
        : false;
    if (!ok) throw new Error(`binding does not hold for ${c.artifact.ref} via ${e.ref}; refusing to build`);
  }
}

// ── negatives: the positive record with exactly one thing changed ─────────────
// wrong-digest: the last hex digit of the first claim's artifact digest is changed.
const wrongDigest = structuredClone(record);
{
  const d = wrongDigest.consumed[0].artifact.digest;
  const last = parseInt(d.at(-1), 16) ^ 1;
  wrongDigest.consumed[0].artifact.digest = d.slice(0, -1) + last.toString(16);
}
// missing-evidence: the second claim's only evidence reference resolves nowhere.
const missingEvidence = structuredClone(record);
missingEvidence.consumed[1].evidence = [{
  ref: src.missing_evidence_ref,
  digest: 'sha256:' + sha256(Buffer.from('consumed-artifact-record.v0: no such bytes', 'utf8')),
  binding: structuredClone(record.consumed[1].evidence[0].binding),
}];
// attester-not-signer: the record is unchanged (it still names the attester), but the
// JWS is produced by the other party under the other party's kid.

const claimExpect = (o = {}) => ({ artifact_digest: true, evidence_resolves: true, evidence_digest: true, evidence_binds: true, ...o });
const expectAll = (claimOverrides = {}, o = {}) => ({
  canonical_bytes: true, attester_signed: true,
  claims: claims.map((_, i) => claimExpect(claimOverrides[i] ?? {})),
  holds: true, ...o,
});

const vectors = [
  { name: 'consumed-and-attested',
    note: 'The positive case. Three APS permit artifacts are named as consumed in the role decision.pre_action; each digest matches the pinned bytes; the PriorSeal authorization carries the APS decision_ref as a context commitment and the PriorSeal report cites all three artifact digests; the named attester signed. Every check passes and the record holds.',
    evaluation_time: src.evaluation_time, record, jws: signRecord(record, attester.kid), expect: expectAll() },
  { name: 'wrong-digest',
    note: 'The first claim names a digest the pinned bytes do not hash to (one hex digit changed). The attester signed it, the evidence resolves, and the bindings still hold, because they are measured against the bytes, not against the digest the record states. Only artifact_digest fails, on that claim.',
    evaluation_time: src.evaluation_time, record: wrongDigest, jws: signRecord(wrongDigest, attester.kid),
    expect: expectAll({ 0: { artifact_digest: false } }, { holds: false }) },
  { name: 'missing-evidence',
    note: 'The second claim references evidence that resolves nowhere. The verifier cannot hash what it does not have and cannot evaluate a binding against it, so evidence_resolves fails and evidence_digest and evidence_binds are not_evaluated on that claim. Nothing else changes.',
    evaluation_time: src.evaluation_time, record: missingEvidence, jws: signRecord(missingEvidence, attester.kid),
    expect: expectAll({ 1: { evidence_resolves: false, evidence_digest: 'not_evaluated', evidence_binds: 'not_evaluated' } }, { holds: false }) },
  { name: 'attester-not-signer',
    note: 'The record names did:example:record-attester, but the JWS was produced by did:example:other-party under its own kid. The payload is canonical and every claim checks against the bytes; the named attester simply did not sign. Only attester_signed fails.',
    evaluation_time: src.evaluation_time, record, jws: signRecord(record, other.kid),
    expect: expectAll({}, { attester_signed: false, holds: false }) },
];

const out = {
  suite: 'consumed-artifact-record-v0',
  spec: 'aeoess/agent-governance-vocabulary#185 (record first, money later) over #179 E2 (APS -> PriorSeal): a signed per-action record of which artifacts one action consumed, in which role, with the evidence a verifier recomputes from',
  status: 'proposed, a first cut for review under the process #185 settles; one pinned fixture and four expected outcomes, not an adopted federation format',
  claim_ceiling: 'holds=true establishes exactly this: the named attester signed a statement that each named artifact (by digest, over the pinned bytes) was consumed in the named role for the named action, and each piece of evidence the statement points to is present, hashes to its stated digest, and binds the artifact the way the statement says. It establishes nothing about the value or importance of the artifact, nothing about payment, nothing about whether the action ran, nothing about whether the artifact or the evidence is valid under its own producer\'s rules (a record MAY cite a lab record as evidence, never required), and nothing about any artifact the record does not name.',
  record: {
    profile: src.profile,
    signing: 'compact JWS (RFC 7515), alg EdDSA (Ed25519), header {alg, kid}, payload = RFC 8785 JCS canonical bytes of the record; signature over ASCII(BASE64URL(header) || "." || BASE64URL(payload)). The verifier resolves the signing key from the attester the record names, never from the header alone; header.kid must agree with record.attester.kid.',
    fields: {
      profile: 'string, constant "consumed-artifact-record.v0".',
      'action.ref': 'string. What action this record is about. Opaque to the verifier, chosen by the attester; SHOULD reuse a shared action identifier the artifacts carry, and MAY be tool-scoped (for example mcp:<server>#<tool>) when they share none.',
      'consumed[]': 'one claim per artifact: "this artifact was consumed in this role".',
      'consumed[].artifact.ref': 'string. Where the bytes are published, pinned to an immutable revision. Opaque to the verifier; it is the key into the byte store.',
      'consumed[].artifact.digest': '"sha256:" + 64 lowercase hex, over the exact bytes at artifact.ref.',
      'consumed[].role': 'string. The job the artifact did in the action. Free string; SHOULD be the shared systems map\'s capability id where one exists (#186/#187), a locally defined id stated as such where none does.',
      'consumed[].evidence[]': 'one or more references a verifier recomputes from. At least one.',
      'consumed[].evidence[].ref': 'string. Where the evidence bytes are published, pinned. Opaque; key into the byte store.',
      'consumed[].evidence[].digest': '"sha256:" + 64 lowercase hex, over the exact evidence bytes.',
      'consumed[].evidence[].binding': 'required. How the evidence binds the artifact; without it evidence_binds cannot be evaluated and the record does not hold. kind "value_equals": the value at artifact_pointer in the artifact equals the value at evidence_pointer in the evidence, after normalize. kind "digest_cited": the value at evidence_pointer in the evidence equals sha256 over the artifact bytes, after normalize. Both kinds are measured against the bytes, never against the digest the record states. Pointers are RFC 6901 JSON pointers. normalize "hex" lowercases and strips a leading "0x" or "sha256:"; it is implied for digest_cited.',
      'attester.id': 'string. Who attested: the consumer that performed the consumption. A producer MAY attest its own separate record under the same action.ref.',
      'attester.kid': 'string. The key the attester signed with, resolved from the verifier\'s own pins for that attester.',
      attested_at: 'RFC 3339 instant at which the attester made the statement. The attester\'s key pin must cover it.',
    },
    not_fields: 'No status label, no verification result, no value, weight, share, price or importance, no statement that the action ran. Whether the record holds is the output of a verifier, never a field.',
  },
  checks: {
    canonical_bytes: 'jcs(JSON.parse(payload)) equals the payload bytes. Recomputability; independent of the signature.',
    attester_signed: 'header.alg is EdDSA, header.kid equals record.attester.kid, the verifier holds a key pinned for (attester.id, kid) whose window covers attested_at, and the Ed25519 signature verifies under it. Binds the named attester to what it signed, and no further.',
    'claims[i].artifact_digest': 'sha256 over the bytes the byte store holds for artifact.ref equals artifact.digest. false when the store holds nothing for the ref.',
    'claims[i].evidence_resolves': 'the byte store holds bytes for every evidence ref of the claim.',
    'claims[i].evidence_digest': 'every evidence item\'s bytes hash to its stated digest. not_evaluated when evidence_resolves is false.',
    'claims[i].evidence_binds': 'every binding of the claim holds, evaluated against the bytes. not_evaluated when evidence_resolves is false or the store holds nothing for the artifact.',
    holds: 'canonical_bytes, attester_signed, and every check of every claim are true. None of the checks is derived from another.',
  },
  action: src.action,
  pins: src.pins,
  byte_store: byteStore,
  attesters,
  vectors,
  hooks: {
    e1: {
      edge: '#179 E1, AgentAvow -> a pre-execution gate: the second journey, once the first holds.',
      artifact: {
        ref: 'https://raw.githubusercontent.com/AgentAvow/AgentAvow/36426cfd/docs/standards/tool-manifest-digest-vectors-v1/tool-manifest-digest-v1-vectors.json',
        note: 'The signed static verdict is the compact JWS at /attestation/jws inside that file; its payload sha256 is 5e159675e62845bd5411932a1f970ed08bb0ea768043cb898a8c2656bfd000fa. A record would name the attestation by the digest of the bytes it consumed.',
      },
      role: 'enforcement.tool_boundary is the gate\'s own role in the systems map; no capability there names the tool-safety evidence the gate consumes. The record needs a role id for that, local or added to the map.',
      evidence_needed: 'A gate-side decision record, pinned, that carries the signed per-tool digest it relied on (for example the value at /scan/toolDigests/tool:ask_wiki_question). Binding would be value_equals between that pointer in the attestation payload and the gate record\'s copy. No such pinned gate record exists yet: the E1 consumers published so far are readers that re-check the fixture, not gates that authorized a call on it.',
      not_a_vector: 'Nothing in this hook is verified by verify.mjs. It states what the second fixture would reference and what is missing.',
    },
  },
};
writeFileSync(here('./consumed-artifact-record-v0-vectors.json'), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${vectors.length} vectors, ${claims.length} claims per record, action ${src.action.ref}`);
