// Rebuilds atd-provenance-signing-v0-vectors.json from source.json. Node 18+, zero deps.
//   node generate.mjs
// Everything is derived, not transcribed: each kid is the RFC 7638 thumbprint of its
// test key, every JWS is signed here, the negatives are one-field edits of the positive,
// and the evaluation times are offsets from the payload's own iat / exp.
//
// Spec: agentnameservice/agent-trust-discovery#27 at 3971f5e.
// The keys in source.json are TEST keys. They are not the production signing key.
import { createHash, createHmac, createPrivateKey, createPublicKey, sign as edSign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const src = JSON.parse(readFileSync(new URL('./source.json', import.meta.url), 'utf8'));
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const seconds = (iso) => Math.floor(Date.parse(iso) / 1000);
const plusS = (iso, s) => new Date(Date.parse(iso) + s * 1000).toISOString().replace('.000Z', 'Z');

// RFC 7638 §3.2: SHA-256 over the required members of the public JWK, in lexicographic
// order, with no whitespace. For an OKP key (RFC 8037 §2) those members are crv, kty, x.
const thumbprintInput = (jwk) => `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`;
const thumbprint = (jwk) => createHash('sha256').update(thumbprintInput(jwk)).digest('base64url');

// #16 signal ids are vendor.dimension.name. The vendor segment is everything before the
// last two dot-separated segments (peeled from the right, so a did:web vendor keeps its
// dots) — the same parse as scorecontainer.vendorSegment. The relying party's backstop
// code is {DIMENSION}_{VENDOR}_SCORE_LOW with the vendor sanitised to [A-Z0-9_].
const vendorSegment = (id) => id.split('.').slice(0, -2).join('.');
const sanitize = (s) => s.toUpperCase().replace(/[^A-Z0-9_]/g, '_');

const publicJwk = (k, kid) => ({ kty: k.kty, crv: k.crv, x: k.x, kid, use: 'sig', alg: 'EdDSA' });
const privateKey = (k) => createPrivateKey({ key: { kty: k.kty, crv: k.crv, x: k.x, d: k.d }, format: 'jwk' });
const rawPublic = (k) => createPublicKey(privateKey(k)).export({ format: 'der', type: 'spki' }).subarray(-32);

const ISS = src.issuer.iss;
const OTHER = src.other_issuer.iss;
const signingKid = thumbprint(src.keys.signing);
const legacyKid = src.keys.legacy.kid;
const otherKid = thumbprint(src.keys.other);

if (vendorSegment(src.issuer.signal) !== ISS) throw new Error('source: signal vendor segment must equal iss (spec §3a)');

// Compact JWS (RFC 7515 §7.1). Signing input is ASCII(BASE64URL(header) || "." || BASE64URL(payload)).
// The payload is embedded as plain JSON; no canonicalisation is required (spec §1).
function jws(header, payload, signer) {
  const h = b64u(JSON.stringify(header));
  const p = b64u(JSON.stringify(payload));
  const input = Buffer.from(`${h}.${p}`, 'ascii');
  return `${h}.${p}.${signer(input)}`;
}
const ed = (k) => (input) => b64u(edSign(null, input, privateKey(k)));
const none = () => '';
// The classic key-confusion forgery: an HMAC keyed with the issuer's public key bytes.
const hmacWithPublicKey = (k) => (input) => b64u(createHmac('sha256', rawPublic(k)).update(input).digest());

const iat = seconds(src.payload.issued_at);
const exp = seconds(src.payload.expires_at);
// Spec §3: iss, sub, subjectClass, iat, exp, dimension, score, riskCodes. Nothing else —
// explanation is unsigned by rule (§3a note on scope) and never enters the payload.
const payload = {
  iss: ISS,
  sub: src.payload.sub,
  subjectClass: src.payload.subjectClass,
  iat,
  exp,
  dimension: src.payload.dimension,
  score: src.payload.score,
  riskCodes: src.payload.riskCodes,
};
const header = { alg: 'EdDSA', kid: signingKid };
const reference = jws(header, payload, ed(src.keys.signing));

// The same verdict, honestly signed by a different issuer under its own key. Used by
// wrong-iss: everything about it is genuine except that it is not agentgraph's.
const otherPayload = { ...payload, iss: OTHER };
const otherHeader = { alg: 'EdDSA', kid: otherKid };
const otherReference = jws(otherHeader, otherPayload, ed(src.keys.other));

// The container (the #18 SignalScore observation) as a relying party holds it. `stored` is
// the observation as recorded, including the unsigned explanation; `evaluated` is what
// scorecontainer.Evaluate derives from it (dimension-prefixed codes only, plus the
// _SCORE_LOW backstop under the threshold). The binding rule reads `stored` (§1 as of
// 3971f5e); `evaluated` is carried so the difference is visible.
const stored = { dimension: src.payload.dimension, score: src.payload.score,
  riskCodes: src.observation.stored_riskCodes_order, explanation: src.observation.explanation };
const backstop = `${stored.dimension.toUpperCase()}_${sanitize(vendorSegment(src.issuer.signal))}_SCORE_LOW`;
const evaluated = { dimension: stored.dimension, score: stored.score, riskCodes: [
  ...stored.riskCodes.filter((c) => c.startsWith(stored.dimension.toUpperCase() + '_')),
  ...(stored.score < src.observation.backstop_threshold ? [backstop] : []),
], explanation: stored.explanation };

const observation = (o = {}) => ({
  subject: src.payload.sub,
  subjectClass: src.payload.subjectClass,
  signal: src.issuer.signal,
  stored,
  provenance: {
    aimId: ISS,
    evidenceUrl: src.observation.evidenceUrl,
    signed: { jws: reference, kid: signingKid, jwks: src.issuer.jwks_url },
  },
  evaluation_time: src.policy.evaluation_time,
  max_age_seconds: src.policy.max_age_seconds,
  ...o,
});
// kid: a string, or null to omit the envelope kid entirely (the missing-kid vector).
const signed = (jwsValue, kid = signingKid, jwksUrl = src.issuer.jwks_url, aimId = ISS) => ({
  aimId, evidenceUrl: src.observation.evidenceUrl,
  signed: { jws: jwsValue, ...(kid === null ? {} : { kid }), jwks: jwksUrl },
});

const ok = {
  iss_bound: true, kid_present: true, key_resolves: true, kid_is_thumbprint: true, alg_allowed: true,
  signature_valid: true, binding: true, subject_bound: true, fresh: true, accept: true,
};
const expect = (o) => ({ ...ok, ...o });

const vectors = [
  { name: 'valid', fails: null,
    note: 'The positive case. The payload names its issuer, subject, class, time and scored values; the header kid is the RFC 7638 thumbprint of a key the issuer publishes; the signal\'s vendor segment equals the signed iss; the container holds the same score and the same risk codes in a different order; the pinned evaluation time is inside [iat, exp). Every check passes. Accept.',
    observation: observation({ evaluated }),
    expect: expect({}) },

  { name: 'explanation-rewritten', fails: null,
    note: 'The positive case with the container\'s free-text explanation replaced by a caption that contradicts the verdict. explanation is unsigned (§3a, note on scope): it is not in the payload, takes part in no check, and the result is identical to `valid`. A relying party MUST NOT present it as attested; the verifier reports it outside the attested set. Accept.',
    observation: observation({ stored: { ...stored, explanation: src.observation.rewritten_explanation } }),
    expect: expect({}) },

  { name: 'score-mismatch', fails: 'binding',
    note: 'The container score was raised after signing (62 to 91). The signature is intact because the signed payload still says 62; the drift is between payload and container. Spec §1: a verification failure, not a warning. Reject.',
    observation: observation({ stored: { ...stored, score: 91 } }),
    expect: expect({ binding: false, accept: false }) },

  { name: 'wrong-sub', fails: 'subject_bound',
    note: 'A valid signed verdict about one tool presented on another tool\'s observation. Spec §3: sub MUST match the observation subject. Reject.',
    observation: observation({ subject: src.observation.foreign_subject }),
    expect: expect({ subject_bound: false, accept: false }) },

  { name: 'wrong-iss', fails: 'iss_bound',
    note: 'Re-attribution. The credential is genuine: signed by did:web:other.example, which publishes the key under its thumbprint kid, with iss did:web:other.example in the signed payload. It is presented on did:web:agentgraph.co\'s signal. The key resolves from the signed iss and the signature verifies; the signal\'s vendor segment (did:web:agentgraph.co) does not equal iss. Spec §3a, step 5. Reject.',
    observation: observation({ provenance: signed(otherReference, otherKid, src.other_issuer.jwks_url, OTHER) }),
    expect: expect({ iss_bound: false, accept: false }) },

  { name: 'vendor-segment-mismatch', fails: 'iss_bound',
    note: 'The cross-vendor dimension collision, from the other direction. A genuine did:web:agentgraph.co credential (iss correct, key resolves, signature verifies) imported under another vendor\'s safety signal (did:web:trustmodel.example.safety.score). dimension matches and sub matches, so §1 and §3 alone would pass; §3a requires the target signal\'s vendor segment to equal iss, and it does not. Reject.',
    observation: observation({ signal: src.foreign_signal }),
    expect: expect({ iss_bound: false, accept: false }) },

  { name: 'alg-none', fails: 'alg_allowed',
    note: 'Protected header alg is "none" and the signature segment is empty. The explicit allowlist (EdDSA only for v1) rejects it before any signature check; signature_valid is therefore not evaluated, not passed. Reject.',
    observation: observation({ provenance: signed(jws({ alg: 'none', kid: signingKid }, payload, none)) }),
    expect: expect({ alg_allowed: false, signature_valid: null, accept: false }) },

  { name: 'alg-off-allowlist', fails: 'alg_allowed',
    note: 'Algorithm confusion. Header alg is HS256 and the signature is an HMAC-SHA256 keyed with the issuer\'s own public key bytes, which is what a verifier that dispatches on the header\'s alg would compute and accept. The allowlist rejects any alg outside it, not only "none". Reject.',
    observation: observation({ provenance: signed(jws({ alg: 'HS256', kid: signingKid }, payload, hmacWithPublicKey(src.keys.signing))) }),
    expect: expect({ alg_allowed: false, signature_valid: null, accept: false }) },

  { name: 'missing-kid', fails: 'kid_present',
    note: 'No kid in the protected header and none in the envelope. The bytes are a genuine Ed25519 signature by the issuer\'s key, so the only thing wrong is that the verifier has no key identifier to resolve. Spec §2 and step 2: kid MUST be present. Nothing that needs a key is evaluated. Reject.',
    observation: observation({ provenance: signed(jws({ alg: 'EdDSA' }, payload, ed(src.keys.signing)), null) }),
    expect: expect({ kid_present: false, key_resolves: null, kid_is_thumbprint: null, signature_valid: null, accept: false }) },

  { name: 'kid-not-thumbprint', fails: 'kid_is_thumbprint',
    note: 'The issuer publishes this key under a stable name (agentgraph-test-legacy-v1) rather than its thumbprint, and the JWS is correctly signed by it. The key resolves and the signature verifies; the kid rule (§2, RFC 7638 thumbprint or otherwise strictly key-derived) fails. Reject.',
    observation: observation({ provenance: signed(jws({ alg: 'EdDSA', kid: legacyKid }, payload, ed(src.keys.legacy)), legacyKid) }),
    expect: expect({ kid_is_thumbprint: false, accept: false }) },

  { name: 'past-exp', fails: 'fresh',
    note: 'Same valid credential, evaluated one hour after its exp. The evaluation reference time is pinned in the vector (spec, deterministic freshness vectors) so the verdict is a property of the corpus. Spec §3b: past exp is treated as unsigned. Reject.',
    observation: observation({ evaluation_time: plusS(src.payload.expires_at, 3600) }),
    expect: expect({ fresh: false, accept: false }) },

  { name: 'stale-iat', fails: 'fresh',
    note: 'The payload carries iat but no exp (the spec allows this: exp is SHOULD), and the relying party\'s max-age is pinned in the vector at 86400 s. Evaluated one second past iat + max-age. Spec §3b: a payload without exp MUST be bounded by max-age against iat. Reject.',
    observation: (() => {
      const { exp: _drop, ...noExp } = payload;
      return observation({ provenance: signed(jws(header, noExp, ed(src.keys.signing))),
        evaluation_time: plusS(src.payload.issued_at, src.policy.max_age_seconds + 1) });
    })(),
    expect: expect({ fresh: false, accept: false }) },

  { name: 'unpublished-key', fails: 'key_resolves',
    note: 'The forgery §3a closes. The payload says iss did:web:agentgraph.co, the header kid is the correct thumbprint of the key used, and the envelope\'s jwks points at a server (other.example) that serves that key. But did:web:agentgraph.co does not publish it. A verifier that resolves keys from the envelope\'s jwks URL accepts this; one that derives the key location from the signed iss finds no such kid under (iss, kid). The same kid resolves under did:web:other.example (see wrong-iss), which is why the cache is keyed by (iss, kid) and not kid alone. Reject.',
    observation: observation({ provenance: signed(jws({ alg: 'EdDSA', kid: otherKid }, payload, ed(src.keys.other)), otherKid, src.other_issuer.jwks_url) }),
    expect: expect({ key_resolves: false, kid_is_thumbprint: null, signature_valid: null, accept: false }) },
];

const out = {
  suite: 'atd-provenance-signing-v0',
  spec: 'agentnameservice/agent-trust-discovery#27 at 3971f5e (provenance signing extension, compact JWS): §1 binding against the stored-observation riskCodes, §2 RFC 7638 thumbprint kid cached by (iss, kid), §3 signed subject and time, §3a iss binds key and vendor, §3b freshness, deterministic freshness vectors',
  status: 'proposed; AgentAvow\'s half of the two-signer conformance corpus the spec requires before the shape locks. Signed with a TEST key, not the production key',
  test_key_notice: 'Every key in this file is a test key generated for this corpus. did:web:agentgraph.co does not publish them; the `issuers` map below stands in for what resolving each iss would return. The production AgentAvow key and its kid (agentgraph-security-v1) are not used here.',
  derivation: 'jws = compact JWS (RFC 7515), header {alg, kid}, payload embedded as plain JSON (no canonicalisation), signature over ASCII(BASE64URL(header) || "." || BASE64URL(payload)). kid = RFC 7638 thumbprint: BASE64URL(SHA-256(\'{"crv":"Ed25519","kty":"OKP","x":"<x>"}\')). iat/exp are seconds since the epoch. vendor segment of a signal id = the id with its trailing .dimension.name removed (peeled from the right; a did:web vendor keeps its dots). backstop code = {DIMENSION}_{VENDOR sanitised to [A-Z0-9_]}_SCORE_LOW.',
  kid_computation: { input: thumbprintInput(src.keys.signing), sha256_base64url: signingKid },
  alg_allowlist: ['EdDSA'],
  signed_fields: ['iss', 'sub', 'subjectClass', 'iat', 'exp', 'dimension', 'score', 'riskCodes'],
  unsigned_fields: ['explanation', 'provenance.aimId', 'provenance.evidenceUrl', 'provenance.signed.jwks'],
  checks: {
    iss_bound: 'payload.iss is a non-empty string and equals the vendor segment of observation.signal (§3a, step 5). The envelope\'s aimId is unsigned and is not consulted.',
    kid_present: 'header.kid is a non-empty string and equals observation.provenance.signed.kid (§2, step 2).',
    key_resolves: 'issuers[payload.iss].jwks has a key with kid = header.kid. Resolution is by (iss, kid) from the location derived from the signed iss; the envelope\'s jwks URL is not consulted (§3a, step 3). An iss that does not resolve fails here. null when kid_present is false or iss is absent.',
    kid_is_thumbprint: 'header.kid equals the RFC 7638 thumbprint of the resolved key (§2). null when no key resolves.',
    alg_allowed: 'header.alg is in alg_allowlist (step 4).',
    signature_valid: 'Ed25519 verifies over the signing input under the resolved key. null when alg_allowed is false or no key resolves; a verifier does not run a signature check it has already refused.',
    binding: 'payload.dimension and payload.score equal observation.stored by scalar equality; payload.riskCodes equals observation.stored.riskCodes by set-equality (order-insensitive, duplicates ignored). Compared against the stored observation, never the evaluated SignalScore, so relying-party backstop codes are excluded by construction (§1, step 6).',
    subject_bound: 'payload.sub equals observation.subject and payload.subjectClass equals observation.subjectClass (§3, step 7).',
    fresh: 'with exp: evaluation_time < exp. Without exp: evaluation_time - iat <= max_age_seconds. Both inputs are pinned in the vector (§3b, step 8; deterministic freshness vectors).',
    accept: 'every other check is true. null is not true.',
  },
  not_evaluated_rule: 'A check reported as null was not run because a check it depends on failed. It is never reported as passed. Each negative fails exactly one check; the rest are true or null.',
  issuers: {
    [ISS]: {
      resolution: `what resolving ${ISS} returns for this corpus (did:web DID document verificationMethod or ${src.issuer.jwks_url}); pinned so nothing is fetched. TEST keys.`,
      jwks: { keys: [publicJwk(src.keys.signing, signingKid), publicJwk(src.keys.legacy, legacyKid)] },
    },
    [OTHER]: {
      resolution: `what resolving ${OTHER} returns for this corpus (${src.other_issuer.jwks_url}); pinned so nothing is fetched. TEST key.`,
      jwks: { keys: [publicJwk(src.keys.other, otherKid)] },
    },
  },
  reference: { header, payload, jws: reference },
  vectors,
};
writeFileSync(new URL('./atd-provenance-signing-v0-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${vectors.length} vectors; signing kid ${signingKid}; backstop ${backstop}`);
