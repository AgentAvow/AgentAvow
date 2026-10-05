// Zero-dependency verifier for the atd-provenance-signing-v0 corpus. Node 18+.
//   node verify.mjs [path-to-vectors.json]
// Exits non-zero on any check whose result differs from the vector's expectation.
//
// Implements the verification algorithm of agentnameservice/agent-trust-discovery#27
// at 3971f5e: kid in header and envelope, iss in the signed payload, keys resolved from
// iss and selected by kid (never from the envelope's jwks), an explicit alg allowlist,
// the signal's vendor segment equal to iss, binding against the stored observation
// values with riskCodes compared as sets, subject match, and freshness against an
// evaluation reference time and max-age pinned in the vector. Nothing is fetched: the
// `issuers` map in the file is what resolving each iss returns for this corpus.
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const file = process.argv[2] ?? new URL('./atd-provenance-signing-v0-vectors.json', import.meta.url);
const set = JSON.parse(readFileSync(file, 'utf8'));
const allow = new Set(set.alg_allowlist);

const thumbprint = (jwk) =>
  createHash('sha256').update(`{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`).digest('base64url');
const vendorSegment = (id) => id.split('.').slice(0, -2).join('.');
const setEqual = (a, b) => Array.isArray(a) && Array.isArray(b)
  && new Set(a).size === new Set(b).size && a.every((x) => b.includes(x));
const parseB64Json = (s) => { try { return JSON.parse(Buffer.from(s, 'base64url').toString('utf8')); } catch { return null; } };
const resolveKey = (iss, kid) => set.issuers[iss]?.jwks.keys.find((k) => k.kid === kid) ?? null;

function checks(obs) {
  const env = obs.provenance.signed;
  const [h, p, s = ''] = env.jws.split('.');
  const header = parseB64Json(h) ?? {};
  const payload = parseB64Json(p) ?? {};
  const hasIss = typeof payload.iss === 'string' && payload.iss.length > 0;

  const iss_bound = hasIss && payload.iss === vendorSegment(obs.signal);
  const kid_present = typeof header.kid === 'string' && header.kid.length > 0 && header.kid === env.kid;
  const key = (kid_present && hasIss) ? resolveKey(payload.iss, header.kid) : null;
  const key_resolves = (kid_present && hasIss) ? key !== null : null;
  const kid_is_thumbprint = key ? header.kid === thumbprint(key) : null;
  const alg_allowed = allow.has(header.alg);
  const signature_valid = (alg_allowed && key)
    ? edVerify(null, Buffer.from(`${h}.${p}`, 'ascii'), createPublicKey({ key, format: 'jwk' }), Buffer.from(s, 'base64url'))
    : null;
  const binding = payload.dimension === obs.stored.dimension
    && payload.score === obs.stored.score
    && setEqual(payload.riskCodes, obs.stored.riskCodes);
  const subject_bound = payload.sub === obs.subject && payload.subjectClass === obs.subjectClass;
  const now = Date.parse(obs.evaluation_time) / 1000;
  const fresh = Number.isInteger(payload.iat) && (
    payload.exp !== undefined ? Number.isInteger(payload.exp) && now < payload.exp
      : now - payload.iat <= obs.max_age_seconds);

  const r = { iss_bound, kid_present, key_resolves, kid_is_thumbprint, alg_allowed, signature_valid, binding, subject_bound, fresh };
  r.accept = Object.values(r).every((v) => v === true);
  return r;
}

// What a relying party may present as attested: the signed payload's fields and nothing
// from the container. explanation is never in it (spec §3a, note on scope).
const attested = (obs) => Object.keys(parseB64Json(obs.provenance.signed.jws.split('.')[1]) ?? {});

let failures = 0;
const check = (label, got, want) => {
  if (String(got) === String(want)) { console.log(`  ok    ${label}`); return; }
  failures++;
  console.log(`  FAIL  ${label}\n        want ${want}\n        got  ${got}`);
};

console.log(`${set.suite}\n${set.status}\nsigning kid ${set.kid_computation.sha256_base64url}\n`);
const byName = {};
for (const v of set.vectors) {
  const got = checks(v.observation);
  byName[v.name] = got;
  for (const a of Object.keys(got)) check(`${v.name}: ${a}`, got[a], v.expect[a]);
}

console.log('\nproperties under test');
const positives = set.vectors.filter((v) => !v.fails);
const negatives = set.vectors.filter((v) => v.fails);
const headerKid = (name) => parseB64Json(set.vectors.find((v) => v.name === name).observation.provenance.signed.jws.split('.')[0])?.kid;
check('every positive accepts', positives.every((v) => byName[v.name].accept === true), 'true');
check('every negative is rejected', negatives.every((v) => byName[v.name].accept === false), 'true');
check('every negative fails exactly one check, and it is the one it is named for',
  negatives.every((v) => {
    const falses = Object.entries(byName[v.name]).filter(([k, val]) => k !== 'accept' && val === false).map(([k]) => k);
    return falses.length === 1 && falses[0] === v.fails;
  }), 'true');
check('kid is the RFC 7638 thumbprint of the published signing key',
  thumbprint(set.issuers[set.reference.payload.iss].jwks.keys[0]) === set.reference.header.kid
    && createHash('sha256').update(set.kid_computation.input).digest('base64url') === set.reference.header.kid, 'true');
check('the signed payload carries exactly the §3 fields, and explanation is not among them',
  JSON.stringify(Object.keys(set.reference.payload)) === JSON.stringify(set.signed_fields)
    && !set.signed_fields.includes('explanation')
    && set.vectors.every((v) => !attested(v.observation).includes('explanation')), 'true');
check('rewriting the container explanation changes no check: it is unsigned and must not be presented as attested',
  JSON.stringify(byName['explanation-rewritten']) === JSON.stringify(byName.valid)
    && set.vectors.find((v) => v.name === 'explanation-rewritten').observation.stored.explanation
      !== set.vectors[0].observation.stored.explanation, 'true');
check('the signal\'s vendor segment equals the signed iss (§3a), and the vendor keeps its dots',
  vendorSegment(set.vectors[0].observation.signal) === set.reference.payload.iss
    && set.reference.payload.iss.includes('.'), 'true');
check('riskCodes bind by set-equality: container order differs from the signed order and the positive still binds',
  JSON.stringify(set.vectors[0].observation.stored.riskCodes) !== JSON.stringify(set.reference.payload.riskCodes)
    && byName.valid.binding, 'true');
check('binding reads the stored observation: the evaluated view carries a backstop code the signer never emitted and the positive still accepts',
  set.vectors[0].observation.evaluated.riskCodes.some((c) => c.endsWith('_SCORE_LOW'))
    && !setEqual(set.vectors[0].observation.evaluated.riskCodes, set.reference.payload.riskCodes)
    && byName.valid.accept, 'true');
check('re-attribution fails on the vendor segment while the foreign issuer\'s key resolves and its signature verifies',
  byName['wrong-iss'].key_resolves && byName['wrong-iss'].signature_valid && !byName['wrong-iss'].iss_bound, 'true');
check('a genuine credential bound to another vendor\'s signal fails on the vendor segment while the signature verifies',
  byName['vendor-segment-mismatch'].signature_valid && !byName['vendor-segment-mismatch'].iss_bound, 'true');
check('the key cache is scoped by (iss, kid): the same kid resolves under its own issuer and not under agentgraph\'s',
  headerKid('wrong-iss') === headerKid('unpublished-key')
    && byName['wrong-iss'].key_resolves === true && byName['unpublished-key'].key_resolves === false, 'true');
check('alg:none and an off-allowlist alg are both refused before any signature check runs',
  !byName['alg-none'].alg_allowed && byName['alg-none'].signature_valid === null
    && !byName['alg-off-allowlist'].alg_allowed && byName['alg-off-allowlist'].signature_valid === null, 'true');
check('a key the issuer does not publish never reaches signature verification, whatever the envelope\'s jwks URL says',
  byName['unpublished-key'].key_resolves === false && byName['unpublished-key'].signature_valid === null, 'true');
check('a correctly signed credential under a non-thumbprint kid verifies and is still rejected',
  byName['kid-not-thumbprint'].signature_valid && !byName['kid-not-thumbprint'].kid_is_thumbprint, 'true');
check('every vector pins an evaluation reference time and a max-age',
  set.vectors.every((v) => Number.isFinite(Date.parse(v.observation.evaluation_time))
    && Number.isInteger(v.observation.max_age_seconds)), 'true');
check('freshness is decided by the pinned evaluation time and max-age',
  !byName['past-exp'].fresh && !byName['stale-iat'].fresh && byName.valid.fresh, 'true');

console.log(failures ? `\n${failures} failure(s)` : '\nall checks passed');
process.exit(failures ? 1 : 0);
