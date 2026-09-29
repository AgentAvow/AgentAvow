// Zero-dependency verifier. Node 18+. Exits non-zero on any failure.
//   node verify.mjs [path-to-vectors.json]
//
// For each vector it recomputes the five axes a gate reports separately and checks
// them against the vector's expectation. Nothing is fetched: the JWK is pinned in
// the file (kid-matched to the JWS header); the jwks_url is there so a consumer can
// cross-check the pin against the live key set if it wants to.
import { createPublicKey, verify as edVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const file = process.argv[2] ?? new URL('./tool-manifest-digest-v0-vectors.json', import.meta.url);
const set = JSON.parse(readFileSync(file, 'utf8'));

function jcs(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}
const pub = createPublicKey({ key: set.issuer.jwk, format: 'jwk' });

function axes(vec) {
  const jws = vec.jws === 'reference' ? set.attestation.jws : vec.jws;
  const [h, p, s] = jws.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
  const payloadBytes = Buffer.from(p, 'base64url');
  const payload = JSON.parse(payloadBytes.toString('utf8'));

  const kidOk = header.alg === 'EdDSA' && header.kid === set.issuer.jwk.kid;
  const signature_valid = kidOk && edVerify(null, Buffer.from(`${h}.${p}`, 'ascii'), pub,
    Buffer.from(s, 'base64url'));
  const canonical_bytes = jcs(payload) === payloadBytes.toString('utf8');
  const subject_binds = payload.subject?.id === vec.gate.subject_id;
  const digest_binds = payload.scan?.toolManifestDigest === vec.gate.observed_manifest_digest;
  const t = Date.parse(vec.gate.evaluation_time);
  const fresh = t >= Date.parse(payload.issuedAt) && t < Date.parse(payload.expiresAt);
  const rely = signature_valid && canonical_bytes && subject_binds && digest_binds && fresh;
  return { signature_valid, canonical_bytes, subject_binds, digest_binds, fresh, rely };
}

let failures = 0;
const check = (label, got, want) => {
  if (String(got) === String(want)) { console.log(`  ok    ${label}`); return; }
  failures++;
  console.log(`  FAIL  ${label}\n        want ${want}\n        got  ${got}`);
};

console.log(`${set.suite}\n${set.author_set}\nsubject ${set.attestation.subject.id} @ ${set.attestation.toolManifestDigest}\n`);
const byName = {};
for (const v of set.vectors) {
  const got = axes(v);
  byName[v.name] = got;
  for (const a of Object.keys(got)) check(`${v.name}: ${a}`, got[a], v.expect[a]);
}

console.log('\nproperties under test');
check('positive case relies', byName['digest-match'].rely, 'true');
check('a valid, fresh grade for the wrong definition does not bind',
  byName['digest-mismatch'].signature_valid && byName['digest-mismatch'].fresh && !byName['digest-mismatch'].digest_binds, 'true');
check('a signed verdict does not verify forever', byName['past-expiry'].fresh, 'false');
check('a grade for one tool cannot be re-attached to another', byName['wrong-subject'].subject_binds, 'false');
check('canonical form is not authenticity: tampered payload is canonical yet unsigned',
  byName['tampered-payload'].canonical_bytes && !byName['tampered-payload'].signature_valid, 'true');
check('every negative fails exactly one axis',
  ['digest-mismatch', 'past-expiry', 'wrong-subject', 'tampered-payload']
    .every(n => Object.entries(byName[n]).filter(([k, v]) => k !== 'rely' && v === false).length === 1), 'true');

console.log(failures ? `\n${failures} failure(s)` : '\nall checks passed');
process.exit(failures ? 1 : 0);
