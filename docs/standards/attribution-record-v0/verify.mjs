// Zero-dependency verifier. Node 18+. Exits non-zero on any failure.
//   node verify.mjs [path-to-vectors.json]
//
// For each vector it recomputes every check a verifier of a consumed-artifact record
// reports separately, from the bytes retained under pins/ and the attester keys pinned
// in the file, and compares them with the vector's expectation. Before the vectors it
// checks that the retained bytes are the ones the thread pinned (APS manifest, PriorSeal
// report). Nothing is fetched. No status label in the file is trusted: "holds" is
// computed here and only here.
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const file = process.argv[2] ?? new URL('./consumed-artifact-record-v0-vectors.json', import.meta.url);
const set = JSON.parse(readFileSync(file, 'utf8'));
const pinsBase = new URL('./', import.meta.url);
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function jcs(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}
// RFC 6901 JSON pointer. "" is the whole document; "~1" is "/", "~0" is "~".
function pointer(doc, ptr) {
  if (ptr === '') return doc;
  if (typeof ptr !== 'string' || ptr[0] !== '/') return undefined;
  let cur = doc;
  for (const raw of ptr.split('/').slice(1)) {
    const key = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = Array.isArray(cur) ? cur[Number(key)] : cur[key];
  }
  return cur;
}
const normHex = (v) => typeof v === 'string' ? v.toLowerCase().replace(/^(0x|sha256:)/, '') : undefined;

// ── the byte store: ref -> bytes retained under pins/ ─────────────────────────
const store = {};
for (const e of set.byte_store) {
  try { store[e.ref] = readFileSync(new URL(e.path, pinsBase)); } catch { /* reported below */ }
}
const attesterKey = {};
for (const a of set.attesters) attesterKey[`${a.id} ${a.kid}`] = a;

// A binding is measured against the bytes, never against what the record says about
// them: digest_cited compares the evidence's citation with sha256 over the artifact
// bytes, so a wrong stated digest fails artifact_digest and nothing else.
function bindingHolds(b, artifact, evidence, bytesDigestHex) {
  if (b.kind === 'value_equals') {
    const a = pointer(artifact, b.artifact_pointer), e = pointer(evidence, b.evidence_pointer);
    const [na, ne] = b.normalize === 'hex' ? [normHex(a), normHex(e)] : [a, e];
    return na !== undefined && typeof na === 'string' && na === ne;
  }
  if (b.kind === 'digest_cited') return normHex(pointer(evidence, b.evidence_pointer)) === bytesDigestHex;
  return false;
}
function parseJson(bytes) { try { return JSON.parse(bytes.toString('utf8')); } catch { return undefined; } }

function evaluate(vec) {
  const [h, p, s] = vec.jws.split('.');
  const header = parseJson(Buffer.from(h, 'base64url')) ?? {};
  const payloadBytes = Buffer.from(p, 'base64url');
  const record = parseJson(payloadBytes);
  if (record === undefined) throw new Error(`${vec.name}: payload is not JSON`);

  const canonical_bytes = jcs(record) === payloadBytes.toString('utf8');

  const pin = attesterKey[`${record.attester?.id} ${record.attester?.kid}`];
  const t = Date.parse(record.attested_at);
  const inWindow = pin && t >= Date.parse(pin.valid_from) && (pin.valid_until === null || t < Date.parse(pin.valid_until));
  let attester_signed = false;
  if (pin && inWindow && header.alg === 'EdDSA' && header.kid === record.attester.kid) {
    const pub = createPublicKey({ key: pin.jwk, format: 'jwk' });
    attester_signed = edVerify(null, Buffer.from(`${h}.${p}`, 'ascii'), pub, Buffer.from(s, 'base64url'));
  }

  const claims = (record.consumed ?? []).map(c => {
    const artBytes = store[c.artifact?.ref];
    const artifact_digest = artBytes !== undefined && 'sha256:' + sha256(artBytes) === c.artifact.digest;
    const evidence = c.evidence ?? [];
    const evidence_resolves = evidence.length > 0 && evidence.every(e => store[e.ref] !== undefined);
    const evidence_digest = evidence_resolves
      ? evidence.every(e => 'sha256:' + sha256(store[e.ref]) === e.digest) : 'not_evaluated';
    let evidence_binds = 'not_evaluated';
    if (evidence_resolves && artBytes !== undefined) {
      const art = parseJson(artBytes);
      evidence_binds = art !== undefined && evidence.every(e => {
        const ev = parseJson(store[e.ref]);
        return ev !== undefined && bindingHolds(e.binding ?? {}, art, ev, sha256(artBytes));
      });
    }
    return { artifact_digest, evidence_resolves, evidence_digest, evidence_binds };
  });
  const holds = canonical_bytes && attester_signed && claims.length > 0
    && claims.every(c => Object.values(c).every(v => v === true));
  return { canonical_bytes, attester_signed, claims, holds, record };
}

let failures = 0;
const check = (label, got, want) => {
  if (String(got) === String(want)) { console.log(`  ok    ${label}`); return; }
  failures++;
  console.log(`  FAIL  ${label}\n        want ${want}\n        got  ${got}`);
};

console.log(`${set.suite}\naction ${set.action.ref}\n`);

console.log('pinned bytes are the ones the thread agreed on');
const refFor = (suffix) => set.byte_store.find(e => e.ref.endsWith(suffix))?.ref;
const manifestRef = refFor('/MANIFEST.sha256');
check('APS MANIFEST.sha256 hashes to the pinned manifest digest',
  store[manifestRef] ? sha256(store[manifestRef]) : 'missing', set.pins.aps.manifest_sha256);
if (store[manifestRef]) {
  const lines = store[manifestRef].toString('utf8').trim().split('\n').map(l => l.trim().split(/\s+/));
  for (const [hex, path] of lines) {
    const ref = refFor('/' + set.pins.aps.dir + '/' + path);
    if (ref) check(`${path} matches its manifest line`, store[ref] ? sha256(store[ref]) : 'missing', hex);
  }
}
check('PriorSeal PAYMENT-LIMIT-REPORT.json hashes to the pinned report digest',
  store[refFor('/PAYMENT-LIMIT-REPORT.json')] ? sha256(store[refFor('/PAYMENT-LIMIT-REPORT.json')]) : 'missing',
  set.pins.priorseal.report_sha256);
for (const e of set.byte_store) check(`byte store: ${e.path}`, store[e.ref] ? sha256(store[e.ref]) : 'missing', e.sha256);

console.log('\nvectors');
const byName = {};
for (const v of set.vectors) {
  const got = evaluate(v);
  byName[v.name] = got;
  check(`${v.name}: decoded record in the file equals the signed payload`, jcs(got.record), jcs(v.record));
  check(`${v.name}: attested_at is not after the pinned evaluation_time`,
    Date.parse(got.record.attested_at) <= Date.parse(v.evaluation_time), 'true');
  check(`${v.name}: canonical_bytes`, got.canonical_bytes, v.expect.canonical_bytes);
  check(`${v.name}: attester_signed`, got.attester_signed, v.expect.attester_signed);
  check(`${v.name}: claim count`, got.claims.length, v.expect.claims.length);
  got.claims.forEach((c, i) => {
    for (const k of Object.keys(c)) check(`${v.name}: claims[${i}].${k}`, c[k], v.expect.claims[i]?.[k]);
  });
  check(`${v.name}: holds`, got.holds, v.expect.holds);
}

console.log('\nproperties under test');
const falses = (r) => [r.canonical_bytes, r.attester_signed, ...r.claims.flatMap(c => Object.values(c))]
  .filter(v => v === false).length;
check('positive record holds', byName['consumed-and-attested'].holds, 'true');
check('a digest the bytes do not hash to fails on that claim only',
  !byName['wrong-digest'].claims[0].artifact_digest && byName['wrong-digest'].claims[0].evidence_binds === true, 'true');
check('evidence that resolves nowhere is reported as unresolved, not as a failed digest or binding',
  !byName['missing-evidence'].claims[1].evidence_resolves
    && byName['missing-evidence'].claims[1].evidence_digest === 'not_evaluated'
    && byName['missing-evidence'].claims[1].evidence_binds === 'not_evaluated', 'true');
check('canonical form is not attestation: a record the named attester did not sign is canonical yet unsigned',
  byName['attester-not-signer'].canonical_bytes && !byName['attester-not-signer'].attester_signed, 'true');
check('no vector holds unless every check is true',
  Object.values(byName).every(r => r.holds === (falses(r) === 0
    && r.claims.every(c => Object.values(c).every(v => v === true)))), 'true');
check('every negative fails exactly one check',
  ['wrong-digest', 'missing-evidence', 'attester-not-signer'].every(n => falses(byName[n]) === 1), 'true');

console.log(failures ? `\n${failures} failure(s)` : '\nall checks passed');
process.exit(failures ? 1 : 0);
