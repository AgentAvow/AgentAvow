// Zero-dependency verifier. Node 18+. Exits non-zero on any failure.
//   node verify.mjs [path-to-vectors.json]
//
// For each vector it recomputes the six axes a gate reports separately and checks
// them against the vector's expectation. It also recomputes every per-tool digest
// from the served tools/list carried in the file and checks it against the signed
// one, so the preimage is under test, not just the comparison. Nothing is fetched:
// the JWK is pinned in the file (kid-matched to the JWS header).
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const file = process.argv[2] ?? new URL('./tool-manifest-digest-v1-vectors.json', import.meta.url);
const set = JSON.parse(readFileSync(file, 'utf8'));

function jcs(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}
const PROFILE = 'agentavow.mcp-tool-definition.v1';
const FIELDS = ['name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations'];
function toolDigest(tool) {
  const body = {};
  for (const f of FIELDS) if (tool[f] !== undefined && tool[f] !== null) body[f] = tool[f];
  return 'sha256:' + createHash('sha256').update(jcs({ profile: PROFILE, tool: body })).digest('hex');
}
function toolKey(name) {
  // Every character outside 0x21-0x7E (so space, controls and all non-ASCII), plus
  // % and =, is percent-encoded as its UTF-8 bytes. If the encoded key body is longer
  // than 128 characters it is cut to its first 96 and suffixed with "~" and the first
  // 16 lowercase hex characters of sha256 over the raw UTF-8 name. The cut is a plain
  // character count and may land inside a %XX triplet.
  const enc = Array.from(name).map(ch =>
    (/[\x21-\x7e]/.test(ch) && ch !== '%' && ch !== '=') ? ch
      : Array.from(Buffer.from(ch, 'utf8')).map(b => '%' + b.toString(16).toUpperCase().padStart(2, '0')).join('')
  ).join('');
  const body = enc.length > 128
    ? enc.slice(0, 96) + '~' + createHash('sha256').update(Buffer.from(name, 'utf8')).digest('hex').slice(0, 16)
    : enc;
  return 'tool:' + body;
}
// RFC 3339 timestamp -> integer microseconds since the epoch (BigInt). Fractional digits
// beyond six are truncated; a missing fraction is zero. Throws on anything else.
function instantMicros(ts) {
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/.exec(ts);
  if (!m) throw new Error(`not an RFC 3339 timestamp: ${ts}`);
  const whole = Date.parse(m[1] + m[3]);
  if (Number.isNaN(whole)) throw new Error(`not an RFC 3339 timestamp: ${ts}`);
  const frac = BigInt(((m[2] ?? '') + '000000').slice(0, 6));
  return BigInt(whole) * 1000n + frac;
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
  const signed = payload.scan?.toolDigests?.[toolKey(vec.gate.tool_name)];
  const tool_binds = typeof signed === 'string';
  const tool_digest_binds = tool_binds ? signed === vec.gate.observed_tool_digest : 'not_evaluated';
  // Compare instants, not strings, and at the precision the timestamps carry: the signed
  // times have microseconds and an explicit offset, the gate times milliseconds and Z, and
  // Date.parse alone truncates to milliseconds.
  const t = instantMicros(vec.gate.evaluation_time);
  const fresh = t >= instantMicros(payload.issuedAt) && t < instantMicros(payload.expiresAt);
  const rely = signature_valid && canonical_bytes && subject_binds && tool_binds
    && tool_digest_binds === true && fresh;
  return { signature_valid, canonical_bytes, subject_binds, tool_binds, tool_digest_binds, fresh, rely };
}

let failures = 0;
const check = (label, got, want) => {
  if (String(got) === String(want)) { console.log(`  ok    ${label}`); return; }
  failures++;
  console.log(`  FAIL  ${label}\n        want ${want}\n        got  ${got}`);
};

console.log(`${set.suite}\n${set.author_set}\nsubject ${set.attestation.subject.id}\n`);

console.log('per-tool digests recompute from the served definitions');
for (const t of set.observed_tools)
  check(`${toolKey(t.name)}`, toolDigest(t), set.attestation.toolDigests[toolKey(t.name)]);
check('served tool count equals signed tool count',
  set.observed_tools.length, Object.keys(set.attestation.toolDigests).length);

// The unsigned convenience map in the file must be the signed one: a consumer that reads
// set.attestation.toolDigests instead of the JWS payload must not be checking a map that
// could have been edited together with observed_tools while the signature stayed valid.
{
  const [, p] = set.attestation.jws.split('.');
  const signedMap = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')).scan?.toolDigests ?? {};
  check('unsigned toolDigests map equals the signed scan.toolDigests',
    jcs(set.attestation.toolDigests), jcs(signedMap));
}

console.log('\nkey encoding');
// Thirteen pairs are part of the pinned set; a file with fewer is not this fixture.
check('key_encoding pair count', (set.key_encoding ?? []).length, 13);
for (const kv of set.key_encoding ?? []) check(`${JSON.stringify(kv.name)} -> ${kv.key}`, toolKey(kv.name), kv.key);

console.log('\nvectors');
const byName = {};
for (const v of set.vectors) {
  const got = axes(v);
  byName[v.name] = got;
  for (const a of Object.keys(got)) check(`${v.name}: ${a}`, got[a], v.expect[a]);
}

console.log('\nproperties under test');
check('positive case relies', byName['tool-match'].rely, 'true');
check('a tool the scan never saw does not bind, and its digest is not evaluated',
  !byName['unknown-tool'].tool_binds && byName['unknown-tool'].tool_digest_binds === 'not_evaluated', 'true');
check('a changed definition for a known tool does not bind',
  byName['tool-drift'].tool_binds && !byName['tool-drift'].tool_digest_binds, 'true');
check('a grade for one server cannot be re-attached to another', byName['wrong-subject'].subject_binds, 'false');
check('a signed verdict does not verify forever', byName['past-expiry'].fresh, 'false');
check('canonical form is not authenticity: tampered payload is canonical yet unsigned',
  byName['tampered-payload'].canonical_bytes && !byName['tampered-payload'].signature_valid, 'true');
check('a gate time inside the window by a sub-millisecond remainder is fresh and relies',
  byName['boundary-fresh'].fresh && byName['boundary-fresh'].rely, 'true');
check('every negative fails exactly one axis',
  ['unknown-tool', 'tool-drift', 'wrong-subject', 'past-expiry', 'tampered-payload']
    .every(n => Object.entries(byName[n]).filter(([k, v]) => k !== 'rely' && v === false).length === 1), 'true');

console.log(failures ? `\n${failures} failure(s)` : '\nall checks passed');
process.exit(failures ? 1 : 0);
