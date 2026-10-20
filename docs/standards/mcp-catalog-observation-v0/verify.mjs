// Zero-dependency verifier for mcp-catalog-observation-v0. Node 18+. Exits non-zero
// on any failure.
//   node verify.mjs [path-to-packet.json]
//
// For each case it evaluates seven axes a gate reports separately, then `rely` (all
// seven true). Nothing is fetched: observer keys, the consumer's policy, the retained
// tools/list response bytes and the catalog the consumer holds are all in the file.
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const file = process.argv[2] ?? new URL('./mcp-catalog-observation-v0-packet.json', import.meta.url);
const set = JSON.parse(readFileSync(file, 'utf8'));
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

// The tool-definition digest and key, exactly as tool-manifest-digest-vectors-v1.
function jcs(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}
const FIELDS = ['name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations'];
function toolDigest(tool) {
  const body = {};
  for (const f of FIELDS) if (tool[f] !== undefined && tool[f] !== null) body[f] = tool[f];
  return 'sha256:' + sha256(jcs({ profile: 'agentavow.mcp-tool-definition.v1', tool: body }));
}
function toolKey(name) {
  const enc = Array.from(name).map(ch =>
    (/[\x21-\x7e]/.test(ch) && ch !== '%' && ch !== '=') ? ch
      : Array.from(Buffer.from(ch, 'utf8')).map(b => '%' + b.toString(16).toUpperCase().padStart(2, '0')).join('')
  ).join('');
  const body = enc.length > 128
    ? enc.slice(0, 96) + '~' + sha256(Buffer.from(name, 'utf8')).slice(0, 16)
    : enc;
  return 'tool:' + body;
}
const digestMap = (tools) => Object.fromEntries(tools.map(t => [toolKey(t.name), toolDigest(t)]));
const sameMap = (a, b) => jcs(a) === jcs(b);

// A tools/list response body: JSON, or Streamable-HTTP SSE whose data lines hold it.
function parseBody(bytes) {
  const text = bytes.toString('utf8');
  const t = text.trimStart();
  const json = t.startsWith('{') ? t
    : text.split(/\r?\n/).filter(l => l.startsWith('data:')).map(l => l.slice(5).trimStart()).join('\n');
  return JSON.parse(json);
}
const b64u = (s) => Buffer.from(s, 'base64url');
// RFC 3339 UTC instants, compared as numbers (milliseconds suffice: the producer
// writes milliseconds; a finer fraction would be truncated here, so reject one).
function instant(s) {
  const m = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,3}))?(?:Z|\+00:00)$/.exec(s ?? '');
  if (!m) throw new Error(`unsupported timestamp ${s}`);
  return Date.parse(m[1] + 'Z') + Number((m[2] ?? '0').padEnd(3, '0'));
}

const keys = Object.fromEntries(set.observers.map(j => [j.kid, createPublicKey({ key: j, format: 'jwk' })]));

function axes(c) {
  const jws = c.jws === 'reference' ? set.reference.jws : c.jws;
  const policy = c.policy ?? set.policy;
  const rawPages = (c.rawPages ?? set.reference.rawPages).map(b64u);
  const catalog = c.consumerCatalog ?? set.reference.consumerCatalog;
  const [h, p, s] = jws.split('.');
  const header = JSON.parse(b64u(h).toString('utf8'));
  const payload = JSON.parse(b64u(p).toString('utf8'));
  const scan = payload.scan ?? {};
  const obs = scan.observation;

  const key = keys[header.kid];
  const signature_valid = header.alg === 'EdDSA' && !!key
    && edVerify(null, Buffer.from(`${h}.${p}`, 'ascii'), key, b64u(s));
  const observer_enrolled = policy.enrolledObservers.includes(header.kid);

  // The catalog the consumer holds is the one the signed digests describe, and the
  // observation binds to the same manifest digest.
  const catalog_binds = sameMap(digestMap(catalog), scan.toolDigests ?? {})
    && (!obs || obs.toolManifestDigest === scan.toolManifestDigest);

  let exchange_binds = 'not_evaluated', endpoint_binds = 'not_evaluated', key_trusted = 'not_evaluated';
  if (obs) {
    // Every retained page is the response the observation recorded, in order, and
    // together they are the signed catalog.
    const pages = obs.toolsList?.pages ?? [];
    exchange_binds = obs.toolsList?.complete === true && pages.length === rawPages.length
      && pages.every((pg, i) => sha256(rawPages[i]) === pg.responseSha256)
      && sameMap(digestMap(rawPages.flatMap(b => parseBody(b).result?.tools ?? [])), scan.toolDigests ?? {});
    const t = obs.transport;
    if (!t) {
      endpoint_binds = key_trusted = 'unavailable';
    } else {
      // The endpoint the consumer configured, reached with no redirect, on a connection
      // whose certificate validated and matched that host, the same on every page.
      const e = policy.expectedEndpoint;
      endpoint_binds = obs.request.scheme === e.scheme && obs.request.host === e.host
        && obs.request.port === e.port && obs.request.path === e.path
        && obs.redirectsFollowed === false && obs.sameConnectionFacts === true
        && t.referenceIdentity === e.host && t.certificatePathValidated === true
        && t.identityMatched === true;
      // The key is one the consumer trusts, or reached by a rotation its policy allows.
      key_trusted = policy.trustedSpki.includes(t.spkiSha256)
        || (policy.rotations ?? []).some(r => policy.trustedSpki.includes(r.from) && r.to === t.spkiSha256);
    }
  }
  const at = instant(policy.evaluationTime);
  const fresh = at >= instant(payload.issuedAt) && at < instant(payload.expiresAt);
  const all = { signature_valid, observer_enrolled, catalog_binds, exchange_binds, endpoint_binds, key_trusted, fresh };
  return { ...all, rely: Object.values(all).every(v => v === true) };
}

let failures = 0;
const check = (label, got, want) => {
  if (String(got) === String(want)) { console.log(`  ok    ${label}`); return; }
  failures++;
  console.log(`  FAIL  ${label}\n        want ${want}\n        got  ${got}`);
};

console.log(`${set.suite}\n${set.status}\n`);
const byName = {};
for (const c of set.cases) {
  const got = axes(c);
  byName[c.name] = got;
  for (const a of Object.keys(c.expect)) check(`${c.name}: ${a}`, got[a], c.expect[a]);
}

console.log('\nproperties under test');
check('the valid control relies', byName['endpoint-expected'].rely, 'true');
check('an authorized rotation relies where the same key without it does not',
  byName['key-rotation-authorized'].rely && !byName['key-unexpected'].rely, 'true');
const ONE_AXIS = ['endpoint-other-name', 'key-unexpected', 'exchange-copied', 'catalog-altered',
  'observer-unenrolled', 'past-expiry', 'tampered-payload'];
check('every negative fails exactly one axis',
  ONE_AXIS.every(n => Object.entries(byName[n]).filter(([k, v]) => k !== 'rely' && v === false).length === 1), 'true');
check('missing transport facts read unavailable, never false',
  byName['transport-unavailable'].endpoint_binds === 'unavailable'
    && byName['transport-unavailable'].key_trusted === 'unavailable', 'true');

console.log(failures ? `\n${failures} failure(s)` : '\nall checks passed');
process.exit(failures ? 1 : 0);
