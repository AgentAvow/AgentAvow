// Zero-dependency verifier. Node 18+. Exits non-zero on any failure.
//   node verify.mjs [path-to-vectors.json]
//
// For each case: JSON.parse the served definition text, recompute the
// agentavow.mcp-tool-definition.v1 preimage and digest with the derivation in
// tool-manifest-digest-vectors-v1/verify.mjs (jcs and toolDigest, copied unchanged),
// and check both against the values the issuer produced. Then check the cases listed
// in same_digest share one digest. Nothing is fetched.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const file = process.argv[2] ?? new URL('./tool-manifest-digest-v1-numbers-vectors.json', import.meta.url);
const set = JSON.parse(readFileSync(file, 'utf8'));

function jcs(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}
const PROFILE = 'agentavow.mcp-tool-definition.v1';
const FIELDS = ['name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations'];
function toolPreimage(tool) {
  const body = {};
  for (const f of FIELDS) if (tool[f] !== undefined && tool[f] !== null) body[f] = tool[f];
  return jcs({ profile: PROFILE, tool: body });
}
const sha256 = s => 'sha256:' + createHash('sha256').update(s).digest('hex');

let failures = 0;
const check = (ok, label) => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}`);
  if (!ok) failures++;
};

check(set.profile === PROFILE, `profile is ${PROFILE}`);
const byName = {};
for (const c of set.cases) {
  const pre = toolPreimage(JSON.parse(c.definition_json));
  const digest = sha256(pre);
  byName[c.name] = digest;
  check(pre === c.preimage, `${c.name}: preimage`);
  check(digest === c.digest, `${c.name}: digest ${c.digest.slice(0, 19)}…`);
}
for (const group of set.same_digest) {
  check(new Set(group.map(n => byName[n])).size === 1, `same digest: ${group.join(' = ')}`);
}
console.log(failures ? `${failures} failure(s)` : `all ${set.cases.length} cases ok`);
process.exit(failures ? 1 : 0);
