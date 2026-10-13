// Rebuilds tool-manifest-digest-v1-annotations-vectors.json from source.json. Node 18+, zero deps.
//   node generate.mjs
// Everything derived here is derived, not transcribed: per-tool digests are recomputed
// from the served tools/list and must equal the signed ones; the tampered JWS is
// re-encoded from the real payload; the drifted definition is the real one with
// annotations.readOnlyHint flipped from true to false and nothing else changed;
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

// ── the per-tool digest, as the issuer defines it (unchanged from v1) ────────
// preimage = JCS({ profile, tool }) where tool keeps only these fields of the served
// definition (a missing or null field is omitted); digest = "sha256:" + hex.
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

// Every served definition must recompute to the digest the issuer signed. If this
// fails, the fixture would be teaching a preimage the issuer does not use.
const recomputed = {};
for (const t of src.observed_tools) recomputed[toolKey(t.name)] = toolDigest(t);
for (const [k, d] of Object.entries(payload.scan.toolDigests))
  if (recomputed[k] !== d) throw new Error(`recomputed digest for ${k} does not match the signed one`);
if (Object.keys(recomputed).length !== Object.keys(payload.scan.toolDigests).length)
  throw new Error('served tool set and signed tool set differ');

const TOOL_NAME = 'search_cloudflare_documentation';
const subject = payload.subject.id;
const tool = src.observed_tools.find(t => t.name === TOOL_NAME);
if (!tool) throw new Error(`${TOOL_NAME} is not in the served tools/list`);
// The case is only meaningful if the signed baseline actually carries readOnlyHint: true.
if (tool.annotations?.readOnlyHint !== true)
  throw new Error(`${TOOL_NAME} does not carry annotations.readOnlyHint === true; refusing to build`);
const toolName = tool.name;
const toolDigestSigned = payload.scan.toolDigests[toolKey(toolName)];
const issuedAt = new Date(payload.issuedAt);
const expiresAt = new Date(payload.expiresAt);
const plusH = (d, hrs) => new Date(d.getTime() + hrs * 3600_000).toISOString();

// The annotation-only drift: the real served definition with readOnlyHint flipped to
// false. Name, title, description, inputSchema, outputSchema and every other annotation
// key are byte-identical.
const drifted = structuredClone(tool);
drifted.annotations.readOnlyHint = false;
const driftedDigest = toolDigest(drifted);
if (driftedDigest === toolDigestSigned) throw new Error('annotation flip did not change the digest');

// A tampered copy: score raised, payload re-canonicalized, original signature kept.
const tampered = structuredClone(payload);
tampered.scan.trustScore = 99;
tampered.scan.trustTier = 'verified';
const tamperedJws = [h, b64u(jcs(tampered)), s].join('.');

const expectAll = (o) => ({ signature_valid: true, canonical_bytes: true, subject_binds: true,
  tool_binds: true, tool_digest_binds: true, fresh: true, rely: true, ...o });
const gate = (o) => ({ subject_id: subject, tool_name: toolName, observed_tool_digest: toolDigestSigned,
  evaluation_time: plusH(issuedAt, 1), ...o });

const vectors = [
  { name: 'annotation-match', note: 'The positive case. The gate authorizes the named tool, whose served definition carries annotations.readOnlyHint: true, computes the digest of the definition it was served, and that digest equals the one the scan signed for that tool, inside the validity window. Every axis passes.',
    gate: gate({}), jws: 'reference', expect: expectAll({}) },
  { name: 'annotation-drift', note: 'The named tool exists, but the definition the gate was served differs from the one the scan graded in one annotation only: readOnlyHint is false instead of true. Name, title, description, inputSchema, outputSchema and the other annotation keys are byte-identical (drift_definition carries the full definition). The annotation is part of the hashed preimage, so the per-tool binding breaks. Do not rely. This says nothing about what the tool does: readOnlyHint is a declaration, not a measurement.',
    gate: gate({ observed_tool_digest: driftedDigest }),
    jws: 'reference', expect: expectAll({ tool_digest_binds: false, rely: false }) },
  { name: 'unknown-tool', note: 'The gate authorizes a tool name the scan never observed. The server, signature and freshness all check; the attestation says nothing about this tool. tool_digest_binds is not evaluated because there is no signed digest to compare. Do not rely.',
    gate: gate({ tool_name: 'purge_cloudflare_cache', observed_tool_digest: toolDigestSigned }),
    jws: 'reference', expect: expectAll({ tool_binds: false, tool_digest_binds: 'not_evaluated', rely: false }) },
  { name: 'wrong-subject', note: 'A valid grade for one server presented for another. Same tool name, same digest, wrong subject. Do not rely.',
    gate: gate({ subject_id: 'mcp:https://mcp.example.com/mcp' }),
    jws: 'reference', expect: expectAll({ subject_binds: false, rely: false }) },
  { name: 'past-expiry', note: 'Same attestation, evaluated after expiresAt. A signed verdict does not verify forever. Treated as unsigned.',
    gate: gate({ evaluation_time: plusH(expiresAt, 1) }),
    jws: 'reference', expect: expectAll({ fresh: false, rely: false }) },
  { name: 'tampered-payload', note: 'Payload edited after signing (trustScore raised to 99), re-canonicalized, original signature kept. Canonical bytes still check; the signature does not. Canonical form is not authenticity. Do not rely.',
    gate: gate({}), jws: tamperedJws, expect: expectAll({ signature_valid: false, rely: false }) },
];

const out = {
  suite: 'tool-manifest-digest-v1-annotations',
  spec: 'Agent-Authority-Conformance/aps-conformance-suite#155 — an annotation-only drift case for the tool-manifest-digest-v1 per-tool binding, in its own pinned packet so the v1 packet and its run records are unchanged',
  status: 'proposed — same derivation, axes and gate shape as tool-manifest-digest-v1; adds a baseline whose served definition carries annotations and a drift case that changes one annotation only',
  claim_ceiling: 'rely=true establishes exactly this: at evaluation_time, the named issuer had signed a static-analysis grade for this server, the grade covered a tool of this name, the definition the gate was served for that tool is the one the scan graded, and the signature, subject and validity window all check. It establishes nothing about runtime behavior, nothing about what the tool does when invoked, nothing about other tools on the server, and nothing about definitions the scan did not observe. Whether a gate proceeds on rely=true is a separately versioned admission policy.',
  establishes: 'An annotation change alone, with every other hashed field byte-identical, breaks the per-tool binding: annotations are part of the preimage. It does not establish anything about what readOnlyHint means for the tool: the hint is a declaration by the server, not a property the scan measured, and nothing here concerns runtime.',
  derivation: {
    attestation: 'compact JWS (RFC 7515), alg EdDSA (Ed25519), payload = RFC 8785 JCS canonical bytes of the verdict; signature over ASCII(BASE64URL(header) || "." || BASE64URL(payload)).',
    subject: 'subject.id = "mcp:" + the endpoint URL that was scanned. The subject is the server, not a tool.',
    tool_digest: `scan.toolDigests["tool:<name>"] = "sha256:" + hex(sha256(JCS({ profile: "${PROFILE}", tool }))) where tool is the served definition restricted to ${FIELDS.join(', ')} (a missing or null field is omitted; _meta and unknown fields are never hashed). A gate can compute observed_tool_digest from the tools/list it is served, with no call to the issuer.`,
    tool_key: 'as in tool-manifest-digest-v1: "tool:" + the name, percent-encoded and length-cut by the v1 rules. The tool names here are plain ASCII; the v1 packet carries the key_encoding pairs.',
    manifest_digest: 'scan.toolManifestDigest = sha-256 folded over the per-tool digests (the v0 whole-server binding; not used by the gate).',
    drift_definition: 'the served definition of the named tool with annotations.readOnlyHint set from true to false; every other field and annotation key unchanged. Its digest is the annotation-drift gate\'s observed_tool_digest.',
  },
  author_set: 'agentgraph (AgentAvow attestation layer, did:web:agentgraph.co).',
  axes: {
    signature_valid: 'Ed25519 verifies under the pinned JWK whose kid matches the JWS header. Binds the signer to what it signed, and no further.',
    canonical_bytes: 'jcs(JSON.parse(payload)) equals the payload bytes. Recomputability check; independent of the signature.',
    subject_binds: 'payload.subject.id equals gate.subject_id.',
    tool_binds: 'payload.scan.toolDigests has the key "tool:<gate.tool_name>" (encoded as above): the scan observed a tool of that name.',
    tool_digest_binds: 'that entry equals gate.observed_tool_digest. "not_evaluated" when tool_binds is false: there is no signed digest to compare.',
    fresh: 'gate.evaluation_time is within [issuedAt, expiresAt), compared as exact instants.',
    rely: 'all six axes true. None of the six is derived from another.',
  },
  issuer: { id: payload.issuer.id, jwks_url: src.jwks_url, jwk: src.jwk },
  attestation: {
    source_url: src.attestation_url,
    subject: payload.subject, issuedAt: payload.issuedAt, expiresAt: payload.expiresAt,
    trustScore: payload.scan.trustScore, toolManifestDigest: payload.scan.toolManifestDigest,
    toolDigests: payload.scan.toolDigests,
    payload_sha256: createHash('sha256').update(Buffer.from(p, 'base64url')).digest('hex'),
    jws: src.jws,
  },
  observed_tools: src.observed_tools,
  drift_definition: drifted,
  vectors,
};
writeFileSync(new URL('./tool-manifest-digest-v1-annotations-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${vectors.length} vectors for ${subject}, tool ${toolName} @ ${toolDigestSigned}; drift @ ${driftedDigest}`);
