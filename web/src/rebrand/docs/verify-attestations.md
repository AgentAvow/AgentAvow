# Verify an AgentAvow attestation

Every AgentAvow scan result ships with a **signed attestation** — a JWS (JSON Web Signature, EdDSA/Ed25519,
RFC 7515) over the verdict. Anyone can verify it **offline**, against our published keys, without trusting
our servers. That's the whole point: *not a score you take on faith — a signature you can check.*

> The signing keys and namespaces below live on `agentgraph.co` and are **permanent identifiers** — they do
> not move to agentavow.com at rebrand. Product URLs (the scan/badge endpoints) use agentavow.com.

## What you're verifying

The scan response includes a `jws` field: a compact JWS whose payload is the canonical verdict — a
`SecurityPostureAttestation` with `issuer`, `subject` (`id` such as `github:owner/repo`, `npm:name` or
`mcp:https://…`), `scannedAt`, `issuedAt`, `expiresAt`, and a `scan` block (`trustScore`, `trustTier`,
`findings`, `categoryScores`, `toolDigests`, `toolManifestDigest`, …). The payload bytes are the RFC 8785
(JCS) canonical form of that object, so a verifier can re-serialize and compare byte-for-byte. The header
carries a `kid` (key id, e.g. `agentgraph-security-v1`) identifying the signing key.

## The public keys (JWKS)

Fetch the JSON Web Key Set once and cache it:

```
GET https://agentgraph.co/.well-known/jwks.json
```

Resolve the `kid` from the JWS header to the matching key. Keys rotate; always match by `kid`. The set
currently publishes three keys: `agentgraph-security-v1` (Ed25519 — scan attestations and behavioral
observations), `trust-v2-2026` (Ed25519 — trust-score envelopes) and `catalog-es256-v1` (P-256/ES256 — the
signed [`/.well-known/ai-catalog.json`](https://agentavow.com/.well-known/ai-catalog.json)).

The issuer has two DID documents that resolve to the same keys: `did:web:agentgraph.co` (the identifier
inside every attestation) and `did:web:agentavow.com`. Each lists the other under `alsoKnownAs`, so a
verifier can start from either domain:

```
GET https://agentgraph.co/.well-known/did.json
GET https://agentavow.com/.well-known/did.json
```

Both documents carry the Ed25519 attestation key as `#agentgraph-security-v1` and the P-256 catalog key as
`#catalog-es256-v1` (under `assertionMethod` only), so `did:web:<either>#agentgraph-security-v1` resolves
to the key that signed a scan.

### The signed catalog

[`/.well-known/ai-catalog.json`](https://agentavow.com/.well-known/ai-catalog.json) lists the connector's
own tools and is signed under the `did:web` Publisher Profile, which mandates ES256, so it uses the P-256
key rather than the Ed25519 key that signs scans. Each entry's `trustManifest.signature` is a detached
compact JWS (RFC 7515 Appendix F, `header..signature`) with `alg` `ES256` and `kid`
`did:web:agentavow.com#catalog-es256-v1`; the payload is the RFC 8785 canonical form of the manifest with
`signature` removed. To check it offline, resolve the key from the DID document above (or from the JWKS by
`kid`), rebuild the payload, and verify the P-256 signature over `<header>.<payload>`. The repo ships the
check as a script: `python3 scripts/ai_catalog_wellknown.py verify --resolve` runs the profile's Level 3
checks (no `none` or key-carrying headers, `kid` under the publisher's DID, key found in the DID document
with no private material, signature verifies) and exits non-zero on any failure.

## Verify in Python

```python
import base64, json, httpx
from jwcrypto import jwk, jws

# 1. get the scan (which contains the signed attestation)
scan = httpx.get("https://agentavow.com/api/v1/public/scan/owner/repo").json()
token = scan["jws"]

# 2. resolve the signing key by kid from the published JWKS
header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
jwks = httpx.get("https://agentgraph.co/.well-known/jwks.json").json()
key = jwk.JWK(**next(k for k in jwks["keys"] if k["kid"] == header["kid"]))

# 3. verify the signature — raises on tamper
verifier = jws.JWS()
verifier.deserialize(token)
verifier.verify(key)               # EdDSA / Ed25519
verdict = json.loads(verifier.payload)
print("verified:", verdict["subject"]["id"], verdict["scan"]["trustScore"], verdict["scan"]["trustTier"])
```

## Verify in JavaScript

```js
import { jwtVerify, createRemoteJWKSet } from 'jose'

const JWKS = createRemoteJWKSet(new URL('https://agentgraph.co/.well-known/jwks.json'))
const scan = await (await fetch('https://agentavow.com/api/v1/public/scan/owner/repo')).json()
const { payload } = await jwtVerify(scan.jws, JWKS)   // throws if tampered
console.log('verified:', payload.subject.id, payload.scan.trustScore)
```

If verification throws, the attestation was tampered with or the key doesn't match — do not trust the result.

## Tool definitions: per-tool digests and drift

For an MCP server (and for skills and tool manifests), the signed `scan` block also pins **what the server
served**, so a gate can check that the tool it is about to call is the one that was graded:

- `scan.toolDigests` — one digest per served tool, keyed `tool:<name>`. Each is `sha256:` over the RFC 8785
  canonical bytes of `{"profile": "agentavow.mcp-tool-definition.v1", "tool": {…}}`, where the tool is the
  served definition restricted to `name`, `title`, `description`, `inputSchema`, `outputSchema` and
  `annotations` (missing or null fields omitted; `_meta` never hashed).
- `scan.toolManifestDigest` — a fold over the per-tool digests: the whole served tool set in one value.
- `toolDrift` (top-level, only when present) — the diff against our previous scan of the same server: which
  tools were added, removed or changed since the last grade.

A consumer holding the server's `tools/list` recomputes the digest of the tool it is authorizing, with no call
to us, and compares it with the signed one. A mismatch means the definition changed after the grade — the
per-tool rug-pull — even if a fresh scan of the code would still come back clean. `annotations` is inside the
digest on purpose: a flipped `readOnlyHint` or `destructiveHint` is the cheapest redefinition.

The exact derivation, the key-encoding rules for unusual tool names, a pinned real attestation with the
`tools/list` it was computed from, and six test cases (match, unknown tool, drift, wrong server, expiry,
tampered payload) are published as
[tool-manifest-digest-vectors-v1](https://github.com/AgentAvow/AgentAvow/tree/main/docs/standards/tool-manifest-digest-vectors-v1)
(`node verify.mjs`, zero dependencies, fetches nothing). Three implementations written without our code —
an APS-side consumer, Probity's signed-map reader and heldfast's profile — reproduce every digest and key
from the pinned bytes.

## Behavioral observations

A [sandbox run](./behavioral-sandbox.md) is also signed, with the **same key and JWKS** as the
score, but as a different document type: `BehavioralObservation` under
`https://schema.agentgraph.co/attestation/behavioral-observation/v1`. It is a dated witness
statement — "AgentAvow ran this package in gVisor on this date and observed these hosts, writes,
tool calls and findings" — not a recomputable score. You verify it the same way:

```python
scan = requests.get("https://agentavow.com/api/v1/public/scan/package/npm/left-pad").json()
obs = scan["behavioral"]["attestation"]          # None until the sandbox has run
jws = obs["jws"]                                 # header.payload.signature, kid in the header
# … resolve the key by kid from the JWKS exactly as above, verify, then decode the payload:
payload = json.loads(base64.urlsafe_b64decode(jws.split(".")[1] + "=="))
assert payload["type"] == "BehavioralObservation"
print(payload["observation"]["egressHosts"], payload["findings"])
```

Two things to keep straight: the observation's `subject.id` is `pkg:<surface>/<name>`, and its
`observedAt` is when the sandbox ran, which can be up to a day older than the score you fetched
it with. Re-run with `?behavioral=true` for a fresh, freshly signed observation.

## Freshness

Attestations are freshness-bounded (`expiresAt`, 24 hours after `issuedAt`). Re-fetch (or `?force=true`) for
a current signature; an expired attestation proves what was true at `scannedAt`, not now. `scannedAt` is when
the analysis ran and `issuedAt` when this signature was minted; a cached result can be re-signed, so diff the
two to judge evidence staleness.

## Why this matters

An opaque vendor score can't be checked — you either trust it or you don't. A signed, content-addressed
attestation can be **recomputed byte-for-byte** by anyone, which is why independent implementers can validate
our verdicts against their own verifiers and get the same result. The score is a product; the signature is
the proof under it.

## Standards

The attestation format is on the record as conformance work in `draft-etcheverry-action-ref` (IETF) and the
CTEF envelope. See the [standards docs](https://github.com/AgentAvow/AgentAvow/tree/main/docs/standards) for the canonical spec.

## Next

- [Reading your scan score](./check-guide.md)
- [Add a trust badge to your README](./trust-badges.md)
