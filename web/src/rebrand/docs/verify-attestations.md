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

Resolve the `kid` from the JWS header to the matching key. Always match by `kid`. The set
currently publishes three keys: `agentgraph-security-v1` (Ed25519 — scan attestations and behavioral
observations), `trust-v2-2026` (Ed25519 — trust-score envelopes) and `catalog-es256-v1` (P-256/ES256 — the
signed [`/.well-known/ai-catalog.json`](https://agentavow.com/.well-known/ai-catalog.json)). The scan key is also
published a second time under its RFC 7638 thumbprint as the `kid`, so the set lists four entries.

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

## Key changes and pinning

The keys are not rotated on a schedule. A key changes only when it is retired on purpose or compromised.

- **Planned change.** We announce it at least 30 days ahead on this page and in the repository, with the new
  key's RFC 7638 thumbprint. Each role (scan attestations, trust-score envelopes, the catalog) has one key at
  a time under a fixed `kid` (plus the scan key's thumbprint `kid`), so on the day of the change the new key replaces the old one under the same
  `kid`; tell them apart by thumbprint. The retired key's public JWK and thumbprint stay on this page and in
  the repository, so attestations it signed can still be checked.
- **Compromise.** We add the key to the revocation list below, with the time the revocation takes effect,
  remove it from the JWKS at once, and post a notice on this page and in the repository.

The JWKS and the DID documents are served from our own domains, so a verifier that trusts only them also
trusts whoever controls those domains. To check a key against a second source, compare its RFC 7638
thumbprint with the list below. This page is also kept in the
[public repository](https://github.com/AgentAvow/AgentAvow/blob/main/web/src/rebrand/docs/verify-attestations.md)
on GitHub, a separate origin, and any change to the list shows in its history.

| `kid` | Key | RFC 7638 thumbprint |
|---|---|---|
| `agentgraph-security-v1` | Ed25519, scan attestations and behavioral observations | `6U8Zqv4KpmzaI_MMt0-72wwKx7p72zvQdULYhS3uUWQ` |
| `trust-v2-2026` | Ed25519, trust-score envelopes | `xr4BogLMhNgo-RysVqQcjPCyfhXmtexql0Enihmi4e4` |
| `catalog-es256-v1` | P-256, signed AI catalog | `dzj8bdIChCQ-S1i7jI81Kcjh3p0kJuFII1tO3e9FrwA` |

### The revocation list

A verifier that pins a key never needs the JWKS again, so removing a key from the JWKS does not reach it.
The signed revocation list does:

```
GET https://agentavow.com/.well-known/key-revocations.json
```

It returns `jws`, a compact JWS (`EdDSA`) over the RFC 8785 bytes of the list, and `payload`, an unsigned
copy for reading. The list gives:

- `type` (`agentavow-key-revocations-v1`) and `issuer` (`did:web:agentgraph.co`).
- `keysCovered`: every key in the JWKS, and every key ever revoked, by `kid` and RFC 7638 thumbprint.
- `revocations`: each revoked key with its `kid`, `thumbprint`, `effectiveFrom`, `reason` and a link to the
  public `notice`.
- `issuedAt`, the time the list was served, and `nextUpdate`, one day later.

To check it:

1. Verify the JWS with a key you already trust, chosen by its RFC 7638 thumbprint, not by the header `kid`
   alone. The list is signed under the `kid` `agentgraph-security-v1`, and a replacement scan key would
   reuse that name with a different key.
2. Read the list decoded from the JWS, not the unsigned copy. Accept it only if `type` and `issuer` are the
   values above.
3. Reject a list whose `issuedAt` is earlier than the last one you accepted. Once `nextUpdate` has passed,
   treat the list you hold as stale and fetch it again before you rely on a pinned key.
4. Entries are only ever added. Once you have seen a validly signed revocation, keep it, even if a later
   list leaves it out.

A covered key with no entry in `revocations` was not revoked in the record that was live when the list was
served. A key missing from `keysCovered` is one the list says nothing about.

If the scan key itself is compromised, we publish its revocation while that key is still the one signing,
so lists carrying the revocation are signed by the key you pinned. We keep that list live for at least two
days, so a verifier that fetches once a day sees it, and post the notice on this page and in the repository
(`src/key_revocations.py`). Only then do we change the key. Attestations issued in those two days are still
signed by the revoked key, so they count as revoked too. Later lists are signed by the new key under the same
`kid`; its thumbprint is added to the table above and to the repository before the swap, so check the new
thumbprint against both before you accept it.

Limits. The list is signed with the scan key, so whoever stole that key could sign a list that leaves it out;
they would still have to serve it to you in place of ours, and a revocation you have already seen stays
revoked. The record behind the list is kept in the public repository (`src/key_revocations.py`), a second
origin with its own history. Our attestations carry their own `issued_at`, not a timestamp from an outside
authority, so `effectiveFrom` cannot show that a given signature was made before a compromise: treat every
signature under a revoked key as revoked.

### The signed catalog

[`/.well-known/ai-catalog.json`](https://agentavow.com/.well-known/ai-catalog.json) follows the AI Catalog
specification's independent Trust Manifests. It lists the connector itself, with AgentAvow's own manifest
(a publisher endorsement, since the signer matches the `urn:air:agentavow.com` identifier), and one
third-party MCP server, GitHub's, with an AgentAvow assessor manifest that points to the signed scan
verdict for the repository its server card names. That entry uses an AgentAvow identifier, not a
`urn:air` one, because AgentAvow is not its publisher. Each manifest carries a `signature` object
(`signer`, `profile` `did-web-v1`, `issuedAt`, `expiresAt`, `jws`); the catalog root carries one too.
The `jws` is a detached compact JWS (RFC 7515 Appendix F, `header..signature`) with `alg` `ES256`, `kid`
`did:web:agentavow.com#catalog-es256-v1`, and `typ` `ai-catalog-trust-manifest+jws` (or `ai-catalog+jws`
for the root). The payload is the RFC 8785 canonical form of the whole manifest (or catalog) with only
`signature.jws` removed, so the signer, profile and timestamps are signed too. The ES256 rule comes from the
`did:web` Signer Profile, which is why the catalog uses the P-256 key rather than the Ed25519 key that
signs scans. The repo ships the check as a script: `python3 scripts/ai_catalog_wellknown.py verify
--resolve` applies the profile (exact profile name, `kid` under the signer, key authorized by
`assertionMethod`, no key-carrying headers), checks that each subject matches its entry and that the
artifact bytes match `entry.digest`, verifies every signature, and exits non-zero on any failure.

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
served**, so a gate can check that the tool it is about to call is the one that was checked:

- `scan.toolDigests` — one digest per served tool, keyed `tool:<name>`. Each is `sha256:` over the RFC 8785
  canonical bytes of `{"profile": "agentavow.mcp-tool-definition.v1", "tool": {…}}`, where the tool is the
  served definition restricted to `name`, `title`, `description`, `inputSchema`, `outputSchema` and
  `annotations` (missing or null fields omitted; `_meta` never hashed).
- `scan.toolManifestDigest` — a fold over the per-tool digests: the whole served tool set in one value.
- `toolDrift` (top-level, only when present) — the diff against our previous scan of the same server: which
  tools were added, removed or changed since the last check.

A consumer holding the server's `tools/list` recomputes the digest of the tool it is authorizing, with no call
to us, and compares it with the signed one. A mismatch means the definition changed after the check — the
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

The attestation format is on the record as conformance work in `draft-etcheverry-action-ref` (an individual Internet-Draft) and the
CTEF envelope. See the [standards docs](https://github.com/AgentAvow/AgentAvow/tree/main/docs/standards) for the canonical spec.

## Next

- [Reading your scan score](./check-guide.md)
- [Add a trust badge to your README](./trust-badges.md)
