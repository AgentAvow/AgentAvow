# Verify an AgentAvow attestation

Every AgentAvow scan result ships with a **signed attestation** — a JWS (JSON Web Signature, EdDSA/Ed25519,
RFC 7515) over the verdict. Anyone can verify it **offline**, against our published keys, without trusting
our servers. That's the whole point: *not a score you take on faith — a signature you can check.*

> The signing keys and namespaces below live on `agentgraph.co` and are **permanent identifiers** — they do
> not move to agentavow.com at rebrand. Product URLs (the scan/badge endpoints) use agentavow.com.

## What you're verifying

The scan response includes a `jws` field: a compact JWS whose payload is the canonical verdict (repo, score,
tier, findings summary, `issued_at`, `expires_at`). The header carries a `kid` (key id, e.g.
`agentgraph-security-v1`) identifying the signing key.

## The public keys (JWKS)

Fetch the JSON Web Key Set once and cache it:

```
GET https://agentgraph.co/.well-known/jwks.json
```

Resolve the `kid` from the JWS header to the matching key. Keys rotate; always match by `kid`.

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
print("verified:", verdict["repo"], verdict["trust_score"], verdict["trust_tier"])
```

## Verify in JavaScript

```js
import { jwtVerify, createRemoteJWKSet } from 'jose'

const JWKS = createRemoteJWKSet(new URL('https://agentgraph.co/.well-known/jwks.json'))
const scan = await (await fetch('https://agentavow.com/api/v1/public/scan/owner/repo')).json()
const { payload } = await jwtVerify(scan.jws, JWKS)   // throws if tampered
console.log('verified:', payload.repo, payload.trust_score)
```

If verification throws, the attestation was tampered with or the key doesn't match — do not trust the result.

## Freshness

Attestations are freshness-bounded (`expires_at`). Re-fetch (or `?force=true`) for a current signature; an
expired attestation proves what was true at `issued_at`, not now.

## Why this matters

An opaque vendor score can't be checked — you either trust it or you don't. A signed, content-addressed
attestation can be **recomputed byte-for-byte** by anyone, which is why independent implementers can validate
our verdicts against their own verifiers and get the same result. The score is a product; the signature is
the proof under it.

## Standards

The attestation format is on the record as conformance work in `draft-etcheverry-action-ref` (IETF) and the
CTEF envelope. See the [standards docs](https://github.com/AgentAvow/AgentAvow/tree/main/docs/standards) for the canonical spec.

## Next

- [Reading your scan grade](./check-guide.md)
- [Add a trust badge to your README](./trust-badges.md)
