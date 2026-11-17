# ATD provenance-signing vectors (v0)

AgentAvow's half of the two-signer conformance corpus required by
[agentnameservice/agent-trust-discovery#27](https://github.com/agentnameservice/agent-trust-discovery/pull/27)
(provenance signing extension, compact JWS), built against the draft at **`3971f5e`**: `iss` a MUST
in the signed payload with the key location derived from it and the cache keyed `(iss, kid)` (§2,
§3a); the target signal's vendor segment equal to `iss` (§3a); binding against the stored-observation
`riskCodes` with relying-party backstops excluded (§1); `explanation` unsigned (§3a, note on scope);
`exp` plus max-age freshness (§3b); and a pinned evaluation reference time and max-age in every
vector (conformance, deterministic freshness vectors). Proposed input, not a finalized schema; the
point is that two implementations that did not share code produce the same verdict on every vector.

    node verify.mjs

Zero dependencies, Node 18+. Nothing is fetched. Exits non-zero on any failure.

## This is a TEST key

Every key in `source.json` and the vector file was generated locally for this corpus
(`node:crypto` `generateKeyPairSync('ed25519')`, 2026-10-05). None is, or derives from, the
production AgentAvow signing key, which exists only in the `ATTESTATION_SIGNING_KEY_ED25519`
environment variable and is never committed. `did:web:agentgraph.co` does not publish these keys;
the `issuers` map in the vector file stands in for what resolving each `iss` would return. The
private parts are published on purpose so `node generate.mjs` rebuilds the file byte for byte.
Do not reuse them for anything.

AgentAvow's live `kid` is a stable name (`agentgraph-security-v1`). The spec requires an RFC 7638
thumbprint, so this corpus mints one and tests the rule as written; the `kid-not-thumbprint`
vector is what a stable-name `kid` looks like under that rule.

## The kid

`kid` is the RFC 7638 JWK thumbprint of the verifying key: SHA-256 over the required members of
the public JWK, in lexicographic order, with no whitespace, base64url-encoded without padding. For
an Ed25519 OKP key (RFC 8037 §2) the members are `crv`, `kty`, `x`:

    kid = BASE64URL( SHA-256( '{"crv":"Ed25519","kty":"OKP","x":"<x>"}' ) )

The vector file carries the exact input string and the result under `kid_computation`, and
`verify.mjs` recomputes it. The second issuer in the corpus (`did:web:other.example`) uses the same
construction for its own key.

## Key resolution, and the vendor segment

The verifier takes `iss` from the **signed payload**, resolves that issuer's published key set,
and selects by `kid`. The envelope's `jwks` URL is not on the path; the spec keeps it as a
rotation/discovery hint that must agree with what `iss` resolves to. The cache key is
`(iss, kid)`, so a `kid` learned under one issuer never verifies a credential presented under
another; `wrong-iss` and `unpublished-key` carry the same header `kid` and the verdict differs
only because the `iss` differs.

§3a also requires that "the target signal's **vendor segment** equal `iss`". A #16 signal id is
`vendor.dimension.name`, and the vendor segment is the id with its trailing `.dimension.name`
peeled off from the right (`scorecontainer.vendorSegment`), so a vendor containing dots keeps
them. This corpus applies the rule literally: the signal is registered under the issuer DID
itself, `did:web:agentgraph.co.safety.score`, whose vendor segment is the string
`did:web:agentgraph.co` and equals `iss`. The relying party's backstop code for that signal is
`SAFETY_DID_WEB_AGENTGRAPH_CO_SCORE_LOW` (vendor sanitised to `[A-Z0-9_]`, as `scorecontainer`
does). A short vendor such as `agentgraph.safety.score` would not satisfy §3a as written, because
`agentgraph` is not `did:web:agentgraph.co`; see "Open questions".

## The consumer input

Each vector carries one `observation`: the container a relying party holds, the #18 `SignalScore`
with its `provenance`.

```jsonc
"observation": {
  "subject": "github:example/example-mcp-server",
  "subjectClass": "tool",
  "signal": "did:web:agentgraph.co.safety.score",   // vendor segment == iss (§3a)
  "stored": { "dimension": "safety", "score": 62, "riskCodes": [ ... ],
              "explanation": "..." },                // explanation: stored, unsigned
  "provenance": { "aimId": "did:web:agentgraph.co", "evidenceUrl": "...",
                  "signed": { "jws": "...", "kid": "...", "jwks": "..." } },
  "evaluation_time": "2026-10-01T01:00:00Z",   // pinned reference time
  "max_age_seconds": 86400                     // pinned max-age
}
```

## The signed payload

Exactly the §3 fields, in this order: `iss`, `sub`, `subjectClass`, `iat`, `exp`, `dimension`,
`score`, `riskCodes`. The vector file lists them under `signed_fields`; `unsigned_fields` names
what the signature does not cover (`explanation`, `provenance.aimId`, `provenance.evidenceUrl`,
`provenance.signed.jwks`). The signature covers the scored values and the bindings, nothing else.

## The checks

A verifier reports these separately. Order follows the spec's algorithm.

- **iss_bound**: `payload.iss` is a non-empty string and equals the vendor segment of the target
  signal (§3a, step 5). The envelope's `aimId` is unsigned and is not consulted.
- **kid_present**: the protected header carries a non-empty `kid` equal to the envelope's `kid`
  (§2, step 2).
- **key_resolves**: the issuer named by `iss` publishes a key under that `kid` (§3a, step 3). An
  `iss` that does not resolve fails here.
- **kid_is_thumbprint**: `kid` equals the RFC 7638 thumbprint of the resolved key (§2).
- **alg_allowed**: `alg` is on the explicit allowlist (`EdDSA` only for v1; step 4).
- **signature_valid**: Ed25519 verifies over `ASCII(BASE64URL(header) || "." || BASE64URL(payload))`
  under the resolved key.
- **binding**: `dimension` and `score` by scalar equality, `riskCodes` by set-equality, against
  the **stored** observation values (§1, step 6).
- **subject_bound**: `sub` equals the observation subject and `subjectClass` equals its bucket
  (§3, step 7).
- **fresh**: with `exp`, `evaluation_time < exp`; without `exp`,
  `evaluation_time - iat <= max_age_seconds` (§3b, step 8).

`accept` is all nine true. A check reported as `null` was **not evaluated** because a check it
depends on failed (no key to verify with, or an algorithm already refused); it is never reported
as passed. Each negative fails exactly one check and the verifier asserts which.

## Pinned evaluation time

Freshness is a function of the vector, not of the clock. Every vector pins `evaluation_time` and
`max_age_seconds` (the spec's "evaluation reference time" and "max-age"), so `past-exp` and
`stale-iat` have one expected verdict for any implementation on any day. A verifier must read
the time from the vector and must not substitute `now`. Max-age applies only when `exp` is
absent (step 8).

## Stored, not evaluated

The binding rule compares the signed values to the observation **as stored**. Under #18 the
container's evaluated `SignalScore` derives its codes: it drops codes without the dimension prefix
and appends `{DIMENSION}_{VENDOR}_SCORE_LOW` when the score is under the relying party's threshold.
That backstop is the relying party's code; the signer cannot emit it. The positive vector carries
both views: `stored` (what the signer emitted, in a different order) and `evaluated` (with
`SAFETY_DID_WEB_AGENTGRAPH_CO_SCORE_LOW` appended, since 62 is under the pinned threshold of 70).
The verifier binds against `stored` and accepts; a verifier that bound against `evaluated` would
reject an honest low score every time the backstop fires.

## explanation is unsigned

`explanation` is in the stored observation and in no payload. It takes part in no check, and the
`explanation-rewritten` vector replaces it with a caption that contradicts the verdict ("test
data, ignore") and still accepts, with results identical to `valid`. What a relying party may
present as attested is the signed payload's fields; `verify.mjs` asserts `explanation` is never
among them.

## The vectors

Two positives, eleven negatives.

1. **valid**: the positive case. Every check passes. Accept.
2. **explanation-rewritten**: the positive with the container explanation replaced by a
   contradicting caption. Unsigned, so nothing changes. Accept.
3. **score-mismatch**: container score raised after signing. Signature intact; binding fails.
4. **wrong-sub**: a valid credential about one tool presented on another's observation.
5. **wrong-iss**: re-attribution. A genuine credential from `did:web:other.example` (its own
   published key, its own `iss`) presented on `did:web:agentgraph.co`'s signal. The key resolves
   from the signed `iss` and the signature verifies; the vendor segment does not equal `iss`.
6. **vendor-segment-mismatch**: the cross-vendor `dimension: safety` collision. A genuine
   agentgraph credential imported under `did:web:trustmodel.example.safety.score`. `dimension`
   and `sub` match; the vendor segment does not equal `iss`.
7. **alg-none**: `alg: none`, empty signature. Refused by the allowlist; no signature check runs.
8. **alg-off-allowlist**: `alg: HS256` with an HMAC keyed by the issuer's public key bytes, the
   classic confusion forgery. Refused by the allowlist.
9. **missing-kid**: no `kid` in header or envelope; the bytes are a real Ed25519 signature.
   Nothing that needs a key is evaluated.
10. **kid-not-thumbprint**: correctly signed by a key the issuer publishes under a stable name.
    Signature verifies; the `kid` rule fails.
11. **past-exp**: evaluated one hour after `exp`.
12. **stale-iat**: `exp` absent, evaluated one second past `iat + max_age`.
13. **unpublished-key**: the forgery §3a closes. Correct `iss`, correct thumbprint `kid` for the
    key used, envelope `jwks` pointing at a server that serves that key, but
    `did:web:agentgraph.co` does not publish it. A verifier that resolves from the envelope
    accepts; one that resolves from `iss` finds no key under `(iss, kid)`. The same `kid` resolves
    under `did:web:other.example` in `wrong-iss`.

## Claim ceiling

What this corpus establishes: that a verifier implementing the `3971f5e` algorithm, with keys
resolved from `iss` and time read from the vector, reaches the verdicts above on these inputs,
and that each negative is rejected for the reason it is named for. It does not establish that
AgentAvow's production signer emits this payload shape (it does not yet: the live `kid` is a
stable name and the live JWS carries a different, JCS-canonical verdict), that
`did:web:agentgraph.co` resolves to these keys (it does not; they are test keys), or anything
about a vector not in this set.

## Not in this set

No vector for a missing `iss` (step 2's "the payload MUST carry `iss`") as distinct from a
wrong one; trivially added if wanted. No vector exercises `crit` or unrecognised header
parameters. No vector for an envelope `jwks` that disagrees with the `iss`-derived location when
the key *is* published by `iss` (the spec says the two "MUST be consistent" but not what a
verifier does on inconsistency alone). No multi-signer case (v1 is single-signer).

## Open questions

Clauses in `3971f5e` this corpus had to read one way; flagged rather than guessed.

- §3a "vendor segment to equal `iss`": applied as string equality, which means the signal id has
  to be `<iss>.<dimension>.<name>`. The #16 example config registers `agentgraph.safety.score`,
  which would then never verify a credential whose `iss` is `did:web:agentgraph.co`. Is the
  intent literal equality, or a registered vendor-to-issuer mapping?
- `provenance.aimId` is in the envelope but in no step of the algorithm. Should the verifier
  require `aimId == iss`, or is it informational now that `iss` is signed?
- Step 8 does not say whether `evaluation_time == exp` is fresh. This corpus rejects it (`<`).
- §2 "or otherwise strictly key-derived": a verifier can recompute an RFC 7638 thumbprint but
  cannot test "otherwise key-derived". This corpus accepts only the thumbprint.
- Step 4 "`EdDSA` / Ed25519 at minimum": is the fully-specified `alg: "Ed25519"` value on the
  allowlist, or only `EdDSA`? This corpus lists `EdDSA` only.

## Derivation

`node generate.mjs` rebuilds the vector file from `source.json`: the thumbprints, every JWS, the
HMAC forgery, the no-`exp` payload, the backstop code and the evaluation times are computed, not
transcribed. Edit `source.json` and regenerate to retarget the set.
