# Trust Score Envelope v2.0 — Specification

**Status:** v2.0 draft, P1 of aggregator rebalance (`docs/internal/trust-score-v2-design.md`)
**Owner:** AgentGraph (kenneives)
**Schema:** [`trust-score-envelope-v2.0.json`](trust-score-envelope-v2.0.json)
**Composes with:** CTEF v0.3.2 (attestation layer) + ERC-8004 (on-chain identity + reputation) + AgentGraph scan corpus + Dominion Observatory `verascore-evidence-schema-v0.1`

---

## §1 — Purpose

The Trust Score Envelope v2.0 is AgentGraph's published, signed, content-addressed aggregate of every substrate-emitter trust signal we know about a subject. It is the visible output of the AgentGraph aggregator.

The envelope makes three guarantees a consumer can independently verify:

1. **Provenance.** Every input contribution names its source DID and content hash. A consumer can re-fetch and re-verify any contribution without trusting AgentGraph.
2. **Methodology transparency.** The per-contribution weighting is exposed — no black-box trust score. A consumer disputing the score knows exactly which input to challenge.
3. **Tamper evidence.** The envelope is JCS-canonical + Ed25519-signed under AgentGraph's published JWKS. The signature covers the envelope minus the proof block itself (depth-first proof-stripping per CTEF v0.3.2 normative addition).

Same substrate discipline as CTEF: byte-for-byte reproducibility across the 5 reference JCS implementations is the conformance bar.

---

## §2 — Canonical preimage

The signed preimage is the SHA-256 of the JCS-canonical (per [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) serialization of the envelope **with the `proof` block removed**.

```
preimage_bytes = JCS(envelope_object - "proof")
preimage_hash  = lowercase_hex(SHA-256(preimage_bytes))
```

Verifiers reconstruct by removing the `proof` block, canonicalizing the remainder, hashing, and checking against the detached payload in `proof.jws`.

JCS rules (unchanged from CTEF v0.3.2):
- Keys in lexicographic order at every nesting level
- No whitespace, no BOM, UTF-8
- Numbers in canonical form (JCS rules)
- No additional fields (`additionalProperties: false` at envelope level)

---

## §3 — Envelope shape (overview)

See [the JSON schema](trust-score-envelope-v2.0.json) for the normative shape. Key sections:

```jsonc
{
  "subject_did":         "<DID of subject this score is about>",
  "subject_kind":        "agent" | "human" | "service",

  "trust_score":         0.74,
  "score_version":       "v2.0",
  "computed_at":         "2026-06-12T14:32:01.000Z",
  "freshness_ttl_seconds": 3600,

  "contributions": [
    { ...per-input breakdown (§3.1)... }
  ],

  "shape_version":       "trust-score-envelope-v2.0",
  "canonicalization":    "jcs-rfc8785-v1",
  "hash_algo":           "sha256",

  "issuer":              "did:web:agentgraph.co",
  "issued_at":           "2026-06-12T14:32:01.000Z",
  "proof": {
    "type":               "Ed25519Signature2020",
    "verificationMethod": "did:web:agentgraph.co#trust-v2-2026",
    "jws":                "<compact JWS>"
  }
}
```

### §3.1 — Contribution shape

Every contribution names:

- `source` — one of `ctef_attestation`, `erc8004_reputation`, `scan_corpus`, `third_party_observer`, `community_signal`, `self_attested`
- `source_attestation_hash` — lowercase-hex SHA-256 of the original artifact (required for the 4 verifiable sources)
- `claim_type` — CTEF closed-set value (for `ctef_attestation`)
- `evidenceType` — Dominion taxonomy value
- `source_provider_did` — issuer DID (third component of the discrimination tuple)
- `raw_signal` — unweighted signal in `[-1.0, 1.0]`
- `weighted_contribution` — after per-claim_type cap + diversity weight + decay
- `freshness_ttl_seconds` — per-contribution validity
- `contested_signal` — boolean for surfaced conflicts
- `_metadata` — source-specific UI detail (not load-bearing for the score)

---

## §4 — Aggregation algorithm

```
trust_score = sum_over_contributions( weighted_contribution )

where weighted_contribution =
   raw_signal
   * per_claim_type_cap
   * provider_diversity_weight
   * freshness_decay

per_claim_type_cap:
  identity   : max 0.60
  authority  : max 0.25
  continuity : max 0.15
  transport  : 0.0  (transport claims = envelope hygiene, NOT trust signal)

provider_diversity_weight (number of distinct source_provider_did values):
  1 distinct provider  : 0.7
  2-3 providers        : 0.9
  4+ providers         : 1.0

freshness_decay (per contribution, t = seconds since contribution issued_at):
  exp(-t / 86400)   // 1-day half-life default; per-contribution TTL overrides

conflict resolution (two attestations with same
  (claim_type, source_provider_did) disagree by > 0.30):
  surface as contested_signal=true, use max(...) — never silent averaging.

negative ERC-8004 feedback:
  allowed to push score down to floor -0.20 (so provably bad reputation
  isn't artificially elevated by in-house signals)

community_signal cap:
  in-house votes/follows/reviews contribute up to 0.10 total
```

The trust score is bounded `[0.0, 1.0]` in the envelope; the floor is enforced AFTER summation. A subject can have a `trust_score: 0.0` even if individual `weighted_contribution` values sum negative.

---

## §5 — Signing

- **Key.** Ed25519 keypair, public key published in AgentGraph's `did:web:agentgraph.co` DID document and `/.well-known/jwks.json` under kid `trust-v2-2026`.
- **Rotation.** Next-key published 30 days before rotation. Verifiers MUST support kid-based key selection.
- **Algorithm.** `EdDSA` (`alg: "EdDSA"`).
- **Format.** Compact JWS with detached payload (header.``.signature), where the implicit payload is `lowercase_hex(SHA-256(JCS(envelope - proof)))`.

The proof block uses `Ed25519Signature2020` framing for DID-method-agnostic verifier compatibility, but the underlying signature primitive is identical to a `did:key#ed25519` JWS.

---

## §6 — Verification procedure

A consumer holding a v2 envelope SHALL verify in this order:

1. **Parse + schema-validate** against `trust-score-envelope-v2.0.json`. Reject on validation failure.
2. **Freshness check:** if `now > computed_at + freshness_ttl_seconds`, the envelope is stale — reject for hot-path use; accept for archival/auditing with the staleness noted.
3. **JCS canonicalize the envelope WITHOUT the proof block.** Hash with SHA-256.
4. **Resolve `proof.verificationMethod`** — fetch the JWKS, select the matching kid.
5. **Verify the JWS signature** over the hash from step 3.
6. **Optionally re-verify any contribution** by fetching its `source_attestation_hash` artifact and recomputing.

If steps 1-5 pass, the envelope is authentic AND fresh. Step 6 is optional and depends on consumer trust posture toward AgentGraph as issuer.

---

## §7 — Conformance bar (substrate discipline)

This spec is conformant when:

1. **Schema:** the envelope passes the JSON Schema in `trust-score-envelope-v2.0.json`.
2. **Canonicalization:** the SHA-256 of the JCS preimage is byte-identical across the 5 reference JCS implementations (`rfc8785` Py, `canonicalize` JS, `gowebpki/jcs` Go, `cyberphone/json-canonicalization` Java, `serde_jcs` Rust) when run on the 5 reference fixture envelopes in `tests/standards/fixtures/trust-score-envelope-v2.0/`.
3. **Signature:** a stock `EdDSA` JWS verifier with the correct public key validates `proof.jws`.

The reference fixture envelopes cover:
1. All-positive aggregate (typical case)
2. ERC-8004 negative feedback near floor
3. Contested-signal case (two providers disagree)
4. Freshness-decay edge (contribution past its TTL)
5. Single-source-only (diversity weight 0.7)

Implementations claiming Trust Score v2 conformance MUST produce byte-identical canonical preimages on all 5 reference fixtures. Byte equality across independent implementations is the bar — not self-attestation.

---

## §8 — Cross-references

- **CTEF v0.3.2:** [agentgraph.co/docs/ctef-v0-3-2](https://agentgraph.co/docs/ctef-v0-3-2) — Layer 1 attestation spec; v2 envelopes consume CTEF attestations as `ctef_attestation` contributions.
- **CTEF v0.4 transactional claim_type (planned Aug 15-22):** v2 envelope shape may extend to v2.1 to carry receipt-layer signals when v0.4 lands.
- **AEOESS architecture (aeoess named on A2A #1628):** v2 envelope IS the attestation-layer aggregate; v0.4 receipt-layer composes via `action_ref` correlation.
- **C1 substrate (`semantic-divergence-boundary-v0`, planned; not yet published):** the discrimination tuple `(claim_type, evidenceType, source_provider_did)` in the v2 contribution shape directly enforces C1 injectivity at envelope assembly time.
- **C4 substrate (`cross-issuer-federation-v0`, planned; not yet published):** v2 envelopes aggregate across the 8 federation issuers; the methodology breakdown names every issuer per contribution.
- **JCS substrate:** [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), in-tree cross-impl runners at `tests/cross-impl/`.

---

## §9 — Open design questions (resolve before v2.0 final)

1. **Signing key rotation cadence.** 30-day next-key publication confirmed; rotation frequency (annual? on-incident only?) needs decision.
2. **ERC-8004 negative feedback floor.** Default -0.20 set; cohort sentiment to confirm in v2 announcement thread.
3. **`contested_signal` UI surface.** Inline yellow flag (lean) vs separate disputes tab.
4. **DID coverage gap.** v2 envelopes require resolvable DID; non-DID entities continue rendering v1 score. Migration path via P2/P3 of aggregator rollout.
5. **v0.4 receipt-layer composition.** Whether v2.1 envelope shape carries receipt-layer signals, or whether receipts are referenced via `source_attestation_hash` only.

---

## §10 — What this spec does NOT do

- **Does not specify the aggregation engine implementation.** §4 is the algorithm; implementations are free to optimize, cache, or distribute as long as the output envelope passes §7 conformance.
- **Does not specify the JWKS rotation infrastructure.** Standard DID-document + JWKS practice; out of scope here.
- **Does not specify revocation of v2 envelopes.** A v2 envelope is point-in-time; staleness is handled by `freshness_ttl_seconds`. Out-of-band revocation (e.g., when a subject's identity is disputed) is a separate disputes protocol.
- **Does not specify trust score policy decisions** (per-claim_type cap values, diversity weights, decay half-life). The algorithm shape is normative; the parameter values in §4 are AgentGraph's defaults — other v2.0 implementations may choose different parameters as long as they're disclosed in the envelope.
