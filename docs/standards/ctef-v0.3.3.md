# CTEF v0.3.3 — Composable Trust Evidence Format

**Version:** 0.3.3 (CTEF-scoped)
**Status:** Published 2026-06-10 (CTEF-scoped). Maintainer-approved.
**Supersedes:** v0.3.2 (published 2026-05-27). Additive, backward-compatible.
**Owner:** AgentGraph (substrate maintainer).
**Canonical home:** `agentgraph-co/agentgraph/docs/standards/ctef-v0.3.3.md`

---

## Scope & posture

v0.3.3 aligns the CTEF envelope shape with the concurrent A2A wire-signing work
(A2A #1829 RFC 9421, the `lawcontinue` tag-parameter sub-thread, A2A #1496
negative paths) so that **a single canonicalization rule produces byte-identical
output across both the wire-signature layer and the embedded `claim_type`
attestation.**

This is a **CTEF-scoped** release. The cross-specification pieces that depend on
partner repositories — the unified error-enum umbrella (`aeoess/agent-governance-vocabulary`),
the cross-extension fixture matrix, and the `a2a-1496-negative-paths/` fixture
directory — are tracked as **in-flight** (§7) and referenced normatively where the
CTEF side is already published. Releasing CTEF-scoped keeps the substrate on its
cadence without blocking on federated convergence; the in-flight items fold in as
partner PRs land.

**Non-goal:** the closed `claim_type` set `{identity, transport, authority,
continuity}` does **not** change. New attestation domains use `claim_subtype`
inside an existing type.

---

## §1 — RFC 9421 wire-signature alignment (new, optional)

v0.3.3 adds an **optional** `wire_binding` block to the envelope, aligning CTEF
with the RFC 9421 `Signature-Input` + `Signature` header pattern.

```jsonc
"wire_binding": {
  "signature_input_components": ["@method", "@path", "content-digest", "created", "nonce", "keyid"],
  "content_digest": "sha-256=:<base64>:",   // RFC 9530, over the wire body
  "created": 1748736000,                     // RFC 9421 created (unix seconds)
  "nonce": "<base64url, ≥128-bit random>",   // RFC 9421 nonce
  "keyid": "<verificationMethod fragment>"
}
```

A verifier MUST be able to reconstruct the RFC 9421 signature base from
`signature_input_components` and verify it against `keyid` resolved per the subject
DID method (including resolve-at-time for ledger-anchored methods).

**Nonce:** ≥128-bit cryptographic randomness. Deterministic derivation
(`hash(created+keyid)`) is prohibited. Verifiers maintain a sliding window
(RECOMMENDED ≤ 300 s). Violations → `STALE_NONCE` (wire layer).

> **In-flight:** exact `wire_binding` field names are provisional pending A2A
> #1829 final (`signature_input_components` array vs. inlining the RFC 9421
> structured-field string). The semantics in this section are stable; the field
> spelling may change in a v0.3.3.x patch when #1829 closes.

## §2 — `claim_type` tag parameter

The RFC 9421 `Signature-Input` line carries a `tag` parameter equal to the
envelope's `claim_type`, so a gateway discriminates by **byte comparison of the
tag** rather than structural inspection of the payload:

```
Signature-Input: sig1=("@method" "@path" "content-digest");created=1748736000;nonce="...";keyid="...";tag="authority"
```

`tag` ∈ `{identity, transport, authority, continuity}` and MUST equal the envelope
`claim_type`. A mismatch is a structural failure → `INVALID_CLAIM_SCOPE`
(authority layer), returned before semantic evaluation.

`tag` is **RECOMMENDED** (not REQUIRED) at the gateway, so permissive verifiers
fall back gracefully to structural inspection when it is absent (per the
rfc9421-strict split). A verifier that *does* see `tag` MUST enforce the equality
check.

## §3 — Two-canonicalization binding

The substrate boundary is a **two-canonicalization stack**, not one. Both are
required; neither subsumes the other.

| Layer | Canonicalization | Commits to |
|---|---|---|
| **Wire** (L1) | RFC 9530 content-digest over wire bytes | "this body crossed this HTTP boundary intact" — survives proxy / gzip / TLS mutations |
| **Structured** (L3/L4) | RFC 8785 JCS over claim fields | "this payload hashes deterministically across implementations" |

The binding: a claim envelope at L3/L4 references the L1 signature tuple
`(@method, @path, content-digest, created, nonce, keyid)` via `wire_binding`. The
envelope's **JCS over those tuple fields** produces a deterministic
cross-implementation hash, while the `content_digest` inside the tuple anchors back
to the actual wire bytes the verifier saw. A divergence in either →
`CANONICALIZATION_MISMATCH` or `CONTENT_DIGEST_MISMATCH` (wire layer).

## §4 — Negative-path requirement

Every v0.3.3 envelope addition lands with at least one `expected_error_code`
conformance vector — **fail-closed by construction.** The four A2A #1496 §5
negative paths map to the published CTEF error vocabulary
(`/.well-known/ctef-error-codes.json`):

| #1496 case | CTEF error code | Layer |
|---|---|---|
| scope expansion | `SCOPE_EXPANSION` | authority |
| delegation depth violation | `DELEGATION_DEPTH_EXCEEDED` | authority |
| signature substitution | `INVALID_SIGNATURE_INPUT` | wire |
| expired chain | `ROTATION_GAP` | continuity |

Plus the `action_ref` correlation near-misses (`AMBIGUOUS_ISSUER_BINDING`,
`RESCOPED_REPLAY`, `SEMANTIC_DRIFT`) at
`/.well-known/action-ref-near-miss-vectors.json`.

## §5 — Backward compatibility

`wire_binding` and the `tag` parameter are **additive and optional.** A v0.3.2
envelope without them remains valid. v0.3.3 verifiers that see them MUST enforce
§1–§4 and MUST fall back to v0.3.2 structural verification when absent. There is
**no change to the JCS canonicalization of existing fields** → all 8 byte-match
validated implementations continue to validate the unchanged surface.

---

## §6 — Error vocabulary (CTEF side, published)

The CTEF-side unified error vocabulary is **live** at
`/.well-known/ctef-error-codes.json` (also `ctef-error-codes-v0.json` in this
repo): **18 codes across 5 layers** (wire / identity / authority / continuity /
correlation). Every code is structural and fail-closed, with cross-spec references
(#1496 §5, the `action_ref` I-D).

| Layer | Example codes |
|---|---|
| wire | `INVALID_SIGNATURE_INPUT`, `CANONICALIZATION_MISMATCH`, `STALE_NONCE`, `CONTENT_DIGEST_MISMATCH` |
| identity | `DID_RESOLUTION_FAILED`, `JWKS_UNREACHABLE`, `IDENTITY_BINDING_INVALID` |
| authority | `INVALID_CLAIM_SCOPE`, `SCOPE_EXPANSION`, `DELEGATION_DEPTH_EXCEEDED` |
| continuity | `ROTATION_GAP`, `EPOCH_MISMATCH`, `SEQUENCE_VIOLATION` |
| correlation | `AMBIGUOUS_ISSUER_BINDING`, `RESCOPED_REPLAY`, `SEMANTIC_DRIFT` |

This is offered as the starting PR for the cross-spec umbrella in
`aeoess/agent-governance-vocabulary` (§7).

---

## §7 — In-flight (cross-specification; not blocking this release)

| Item | Owner | Folds in when |
|---|---|---|
| Unified error-enum umbrella (CTEF + APS + AIM + Hippo + #1496 §5) | aeoess (`agent-governance-vocabulary`) | umbrella issue opens; CTEF side already published (§6) |
| Exact `wire_binding` field names | A2A #1829 (jschoemaker) | #1829 final → v0.3.3.x patch |
| Cross-extension fixture matrix (CTEF / APS / AIM / Hippo / Envoys byte-match) | AgentGraph + partners | rolling, as partners PR byte-match results |
| `a2a-1496-negative-paths/` fixture directory + verifier runner | aeoess (`aps-conformance-suite`) | aeoess scaffolds; AgentGraph contributes the 4 vectors |

---

## §8 — Reference architecture (folded forward from launch convergence)

- **Substrate-and-primitive layering** (Erik Newton, A2A #1725): substrate
  (wire-format + canonicalization) → primitives (CTEF identity / Concordia /
  AgentID / ERC-8004) → runtimes. v0.3.3 anchors on this 3-layer model.
- **Per-receipt-type attribution** (aeoess, A2A #1786): the protocol spans layers;
  the *receipts* are attributed. APS `bilateral_receipt` → envelope (wire); APS
  `delegation_receipt` → authority; APS `rotation-attestation` → continuity. This
  replaces the looser per-protocol attribution from the launch litepaper.

---

## §9 — Conformance

1. **JCS canonicalization (RFC 8785) is non-negotiable.** Any v0.3.3 envelope
   change MUST produce byte-identical output across all 8 byte-match validated
   implementations.
2. **Negative-path coverage is mandatory** — every addition ships with at least
   one `expected_error_code` vector.
3. **Closed `claim_type` set stays closed** — `{identity, transport, authority,
   continuity}`; new domains use `claim_subtype`.

---

## Changelog (v0.3.2 → v0.3.3)

- **Added** optional `wire_binding` block (§1) — RFC 9421 / RFC 9530 wire-signature
  alignment.
- **Added** `claim_type` `tag` parameter (§2) — byte-comparison gateway
  discrimination; RECOMMENDED.
- **Specified** the two-canonicalization binding (§3) — wire content-digest +
  structured JCS, formally bound via `wire_binding`.
- **Mandated** negative-path coverage (§4) + published the 18-code error
  vocabulary (§6).
- **Adopted** substrate-and-primitive layering + per-receipt-type attribution (§8).
- **No change** to existing-field JCS canonicalization — full v0.3.2 backward
  compatibility.

---

*Licence: [CC BY 4.0](LICENSE-CC-BY-4.0.txt); see [CTEF-LICENSE.md](CTEF-LICENSE.md).*
