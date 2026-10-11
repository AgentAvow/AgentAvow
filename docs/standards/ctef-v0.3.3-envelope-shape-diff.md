# CTEF v0.3.3 — Envelope-Shape Diff (Artifact 1)

**Status:** draft (CTEF-side). Normative diff from v0.3.2.
**Scope:** envelope-shape alignment with concurrent A2A wire-signing work
(A2A #1829 RFC 9421, lawcontinue tag-parameter, A2A #1496 negative paths).
**Non-goal:** the closed `claim_type` set `{identity, transport, authority,
continuity}` does NOT change; new domains use `claim_subtype` inside existing types.

This is a coordination draft; canonical spec text lands in the CTEF main RFC once
consensus is reached on A2A #1829 / #1786.

---

## §1 — RFC 9421 wire-signature alignment

v0.3.3 aligns the CTEF envelope with the RFC 9421 `Signature-Input` + `Signature`
pattern so a **single canonicalization rule produces byte-identical output across
both the wire-signature layer and the embedded `claim_type` attestation.**

**New (optional) `wire_binding` block** on the envelope:

```jsonc
"wire_binding": {
  "signature_input_components": ["@method", "@path", "content-digest", "created", "nonce", "keyid"],
  "content_digest": "sha-256=:<base64>:",     // RFC 9530, over the wire body
  "created": 1748736000,                       // RFC 9421 created (unix seconds)
  "nonce": "<base64url, ≥128-bit random>",     // RFC 9421 nonce
  "keyid": "<verificationMethod fragment>"
}
```

A verifier MUST be able to reconstruct the RFC 9421 signature base from
`signature_input_components` and verify it against `keyid` resolved per the
subject DID method (including resolve-at-time for ledger-anchored methods).

**Nonce:** ≥128-bit cryptographic randomness; deterministic derivation
(`hash(created+keyid)`) is prohibited; verifiers maintain a sliding window
(RECOMMENDED ≤300s). Violations → `STALE_NONCE` (wire layer).

## §2 — `claim_type` tag parameter (lawcontinue, A2A #1786)

The RFC 9421 `Signature-Input` line carries a `tag` parameter equal to the
envelope's `claim_type`, so a gateway discriminates by **byte comparison of the
tag** rather than structural inspection of the payload:

```
Signature-Input: sig1=("@method" "@path" "content-digest");created=1748736000;nonce="...";keyid="...";tag="authority"
```

`tag` ∈ `{identity, transport, authority, continuity}` and MUST equal the
envelope `claim_type`. A mismatch is a structural failure → `INVALID_CLAIM_SCOPE`
(authority layer), returned before semantic evaluation.

## §3 — Two-canonicalization binding (chopmob-cloud, A2A #1829)

The substrate boundary is a **two-canonicalization stack**, not one:

| Layer | Canonicalization | Commits to |
|---|---|---|
| **Wire** (L1) | RFC 9530 content-digest over wire bytes | "this body crossed this HTTP boundary intact" — survives proxy/gzip/TLS mutations |
| **Structured** (L3/L4) | RFC 8785 JCS over claim fields | "this payload hashes deterministically across implementations" |

The binding: a claim envelope at L3/L4 references the L1 signature tuple
`(@method, @path, content-digest, created, nonce, keyid)` via `wire_binding`. The
envelope's **JCS over those tuple fields** produces a deterministic
cross-implementation hash, while the `content_digest` inside the tuple anchors
back to the actual wire bytes the verifier saw. Neither canonicalization subsumes
the other; both are required. A divergence in either → `CANONICALIZATION_MISMATCH`
or `CONTENT_DIGEST_MISMATCH` (wire layer).

## §4 — Negative-path requirement (A2A #1496 §5)

Every v0.3.3 envelope addition lands with at least one `expected_error_code`
conformance vector (fail-closed by construction). The four #1496 negative paths
map to the unified error vocabulary (`/.well-known/ctef-error-codes.json`):

| #1496 case | CTEF error code | Layer |
|---|---|---|
| scope expansion | `SCOPE_EXPANSION` | authority |
| delegation depth violation | `DELEGATION_DEPTH_EXCEEDED` | authority |
| signature substitution | `INVALID_SIGNATURE_INPUT` | wire |
| expired chain | `ROTATION_GAP` | continuity |

Plus the `action_ref` correlation near-misses (`AMBIGUOUS_ISSUER_BINDING`,
`RESCOPED_REPLAY`, `SEMANTIC_DRIFT`) published at
`/.well-known/action-ref-near-miss-vectors.json`.

## §5 — Backward compatibility

`wire_binding` and the `tag` parameter are **additive and optional**. A v0.3.2
envelope without them remains valid; v0.3.3 verifiers that see them MUST enforce
§1–§4, and MUST fall back to v0.3.2 structural verification when absent. No change
to the JCS canonicalization of existing fields → all 8 byte-match implementations
continue to validate the unchanged surface.

---

## Open (pending cohort convergence)

- Exact `wire_binding` field names pending A2A #1829 final (`signature_input_components`
  vs inlining the RFC 9421 structured-field string).
- Whether `tag` is REQUIRED or RECOMMENDED at the gateway — lean RECOMMENDED so
  permissive verifiers fall back gracefully (per the rfc9421-strict split).
- Negative-path fixtures land in `aeoess/aps-conformance-suite/fixtures/composition/a2a-1496-negative-paths/`
  once aeoess scaffolds the directory.

---

*Licence: [CC BY 4.0](LICENSE-CC-BY-4.0.txt); see [CTEF-LICENSE.md](CTEF-LICENSE.md).*
