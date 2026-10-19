# CTEF v0.3.4 — `binding.class` per-signal diff (seed draft)

**Status:** seed draft. Opened per invitation from kenneives on
[A2A #1734](https://github.com/a2aproject/A2A/discussions/1734) (comment
18867889, 2026-10-11): *"would you open the field as a PR against the v0.3.4
draft?"* No v0.3.4 file existed yet at PR time, so this diff seeds the cycle
the way `ctef-v0.3.3-envelope-shape-diff.md` seeded v0.3.3.
**Origin:** the broader distinction this field leans on — a signature does not
establish the truth of a claim, and an evidence commitment does not establish
that the evidence is available, relevant, or sufficient — was first articulated
in this thread by @Jsand-187 (A2A #1734 comment 18528762, 2026-09-20). The
field itself (a per-signal `measured`/`asserted` classification) was proposed
by @imokokok (comment 18860798) and adopted into the v0.3.4 direction with the
per-signal decomposition by kenneives (comment 18867889).
**Non-goals:** `claim_type`, `wire_binding` (v0.3.3 §1) and both
canonicalization rules are unchanged. No new error codes are minted here — any
code lands through the unified vocabulary (hosted in
`aeoess/agent-governance-vocabulary`).

> Maintainer note: the CONTRIBUTING table currently names only the vector
> folders as contribution surfaces; this file is under `docs/standards/` on
> the maintainer's explicit in-thread invitation. Happy to re-home or convert
> to an issue if a different path is preferred.
>
> **r2 (2026-10-12):** adopted review feedback from babyblueviper1 (§5
> append-only requirement) and vdineshk (§4 `live_source` capture recipe), both
> from PR review comments.
>
> **r3 (2026-10-13):** corrected the confidence-product explanation per
> kenneives; bound each `live_source` recipe to a digest and explicit format /
> canonicalization per follow-up from babyblueviper1 and vdineshk; added the
> CTEF license line.
>
> **r4 (2026-10-13):** clarified that a verified recipe does not establish
> historical-input availability or a live-source match, and unavailable
> historical inputs do not mean “no drift,” per babyblueviper1's follow-up.

---

## §1 — Motivation

The confidence arithmetic composes signal confidences multiplicatively. When
`measured` and `asserted` confidences are multiplied, nothing in the result
distinguishes the asserted factor from the measured one, so the product carries
a trust level only the issuer can vouch for.

One attestation can also legitimately carry both classes. The decomposition
kenneives gave for AgentAvow (A2A #1734, comment 18867889):

| Signal | Class | Why |
|---|---|---|
| per-tool definition digests | `measured` | anyone recomputes them from the served `tools/list` |
| 0–100 score | `measured` *given the findings* | computed under the published scoring model selected by the signed `scannedAt` |
| the findings themselves | `asserted` | unless the scan is re-run at the pinned commit |

A per-attestation class forces exactly the collapse the field exists to
prevent; the class therefore attaches **per signal**, not per envelope.

## §2 — Field definition (optional, per signal)

```jsonc
"binding": {
  "class": "measured",              // REQUIRED: "measured" | "asserted"
  "recompute": "live_source",       // measured only: "pinned_inputs" | "live_source"
  "recipe_sha256": "<64 lowercase hex>", // live_source only: pins the recipe body
  "recipe_format": "ctef-live-capture-recipe/1", // live_source only
  "recipe_canonicalization": "RFC8785-JCS", // live_source only
  "recipe": {                        // exactly one of recipe / recipe_uri
    "endpoint": "https://example.test/source",
    "request": { "method": "GET" },
    "canonical_representation": "RFC8785-JCS",
    "captured_at": "2026-10-13T00:00:00Z"
  },
  // "recipe_uri": "https://…",      // use this instead of recipe for a reference
  "settlement": "https://…"         // asserted only: issuer's public settle commitment
}
```

The `binding` object attaches to each **signal entry** inside the envelope
payload. Normative rules:

1. An envelope whose payload mixes classes MUST carry `binding` per signal
   entry. An envelope-level `binding` over a mixed payload is a structural
   defect: verifiers MUST treat every signal in it as class-unassessable
   (fail-closed), never inherit the envelope value.
2. **Default when absent:** a signal without `binding` is treated as
   `asserted` — fail-closed; unverifiable signals do not gain measured
   weighting by omitting the field.
3. `recompute` and `settlement` are each valid only for their class (§4, §5).
   A `live_source` binding MUST include `recipe_sha256`, `recipe_format`, and
   `recipe_canonicalization`, and MUST provide exactly one of `recipe` (inline
   body) or `recipe_uri` (reference).

## §3 — Class definitions

- **`measured`** — any verifier can recompute the signal value from inputs
  referenced by the envelope (or its `tools/list`-equivalent source) and obtain
  byte-identical output.
- **`asserted`** — the issuer attests the value and takes accountability for
  it; no independent recompute path is offered. `asserted` is not a downgrade
  marker: it is the class that makes issuer identity and settlement commitment
  load-bearing.

## §4 — `recompute` semantics (`measured` only)

- **`pinned_inputs`** — the verifier recomputes against pinned inputs. A
  mismatch is **tampering evidence** (hard failure).
- **`live_source`** — the verifier recomputes against the live source. A
  mismatch is a **drift signal** (soft, time-bounded re-check), not proof of
  tampering. A `live_source` signal MUST carry a reproducible capture recipe —
  source endpoint, request/initialization steps, canonical representation, and
  capture time. The required `binding.recipe_sha256` pins the recipe body
  whether it is inline or referenced; `recipe_format` and
  `recipe_canonicalization` identify how to interpret and canonicalize it. The
  digest is SHA-256 over the recipe bytes produced by that canonicalization.
  Naming the recompute mode without this bound recipe still leaves two
  independent verifiers free to hash different representations of the same
  response.

  A verifier MUST report one recipe outcome: `absent` (a required binding
  member or body/reference is missing), `referenced_unavailable` (the referenced
  body could not be retrieved), `digest_mismatch` (the retrieved or inline body
  does not match `recipe_sha256`), or `verified` (the body is available and its
  digest matches). Historical capture-input availability is a separate status,
  even when the recipe is verified. A `verified` recipe establishes only that
  the recipe body matches its digest; it does not establish that historical
  capture inputs were available or that the live source matched them. If the
  historical inputs are unavailable, the observation cannot be repeated and
  that absence MUST NOT be reported or inferred as "no drift." The first three
  recipe outcomes also do not establish "no drift."

The two values are what let the same boolean (recompute failed) route to two
different verdict paths without ambiguity.

## §5 — `settlement` pointer (`asserted` only, optional)

An `asserted` signal MAY carry a `settlement` URI pointing at where the issuer
publicly commits to settle disputes about the asserted value. The pointer does
not upgrade the signal's class and is not a recompute path; it makes the
issuer's accountability addressable.

A settlement URI only makes accountability addressable if the issuer cannot
edit what it points to after a dispute starts; otherwise the pointer is a
promise, not a commitment. The target SHOULD therefore be append-only and
committed **before** the outcome it covers (hash-pinned or externally
anchored), so a verifier can tell whether the commitment changed after the
fact. A live worked example: babyblueviper1's decision-receipt slot (review
comment on this PR) — a BIP-340 signature over salted commitments to the
choice, a `conflicts` list that surfaces equivocation by the same key, and a
daily Merkle log chained by `prev_root` whose root is OpenTimestamps-anchored.

## §6 — Gateway weighting rule (RECOMMENDED)

A gateway SHOULD multiply only the confidences it can recompute (`measured`),
and aggregate `asserted` signals through issuer accountability (verification
path, settlement commitment) rather than into the same product. Verdict
`reasoning` blocks SHOULD record the per-signal class so the arithmetic is
checkable downstream.

## §7 — Backward compatibility

`binding` is optional and lives inside the payload envelope; v0.3.3 verifiers
that ignore unknown payload members are unaffected. No canonicalization change
— JCS already covers the payload, so `binding` enters existing hashes without
a migration.

*Licence: CC BY 4.0; see CTEF-LICENSE.md.*
