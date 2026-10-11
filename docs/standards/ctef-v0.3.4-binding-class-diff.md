# CTEF v0.3.4 — `binding.class` per-signal diff (seed draft)

**Status:** seed draft. Opened per invitation from kenneives on
[A2A #1734](https://github.com/a2aproject/A2A/discussions/1734) (comment
18867889, 2026-10-11): *"would you open the field as a PR against the v0.3.4
draft?"* No v0.3.4 file existed yet at PR time, so this diff seeds the cycle
the way `ctef-v0.3.3-envelope-shape-diff.md` seeded v0.3.3.
**Origin:** field proposed by @imokokok (A2A #1734 comment 18860798); adopted
into the v0.3.4 direction with the per-signal decomposition by kenneives
(comment 18867889).
**Non-goals:** `claim_type`, `wire_binding` (v0.3.3 §1) and both
canonicalization rules are unchanged. No new error codes are minted here — any
code lands through the unified vocabulary (hosted in
`aeoess/agent-governance-vocabulary`).

> Maintainer note: the CONTRIBUTING table currently names only the vector
> folders as contribution surfaces; this file is under `docs/standards/` on
> the maintainer's explicit in-thread invitation. Happy to re-home or convert
> to an issue if a different path is preferred.

---

## §1 — Motivation

The confidence arithmetic composes signal conficiencies multiplicatively. When
`measured` and `asserted` signals enter one product, the asserted ones are
silently upgraded to the geometric mean of the two trust levels — the product
hides the split the arithmetic needs to respect.

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
  "recompute": "pinned_inputs",     // measured only: "pinned_inputs" | "live_source"
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
  tampering.

The two values are what let the same boolean (recompute failed) route to two
different verdict paths without ambiguity.

## §5 — `settlement` pointer (`asserted` only, optional)

An `asserted` signal MAY carry a `settlement` URI pointing at where the issuer
publicly commits to settle disputes about the asserted value. The pointer does
not upgrade the signal's class and is not a recompute path; it makes the
issuer's accountability addressable.

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
