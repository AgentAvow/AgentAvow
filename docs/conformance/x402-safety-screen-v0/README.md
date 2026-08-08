# x402 endpoint-safety screen — PRE_PAYMENT_GUARD plugin (v0)

A reference implementation + conformance vectors for an **endpoint-safety** screen
under the converging x402 pre-payment guard interface
([x402-foundation/x402#2533](https://github.com/x402-foundation/x402/issues/2533)).

It's the third screen alongside evidai's **authorization** plugin and the **payload/PII**
screen: same chokepoint, orthogonal concern. This one refuses to pay an x402 endpoint that
AgentGraph has graded **critical/high** — *score before money moves.*

## Interface (matches the thread)

```
declares: ["resource_url", "safety_attestation"]          # keys_off_raw
screen(input, ctx) -> {"verdict": "admit"|"deny", "reason"?: str, "entities"?: [str]}
```

- **Deny-only, mutation-free.** It reads the supplied AgentGraph safety attestation and
  decides; it changes nothing a downstream screen sees. That purity is what makes the verdict
  byte-reproducible offline — the same property the authorization and payload screens have.
- **Pure / no network.** The endpoint's signed safety attestation is passed in as
  `input["safety_attestation"]` (the host fetches + signature-verifies it before the guard
  runs, via `agentgraph_sdk.verify`), exactly as a payload screen receives the payload.
- **Missing attestation → `admit` with `reason: "no_safety_attestation"`** (never a silent
  pass). Whether an un-attested endpoint is acceptable is the host's policy decision (a
  `require_safety` flag), the same philosophy as SafeAgent's `require_attestation`.

## The verdict is the proof, not a parallel artifact

Per @evidai's point on #2533: the guard verdict *is* the pre-execution decision a settlement
record anchors. This safety verdict is designed to be carried in AgentGraph's
[`pre-execution-verdict-v0`](../../standards/v0.4-pre-execution-verdict-v0.md) envelope —
`admission.verdict` + a `binding_digest`/`action_ref` — so a `PRE_PAYMENT_GUARD` verdict and
an `action_ref` are the decision and its proof, the same shape on both sides.

## Conformance

### v0: screen determinism + verdict canonicalization

`safety_screen_v0.json` pins, for 5 vectors, the RFC 8785 canonical bytes + SHA-256 of the
verdict the reference screen produces. Reproduce:

```bash
pip install rfc8785==0.1.4
python3 verify_fixture.py     # 5/5 byte-for-byte
```

| Vector | Verdict |
|---|---|
| admit_clean (grade A, 0 critical/high) | admit |
| deny_critical (2 critical) | deny |
| deny_high (4 high) | deny |
| admit_no_attestation (un-attested) | admit + reason |
| deny_critical_and_high | deny + entities |

Same byte-verifiable pattern AlgoVoi uses (we cross-validate their JCS corpus 253/253) — so
this screen's verdict is reproducible offline by any implementation, no trust in ours.

**Scope of v0 (precise).** v0 proves exactly two things: the screen is **deterministic**, and
its verdict object is **canonicalized** reproducibly (JCS bytes + SHA-256). It does **not**
exercise the two host-level checks that sit *ahead* of the screen (signature verification and
`action_ref` binding), which the interface (above) puts in the host and which `verify_fixture.py`
never runs. That gap is the reviewer's correct critique on
[#2533](https://github.com/x402-foundation/x402/issues/2533); v0.1 closes it.

### v0.1: host-level signature + action_ref binding (runnable)

`v0.1/` adds vectors that exercise the two checks the host performs before the screen, as
runnable code rather than prose:

1. **Signature against published JWKS.** A signed
   [`pre-execution-verdict-v0`](../../standards/v0.4-pre-execution-verdict-v0.md) envelope
   carrying the v0 safety verdict, signed EdDSA/Ed25519 as a detached JWS over the RFC 8785 JCS
   canonical, proof-stripped verdict (the same discipline as `src/trust/envelope_v2.py`). Each
   vector embeds its own JWKS so it verifies offline. `sig_valid` verifies; `sig_tampered_payload`
   (a field mutated after signing) and `sig_foreign_key` (signed by a key absent from the JWKS)
   both fail.
2. **`action_ref`-to-effective-call binding.** The verdict binds an `action_ref` computed as
   `"sha256:" + hex(SHA-256(JCS({agent_id, action_type, scope, timestamp_ms})))`, the same
   recipe as `src/trust/action_ref_vectors.py`. The host recomputes it over the effective call it
   is about to make and requires a match. `bind_match` (effective call equals the bound call)
   passes; `bind_mismatch` (call drifted to a different endpoint) fails.

```bash
pip install rfc8785==0.1.4 cryptography
cd v0.1
python3 gen_v0_1.py       # regenerate the vectors byte-for-byte (fixed Ed25519 seeds)
python3 verify_v0_1.py    # 5/5; exits non-zero if any vector misbehaves
```

| Vector | Check | Expected |
|---|---|---|
| sig_valid | signature vs JWKS | pass |
| sig_tampered_payload | signature vs JWKS | fail |
| sig_foreign_key | signature vs JWKS | fail |
| bind_match | action_ref vs effective call | pass |
| bind_mismatch | action_ref vs effective call | fail |

`verify_v0_1.py` uses only stdlib + the same `cryptography`/`rfc8785` the product uses; the
signing and `action_ref` primitives are byte-for-byte identical to `src/trust/envelope_v2.py`
and `src/trust/action_ref_vectors.py` (asserted by `gen_v0_1.py` when the source tree is
present). Signatures are reproducible from fixed seeds, so regeneration is byte-identical.

**What each layer proves.** v0 proves screen determinism + verdict canonicalization. v0.1 adds
the host-level signature-against-JWKS and `action_ref`-binding checks as runnable vectors. The
two together cover screen output *and* the host checks the interface relies on around it.
