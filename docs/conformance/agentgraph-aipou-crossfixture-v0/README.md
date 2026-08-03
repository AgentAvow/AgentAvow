# AgentGraph `action_ref` ↔ AIPOU `workReceiptId` cross-fixture (v0)

**Interoperability validation of evidence _linkage_ only.** This fixture asserts no reward, no claim,
no integration status, and no endorsement by either project. It uses hashes and public verification
material only — no raw prompts or outputs.

Requested on [microsoft/autogen#7476](https://github.com/microsoft/autogen/discussions/7476) by
[@0xddneto](https://github.com/0xddneto) (AIPOU): *"one canonical action_ref → AIPOU workReceiptId +
digest link, then two fail-closed cases for action-ref mismatch and digest mismatch. It should validate
only evidence linkage; no reward, claim, or integration status is implied."*

## What it demonstrates

Two independent verifiers, each checking only what it owns:

| Vector | AIPOU (`external-evidence-link-v1`) | AgentGraph (`action_ref` recompute) | Outcome |
|---|---|---|---|
| `valid_link` | **accept** | **match** | link is honored |
| `action_ref_mismatch__fail_closed` | accept (structurally valid) | **reject** (recompute ≠ `source.id`) | **fail-closed — AgentGraph-owned** |
| `digest_mismatch__fail_closed` | **reject** (`linkDigest` mismatch) | n/a | **fail-closed — AIPOU-owned** |

The point: a valid cross-link requires **both** sides to independently accept. The AgentGraph side
recomputes `action_ref` from the published preimage and binds it to `link.source.id`; the AIPOU side
recomputes `linkDigest` over the canonical link payload and binds the receipt `digest`. Tampering with
either half is caught by exactly one side, and neither side has to trust the other's operator.

## Definitions

- **AgentGraph `action_ref`** = `"sha256:" + hex(SHA-256(JCS({agent_id, action_type, scope, timestamp_ms})))`,
  RFC 8785 (JCS) canonicalization. Reference impl: `src/trust/action_ref_vectors.py::compute_action_ref`.
- **AIPOU link** = `external-evidence-link-v1`, `linkDigest = sha256(canonicalize({scheme, relation,
  source, target, privacy, issuedAt}))`. Reference impl:
  [`examples/lifecycle-adapter/external-evidence-link.mjs`](https://github.com/0xddneto/AI-Proof-of-Us/blob/main/examples/lifecycle-adapter/external-evidence-link.mjs).

`source` (AgentGraph) = the pre-execution action authorization; `target` (AIPOU) = the later-recorded
work receipt; `relation = "input_to"`.

## Reproduce

**AIPOU side** (Node ≥ 18) — validates `linkDigest` and structure:

```js
import { validateExternalEvidenceLink } from "./external-evidence-link.mjs"; // from 0xddneto/AI-Proof-of-Us
import fixture from "./fixture.json" assert { type: "json" };
for (const v of fixture.vectors) {
  try { console.log(v.name, validateExternalEvidenceLink(v.link) ? "accept" : "reject"); }
  catch (e) { console.log(v.name, "reject:", e.message); }
}
// valid_link -> accept ; action_ref_mismatch -> accept (structurally) ; digest_mismatch -> reject
```

**AgentGraph side** (Python) — recomputes `action_ref` and binds it to `source.id`:

```python
import json
from src.trust.action_ref_vectors import compute_action_ref
fx = json.load(open("fixture.json"))
mat = fx["agentgraph_recompute_material"]
for v in fx["vectors"]:
    if v["name"] == "digest_mismatch__fail_closed":
        continue  # AIPOU-owned
    scope = "valid_read_scope" if "valid" in v["agentgraph_check"]["recompute_over"] else "mismatch_write_scope"
    got = compute_action_ref(**mat[scope]["preimage"])
    print(v["name"], "accept" if got == v["link"]["source"]["id"] else "reject")
# valid_link -> accept ; action_ref_mismatch -> reject
```

## Status / alignment note (v1 — 2026-08-03)

**Aligned with AIPOU's frozen artifact.** The earlier placeholder AIPOU receipt digest has been swapped
for [@0xddneto](https://github.com/0xddneto)'s **frozen v0.4-canonical** work receipt
(`workReceiptId 0x34d3be87…`, `digest sha256:059075bc…`) from
[`examples/lifecycle-adapter/agentgraph-cross-fixtures.json`](https://github.com/0xddneto/AI-Proof-of-Us/blob/main/examples/lifecycle-adapter/agentgraph-cross-fixtures.json).
The fail-closed semantics are unchanged; only the referenced digests are now real. New valid
`linkDigest = sha256:30759a95…`.

To complete the loop mutually, our real **run-123 canonical-envelope digest**
(`sha256:8547074431a45ce0…`, RFC 8785 / JCS) is exposed in `parties.agentgraph.canonical_envelope_digest`
— the AIPOU side can swap that in for its placeholder AgentGraph digest so both fixtures reference each
other's real artifacts.

`observed_results` in `fixture.json` records the actual output of AIPOU's reference validator on each
vector at generation time.
