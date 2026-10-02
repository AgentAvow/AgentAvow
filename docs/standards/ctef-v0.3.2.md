# CTEF v0.3.2 — Composable Trust Evidence Format clears the substrate gate

*10 independent implementations. 5 JCS canonicalizers across 5 languages. 53 conformance vectors. 265 byte-for-byte agreements. Zero divergence.*

**Published: May 27, 2026**

## The cross-framework trust problem

If you're building agent-to-agent infrastructure in 2026, you've likely hit a wall that didn't exist eighteen months ago: how does an agent built on framework A verify a claim emitted by framework B, attested to by framework C, with a behavioral history carried forward from framework D?

Each framework has its own envelope shape. Each has its own canonicalization rules (or lacks them entirely). Each has its own signature pattern, often with subtly incompatible JOSE-vs-COSE-vs-raw-bytes choices. Each ecosystem accumulates its own trust assumptions about identity, authority, transport, and continuity claims.

The naïve solutions all fail:

- **A shared authority server** — the thing the architecture is supposed to avoid. The whole point of decentralized agent identity is no shared root.
- **Cross-framework adapters** — quadratic explosion. With N frameworks you need N² adapters, each one a vector for trust-equivalence drift.
- **Schema-level validation** — JSON schemas don't fix canonicalization. Two semantically equivalent payloads can serialize to different bytes; signature verification breaks; the relying party rejects valid claims it should accept.

The pattern that emerged from eighteen months of working-group coordination across A2A, MCP, x402, AP2, ERC-8004, and adjacent ecosystems: **a substrate layer that every framework can emit and every consumer can verify**, with zero cross-framework knowledge required.

CTEF — Composable Trust Evidence Format — is that substrate.

## What v0.3.2 publishes

Six normative additions, each driven by a partner-thread interop incident that surfaced during the v0.3.1 → v0.3.2 cycle:

**1. Depth-first proof-stripping.** Implementations MUST recurse into nested chain objects when stripping proofs for canonicalization. Top-level proof-stripping is insufficient. This caught when a gateway-verdict envelope failed to verify under three implementations that had previously passed v0.3.1 — the proofs were nested, not top-level, and the implementations were not recursing.

**2. Authority chain composition: scope-narrowing-only.** When authority claims compose across a delegation chain, each downstream link can only narrow the scope of the original grant, never widen it. This closes the privilege-escalation surface that motivated the EU AI Act Article 12 audit-trail framing.

**3. Stale-action policy.** Explicit normative semantics for what verification looks like when an attestation references a state that has since rotated (key rotation, identity revocation, policy version change). The previous behavior was implementation-defined; v0.3.2 pins fail-closed semantics with `INVALID_STATE_BINDING` as the canonical error code.

**4. Required-vs-informational field discipline.** Every field in the CTEF envelope has a normative classification as either required (conformance MUST fail if absent) or informational (consumers MAY ignore). The classification is baked into the conformance harness — implementations that silently accept missing required fields fail the v0.3.2 acceptance bar.

**5. Behavioral claim_type with TTL-cap MUST.** When an attestation carries behavioral evidence — for example, empirical trust scoring across thousands of MCP servers — the TTL is normatively capped to prevent stale-behavior poisoning of long-running agents. Behavioral evidence decays in a way cryptographic identity does not, and v0.3.2 makes that semantic difference explicit.

**6. `claim_subtype: tier_upgrade` registry first entry.** A `tier_upgrade_proof` fixture lands as the first reference implementation of the authority-claim subtype registry pattern. Future authority subtypes follow the same shape: discrimination tuple `(claim_type, claim_subtype, source_provider_did)` enforced for injectivity; signed verdict envelope; live `did:web` resolution; `policy_ref: sha256:<jcs-hash>` for audit-trail integrity across policy rotation.

## The substrate-evidence density

The bar a substrate spec needs to clear before it's actually a substrate (and not just a proposal) is empirical byte-match across multiple independent implementations. Talk is cheap; bytes are not.

The v0.3.2 publish window crosses two such bars concurrently.

### JCS canonicalization × vector sets

Five independent JCS canonicalization implementations validated against four distinct vector sets — twenty cells, every cell byte-identical, 265 byte-for-byte agreements:

| Implementation | Lang | CTEF/APS (14) | AP2 OMH v0 (7) | privacy_class v0.1 (13) | per-chain envelope v0 (19) |
|---|---|---|---|---|---|
| `rfc8785@0.1.4` | Python (Trail of Bits / William Woodruff) | ✓ | ✓ | ✓ | ✓ |
| `canonicalize@3.0.0` | JavaScript (Samuel Erdtman; Anders Rundgren contributor) | ✓ | ✓ | ✓ | ✓ |
| `gowebpki/jcs@v1.0.1` | Go (Web PKI WG) | ✓ | ✓ | ✓ | ✓ |
| `cyberphone/json-canonicalization` | Java (Anders Rundgren — **RFC 8785 reference**) | ✓ | ✓ | ✓ | ✓ |
| `serde_jcs@0.2.0` | Rust | ✓ | ✓ | ✓ | ✓ |

The fourth row matters most. `cyberphone/json-canonicalization` is Anders Rundgren's reference Java implementation, cited in RFC 8785 itself. When the spec author's own reference implementation produces byte-identical output to a Python library, a JavaScript package, a Go module, and a Rust crate — across four independently-authored vector sets covering 53 distinct canonicalization edge cases — the cross-runtime determinism question is closed concretely. Four non-overlapping author sets, five language runtimes, 265 byte-for-byte agreements, zero divergence.

The substrate is reproducible in-tree at [`agentgraph-co/agentgraph/tests/cross-impl/`](https://github.com/agentgraph-co/agentgraph/tree/v0.3.3-cross-extension-matrix/tests/cross-impl) — single-file runner per language, repo-pinned fixture set, run any one runner and get `53/53 PASS` or a structured divergence report.

### Implementations × byte-match validation

Ten independent implementations have reproduced the CTEF v0.3.2 reference vectors: AgentGraph (substrate maintainer), APS, AgentID, @nobulex/crypto, HiveTrust, msaleme/red-team-blue-team-agent-fabric, Foxbook, ArkForge, Agent Community Verifiability Gate, and AlgoVoi.

No coordination. Each implementation built independently, validated independently, produced byte-identical canonical attestations against the same reference vectors.

## What CTEF v0.3.2 enables

The architectural pattern that matters: **every framework can be a substrate emitter without any framework being authoritative**.

A relying-party agent in mid-2026 doesn't get to pick the framework its counterparty was built on. An A2A agent might need to verify a claim chain that started life as an x402 settlement-retention anchor (signed with ES256/P1363), was attested by an ERC-8004 identity registration (anchored on Ethereum mainnet), passed through an MCP tool invocation, and was carried forward into a behavioral-trust update (third-party observer, EU AI Act compliance posture).

Four ecosystems. Four independent emitters. Four distinct security models. One substrate.

CTEF v0.3.2 lets each emitter speak its own protocol semantics on top of byte-equivalent canonical attestations. The consuming agent verifies the JCS_hash + signature against the substrate, with no need to know which framework emitted what. If the verification passes, the claim is composable.

### The mainstream just caught up

This publish lands in a week where the broader market has visibly caught up to the problem space CTEF was designed for. In the last fortnight: Anthropic announced Mythos-class models opening more capable autonomous agents to the public; Google publicly admitted it is "navigating AI security in real time" without a paved path; the Keyrock and CoinDesk reports document AI agents settling in stablecoins as the default payment layer; and a single npm account compromise infected 314 packages in a 22-minute burst (16M weekly downloads affected), exactly the supply-chain class-of-attack the substrate's trust composition was built to bound.

The framing of "trust infrastructure for autonomous agents" was contested 18 months ago and obvious now. What changed isn't the architecture — it's that the market caught up to why the architecture matters.

## What's next

**v0.3.2 is the last byte-match-led publish.** The substrate is solved — five implementations, four languages, four non-overlapping author sets, 53 conformance vectors, 265 byte-for-byte agreements, zero divergence. That bar has been cleared. What comes next composes ON TOP of that substrate, not against it.

**v0.3.3 — Cross-extension URN-layer matrix (target: mid-June).** A row-per-URN-namespace table binding substrate emitters to claim_type, evidenceType, and live fixture sets. Six rows are already accepted with named PR authors: `urn:x402:audit-chain` (settlement-retention authority), `urn:nobulex:receipt` (behavioral continuity), `urn:concordia:receipt` (third-party authority), `urn:observatory:eval` (behavioral evidence), `urn:x402:receipt:stark-vauban-pay-v1` (cryptographic settlement), plus the substrate matrix itself.

**v0.4 — Trust-gated payments + composability (target: Q3 2026).** As AI agents adopt crypto rails as the default settlement layer, every settlement becomes a trust-check moment. v0.4 opens trust-gated payment middleware, APP↔CTEF composability, and the `transactional` claim_type that captures the payment/negotiation/commitment lifecycle.

## Read more

- **Cross-extension matrix:** [v0.3.3 working doc](https://github.com/agentgraph-co/agentgraph/blob/v0.3.3-cross-extension-matrix/docs/standards/v0.3.3-working-doc.md)
- **Conformance vectors:** `/.well-known/cte-test-vectors.json`
- **Interop harness:** `/.well-known/interop-harness.json`
- **GitHub:** [agentgraph-co/agentgraph](https://github.com/agentgraph-co/agentgraph)
- **State of Agent Security 2026:** [agentgraph.co](https://agentgraph.co) (free download)

If you maintain a framework that emits trust-relevant attestations — identity, transport, authority, or continuity — the v0.3.3 cross-extension matrix branch is open for PRs. The substrate gate is the only filter; we will not be picky about ecosystem affiliation.

---

*Composable trust isn't a framework. It's the floor under all the frameworks.*
