# AgentAvow Safety Model — v1.0

**Status:** Stable · **Model version:** `safety-model-v1` · **Last updated:** 2026-10-02 (§5 tier table aligned with the API's six `trust_tier` values)

This document specifies the **model** AgentAvow uses to turn a scan into a 0–100 safety
score, a tier, and a Certified verdict. It is the declarative, versioned counterpart to
the CTEF evidence format: CTEF says *"here is the signed evidence"*, this says *"here is
exactly how that evidence composes into a score"*. Publishing the model is the point — a
trust score you can recompute is only meaningful if the composition rule is open.

The model (what is measured and how it composes) is specified here; it is deliberately
separate from the **implementation** (`src/scanner/`) and the **evidence** (the signed
JWS/CTEF envelope). An independent implementer can read this document and reproduce a
conforming score from the same findings.

The key words MUST, SHOULD, MAY are to be interpreted per BCP 14 (RFC 2119/8174).

---

## 1. Scope & entities

A **target** is any coordinate an agent can connect to: a GitHub repo, an npm/PyPI/crates
package, a Hugging Face model, a Docker image, an MCP server, or an OpenClaw skill. The
model scores the **published artifact** where one exists (`scan_depth = artifact`), else
the source repo.

The score answers one question: **"is it safe to connect?"** — a code-safety posture. It
is explicitly **not** an adoption or popularity signal (that is a separate, never-mixed
axis) and not a correctness or quality rating.

## 2. Detection categories

A scan runs **12 detection categories**. Each finding carries a `category`, a `severity`
(`critical` | `high` | `medium` | `low` | `info`), and a location (`file_path[:line]` or a
manifest entry). The categories:

| Category | What it detects |
|---|---|
| Secret hygiene | Exposed API keys, tokens, credentials |
| Code safety (unsafe exec) | Shell-outs, `eval`, dynamic code paths |
| Obfuscation | Hidden / deliberately unreadable payloads |
| Dynamic / remote load | Code fetched and executed at runtime |
| Hidden unicode | Bidi / homoglyph / zero-width tricks |
| Prompt injection | Surfaces where input can hijack the agent |
| Insecure deserialization | Unsafe `pickle`/`yaml`/`marshal`-style loads |
| Data handling / exfiltration | Where data goes; calls to external hosts |
| Toxic flow | Untrusted-input → sensitive-sink chains |
| Filesystem access | Unscoped file read/write |
| Dependency health | Known-vulnerable / malicious dependencies (OSV/deps.dev) |
| Artifact drift | Published bytes diverging from source (injected files, install hooks) |

## 3. Severity weights

First-party **code** findings deduct from the score by severity. Dependency findings use a
separate bounded penalty (§6), never the linear per-finding model (so a monorepo's
transitive tail can't floor a whole library).

| Severity | Code deduction |
|---|---|
| critical | **22** each — uncapped, never scaled, never discounted |
| high | 8 each |
| medium | 3 each |
| low / info | 0 (surfaced, not scored) |

Findings in tests / fixtures / examples count at a fraction (shipped-vs-non-shipped
weighting), so test noise can't tank the grade of what a target actually ships.

## 4. Composition

Let `C`, `H`, `M` be the (shipped-weighted) counts of critical / high / medium **code**
findings.

1. **Base.** `score = 84` if `C+H+M < 0.5` (clean), else `68`. Hygiene bonuses (§5) are
   deliberately small so documentation alone cannot lift an unsafe tool to the top.
2. **Critical deduction.** `crit_ded = 22 × C`. Uncapped, and **not** file-ratio-scaled —
   a single critical always bites, so a tool with a critical can never sit in the Trusted
   band.
3. **High/medium deduction.** `hm = 8×H + 3×M`, then **capped at 42** (a large trusted lib
   that legitimately repeats a pattern isn't floored by volume), then **file-ratio scaled**
   (`0.4` at ~1% of files affected → `1.0` at ≥25%).
4. `score -= crit_ded + hm_capped_scaled`.
5. **Dependency / supply-chain** penalty (§6), subtracted.
6. **Provenance** delta (§7) and **maintainer** delta (§7), added (both bounded, absent = 0).
7. **Positive signals**: `+3` each, capped `+9`. **Good practices**: README `+2`, LICENSE
   `+2`, tests `+2`. Inline-suppression deterrent: >3 suppressions cost `−3` each beyond 3.
8. **Clamp** to `[0, 100]`.

### 4.1 MCP / media tools — expected capabilities
An MCP server or media tool legitimately touches `fs_access` and `unsafe_exec`. For those
targets, **high/medium** findings *in those expected categories* deduct at **50%**. A
**critical is never discounted** — MCP or not, a critical deducts in full. (This replaced an
earlier rule that zeroed expected-category findings entirely, which let MCP servers with
critical findings score 100.)

## 5. Tiers & posture

The clamped score maps to a tier and a recommended execution posture a gateway MAY apply:

| Score | Tier (`trust_tier`) | Colour | Posture | Requests/min | Tokens/call | Confirmation |
|---|---|---|---|---|---|---|
| 96–100 | Verified (`verified`) | deep green | Connect normally · no limits | unlimited | unlimited | no |
| 81–95 | Trusted (`trusted`) | green | Auto-approve within budget | 60 | 8192 | no |
| 51–80 | Standard (`standard`) | light green | Standard rate + token limits | 30 | 4096 | no |
| 31–50 | Minimal (`minimal`) | amber | Confirm on sensitive calls | 15 | 2048 | yes |
| 11–30 | Restricted (`restricted`) | orange | Gated · manual approval | 5 | 1024 | yes |
| 0–10 | Blocked (`blocked`) | red | Do not connect | 0 | 0 | yes |

These are the six tiers the API has always emitted in `trust_tier` / `recommended_limits`
(`src/trust_tiers.py`); earlier revisions of this table listed a five-word display
scheme at different floors, which no surface shows any more.

Adoption is a **separate** axis (teal→magenta, never a safety colour) and never alters the
safety score.

**Unscannable** is distinct from a low score: a target that can't be fetched (empty /
private / unreachable) is `trust_score = null` / "fetch error", **not** a 0/Blocked grade.

## 6. Dependencies (bounded)

Dependency / install-hook findings map to `dependency_health` and use a bounded penalty
(not linear per-finding), so a known-malicious dependency floors the target while a long
tail of low-severity transitive advisories does not dominate. The `dependency_health`
category card mirrors this bounded penalty.

## 7. Additive signals (bounded)

- **Provenance** (Phase 3): a package whose build provenance verifies and binds artifact→
  source earns a small bonus; one that *claims* provenance but fails verification takes a
  small penalty; absent = 0 (never penalised).
- **Maintainer** (Phase 5): clear negatives (archived / abandoned) deduct a small, capped
  amount; positives fold into the positive-signals bonus. Absent = 0.

## 8. Certified (the gate)

**Certified** is not "a high score" — it is a **6-point conjunctive gate**. A target is
Certified only when **all** hold:

1. `artifact_scanned` — the published artifact was scanned, not just the repo.
2. `provenance_verified` — build provenance verifies **and** matches the source claim.
3. `no_drift` — no injected/modified files, no install hook.
4. `no_critical_or_high` — zero critical/high across code + supply chain; no known-malicious dep.
5. `recompute_ready` — a signed verdict with pinned snapshots.
6. `full_coverage` — not a sampled / truncated scan.

Certified is **revocable**: it holds only while every check holds, re-evaluated on every
scan. It gates the top label only — it never lowers a grade.

## 9. Attestation & recomputation

The canonical verdict (this model applied to the findings) is serialized with RFC 8785 JCS
and signed with Ed25519 (JWS / EdDSA, RFC 7515). Anyone holding the findings + this model +
the public JWKS can recompute the score byte-for-byte and verify the signature offline. The
score is the product; the signature is the proof under it.

## 10. Versioning

This is `safety-model-v1`. A change to any weight, threshold, tier boundary, or the
Certified gate is a new model version; scores carry the model version they were computed
under so a recompute uses the matching rules. Non-normative examples and notes may change
without a version bump.

## 11. The phrase layer (decision)

Every surface leads with one of three answers, derived from the scored result. The score,
tier and Certified verdict above are unchanged by it; it adds no input to sections 3–8.

| `decision` | Phrase | Short label |
|---|---|---|
| `safe` | Safe to connect | Safe |
| `review` | Review before you connect | Review |
| `do_not_connect` | Do not connect | Blocked |

Rule, first match wins:

1. `do_not_connect` — a canary credential left the behavioral sandbox; the scanned version
   is in an OpenSSF MAL advisory; a known-malicious dependency; a blocking critical defect
   (shipped, installed, `kind = defect`; a capability never counts); any other critical
   behavioral finding.
2. `review` — a blocking high defect; a high behavioral finding; a published advisory
   affecting the scanned version; a deprecated package; a trust score below 51; or fewer
   than 8 files scanned with no critical, high or medium finding.
3. `safe` — otherwise.

The decision is computed from the result after the signed behavioral observation is
applied (section 9), so phrase and score agree. Adoption is never an input. Advisory
behavioral results (a live probe, a run that did not happen, needed credentials, or timed
out) contribute no finding. While the sandbox run is pending, the decision comes from the
static evidence and is marked provisional (`decision_final = false`); it may move to
`review` when the run lands.

Each decision carries `decision_reason`, one sentence naming the triggering condition.
The decision is **unsigned**: it travels beside the signed verdict, derived from the same
scan result; it is not part of the JWS payload. Certified (section 8) is a separate
axis and is shown beside the phrase ("Safe to connect · Certified"). Reference
implementation: `src/scanner/verdict.py` (`decide`).

---

*Conformance: an implementation conforms when, given the same findings and signals, it
produces the same clamped score, tier, and Certified verdict as specified here. Reference
implementation: `src/scanner/scan.py` (`_calculate_trust_score`, `_certified_status`).*
