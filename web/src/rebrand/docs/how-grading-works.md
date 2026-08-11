# How grading works

AgentAvow answers one question: **is this tool safe for your agent to connect to?** We point a scanner at a tool — a GitHub repo, an npm or PyPI package, a live MCP server, or an Agent Skill — and return a **signed, offline-verifiable A+→F grade** with the findings behind it.

The grade is the product. **The signature under it is the proof.** Anyone can recompute the verdict byte-for-byte and check it against our public keys, without trusting us.

## Two separate scores

We publish **two** scores and never mix them:

- **Trust** — *is it safe?* The signed A+→F letter, from static analysis + supply-chain + provenance.
- **Adoption** — *do real, independent parties rely on it?* A distinct score (with "rising" vs "established" badges) from downloads, reverse-dependents, stars, and first-party signals.

A widely-adopted tool can still be a serious trust risk (bigger blast radius, not higher trust). A pristine unknown can be A-grade trust with near-zero adoption. **Popular is not the same as safe** — so adoption never raises the trust letter. It only weights how *grave* a finding is (a CVE in a package with 40k dependents matters more than one with none).

## The trust grade: A+ → F

The letter maps to a 0–100 score and a recommended execution posture (rate limits, token budget, confirmation prompts). **F and "known-malicious" (MAL) dependencies block execution.**

### A+ is "Certified" — earned, not just a high score

**A+ is a distinct, cryptographically-earned tier.** A clean 100 that we only saw the *repo* for is an **A, not an A+**. A+ requires **all six** of:

1. We scanned the **published artifact**, not just the repo.
2. **Build provenance is verified** and cryptographically bound to the source (Sigstore / PEP-740).
3. **No drift** — the artifact matches its source; no install-time hooks.
4. **Zero critical/high** findings, and no known-malicious dependency.
5. The signed verdict **recomputes offline** against its pinned snapshots.
6. **No coverage gaps** — not a sampled scan.

Certification is **re-checked every scan and is revocable**: if provenance expires, drift appears, or a new critical lands, the tier drops from A+ to A automatically. "Certified" means *currently, verifiably true* — not "was true once." It is not buyable, not self-attested, and not reachable by a repo-only scan no matter how clean.

## Coverage & offline recompute

Every verdict carries a **coverage block** stating exactly what was measured: the surface, the scan depth (`repo-only` / `artifact` / `artifact+live`), the exact artifact digest, the provenance binding, and the dated snapshot of every external database consulted (OSV export, registry timestamp, Rekor index). That's what makes the grade **recomputable** — pin the bytes and the DB dates, and any verifier re-derives the identical verdict and checks the signature against our public JWKS. See **Verify an attestation**.

## Supply-chain scoring

Dependencies are checked against a real vulnerability database (OSV) across the full resolved tree — not a regex list. Vulnerabilities apply a **bounded, saturating penalty** (a CVE-class hit is capped; it can't false-fail a healthy package on transitive noise), while a **known-malicious (MAL) package is disqualifying**. Dev-only dependencies are excluded — a consumer never installs them.

## The surfaces we grade

| Surface | What we grade |
|---|---|
| **GitHub repo** | The 12-category static scan of the source. |
| **npm / PyPI package** | The **published artifact** by coordinate (`npm:chalk`, `pypi:requests`) — real bytes, drift vs source, and its build provenance. This is where **A+** is earned. |
| **MCP server** | The **live tool surface** it actually serves — schema risk, hidden instructions in tool descriptions, dangerous-capability taxonomy + the lethal trifecta, annotation truthfulness. |
| **Agent Skill (OpenClaw)** | The capability manifest — the `allowed-tools` **auto-exec grant**, always-loaded-description injection, lifecycle-hook escalation, and credential-exfil in bundled scripts. |

## Add it to your agent

Every score page has an **"Add to your agent"** button — the graded tool, ready to connect. One click for Cursor, VS Code, or Goose (MCP servers); copy commands for Claude Code, Gemini, and Codex; the install one-liner for packages; the clone command for skills. The grade travels with the install.
