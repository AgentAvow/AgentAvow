# How scoring works

AgentAvow answers one question: **is this tool safe for your agent to connect to?** We point a scanner at a tool — a GitHub repo, a package (npm, PyPI, crates), a Hugging Face model, a container image, a live MCP server, or an Agent Skill — and return a **signed, offline-verifiable 0–100 trust score** with the findings behind it.

The score is the product. **The signature under it is the proof.** Anyone can recompute the verdict byte-for-byte and check it against our public keys, without trusting us.

## Two separate scores

We publish **two** scores and never mix them:

- **Trust** — *is it safe?* The signed 0–100 score, from static analysis + supply-chain + provenance.
- **Adoption** — *do real, independent parties rely on it?* A distinct signal (with "rising" vs "established" states) from downloads, reverse-dependents, stars, and first-party data.

A widely-adopted tool can still be a serious trust risk (bigger blast radius, not higher trust). A pristine unknown can be top-tier **Trusted** with near-zero adoption. **Popular is not the same as safe** — so adoption never raises the trust score. It only weights how *grave* a finding is (a CVE in a package with 40k dependents matters more than one with none).

## The trust score: 0–100

The score maps to a **tier** and a recommended execution posture (rate limits, token budget, confirmation prompts):

- **80–100 · Trusted** — connect normally.
- **60–79 · Standard** — standard rate + token limits.
- **40–59 · Caution** — confirm on sensitive calls.
- **20–39 · Restricted** — gated, manual approval.
- **0–19 · Blocked** — do not connect.

A **Blocked** score and any **known-malicious (MAL)** dependency block execution.

### Certified — the earned top tier

**Certified is a distinct, cryptographically-earned tier** — not just a high number. A clean 100 we only saw the *repo* for is **Trusted, not Certified**. Certification requires **all six** of:

1. We scanned the **published artifact**, not just the repo.
2. **Build provenance is verified** and cryptographically bound to the source (Sigstore / PEP-740).
3. **No drift** — the artifact matches its source; no install-time hooks.
4. **Zero critical/high** findings, and no known-malicious dependency.
5. The signed verdict **recomputes offline** against its pinned snapshots.
6. **No coverage gaps** — not a sampled scan.

Certification is **re-checked every scan and is revocable**: if provenance expires, drift appears, or a new critical lands, certification is revoked automatically. "Certified" means *currently, verifiably true* — not "was true once." It is not buyable, not self-attested, and not reachable by a repo-only scan no matter how clean.

## Coverage & offline recompute

Every verdict carries a **coverage block** stating exactly what was measured: the surface, the scan depth (`repo-only` / `artifact` / `artifact+live`), the exact artifact digest, the provenance binding, and the dated snapshot of every external database consulted (OSV export, registry timestamp, Rekor index). That's what makes the score **recomputable** — pin the bytes and the DB dates, and any verifier re-derives the identical verdict and checks the signature against our public JWKS. See **Verify an attestation**.

## Supply-chain scoring

Dependencies are checked against a real vulnerability database (OSV) across the full resolved tree — not a regex list. Vulnerabilities apply a **bounded, saturating penalty** (a CVE-class hit is capped; it can't false-fail a healthy package on transitive noise), while a **known-malicious (MAL) package is disqualifying**. Dev-only dependencies are excluded — a consumer never installs them.

## The surfaces we score

Point AgentAvow at anything your agent connects to — a repo, a package on four registries, a model, a container, a live server, or a skill:

- **GitHub repo** (`github.com/owner/repo`) — the 12-category static scan of the source. Large monorepos are scored on a **shipped-code-first sample** (test/vendored files ranked last), disclosed as `sampled`.
- **npm package** (`npm:chalk`) — the **published artifact**: real bytes, drift vs source, install-hook detection, and its build provenance.
- **PyPI package** (`pypi:requests`) — the published sdist/wheel: real bytes, `setup.py` install-exec, drift, and provenance.
- **crates (Rust)** (`crates:serde`) — the published `.crate`, the real extracted tree through the same engine.
- **Hugging Face model** (`hf:org/model`) — the model card, configs, and any custom `modeling_*.py` — **plus a census of the weight format**: pickle-backed weights (`.bin`/`.pt`/`.ckpt`) execute arbitrary code on load, so they raise an `insecure_deserialization` finding (a safetensors copy lowers it).
- **Container image** (`docker:nginx`, `ghcr.io/org/img`) — the **image config** (runs-as-root, secrets baked into `ENV`/labels, exposed SSH, a stale base) **plus a bounded scan of the actual layer filesystem** (the 12-category engine over the code baked into the image, newest layers first).
- **MCP server** (`mcp:https://…`) — the **live tool surface** it actually serves: schema risk, hidden instructions in tool descriptions, dangerous-capability taxonomy + the lethal trifecta, annotation truthfulness.
- **Agent Skill (OpenClaw)** (`owner/repo`) — the capability manifest: the `allowed-tools` **auto-exec grant**, always-loaded-description injection, lifecycle-hook escalation, and credential-exfil in bundled scripts.

Every published surface is scanned on the **real artifact bytes** (`scan_depth = artifact`), so its score recomputes offline against the exact digest. Today **Certified** (verified provenance) is reachable for **npm & PyPI** — the ecosystems that publish Sigstore / PEP-740 provenance we can cryptographically bind to source. crates, Hugging Face, and containers are artifact-scored and can reach a top score, but can't be Certified yet — only because there's no provenance to verify, not because of any finding.

## Add it to your agent

Every score page has an **"Add to your agent"** button — the scored tool, ready to connect. **One click for Cursor, VS Code, or Goose** for any MCP server, whether it's a live endpoint or a package that runs one (`npx`/`uvx`) — plus copy commands for Claude Code, Gemini, and Codex. Other surfaces get the right install for what they are: `npm`/`pip`/`cargo add` for packages, `from_pretrained` / the hub CLI for models, `docker pull` for images, a clone for skills. The score travels with the install.

## Adoption, per surface

The second score is real and surface-specific — never a fabricated number. npm/PyPI use registry downloads + reverse-dependents; crates and Hugging Face use downloads (and HF likes); containers use Docker Hub pulls; repos, MCP servers, and skills use GitHub stars. A live MCP endpoint with no repo behind it shows **no adoption signal** rather than a guess. Adoption sorts the catalog ("widely relied upon") and weights finding gravity — it never moves the trust score.
