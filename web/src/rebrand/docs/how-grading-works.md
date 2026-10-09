# How scoring works

AgentAvow answers one question: **is this tool safe for your agent to connect to?** We point a scanner at a tool — a GitHub repo, a package (npm, PyPI, crates), a Hugging Face model, a container image, a live MCP server, or an Agent Skill — and answer with one of three phrases and the one reason behind it. Under the answer sit the evidence: a **signed, offline-verifiable 0–100 trust score**, the adoption score, and the findings.

**The signature under it is the proof.** Anyone can recompute the verdict byte-for-byte and check it against our public keys, without trusting us.

## The answer: three phrases

| Answer | Short label | `decision` | When |
|---|---|---|---|
| **Safe to connect** | Safe | `safe` | nothing below applies, including a clean scan of very little code (the reason says so) |
| **Review before you connect** | Review | `review` | a high finding, a published advisory on this version, a deprecated package, or a score under 51 |
| **Do not connect** | Blocked | `do_not_connect` | a critical finding, a planted credential leaving the sandbox, a critical sandbox finding, or a known-malicious package |

The reason always rides next to the phrase: "one high finding: undeclared network call", "nothing found in 1,200 files", "nothing found; little code to inspect", "a planted credential left the sandbox". The API returns it as `decision_reason`.

The rule, in the order it is checked (the first match wins):

1. **Do not connect** — a canary credential left the [sandbox](./behavioral-sandbox.md); this version is listed as malicious (OpenSSF MAL advisory); a known-malicious dependency; a blocking critical finding in the code (shipped, installed, a defect — never a capability); any other critical sandbox finding.
2. **Review before you connect** — a blocking high finding in the code; a high sandbox finding (undeclared network call, an internal address fetched, a read-only tool that wrote files); a published advisory that affects the scanned version; a deprecated package; or a trust score under 51.
3. **Safe to connect** — everything else. When fewer than 8 files were scanned and nothing critical, high or medium was found, the answer is still Safe and the reason says so: "nothing found; little code to inspect". For a remote MCP server, where we read the tool definitions it serves and not its code, the reason is "tool definitions clean; server code not inspected". The trust score stays capped at 74 (3 files or fewer) or 82 (4 to 7 files), so the thin evidence still shows in the number.

Adoption is never an input. Advisory results never count either: a live probe of a remote server, a sandbox that did not run, needed credentials or timed out adds no finding. While the sandbox is still running, the answer comes from the static scan, says "sandbox still running", and carries `decision_final: false`; it can move to Review when the run lands, shown as an update.

The answer is unsigned and sits beside the signed verdict; the score, tier and findings it reads are the signed ones. Certified is a separate axis: a Certified tool reads **Safe to connect · Certified**.

## Two separate scores

We publish **two** scores and never mix them:

- **Trust** — *is it safe?* The signed 0–100 score, from static analysis + supply-chain + provenance.
- **Adoption** — *do real, independent parties rely on it?* A distinct signal (with "rising" vs "established" states) from downloads, reverse-dependents, stars, and first-party data.

A widely-adopted tool can still be a serious trust risk (bigger blast radius, not higher trust). A pristine unknown can be top-tier **Trusted** with near-zero adoption. **Popular is not the same as safe** — so adoption is never an input to the trust score or the three-phrase answer. A CVE costs the same points in a package with 40k dependents as in one with none. Adoption is the second score, reported beside the first: it tells you how many independent parties rely on the tool, which is what is at stake if the trust score is wrong.

## The trust score: 0–100

The score is evidence under the answer. It also maps to one of **six tiers** (the API's `trust_tier`), shown as detail, and a recommended execution posture (`recommended_limits`: requests per minute, token budget per call, whether to confirm first):

- **96–100 · Verified** — connect normally; no limits.
- **81–95 · Trusted** — auto-approve within budget (60 requests/min, 8192 tokens/call).
- **51–80 · Standard** — standard rate + token limits (30 requests/min, 4096 tokens/call).
- **31–50 · Minimal** — confirm on sensitive calls (15 requests/min, 2048 tokens/call).
- **11–30 · Restricted** — gated, manual approval (5 requests/min, 1024 tokens/call).
- **0–10 · Blocked** — execution denied (0 requests/min, 0 tokens).

The tier tells a gateway how hard to throttle; the phrase tells a person what to do. A known-malicious (MAL) dependency is **Do not connect** whatever the score.

### Findings vs. capabilities

Every static finding carries a `kind`. A **defect** is something a reviewer would agree is wrong — a shell command built from a variable, `node -e` / `python -c` with dynamic code, a `curl … | sh`, a PEM key body, a payload decoded and exec'd — and it moves the trust score. A **capability** is something the tool *does* — runs a fixed command (`git status`), evaluates its own expressions, writes a file at a path you give it, unpickles its own cache — and is listed in `capabilities` so you can see it, but it never moves the score and never blocks. A finding in a file a consumer never installs (an sdist's `Makefile`, `scripts/`, `bench/`; anything absent from the wheel) is reported with `installed: false` and is informational only.

### Certified — the earned top tier

**Certified is a distinct, cryptographically-earned tier** — not just a high number. A clean 100 we only saw the *repo* for is **Trusted, not Certified**. Certification requires **all six** of:

1. We scanned the **published artifact**, not just the repo.
2. **Build provenance is verified** and cryptographically bound to the source (Sigstore / PEP-740).
3. **No drift** — the artifact matches its source; no install-time hooks.
4. **Zero critical/high** findings, and no known-malicious dependency.
5. The signed verdict **recomputes offline** against its pinned snapshots.
6. **Complete scan** — the whole tree was read, not sampled or truncated.

Certification is **re-checked every scan and is revocable**: if provenance expires, drift appears, or a new critical lands, certification is revoked automatically. "Certified" means *currently, verifiably true* — not "was true once." It is not buyable, not self-attested, and not reachable by a repo-only scan no matter how clean.

See the [**Certified page**](/certified) for the live gate, the hard disqualifiers, and the tools that are Certified today.

## Coverage & offline recompute

Every verdict carries a **coverage block** stating exactly what was measured: the surface, the scan depth (`repo-only` / `artifact` / `artifact+live`), the exact artifact digest, the provenance binding, and the dated snapshot of every external database consulted (OSV export, registry timestamp, Rekor index). That's what makes the score **recomputable** — pin the bytes and the DB dates, and any verifier re-derives the identical verdict and checks the signature against our public JWKS. See **Verify an attestation**.

## Supply-chain scoring

Dependencies are checked against a real vulnerability database (OSV) across the full resolved tree — not a regex list. Vulnerabilities apply a **bounded, saturating penalty** (a CVE-class hit is capped; it can't false-fail a healthy package on transitive noise), while a **known-malicious (MAL) package is disqualifying**. Dev-only dependencies are excluded — a consumer never installs them.

## Deprecated packages

A package can be clean and still a bad choice: its maintainer has retired it and no security fixes are coming. When the registry carries that signal, the scan reports it as a **medium maintenance finding** (dependency-health axis) that quotes the maintainer's message:

- **npm** — the resolved version is marked `deprecated`.
- **PyPI** — the release is **yanked** (with its reason, when given), or the project carries the `Development Status :: 7 - Inactive` classifier.

The finding lowers the score like any medium finding, and the answer reads **Review before you connect** ("the maintainer has deprecated this package"). It does not cap the score the way a critical does. The score page shows a deprecation banner, and the MCP server and Claude Code plugin lead with "deprecated by its maintainer" instead of "clean". GitHub repos already carry the equivalent signal when the repo is **archived**.

## The behavioral sandbox

Static analysis reads a tool. For packages and MCP servers we also **run** it: a fresh gVisor container installs it, starts an MCP server and calls every tool with synthetic arguments, and plants canary credentials in the environment variables it reads. The result (hosts contacted, files written, tool calls, findings) is signed as a separate **BehavioralObservation** with the same key as the score, and shown beside the score on the result page. The signed observation is also an input to the trust score by fixed rules: a leaked canary credential or critical behavioral finding caps the score at 45, a high finding costs 10 and caps it at 70, and a clean full exercise adds 3. The attestation records the evidence so the number stays recomputable. Details, and what a clean run does and does not prove, are in [Behavioral sandbox](./behavioral-sandbox.md#how-the-sandbox-moves-the-score).

## The surfaces we score

Point AgentAvow at anything your agent connects to — a repo, a package on four registries, a model, a container, a live server, or a skill:

- **GitHub repo** (`github.com/owner/repo`) — the static scan of the source. Large monorepos are scored on a **shipped-code-first sample** (test/vendored files ranked last), disclosed as `sampled`.
- **npm package** (`npm:chalk`) — the **published artifact**: real bytes, drift vs source, install-hook detection, and its build provenance.
- **PyPI package** (`pypi:requests`) — the published sdist/wheel: real bytes, `setup.py` install-exec, drift, and provenance.
- **crates (Rust)** (`crates:serde`) — the published `.crate`, the real extracted tree through the same engine.
- **Hugging Face model** (`hf:org/model`) — the model card, configs, and any custom `modeling_*.py` — **plus a census of the weight format**: pickle-backed weights (`.bin`/`.pt`/`.ckpt`) execute arbitrary code on load, so they raise an `insecure_deserialization` finding (a safetensors copy lowers it).
- **Container image** (`docker:nginx`, `ghcr.io/org/img`) — the **image config** (runs-as-root, secrets baked into `ENV`/labels, exposed SSH, a stale base) **plus a bounded scan of the actual layer filesystem** (the same static engine over the code baked into the image, newest layers first).
- **MCP server** (`mcp:https://…`) — the **live tool surface** it actually serves: schema risk, hidden instructions in tool descriptions, dangerous-capability taxonomy + the lethal trifecta, annotation truthfulness.
- **Agent Skill (OpenClaw)** (`owner/repo`) — the capability manifest: the `allowed-tools` **auto-exec grant**, always-loaded-description injection, lifecycle-hook escalation, and credential-exfil in bundled scripts.

Every published surface is scanned on the **real artifact bytes** (`scan_depth = artifact`), so its score recomputes offline against the exact digest. Today **Certified** (verified provenance) is reachable for **npm & PyPI** — the ecosystems that publish Sigstore / PEP-740 provenance we can cryptographically bind to source. crates, Hugging Face, and containers are artifact-scored and can reach a top score, but can't be Certified yet — only because there's no provenance to verify, not because of any finding.

## Add it to your agent

Every score page has an **"Add to your agent"** button — the scored tool, ready to connect. **One click for Cursor, VS Code, or Goose** for any MCP server, whether it's a live endpoint or a package that runs one (`npx`/`uvx`) — plus copy commands for Claude Code, Gemini, and Codex. Other surfaces get the right install for what they are: `npm`/`pip`/`cargo add` for packages, `from_pretrained` / the hub CLI for models, `docker pull` for images, a clone for skills. The score travels with the install.

## Adoption, per surface

The second score is real and surface-specific — never a fabricated number. npm/PyPI use registry downloads + reverse-dependents; crates and Hugging Face use downloads (and HF likes); containers use Docker Hub pulls; repos, MCP servers, and skills use GitHub stars. A live MCP endpoint with no repo behind it shows **no adoption signal** rather than a guess. Adoption sorts the catalog ("widely relied upon") and is shown beside the trust score — it never moves it.
