# Is this tool safe? Reading your AgentAvow scan

AgentAvow scans the tools, MCP servers, packages, and skills your AI agents connect to, and answers with one
of three phrases — **Safe to connect**, **Review before you connect**, or **Do not connect** — plus the reason,
backed by a **signed 0–100 trust score** you can verify yourself. This guide explains how to read a result.

## Run a check

No account, no install. Paste any of these into the check box, or hit the API directly:

- a GitHub repo — `github.com/owner/repo` or `owner/repo`
- an MCP server, an npm, PyPI or crates package, a Hugging Face model, or a Docker image
- an Agent Skill (`skill:owner/repo`); a repo holding many skills is graded skill by skill, and its result is
  the worst of them
- a wallet address (`0x…` or a Solana address); it opens the result for the repo linked to that wallet, or
  says the wallet isn't linked to a tool yet

```
GET https://agentavow.com/api/v1/public/scan/{owner}/{repo}
```

The result is cached for 1 hour. Add `?force=true` to force a fresh scan.

### Pin a version

A package scan reads the latest release unless you say otherwise. Add `?version=` to scan the exact release
you are about to install:

```
GET https://agentavow.com/api/v1/public/scan/package/{npm|pypi|crates|docker}/{name}?version=1.2.3
```

For npm, PyPI and crates that is the published version; for a container image it is the tag. The scan
runs on that release's bytes, and a published advisory (GHSA / PYSEC / CVE) against the package itself is
reported as a finding only when it affects the version scanned, with the fixed release named in the
remediation. In the [MCP connector](./mcp-connector.md), pin the same way inside the package name:
`chalk@5.3.0`, `@scope/name@1.2.3`, `requests==2.32.5`, `serde@1.0.200`.

## The answer

Every result leads with one answer and the one condition that triggered it (`decision` and
`decision_reason` in the response):

- **Safe to connect** (`safe`, short label *Safe*) — nothing blocking found, e.g. "nothing found in 340 files".
  A clean scan of very little code also reads Safe, with the reason "nothing found; little code to
  inspect" (or, for a remote MCP server, "tool definitions clean; server code not inspected"), and its
  score stays capped at 74 or 82.
- **Review before you connect** (`review`, *Review*) — a high finding in the code or the sandbox, a published
  advisory affecting the version scanned, a deprecated package, or a score under 51.
- **Do not connect** (`do_not_connect`, *Blocked*) — a critical finding, a planted credential leaving the
  sandbox, a critical sandbox finding, or a known-malicious package or dependency.

The popularity of a tool never changes the answer. While the sandbox is still running the reason ends
"sandbox still running" and `decision_final` is `false`; the answer can move once the run lands. The exact
rule is in [How scoring works](./how-grading-works.md#the-answer-three-phrases).

## The score

Under the answer sits the evidence: a **0–100 trust score** and the separate adoption score. The subscores
tell you *why* the trust score is what it is. It maps to one of **six tiers**, shown as detail — the
`trust_tier` field in the response (higher is safer). A tier sets a recommended execution posture (rate
limit, token budget, whether to confirm each call); **the answer, not the tier, says whether to connect.**

- **96–100 · Verified** (`verified`) — connect normally, no limits.
- **81–95 · Trusted** (`trusted`) — auto-approve within budget (60 requests/min, 8,192 tokens).
- **51–80 · Standard** (`standard`) — standard rate and token limits (30/min, 4,096).
- **31–50 · Minimal** (`minimal`) — confirm on sensitive calls (15/min, 2,048).
- **11–30 · Restricted** (`restricted`) — gated, manual approval (5/min, 1,024).
- **0–10 · Blocked** (`blocked`) — no calls.

A tier and the answer can differ: a tool with one high finding can still score in the Trusted band and read
Review before you connect, and a shipped critical caps the score at 45 (Minimal) while the answer is Do not
connect.

**Certified** is not a score band and not one of the three answers. It rides beside the answer ("Safe to
connect · Certified") and is a separate set of checks the response reports under
`certified.checks` — the published artifact was scanned, build provenance is verified, no drift, no
critical or high finding, the verdict recomputes offline, and the whole tree was read — and every check must
pass. The mark itself shows only beside Safe to connect, at a score of 81 or above, once the sandbox result is
in and with 8 or more files inspected; the response carries that display value as `certified_mark` (see
[How scoring works](./how-grading-works.md)).

### Subscores

The trust score is computed from the findings themselves (penalties by severity, with ceilings for blocking
findings), not averaged from the subscores. Alongside it, five subscores are reported as independent axes so
you can see where the findings land:

- **Secret hygiene** — hardcoded tokens, keys, credentials
- **Code safety** — unsafe `exec`/shell, obfuscation, prompt injection, remote code loading, insecure deserialization, published advisories
- **Data handling** — exfiltration surfaces, toxic capability combinations
- **Filesystem access** — unrestricted file reads and writes
- **Dependency health** — known-vulnerable or malicious dependencies, install hooks, deprecated packages

Each finding carries a finer category (`prompt_injection`, `exfiltration`, `install_hook`, …) that maps onto
one of these five axes.

## Score → recommended posture

Each tier maps to a **recommended execution posture** — returned as `recommended_limits` (requests per
minute, max tokens per call, whether to confirm first) — so a gateway or framework can act on it automatically:

- **Verified** — connect normally; no limits.
- **Trusted** — auto-approve within budget: 60 requests/min, 8192 tokens/call, no confirmation.
- **Standard** — standard rate + token limits: 30 requests/min, 4096 tokens/call, no confirmation.
- **Minimal** — confirm before sensitive tool calls: 15 requests/min, 2048 tokens/call.
- **Restricted** — human-in-the-loop; no autonomous execution: 5 requests/min, 1024 tokens/call, confirm every call.
- **Blocked** — execution denied.

## Findings

Each finding lists a **severity** (critical / high / medium / low), the category, and where it was found.
A finding is evidence, not an opinion — it points at the exact line or manifest entry. This is the "review"
of a tool: recomputable scan evidence, not a star rating.

**Deprecated packages.** If the maintainer has retired an npm or PyPI package (npm `deprecated`, a yanked
PyPI release, or the `Development Status :: 7 - Inactive` classifier), you'll see a **medium maintenance
finding** quoting their message and a deprecation banner on the result, and the answer reads **Review before
you connect**. No more security fixes are coming, so don't adopt it for new work.

False positive? See [how scoring works](./how-grading-works.md).

## Declare your tool's scope (optional)

Own the tool? Drop an [`.agentavow.yml`](https://github.com/AgentAvow/AgentAvow/blob/main/.agentavow.yml) at your
repo root declaring the hosts it contacts and the capabilities it uses — AgentAvow surfaces it on your score page
as **Declared scope**, and the behavioral tier holds the tool to it: any egress it didn't declare becomes a finding.

## The sandbox result

For npm and PyPI packages, container images, and MCP servers published as packages, AgentAvow also **runs**
the tool in an isolated gVisor sandbox the first time it is scanned. An MCP server is started and **every tool is
called** with synthetic arguments; the environment variables the tool reads hold **canary credentials** (fake,
unique values). The result panel shows which tools were exercised, the hosts the tool contacted, the files it
wrote, and any behavioral findings: undeclared egress, a read-only tool that wrote files, a canary that left the
machine (critical), or a secret returned in a tool result. If a server could not be started, the panel says why
(for example `needs_credentials` or `missing_binary`); that is never a finding.

Each run is signed as a **BehavioralObservation** (same key as the score) and shown beside the score. The panel
fills in on its own while a run is in progress; press **Run now** (or **Re-run behavioral analysis**) to force a
fresh run.

See [Behavioral sandbox](./behavioral-sandbox.md) for what the sandbox runs, observes, and never does.

## Shareable results & the signature

Every result lives at a shareable URL — `agentavow.com/check/{owner}/{repo}` — and ships with a **signed JWS
attestation** (EdDSA) anyone can verify offline against our public keys. You don't have to trust the number;
you can recompute it. See [Verify an AgentAvow attestation](./verify-attestations.md).

## Stay safe over time

Tools change after you vet them. **Watch** a tool and we re-scan it and alert you the moment its score drops
or its signed definition changes (every alert leads with the tool's current answer) — the rug-pull you'd otherwise miss. For an MCP server the attestation pins
one digest per served tool (`scan.toolDigests`, keyed `tool:<name>`) plus a digest of the whole set, and a
re-scan reports `toolDrift` — which tools were added, removed or changed since the last grade — so you can
see exactly what moved, not just that something did. A gate can recompute the digest of the tool it is about
to call from the server's own `tools/list` and refuse on mismatch; see
[Verify an AgentAvow attestation](./verify-attestations.md#tool-definitions-per-tool-digests-and-drift). Once the sandbox has run a watched tool, a
later run that adds behavioral findings (a leaked canary, a new undeclared host) raises an alert too.

In CI, the [GitHub Action](https://github.com/AgentAvow/AgentAvow/tree/main/github-action) prints the answer
first, then a `Sandbox:` line with the result; it fails the build on **Do not connect** by default
(`fail_on`), and `fail_on_behavioral: true` also fails it on a high or critical sandbox finding. See
[Gate on the answer](./gate-on-the-grade.md).

## Next

- [Add a trust badge to your README](./trust-badges.md)
- [Verify an AgentAvow attestation](./verify-attestations.md)
- Browse the [trust catalog](https://agentavow.com/browse)
