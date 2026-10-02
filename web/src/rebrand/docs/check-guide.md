# Is this tool safe? Reading your AgentAvow scan

AgentAvow scans the tools, MCP servers, packages, and skills your AI agents connect to, and returns a
**signed 0–100 safety score** you can verify yourself. This guide explains what the score means and how to
read a result.

> Staged rebrand doc. Product/serving URLs use `agentavow.com` (the post-cutover host). Verification
> identifiers (JWKS, `@context`) stay on `agentgraph.co` — those are permanent and never move.

## Run a check

No account, no install. Paste any of these into the check box, or hit the API directly:

- a GitHub repo — `github.com/owner/repo` or `owner/repo`
- an MCP server, an npm or PyPI package, an OpenClaw skill
- a wallet address (resolves to the linked agent's repo scan)

```
GET https://agentavow.com/api/v1/public/scan/{owner}/{repo}
```

The result is cached for 1 hour. Add `?force=true` to force a fresh scan.

## The score

Every scan returns a single **0–100 trust score**. The score is the headline; the subscores tell you *why*.
It maps to a **tier** (higher is safer):

- **80–100 · Trusted** — no high or critical findings, clean dependencies.
- **60–79 · Standard** — minor issues; safe for most uses.
- **40–59 · Caution** — real findings worth reviewing before you connect.
- **20–39 · Restricted** — high-severity issues present; human-in-the-loop.
- **0–19 · Blocked** — critical issues; do not connect.

The earned top tier, **Certified**, is separate — a score of 96+ *plus* verified provenance, no drift, and full
coverage (see [How scoring works](./how-grading-works.md)).

### Subscores

The overall score is composed from category subscores, each independently scored:

- **Secret hygiene** — hardcoded tokens, keys, credentials
- **Code safety** — unsafe `exec`/shell, dangerous sinks
- **Data handling** — exfiltration surfaces, over-broad permissions
- **Dependencies** — known-vulnerable packages
- …across **12 detection categories** total.

## Score → recommended posture

Each tier maps to a **recommended execution posture**, so a gateway or framework can act on it automatically:

- **Trusted** — connect normally, standard budget.
- **Standard** — standard rate + token limits.
- **Caution** — confirm before sensitive tool calls.
- **Restricted** — human-in-the-loop; no autonomous execution.
- **Blocked** — execution denied.

## Findings

Each finding lists a **severity** (critical / high / medium / low), the category, and where it was found.
A finding is evidence, not an opinion — it points at the exact line or manifest entry. This is the "review"
of a tool: recomputable scan evidence, not a star rating.

**Deprecated packages.** If the maintainer has retired an npm or PyPI package (npm `deprecated`, a yanked
PyPI release, or the `Development Status :: 7 - Inactive` classifier), you'll see a **medium maintenance
finding** quoting their message and a deprecation banner on the result. It lowers the score but is not a
blocker. No more security fixes are coming, so don't adopt it for new work.

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
or its signed definition changes — the rug-pull you'd otherwise miss. Once the sandbox has run a watched tool, a
later run that adds behavioral findings (a leaked canary, a new undeclared host) raises an alert too.

In CI, the [GitHub Action](https://github.com/AgentAvow/AgentAvow/tree/main/github-action) prints a `Sandbox:`
line with the result, and `fail_on_behavioral: true` fails the build on a high or critical sandbox finding.

## Next

- [Add a trust badge to your README](./trust-badges.md)
- [Verify an AgentAvow attestation](./verify-attestations.md)
- Browse the [trust catalog](https://agentavow.com/browse)
