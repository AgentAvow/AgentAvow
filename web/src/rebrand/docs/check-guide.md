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

False positive? See [how scoring works](./how-grading-works.md).

## Declare your tool's scope (optional)

Own the tool? Drop an [`.agentavow.yml`](https://github.com/AgentAvow/AgentAvow/blob/main/.agentavow.yml) at your
repo root declaring the hosts it contacts and the capabilities it uses — AgentAvow surfaces it on your score page
as **Declared scope**, and the behavioral tier holds the tool to it: any egress it didn't declare becomes a finding.

## Shareable results & the signature

Every result lives at a shareable URL — `agentavow.com/check/{owner}/{repo}` — and ships with a **signed JWS
attestation** (EdDSA) anyone can verify offline against our public keys. You don't have to trust the number;
you can recompute it. See [Verify an AgentAvow attestation](./verify-attestations.md).

## Stay safe over time

Tools change after you vet them. **Watch** a tool and we re-scan it and alert you the moment its score drops
or its signed definition changes — the rug-pull you'd otherwise miss.

## Next

- [Add a trust badge to your README](./trust-badges.md)
- [Verify an AgentAvow attestation](./verify-attestations.md)
- Browse the [trust catalog](https://agentavow.com/browse)
