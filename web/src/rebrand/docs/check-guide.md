# Is this tool safe? Reading your AgentAvow scan

AgentAvow scans the tools, MCP servers, packages, and skills your AI agents connect to, and returns a
**signed safety grade** you can verify yourself. This guide explains what the grade means and how to read a
result.

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

## The grade

Every scan returns a single **letter grade (A+ → F)** plus a 0–100 score. The grade is the headline; the
subscores tell you *why*.

- **A+ / A** — Trusted: no high or critical findings, clean dependencies
- **B** — Good: minor issues, safe for most uses
- **C** — Caution: real findings worth reviewing before you connect
- **D** — Risky: high-severity issues present
- **F** — Blocked: critical issues; do not connect

### Subscores

The overall grade is composed from category subscores, each independently graded:

- **Secret hygiene** — hardcoded tokens, keys, credentials
- **Code safety** — unsafe `exec`/shell, dangerous sinks
- **Data handling** — exfiltration surfaces, over-broad permissions
- **Dependencies** — known-vulnerable packages
- …across **12 detection categories** total.

## Trust tiers → recommended limits

Each grade maps to a **trust tier** with a recommended execution posture, so a gateway or framework can act
on it automatically:

- `verified` (96–100) — unlimited execution
- `trusted` (81–95) — 60 req/min, 8K tokens
- `standard` (51–80) — 30 req/min, 4K tokens
- `minimal` (31–50) — 15 req/min, user confirmation
- `restricted` (11–30) — 5 req/min, user confirmation
- `blocked` (0–10) — execution denied

## Findings

Each finding lists a **severity** (critical / high / medium / low), the category, and where it was found.
A finding is evidence, not an opinion — it points at the exact line or manifest entry. This is the "review"
of a tool: recomputable scan evidence, not a star rating.

False positive? See [Scan false positives & suppression](./security-scan-false-positives.md).

## Shareable results & the signature

Every result lives at a shareable URL — `agentavow.com/check/{owner}/{repo}` — and ships with a **signed JWS
attestation** (EdDSA) anyone can verify offline against our public keys. You don't have to trust the number;
you can recompute it. See [Verify an AgentAvow attestation](./verify-attestations.md).

## Stay safe over time

Tools change after you vet them. **Watch** a tool and we re-scan it and alert you the moment its grade drops
or its signed definition changes — the rug-pull you'd otherwise miss.

## Next

- [Add a trust badge to your README](./trust-badges.md)
- [Verify an AgentAvow attestation](./verify-attestations.md)
- Browse the [trust catalog](https://agentavow.com/browse)
