# AgentAvow Trust Scan - GitHub Action

Check the security posture of any public repository using the [AgentAvow](https://agentavow.com) trust infrastructure. Every pull request gets an automated trust scan comment that leads with one of three answers — **Safe to connect**, **Review before you connect**, or **Do not connect** — and the one reason behind it, with both scores (the 0–100 trust score and the adoption score), the category breakdown and actionable findings underneath.

No API key required. Works on any public repository.

## Quick Start

Add this to `.github/workflows/trust-scan.yml` in your repository:

```yaml
name: AgentAvow Trust Scan

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  pull-requests: write

jobs:
  trust-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: AgentAvow/AgentAvow/github-action@main
```

That's it. Every PR will now receive a trust scan comment, and the check fails when the
answer is **Do not connect**.

## The three answers

| Answer | When | `decision` |
|--------|------|------------|
| **Safe to connect** | nothing blocking found, including a clean scan of very little code (the reason says so) | `safe` |
| **Review before you connect** | a high finding (code or sandbox), a published advisory on this version, a deprecated package, or a score under 51 | `review` |
| **Do not connect** | a critical finding, a planted credential leaving the sandbox, or a known-malicious dependency | `do_not_connect` |

The answer always comes with its reason ("one high finding: undeclared network call").
The six trust tiers (Verified … Blocked) are shown underneath as detail. A Certified
tool reads "Safe to connect · Certified".

## Configuration

| Input | Default | Description |
|-------|---------|-------------|
| `fail_on` | `do_not_connect` | Fail the workflow on this answer or worse: `do_not_connect`, `review`, or `none` |
| `comment_on_pr` | `true` | Post a comment on the PR with scan results |
| `fail_on_behavioral` | `false` | Fail the workflow if the behavioral sandbox run has a high/critical finding |
| `min_score` | *(unset)* | Legacy: minimum trust score checked when `fail_on_findings` is true (51 when unset) |
| `fail_on_findings` | `false` | Legacy: fail the workflow if the score is below `min_score` |

### Fail on anything that needs a review

```yaml
- uses: AgentAvow/AgentAvow/github-action@main
  with:
    fail_on: review
```

### Legacy: enforce a minimum trust score

`min_score` keeps working when you set it. Before this release it defaulted to 60;
it now has no default, and `fail_on_findings: true` on its own checks against 51,
the score under which the answer reads "Review before you connect".

```yaml
- uses: AgentAvow/AgentAvow/github-action@main
  with:
    min_score: 70
    fail_on_findings: true
```

PRs with a trust score below 70 will fail the check, blocking merge (if you use branch protection rules).

### Gate on sandbox behavior

When the repository maps to a published npm, PyPI or Docker package, AgentAvow also
runs it in an isolated sandbox (gVisor) and reports what it actually did: which MCP
tools were exercised, where it sent traffic, and whether it read secrets it should
not have. The scan output and the PR comment carry one `Sandbox` line, for example:

```
Sandbox (gVisor, signed): called 4 tool(s), 1 behavioral finding(s), unexpected egress: telemetry.example.net; trust score -10 from the sandbox
```

While the first run is still in flight the line reads
`Sandbox: running now — the observed behavior (and its effect on the score) appears on the next scan`.
A server the sandbox installed but could not start reads
`Sandbox (gVisor, signed): installed; server not started (needs credentials) — not a finding; 0 behavioral finding(s), no unexpected egress`.

To block a merge on a high/critical behavioral finding:

```yaml
- uses: AgentAvow/AgentAvow/github-action@main
  with:
    fail_on_behavioral: true
```

The sandbox run is signed as its own observation, and that signed observation also
moves the trust score by fixed rules: a leaked canary credential or critical
behavioral finding caps the score at 45, a high finding costs 10 and caps it at 70,
medium findings cost 5, and a clean full exercise adds 3. The line's trailing
`trust score ±N from the sandbox` is that delta; the attestation records the evidence
so the number stays recomputable (see
[Behavioral sandbox](https://agentavow.com/docs/behavioral-sandbox)). `min_score` and
`fail_on_behavioral` are still two separate gates: the first reads the score after the
sandbox delta, the second fails on the finding itself even when the score clears the
threshold. A pending or absent sandbox run never fails the step.

### Disable PR comments

```yaml
- uses: AgentAvow/AgentAvow/github-action@main
  with:
    comment_on_pr: false
```

Results will still appear in the GitHub Actions job summary.

## What the PR comment looks like

Every scanned PR receives a comment like this:

---

## AgentAvow Trust Scan

### Review before you connect
2 high findings, including shell command built from user input

**Trust score 67/100** (tier: Standard) — Scan result: warnings

| Category | Score |
|----------|-------|
| secret hygiene | 100 |
| code safety | 41 |
| data handling | 85 |
| filesystem access | 65 |
| dependency health | 90 |

**Findings:** 0 critical, 2 high, 5 medium, 3 low

**Sandbox (gVisor, signed): called 4 tool(s), 0 behavioral finding(s), no unexpected egress; trust score +3 from the sandbox**

[View full report](https://agentavow.com/check/owner/repo) | [Add badge to README](https://agentavow.com/api/v1/public/scan/owner/repo/badge)

> *This is a code security scan score. [Full composite trust score](https://agentavow.com/check/owner/repo) (including identity verification and external signals) is available on AgentAvow.*

---

The comment is updated on each push to the PR (previous comments are replaced, not stacked).

## Add a trust badge to your README

Include a live trust badge in your README:

```markdown
[![AgentAvow Trust Score](https://agentavow.com/api/v1/public/scan/OWNER/REPO/badge)](https://agentavow.com/check/OWNER/REPO)
```

Replace `OWNER` and `REPO` with your GitHub org/user and repository name.

## Full report

Click "View full report" in the PR comment (or visit `https://agentavow.com/check/OWNER/REPO` directly) to see:

- Detailed category-by-category breakdown
- Individual findings with file paths and remediation guidance
- Historical trust score trend
- Comparison against similar repositories

## How it works

1. The action calls the AgentAvow public scan API (`GET /api/v1/public/scan/{owner}/{repo}`)
2. AgentAvow analyzes the repository for security and trust signals across multiple categories
3. Results are posted as a PR comment and written to the GitHub Actions job summary
4. The workflow fails on **Do not connect** by default (`fail_on`), or on the legacy score floor if you set one

No source code is uploaded. The scan uses publicly available repository metadata and content already visible on GitHub.

## Requirements

- The repository must be **public**. This action calls the public scan API, which reads public repos only. A private repo can be scanned two other ways: signed in, `POST /api/v1/account/private-scan` with `{owner, repo, token}` scans it with a GitHub token you supply in the request (used for that scan, never stored, never added to the public catalog); or run the scanner inside your own runner with the [local-scan action](../local-scan-action/), which sends nothing anywhere.
- The workflow needs `pull-requests: write` permission to post comments
- Runs on `ubuntu-latest` (uses `bash`, `curl`, and `jq`)

## Links

- [AgentAvow](https://agentavow.com) -- Trust infrastructure for AI agents and humans
- [Check any repo](https://agentavow.com/check) -- Free security posture check
- [AgentAvow MCP Server](https://github.com/AgentAvow/AgentAvow/tree/main/sdk/mcp-server) -- Use trust data in your AI workflows
