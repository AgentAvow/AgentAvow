# AgentAvow Trust Scan - GitHub Action

Check the security posture of any public repository using the [AgentAvow](https://agentavow.com) trust infrastructure. Every pull request gets an automated trust scan comment with a 0–100 trust score, category breakdown, and actionable findings.

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
      - uses: agentgraph-co/agentgraph/github-action@main
```

That's it. Every PR will now receive a trust scan comment.

## Configuration

| Input | Default | Description |
|-------|---------|-------------|
| `min_score` | `60` | Minimum trust score (0-100) to pass the check |
| `fail_on_findings` | `false` | Fail the workflow if the score is below `min_score` |
| `comment_on_pr` | `true` | Post a comment on the PR with scan results |

### Enforce a minimum trust score

```yaml
- uses: agentgraph-co/agentgraph/github-action@main
  with:
    min_score: 70
    fail_on_findings: true
```

PRs with a trust score below 70 will fail the check, blocking merge (if you use branch protection rules).

### Disable PR comments

```yaml
- uses: agentgraph-co/agentgraph/github-action@main
  with:
    comment_on_pr: false
```

Results will still appear in the GitHub Actions job summary.

## What the PR comment looks like

Every scanned PR receives a comment like this:

---

## AgentAvow Trust Scan

**Grade: B (67/100)** -- Use with Caution

| Category | Score |
|----------|-------|
| Secret Hygiene | 100 |
| Code Safety | 41 |
| Data Handling | 85 |
| Filesystem Access | 65 |

**Findings:** 0 critical, 2 high, 5 medium, 3 low

[View full report](https://agentavow.com/check/owner/repo) | [Add badge to README](https://agentavow.com/api/v1/public/scan/owner/repo/badge)

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
4. Optionally, the workflow fails if the score is below your configured threshold

No source code is uploaded. The scan uses publicly available repository metadata and content already visible on GitHub.

## Requirements

- The repository must be **public** (private repo scanning requires an API key -- coming soon)
- The workflow needs `pull-requests: write` permission to post comments
- Runs on `ubuntu-latest` (uses `bash`, `curl`, and `jq`)

## Links

- [AgentAvow](https://agentavow.com) -- Trust infrastructure for AI agents and humans
- [Check any repo](https://agentavow.com/check) -- Free security posture check
- [AgentAvow MCP Server](https://github.com/agentgraph-co/agentgraph/tree/main/sdk/mcp-server) -- Use trust data in your AI workflows
