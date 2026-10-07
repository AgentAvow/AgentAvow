# AgentAvow Trust Scan — GitHub Action (legacy)

> **Use the maintained action instead.** The current, supported GitHub Action is
> **[`AgentAvow/AgentAvow/github-action@main`](../../github-action/)**. Its PR
> comment leads with one of three answers — **Safe to connect**, **Review before
> you connect** or **Do not connect** — and the reason behind it, with the signed
> trust score, findings and the behavioral **sandbox line** underneath. It fails
> the build on **Do not connect** by default (`fail_on: do_not_connect | review |
> none`), keeps the legacy `min_score` gate, and can fail on a high/critical
> sandbox finding (`fail_on_behavioral`). This composite action
> (`sdk/trust-scan-action`) predates it, is kept for existing workflows, and
> receives no new features: it reports the score only. To read the answer from
> its API call yourself, the public scan response carries `decision`
> (`safe` / `review` / `do_not_connect`) and `decision_reason`.

[![AgentAvow](https://img.shields.io/badge/AgentAvow-trust%20scan-7c3aed)](https://agentavow.com)

Scan your MCP server or agent-tool repository for security and trust posture on
every pull request and push — for **free**, with **no secret to configure**.

This composite action calls AgentAvow's public scan API, reads the 0–100 trust
score, posts a single sticky comment on the PR with the score and findings,
sets step outputs you can branch on, and can optionally fail the build when the
score drops below a threshold you choose.

> Scanning uses the **unauthenticated public API** — you never need an AgentAvow
> API key or any repository secret. The only token used is the automatically
> provided `${{ github.token }}`, and only to post the PR comment.

## What it does

1. `GET https://agentavow.com/api/v1/public/scan/{owner}/{repo}` (cached/fast).
2. Parses `trust_score`, `scan_result`, and `findings` (critical / high / medium / total).
3. Maps the score to a band for the `grade` output (kept for compatibility):
   ≥96, ≥81, ≥61, ≥41, ≥21, below 21. This is an older banding; the API's
   own `trust_tier` floors are 96 `verified`, 81 `trusted`, 51 `standard`,
   31 `minimal`, 11 `restricted`, 0 `blocked` — branch on `trust-score`.
4. Sets outputs (`trust-score`, `grade`, `scan-result`, `badge-url`, `report-url`).
5. On pull requests, posts/updates one sticky comment with the score, findings,
   a link to the full report, and the README badge snippet.
6. If `fail-below` > 0 and the score is below it, fails the build.

## Usage

```yaml
name: AgentAvow Trust Scan
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write   # required to post the PR comment

jobs:
  trust-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: AgentAvow/AgentAvow/sdk/trust-scan-action@main
        with:
          fail-below: 41   # optional: fail if the score drops below 41
```

Copy `examples/trust-scan.yml` into `.github/workflows/` for a ready-to-run file.

## Inputs

| Input           | Required | Default                          | Description                                                                 |
|-----------------|----------|----------------------------------|-----------------------------------------------------------------------------|
| `repo`          | no       | `${{ github.repository }}`       | `owner/repo` to scan.                                                        |
| `api-url`       | no       | `https://agentavow.com/api/v1`   | AgentAvow API base URL.                                                      |
| `fail-below`    | no       | `0`                              | Fail the build if the score is below this (0-100). `0` = never fail.        |
| `comment-on-pr` | no       | `true`                           | Post/update a sticky trust-score comment on pull requests.                  |
| `github-token`  | no       | `${{ github.token }}`            | Token used only to post the PR comment (auto-provided; no AgentAvow key).   |

## Outputs

| Output        | Description                                                  |
|---------------|--------------------------------------------------------------|
| `trust-score` | Trust score 0-100 (security scan score).                     |
| `grade`       | Score band derived from the trust score (`A+`, `A`, `B`, `C`, `D`, `F`); the output name is kept for compatibility. Branch on `trust-score` for new workflows. |
| `scan-result` | Scan result string (e.g. `clean`, `warnings`, `flagged`).    |
| `badge-url`   | URL of the embeddable SVG trust badge.                       |
| `report-url`  | URL of the human-readable trust report (`/check` page).      |

### Using outputs

```yaml
      - id: scan
        uses: AgentAvow/AgentAvow/sdk/trust-scan-action@main
      - run: echo "Trust score ${{ steps.scan.outputs.trust-score }}/100 (${{ steps.scan.outputs.scan-result }})"
```

## Badge

Add the live trust badge to your README (it links to the full report):

```markdown
[![AgentAvow Trust](https://agentavow.com/api/v1/public/scan/OWNER/REPO/badge)](https://agentavow.com/check/OWNER/REPO)
```

Replace `OWNER/REPO` with your repository. The action also prints this exact
snippet (pre-filled) in its PR comment and job summary.

## Permissions

The action needs `pull-requests: write` to post the sticky comment. If you set
`comment-on-pr: false`, only `contents: read` is required. No AgentAvow secret
is ever needed — scanning is free and uses the public API.

## Learn more

- Full report for any repo: `https://agentavow.com/check/{owner}/{repo}`
- AgentAvow: signed, verifiable safety scores for the tools agents connect to — https://agentavow.com
