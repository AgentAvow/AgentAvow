# AgentAvow scan for Bitbucket Pipelines

Run the AgentAvow tool-safety scan inside Bitbucket Pipelines, on the code the step just checked out. The scan is offline: no code leaves the runner. The step prints the answer (Safe to connect, Review before you connect, or Do not connect) and the trust score, posts a Code Insights report to the commit and pull request, and by default fails when the answer is Do not connect.

## What is in this directory

| File | Purpose |
|------|---------|
| `pipe.yml` | Pipe metadata: name, image, variables. |
| `Dockerfile` | The pipe image: the scanner image plus an entrypoint. Published as `ghcr.io/agentavow/scanner:pipe-0.1`. |
| `bitbucket-pipelines.example.yml` | Both ways to run it, ready to copy. |

The wrapper itself is `src/scanner/ci_bitbucket.py`, installed in the scanner image as `agentavow-bitbucket`.

## Using the pipe

```yaml
- step:
    name: AgentAvow scan
    script:
      - pipe: docker://ghcr.io/agentavow/scanner:pipe-0.1
        variables:
          FAIL_ON: "do_not_connect"
    artifacts:
      - agentavow-*.json
      - agentavow-*.md
```

## Using the scanner image as the step image

```yaml
- step:
    name: AgentAvow scan
    image: ghcr.io/agentavow/scanner:0.1
    script:
      - export FAIL_ON=do_not_connect
      - agentavow-bitbucket
```

Behind a firewall, mirror `ghcr.io/agentavow/scanner:0.1` (and `:pipe-0.1` for the pipe form) into your registry and reference the mirror.

## Variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `FAIL_ON` | `do_not_connect` | Fail on this answer or worse. `review` also fails on Review before you connect; `none` reports without gating. |
| `FAIL_ON_FINDINGS` | `none` | Also fail on any finding at or above `critical`, `high` or `medium`. |
| `SCAN_PATHS` | `.` | Space-separated directories to scan. Each gets its own report (`agentavow-scan-<path>.json`) and its own Code Insights report. |
| `CODE_INSIGHTS` | `true` | Post the Code Insights report and annotations. |
| `MIN_SCORE` | `0` | Legacy score gate; `0` turns it off. Gate on `FAIL_ON` instead. |
| `BITBUCKET_ACCESS_TOKEN` | empty | Only for runners without the Pipelines proxy (self-hosted). A repository access token with pull request and repository scopes. |

## What you get

- **Build log:** the answer and its reason, the trust score and tier, the gate outcome and the top findings, with a link to what an offline scan covers.
- **Files:** `agentavow-scan.json` (every finding with file, line, severity and remediation), `agentavow-summary.md`, and `agentavow-insights.json`. Add them to `artifacts:` to keep them.
- **Code Insights:** a report named AgentAvow on the commit and pull request, PASSED or FAILED by the gate, with the answer, trust score, tier and counts; and one annotation per finding (up to 1,000), shown on its line in the pull-request diff.

A Code Insights upload problem is logged as a warning and never fails the step. The gate alone decides the exit code: `0` passed, `1` the gate failed, `2` a scan could not run.

## What an offline scan leaves out

Dependency CVE enrichment, published-artifact diffing, maintainer signals, the behavioral sandbox, the adoption score, and a signature: each needs a network, a key or infrastructure the runner does not have. The static trust score is computed exactly as the hosted service computes it. For a signed attestation a third party can verify, run a hosted scan on top.

Bitbucket repositories can't be checked on agentavow.com itself yet; the hosted Check reads GitHub repositories. This pipe is how you check them today.
