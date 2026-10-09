# Run AgentAvow locally & in CI

Scan your own code **without sending it anywhere** — same engine, same score as a hosted AgentAvow scan, but offline. Built for the inner loop and for private repos.

## Why local

The hosted `/check` scan reads a repo from GitHub, so it only sees **public** code. If your repo is private — or you just want a fast result in your editor/CI without a round-trip — run the same scanner locally. Nothing leaves your machine or your runner.

What you get locally is **identical** to a hosted scan of the same tree: the same detection rules and finding categories, the same five sub-score axes, the same scoring, the same MCP/allowlist handling. The only hosted-only extras are network signals (dependency CVE enrichment, published-artifact diffing, maintainer metadata) — additive, and absent locally by design.

**One thing local scanning does _not_ do: mint a signed attestation.** That needs AgentAvow's key. A local scan *proves the findings* for your inner loop; when you need a third-party-verifiable attestation, run the hosted scan on top. The external attestation is still the thing only we can give you.

## CLI

```bash
pip install "git+https://github.com/AgentAvow/AgentAvow.git"
agentavow scan .
```

Useful flags:

```bash
agentavow scan .              # human summary
agentavow scan . --json out.json      # structured findings (file · line · severity · remediation)
agentavow scan . --sarif out.sarif    # SARIF 2.1.0 for code-scanning tools
agentavow scan . --gitlab-code-quality gl-code-quality-report.json   # GitLab MR widget
agentavow scan . --bitbucket-insights insights.json   # Bitbucket Code Insights report + annotations
agentavow scan . --markdown summary.md                # short summary: answer, scores, gate, top findings
agentavow scan . --fail-on do_not_connect   # exit non-zero when the answer is Do not connect
agentavow scan . --fail-on review           # also exit non-zero on Review before you connect
agentavow scan . --fail-on high             # exit non-zero on any high/critical finding
agentavow scan . --min-score 60             # legacy: exit non-zero below a trust score
```

`--fail-on` can be repeated, so one run can gate on the answer and on a finding severity. The human summary leads with the answer (Safe to connect, Review before you connect, or Do not connect) and its reason, then the trust score.

The scan covers **git-tracked files only** — the same surface the hosted grade is computed over — so your build artifacts, data dumps, and gitignored caches never skew the score.

## GitHub Action (private repos)

The Action runs the scan **inside your runner**, on the code you just checked out. Private repos work with no token and no data leaving the runner.

```yaml
name: agent-safety
on: [pull_request]
permissions:
  contents: read
  security-events: write   # for SARIF upload
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AgentAvow/AgentAvow/local-scan-action@main
        with:
          fail-on: "do_not_connect"   # fail the PR when the answer is Do not connect
                                      # ("review" also fails on Review; "high" fails on any high/critical finding)
```

Findings show up as inline PR annotations (via code scanning) and a job-summary; `decision`, `decision-reason`, `trust-score` and `tier` are exposed as step outputs. `min-score` still works as a legacy score gate. Full reference: [local-scan-action](https://github.com/AgentAvow/AgentAvow/tree/main/local-scan-action).

## GitLab CI (self-managed, behind a firewall)

If your GitLab instance cannot be reached from the internet, the hosted scanner cannot see your repositories. The same scan runs inside your own runner instead, from a slim image you mirror into your registry. Nothing leaves your network.

The image is published as `ghcr.io/agentavow/scanner:0.1` (built from `docker/scanner.Dockerfile`: `python:3.12-slim` plus `git`, `httpx`, `pyyaml` and the scanner package). Pull it and mirror it into a registry your runners can reach, or build it yourself from the repository root:

```bash
docker pull ghcr.io/agentavow/scanner:0.1
# or build it:
docker build -f docker/scanner.Dockerfile -t registry.example.internal/mirrors/agentavow/scanner:0.1 .
docker push registry.example.internal/mirrors/agentavow/scanner:0.1
```

### Component

GitLab 17.0 or newer can include the scan as a CI/CD component. By default it fails the pipeline when the answer is Do not connect. Pin the version after `@`; it is a git tag you create on your component project (AgentAvow does not publish component tags yet).

```yaml
include:
  - component: $CI_SERVER_FQDN/<group>/agentavow-scan/scan@<your-tag>
    inputs:
      fail_on: do_not_connect  # or review; none reports without gating
      fail_on_findings: high   # also fail on any high or critical finding (optional)
      image: registry.example.internal/mirrors/agentavow/scanner:0.1
```

Self-managed instances cannot reach components hosted on gitlab.com. Mirror the AgentAvow repository into your instance and point the include at the mirror, or use the plain job below.

### Plain include

For older instances, or when you want to own the YAML, include the job file from your mirror (at `main` or a tag you create there), or copy it into your repository.

```yaml
include:
  - project: <group>/agentavow
    ref: main
    file: /gitlab/agentavow-scan.gitlab-ci.yml

variables:
  AGENTAVOW_IMAGE: registry.example.internal/mirrors/agentavow/scanner:0.1
  AGENTAVOW_FAIL_ON_ANSWER: "do_not_connect"   # do_not_connect | review | none
```

### What you get

The job log leads with the answer and the trust score. Two artifacts are published on every run, pass or fail: `agentavow-scan.json` (every finding with file, line, severity and remediation) and `gl-code-quality-report.json`, which GitLab reads as a Code Quality report and shows in the merge-request widget on every tier. The job runs on merge-request pipelines and on the default branch; the default-branch run is the baseline GitLab diffs an MR against.

### What a local scan does not include

Each of these needs a network, a key, or infrastructure the runner does not have, so a local or CI scan leaves them out:

- dependency CVE enrichment (advisory lookups against OSV)
- published-artifact diffing (comparing the registry package to the source)
- maintainer signals
- the behavioral sandbox
- the adoption score
- a signature

The static score is computed exactly as the hosted service computes it, so the number you see in CI is the number a hosted scan of the same tree starts from. For a signed attestation a third party can verify, run the hosted scan on top.

Full reference, including inputs, exit codes and the report format: [gitlab/README.md](https://github.com/AgentAvow/AgentAvow/tree/main/gitlab).

## Bitbucket Pipelines

The same offline scan runs as a Bitbucket Pipe. It prints the answer and the trust score to the build log, writes the JSON report and a Markdown summary next to the checkout, and posts a **Code Insights** report: one report on the commit and pull request, and one annotation per finding on its line in the PR diff. By default the step fails when the answer is Do not connect. No token is needed: inside Bitbucket Cloud Pipelines the build's own proxy authenticates the Code Insights calls.

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: AgentAvow scan
          script:
            - pipe: docker://ghcr.io/agentavow/scanner:pipe-0.1
              variables:
                FAIL_ON: "do_not_connect"   # do_not_connect | review | none
                FAIL_ON_FINDINGS: "none"    # none | critical | high | medium
                SCAN_PATHS: "."             # space-separated directories
          artifacts:
            - agentavow-*.json
            - agentavow-*.md
```

Or use the scanner image as the step image and run the same wrapper:

```yaml
      - step:
          name: AgentAvow scan
          image: ghcr.io/agentavow/scanner:0.1
          script:
            - agentavow-bitbucket
```

Behind a firewall, mirror the image into your registry and point the pipe or the step at the mirror. On a self-hosted runner without the Pipelines proxy, set `BITBUCKET_ACCESS_TOKEN` (a repository access token with pull request and repository scopes) for Code Insights, or `CODE_INSIGHTS: "false"` to skip it. Full reference: [bitbucket/README.md](https://github.com/AgentAvow/AgentAvow/tree/main/bitbucket).

## Azure DevOps

The scan runs as an Azure Pipelines job template. Reference the AgentAvow repository as a pipeline resource (from GitHub through a service connection, or from a mirror in Azure Repos) and add the template. Each run uploads a summary to the run's **Extensions** tab (answer, trust score, gate outcome, top findings), publishes the JSON, SARIF and summary files as the `CodeAnalysisLogs` artifact (the SARIF SAST Scans Tab extension renders it), and fails the job when the answer is Do not connect.

```yaml
resources:
  repositories:
    - repository: agentavow
      type: github
      name: AgentAvow/AgentAvow
      endpoint: <your GitHub service connection>
      ref: refs/heads/main          # pin a commit or tag for a reproducible gate

jobs:
  - template: azure-devops/templates/agentavow-scan.yml@agentavow
    parameters:
      failOn: do_not_connect        # do_not_connect | review | none
      failOnFindings: none          # none | critical | high | medium
      scanPaths: ['.']
      image: myregistry.azurecr.io/mirrors/agentavow/scanner:0.1   # optional mirror
```

The template needs a Linux agent with Docker; Microsoft-hosted `ubuntu-latest` has it. Set `continueOnError: true` to report without blocking for a first rollout. Full reference: [azure-devops/README.md](https://github.com/AgentAvow/AgentAvow/tree/main/azure-devops).

Bitbucket and Azure DevOps repositories can't be checked on agentavow.com itself yet: the hosted Check reads GitHub repositories. The CI scan above is how you check them today.

## Actioning the output

`--json` emits every finding with `category`, `severity`, `file`, `line`, and a `remediation` string — enough to drive a fix in your inner loop or fail a check. `--sarif` feeds GitHub code scanning (or any SARIF viewer) so findings land as annotations on the exact line. `--gitlab-code-quality` writes the GitLab Code Quality report for the merge-request widget. `--bitbucket-insights` writes a Bitbucket Code Insights report and its annotations, and `--markdown` a short summary for CI summary pages.

## Tuning false positives

Three knobs, all honored by the same local engine:

- **Allowlist** — `src/scanner/allowlist.json`: `{file_path, name}` glob entries suppress a known-safe pattern in a path (e.g. `tests/*`).
- **Inline** — append `ag-scan:ignore` to a source line to suppress that line's low and medium findings. A critical or high finding on the same line is still reported, and every suppression still counts toward the suppression penalty.
- **Context** — MCP servers get `fs_access`/`unsafe_exec` findings automatically discounted (they're expected for that tool class); detection keys off `server.json`/`mcp.json` or an `mcp` mention in your manifest. If an MCP is being over-flagged, confirm it's being *detected* as one.

## Same score, no drift

The local path imports the hosted scanner's detection and scoring directly — it doesn't re-implement them. Add a detection rule or change the scoring on the service and the CLI + Action inherit it automatically.

## Next

- [Reading your scan score](./check-guide.md)
- [Gate on the answer](./gate-on-the-grade.md)
- [Declare your tool's scope](./check-guide.md)
