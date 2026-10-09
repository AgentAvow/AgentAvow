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
agentavow scan . --min-score 60       # exit non-zero below 60 (gate a commit hook)
agentavow scan . --fail-on high       # exit non-zero on any high/critical finding
```

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
          min-score: "60"    # fail the PR below 60
          fail-on: "high"    # or fail on any high/critical (optional)
```

Findings show up as inline PR annotations (via code scanning) and a job-summary; `trust-score` and `tier` are exposed as step outputs. Full reference: [local-scan-action](https://github.com/AgentAvow/AgentAvow/tree/main/local-scan-action).

## GitLab CI (self-managed, behind a firewall)

If your GitLab instance cannot be reached from the internet, the hosted scanner cannot see your repositories. The same scan runs inside your own runner instead, from a slim image you mirror into your registry. Nothing leaves your network.

The image is `docker/scanner.Dockerfile` in the AgentAvow repository (intended name `ghcr.io/agentavow/scanner`): `python:3.12-slim` plus `git`, `httpx`, `pyyaml` and the scanner package. Build it from the repository root and push it to a registry your runners can pull from.

```bash
docker build -f docker/scanner.Dockerfile -t registry.example.internal/mirrors/agentavow/scanner:0.1 .
docker push registry.example.internal/mirrors/agentavow/scanner:0.1
```

### Component

GitLab 17.0 or newer can include the scan as a CI/CD component. Pin the version after `@`; it is a git tag on the component project.

```yaml
include:
  - component: $CI_SERVER_FQDN/<group>/agentavow-scan/scan@1.0.0
    inputs:
      min_score: 81          # fail below the "Safe to connect" floor
      fail_on_findings: high # also fail on any high or critical finding (optional)
      image: registry.example.internal/mirrors/agentavow/scanner:0.1
```

Self-managed instances cannot reach components hosted on gitlab.com. Mirror the AgentAvow repository into your instance and point the include at the mirror, or use the plain job below.

### Plain include

For older instances, or when you want to own the YAML, include the job file from a mirror at a pinned tag, or copy it into your repository.

```yaml
include:
  - project: <group>/agentavow
    ref: v0.1.0
    file: /gitlab/agentavow-scan.gitlab-ci.yml

variables:
  AGENTAVOW_IMAGE: registry.example.internal/mirrors/agentavow/scanner:0.1
  AGENTAVOW_MIN_SCORE: "81"
```

### What you get

The job log leads with the verdict phrase and the trust score. Two artifacts are published on every run, pass or fail: `agentavow-scan.json` (every finding with file, line, severity and remediation) and `gl-code-quality-report.json`, which GitLab reads as a Code Quality report and shows in the merge-request widget on every tier. The job runs on merge-request pipelines and on the default branch; the default-branch run is the baseline GitLab diffs an MR against.

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

## Actioning the output

`--json` emits every finding with `category`, `severity`, `file`, `line`, and a `remediation` string — enough to drive a fix in your inner loop or fail a check. `--sarif` feeds GitHub code scanning (or any SARIF viewer) so findings land as annotations on the exact line. `--gitlab-code-quality` writes the GitLab Code Quality report for the merge-request widget.

## Tuning false positives

Three knobs, all honored by the same local engine:

- **Allowlist** — `src/scanner/allowlist.json`: `{file_path, name}` glob entries suppress a known-safe pattern in a path (e.g. `tests/*`).
- **Inline** — append `ag-scan:ignore` to a source line to suppress that line's low and medium findings. A critical or high finding on the same line is still reported, and every suppression still counts toward the suppression penalty.
- **Context** — MCP servers get `fs_access`/`unsafe_exec` findings automatically discounted (they're expected for that tool class); detection keys off `server.json`/`mcp.json` or an `mcp` mention in your manifest. If an MCP is being over-flagged, confirm it's being *detected* as one.

## Same score, no drift

The local path imports the hosted scanner's detection and scoring directly — it doesn't re-implement them. Add a detection rule or change the scoring on the service and the CLI + Action inherit it automatically.

## Next

- [Reading your scan score](./check-guide.md)
- [Gate on the score](./gate-on-the-grade.md)
- [Declare your tool's scope](./check-guide.md)
