# Run AgentAvow locally & in CI

Scan your own code **without sending it anywhere** — same engine, same score as a hosted AgentAvow scan, but offline. Built for the inner loop and for private repos.

> Staged rebrand doc. Product URLs use `agentavow.com`; the signing keys (JWKS) stay on `agentgraph.co`.

## Why local

The hosted `/check` scan reads a repo from GitHub, so it only sees **public** code. If your repo is private — or you just want a fast result in your editor/CI without a round-trip — run the same scanner locally. Nothing leaves your machine or your runner.

What you get locally is **identical** to a hosted scan of the same tree: the same 12 detection categories, the same scoring, the same MCP/allowlist handling. The only hosted-only extras are network signals (dependency CVE enrichment, published-artifact diffing, maintainer metadata) — additive, and absent locally by design.

**One thing local scanning does _not_ do: mint a signed attestation.** That needs AgentAvow's key. A local scan *proves the findings* for your inner loop; when you need a third-party-verifiable attestation, run the hosted scan on top. The external attestation is still the thing only we can give you.

## CLI

```bash
pip install "agentavow @ git+https://github.com/AgentAvow/AgentAvow.git"
agentavow scan .
```

Useful flags:

```bash
agentavow scan .              # human summary
agentavow scan . --json out.json      # structured findings (file · line · severity · remediation)
agentavow scan . --sarif out.sarif    # SARIF 2.1.0 for code-scanning tools
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

## Actioning the output

`--json` emits every finding with `category`, `severity`, `file`, `line`, and a `remediation` string — enough to drive a fix in your inner loop or fail a check. `--sarif` feeds GitHub code scanning (or any SARIF viewer) so findings land as annotations on the exact line.

## Tuning false positives

Three knobs, all honored by the same local engine:

- **Allowlist** — `src/scanner/allowlist.json`: `{file_path, name}` glob entries suppress a known-safe pattern in a path (e.g. `tests/*`).
- **Inline** — append `ag-scan:ignore` to a source line to suppress that line's findings.
- **Context** — MCP servers get `fs_access`/`unsafe_exec` findings automatically discounted (they're expected for that tool class); detection keys off `server.json`/`mcp.json` or an `mcp` mention in your manifest. If an MCP is being over-flagged, confirm it's being *detected* as one.

## Same score, no drift

The local path imports the hosted scanner's detection and scoring directly — it doesn't re-implement them. Add a detection rule or change the scoring on the service and the CLI + Action inherit it automatically.

## Next

- [Reading your scan score](./check-guide.md)
- [Gate on the score](./gate-on-the-grade.md)
- [Declare your tool's scope](./check-guide.md)
