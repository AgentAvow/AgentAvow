# AgentAvow Local Scan — GitHub Action

Run AgentAvow's tool-safety scan **inside your CI runner**, on your checked-out code.

- **Private repos work.** The scan runs on the code already checked out in the runner — nothing is sent to AgentAvow, and no token is handed to us.
- **Same grade as a hosted scan.** It uses the exact same detection engine and scoring (`src/scanner/local_scan.py` → shared `scan.py` helpers), over the same file set (git-tracked files only), so the score matches a hosted scan of the same tree.
- **Actionable output.** Emits SARIF (inline PR annotations via code scanning) and a JSON findings file, and can fail the build on a minimum score or a severity threshold.

> A local/CI scan proves the findings. It does **not** mint a signed attestation — that requires AgentAvow's key. For a third-party-verifiable attestation, use the hosted scan/REST API on top.

## Usage

```yaml
name: agent-safety
on: [pull_request]

permissions:
  contents: read
  security-events: write   # only needed for upload-sarif

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AgentAvow/AgentAvow/local-scan-action@main
        with:
          path: .
          min-score: "60"     # fail the job below 60 (omit to not gate on score)
          fail-on: "high"     # or: fail on any high/critical finding (optional)
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan. |
| `min-score` | `""` | Fail if the trust score is below this (0–100). Empty = no score gate. |
| `fail-on` | `""` | Fail if any finding at/above `critical`/`high`/`medium` is present. |
| `upload-sarif` | `true` | Upload `results.sarif` to GitHub code scanning. |
| `ref` | `main` | AgentAvow scanner version (git ref) to install. |

## Outputs

| Output | Description |
|--------|-------------|
| `trust-score` | The computed 0–100 score. |
| `tier` | Trusted / Standard / Caution / Restricted / Blocked. |

## Same thing locally (inner loop)

```bash
pip install "git+https://github.com/AgentAvow/AgentAvow.git"
agentavow scan . --min-score 60 --sarif out.sarif --json out.json
```
