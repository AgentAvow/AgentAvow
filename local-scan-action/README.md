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
          fail-on: "do_not_connect"  # fail on "Do not connect" (or: review, high, critical)
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan. |
| `min-score` | `""` | Fail if the trust score is below this (0–100). Empty = no score gate. |
| `fail-on` | `""` | Fail on the answer `do_not_connect` (Do not connect) or `review` (Review before you connect, or worse); or on any finding at/above `critical`/`high`/`medium`. |
| `upload-sarif` | `true` | Upload `results.sarif` to GitHub code scanning. |
| `ref` | `main` | AgentAvow scanner version (git ref) to install. |

## Outputs

| Output | Description |
|--------|-------------|
| `decision` | The headline answer: `safe` (Safe to connect), `review` (Review before you connect) or `do_not_connect` (Do not connect). |
| `decision-reason` | The one condition behind it, e.g. `one high finding: os.system / os.popen (Python)`. |
| `trust-score` | The computed 0–100 score (evidence under the answer). |
| `tier` | Detail under the answer: Verified / Trusted / Standard / Minimal / Restricted / Blocked (floors 96 / 81 / 51 / 31 / 11 / 0). |

## Same thing locally (inner loop)

```bash
pip install "git+https://github.com/AgentAvow/AgentAvow.git"
agentavow scan . --fail-on do_not_connect --sarif out.sarif --json out.json
```
