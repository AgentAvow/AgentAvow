# AgentAvow scan for Azure DevOps

Run the AgentAvow tool-safety scan inside Azure Pipelines, on the code the job just checked out. The scan is offline: no code leaves the agent. Each run uploads a summary to the run's Extensions tab, publishes the reports as a pipeline artifact, and by default fails the job when the answer is Do not connect.

## What is in this directory

| File | Purpose |
|------|---------|
| `templates/agentavow-scan.yml` | The job template. |
| `azure-pipelines.example.yml` | A complete pipeline that uses it. |

The template runs `agentavow scan` from the scanner image, `ghcr.io/agentavow/scanner:0.1` (built from `docker/scanner.Dockerfile`), so it needs a Linux agent with Docker. Microsoft-hosted `ubuntu-latest` has it.

## Using the template

Reference the AgentAvow repository as a resource, then add the template as a job:

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
      failOn: do_not_connect
```

Without a GitHub service connection, import the repository into Azure Repos and use `type: git` with `name: <project>/agentavow`. Behind a firewall, mirror the scanner image into Azure Container Registry and pass it as `image`.

## Parameters

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `failOn` | `do_not_connect` | Fail on this answer or worse. `review` also fails on Review before you connect; `none` reports without gating. |
| `failOnFindings` | `none` | Also fail on any finding at or above `critical`, `high` or `medium`. |
| `scanPaths` | `['.']` | Directories to scan. Each gets its own summary and reports. |
| `image` | `ghcr.io/agentavow/scanner:0.1` | The scanner image; point it at your mirror. |
| `minScore` | `0` | Legacy score gate; `0` turns it off. |
| `continueOnError` | `false` | Report without failing the job, for a first rollout. |
| `jobName` | `agentavow_scan` | Name of the generated job. |
| `dependsOn` | `[]` | Jobs to run first. |
| `pool` | `vmImage: ubuntu-latest` | The agent pool. |

## What you get

- **Extensions tab:** a summary per path with the answer and its reason, the trust score and tier, the gate outcome and the top findings.
- **`CodeAnalysisLogs` artifact:** `agentavow-scan.json` (every finding with file, line, severity and remediation), `agentavow.sarif` and the summary. With the Microsoft SARIF SAST Scans Tab extension installed, the SARIF shows in the run's Scans tab.
- **Errors in the run log:** a failed gate is logged as an error naming the path.

## What an offline scan leaves out

Dependency CVE enrichment, published-artifact diffing, maintainer signals, the behavioral sandbox, the adoption score, and a signature: each needs a network, a key or infrastructure the agent does not have. The static trust score is computed exactly as the hosted service computes it. For a signed attestation a third party can verify, run a hosted scan on top.

Azure DevOps repositories can't be checked on agentavow.com itself yet; the hosted Check reads GitHub repositories. This template is how you check them today.
