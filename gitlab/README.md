# AgentAvow scan for GitLab CI

Run the AgentAvow tool-safety scan inside your own GitLab runner, on the code the pipeline just checked out. Nothing leaves your network: no token, no upload, no call to agentavow.com. By default the job fails when the answer is Do not connect, and it publishes a Code Quality report so findings appear in the merge-request widget.

Built for self-managed GitLab behind a firewall, where the hosted scanner cannot reach your repositories.

## What is in this directory

| File | Purpose |
|------|---------|
| `templates/scan.yml` | The CI/CD component (`include: component:`), with typed inputs. |
| `agentavow-scan.gitlab-ci.yml` | The same job as a plain includable file, for instances that cannot use components. |
| `../docker/scanner.Dockerfile` | The slim scanner image the job runs in, published as `ghcr.io/agentavow/scanner:0.1`. |

## What the scan is

`agentavow scan` is the same static engine and scoring the hosted service runs: the 12 detection categories, the allowlist and inline suppressions, MCP-server context, dependency findings from manifests and lockfiles, and the 0-100 trust score. It reads git-tracked files only, so the score matches a hosted scan of the same tree.

Two outputs per run:

- `agentavow-scan.json`: the verdict phrase, the trust score, counts, the per-category sub-scores, and every finding with file, line, severity and remediation.
- `gl-code-quality-report.json`: the findings in GitLab Code Quality format. GitLab reads it from `artifacts:reports:codequality` and shows new and fixed findings in the MR widget, on every GitLab tier.

The job log leads with the verdict and the score:

```
AgentAvow — my-mcp-server
  Verdict     : Review before you connect
  Trust score : 52/100  (Standard)
  Files       : 41 scanned
  Findings    : 0 critical · 2 high · 1 medium · 0 low
```

What a local scan does not include, because each needs a network or a key the runner does not have: dependency CVE enrichment, published-artifact diffing, maintainer signals, the behavioral sandbox, the adoption score, and a signature. Those are additive. Their absence leaves the static score intact, and a hosted scan of the same tree computes the identical static portion on top of them.

## The image

`docker/scanner.Dockerfile` at the repository root builds `python:3.12-slim` plus `git`, `httpx`, `pyyaml` and the scanner package. No web stack, no database driver. Pull the published image, `ghcr.io/agentavow/scanner:0.1`, and mirror it into the registry your runners can reach. Or build it yourself from the repository root:

```bash
docker build -f docker/scanner.Dockerfile -t registry.example.internal/mirrors/agentavow/scanner:0.1 .
docker push registry.example.internal/mirrors/agentavow/scanner:0.1
```

Either way, pin a tag. The image has no entrypoint, so it works as a GitLab job image; `CMD` runs `agentavow scan .` for plain `docker run -v "$PWD:/src"`.

The image sets `safe.directory=*` for git. Runners check the repository out as a different user than the job runs as, and without that setting git refuses to list the files and the scan would fall back to a filesystem walk with a different file set.

## Using the component

Components need GitLab 17.0 or newer on the instance that runs the pipeline, and a component project it can reach. The component is published from this directory to a GitLab project; until that exists, mirror the AgentAvow repository into your instance and point the include at the mirror.

```yaml
include:
  - component: $CI_SERVER_FQDN/<group>/agentavow-scan/scan@<your-tag>
    inputs:
      fail_on: do_not_connect
      fail_on_findings: high
      image: registry.example.internal/mirrors/agentavow/scanner:0.1
```

Pin the version after `@`. It is a git tag you create on your component project (AgentAvow does not publish component tags yet); `@~latest` follows the newest release and is the wrong choice for a gate you want to stay reproducible.

Inputs:

| Input | Default | Meaning |
|-------|---------|---------|
| `fail_on` | `do_not_connect` | Fail on this answer or worse. `review` also fails on Review before you connect; `none` reports without gating on the answer. |
| `min_score` | `0` | Legacy. Also fail when the trust score is below this; `0` turns it off. Gate on `fail_on` instead. |
| `fail_on_findings` | `none` | Also fail on any finding at or above `critical`, `high` or `medium`. |
| `path` | `.` | Directory to scan, relative to the repository root. Report paths are prefixed so the widget still points at the right file. |
| `image` | `ghcr.io/agentavow/scanner:0.1` | The scanner image. Set it to your internal mirror. |
| `stage` | `test` | Pipeline stage. |
| `allow_failure` | `false` | Report without blocking. Good for the first week. |
| `job_name` | `agentavow-scan` | Name of the generated job. |

The job runs on merge-request pipelines and on the default branch. Both matter: the default-branch run is the baseline GitLab diffs an MR's report against, so without it the widget cannot say which findings are new.

## Using the plain include

For an instance that cannot use components, or when you want to own the YAML:

```yaml
include:
  - project: <group>/agentavow            # your mirror of github.com/AgentAvow/AgentAvow
    ref: main                              # or a tag you create on your mirror
    file: /gitlab/agentavow-scan.gitlab-ci.yml

variables:
  AGENTAVOW_IMAGE: registry.example.internal/mirrors/agentavow/scanner:0.1
  AGENTAVOW_FAIL_ON_ANSWER: "do_not_connect"   # do_not_connect | review | none
  AGENTAVOW_FAIL_ON: "high"
```

Or copy the file into your repository and `include: - local: ...`. Both the mirror and the copy need to be updated by hand when a new version ships.

## Running the same thing by hand

```bash
docker run --rm -v "$PWD:/src" ghcr.io/agentavow/scanner:0.1 \
  agentavow scan . --fail-on do_not_connect --gitlab-code-quality gl-code-quality-report.json
```

Or without the image: `pip install "git+https://github.com/AgentAvow/AgentAvow.git"` and run `agentavow scan .`.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The answer is better than `fail_on`, the score is at or above `min_score` (when set), and no finding is at or above `fail_on_findings`. |
| `1` | The gate failed. Reports are still written. |
| `2` | The scan could not run (not a directory, empty tree, bad arguments). |

## Code Quality report details

Each finding becomes one issue. Severity maps critical to `blocker`, high to `critical`, medium to `major`, low to `minor`, info to `info`. The fingerprint hashes the path, the rule, and the finding's position among identical hits in that file, and leaves the line number out, so an edit above a finding does not make GitLab report it as new.

SARIF is also available (`--sarif`) for the GitLab Ultimate security dashboard and for other tools; the Code Quality report is the one that works on every tier.
