# AgentAvow scanner: the slim, mirrorable CI image.
#
# Published as ghcr.io/agentavow/scanner:0.1 (rebuilt from main by CI).
#
# This image carries ONLY the offline static scanner (`agentavow scan`): the same
# 12-category detection engine and scoring the hosted service runs, over a checked-out
# tree. No web stack, no database driver, no network calls at scan time. It is meant
# to be pulled once into an internal registry and run inside CI behind a firewall.
#
# Build from the repository root (the build context must include src/):
#     docker build -f docker/scanner.Dockerfile -t ghcr.io/agentavow/scanner:dev .
#
# Run on any checkout:
#     docker run --rm -v "$PWD:/src" ghcr.io/agentavow/scanner:dev
#     docker run --rm -v "$PWD:/src" ghcr.io/agentavow/scanner:dev \
#         agentavow scan . --min-score 81 --gitlab-code-quality gl-code-quality-report.json
#
# What it contains (and why):
#   - python:3.12-slim          prod runs 3.12; the scanner targets 3.11+
#   - git                       the CLI scans git-tracked files (`git ls-files`) so a
#                               local score matches a hosted scan of the same tree
#   - httpx, pyyaml             the only third-party imports the scanner reaches:
#                               scan.py imports httpx at module level (the hosted fetch
#                               path, unused here); pyyaml reads the optional
#                               .agentavow.yml / .agentgraph-scan.yml files
#   - src/scanner/, src/trust_tiers.py
#                               the engine, patterns, allowlist, verdict + tier tables
# tests/test_scanner_image_closure.py asserts the scanner never imports anything outside
# that set, so a change in src/ that would break this image fails CI first.

FROM python:3.12-slim

LABEL org.opencontainers.image.title="AgentAvow scanner" \
      org.opencontainers.image.description="Offline tool-safety scan: same engine and score as agentavow.com, nothing leaves the runner" \
      org.opencontainers.image.source="https://github.com/AgentAvow/AgentAvow" \
      org.opencontainers.image.url="https://agentavow.com/docs/run-locally" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/agentavow \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
# CI runners check the repository out as one user and run the job as another; without
# this git refuses to list a checkout it considers "dubiously owned" and the scan would
# silently fall back to a filesystem walk (a different file set, a different score).
ENV GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0=safe.directory \
    GIT_CONFIG_VALUE_0=*

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pinned to the same ranges as pyproject.toml. Nothing else: no FastAPI, no SQLAlchemy.
RUN pip install "httpx>=0.25,<1.0" "pyyaml>=6.0,<7.0"

# The scanner package and the tier table it displays with. The build context's
# .dockerignore keeps __pycache__ and tests out.
COPY src/__init__.py /opt/agentavow/src/__init__.py
COPY src/trust_tiers.py /opt/agentavow/src/trust_tiers.py
COPY src/scanner/ /opt/agentavow/src/scanner/

# `agentavow` on PATH, same entry point pyproject.toml registers (src.scanner.local_scan:main).
# `agentavow-bitbucket` is the Bitbucket Pipelines wrapper (bitbucket/README.md): it
# runs the scan per SCAN_PATHS and posts a Code Insights report.
RUN printf '#!/bin/sh\nexec python3 -m src.scanner.local_scan "$@"\n' > /usr/local/bin/agentavow \
    && printf '#!/bin/sh\nexec python3 -m src.scanner.ci_bitbucket "$@"\n' > /usr/local/bin/agentavow-bitbucket \
    && chmod 0755 /usr/local/bin/agentavow /usr/local/bin/agentavow-bitbucket \
    && python3 -m compileall -q /opt/agentavow/src \
    && agentavow --help >/dev/null

# No ENTRYPOINT on purpose: GitLab's docker executor runs the job's `script` through
# the image's shell, and an entrypoint would get in the way. CMD is for `docker run`.
WORKDIR /src
CMD ["agentavow", "scan", "."]
