"""Run the Azure Pipelines template's scan step outside Azure, for CI smoke tests.

Extracts the bash step from azure-devops/templates/agentavow-scan.yml, substitutes
the two agent macros it uses, and runs it with the template's env mapping filled
from the parameter defaults (or overrides). Exits with the step's exit code.

    python3 scripts/ci/run_azure_template.py --image agentavow/scanner:dev \
        --sources "$PWD" --temp /tmp/agent --fail-on none
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import yaml

TEMPLATE = Path(__file__).resolve().parents[2] / "azure-devops" / "templates" / "agentavow-scan.yml"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--sources", required=True)
    ap.add_argument("--temp", required=True)
    ap.add_argument("--fail-on", default=None)
    ap.add_argument("--paths", default=None, help="';'-separated scan paths")
    ap.add_argument("--repo", default="AgentAvow/AgentAvow")
    a = ap.parse_args()

    tpl = yaml.safe_load(TEMPLATE.read_text())
    defaults = {p["name"]: p["default"] for p in tpl["parameters"]}
    step = next(s for s in tpl["jobs"][0]["steps"] if "bash" in s)
    script = (step["bash"].replace("$(Agent.TempDirectory)", a.temp)
              .replace("$(Build.SourcesDirectory)", a.sources))
    env = dict(os.environ,
               AGENTAVOW_IMAGE=a.image,
               AGENTAVOW_REPO=a.repo,
               AGENTAVOW_PATHS=a.paths or ";".join(defaults["scanPaths"]),
               AGENTAVOW_FAIL_ON_ANSWER=a.fail_on or defaults["failOn"],
               AGENTAVOW_FAIL_ON=defaults["failOnFindings"],
               AGENTAVOW_MIN_SCORE=str(defaults["minScore"]))
    Path(a.temp).mkdir(parents=True, exist_ok=True)
    return subprocess.run(["bash", "-c", script], env=env).returncode


if __name__ == "__main__":
    sys.exit(main())
