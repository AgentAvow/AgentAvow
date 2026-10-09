"""Bitbucket Pipelines wrapper for ``agentavow scan`` (the pipe and the image step).

Runs the offline scan on the checkout, once per path in ``SCAN_PATHS``, prints the
answer and the trust score to the build log, writes the JSON report and a Markdown
summary next to the checkout, and posts a Code Insights report with one annotation
per finding so the result shows on the commit and inside the pull-request diff.

Configuration (environment variables, as pipe ``variables:`` or step env):

  FAIL_ON           do_not_connect (default) | review | none
  FAIL_ON_FINDINGS  none (default) | critical | high | medium
  MIN_SCORE         legacy score gate, 0 (default) turns it off
  SCAN_PATHS        space-separated directories to scan (default ".")
  CODE_INSIGHTS     true (default) | false
  BITBUCKET_ACCESS_TOKEN
                    optional. Inside Bitbucket Cloud Pipelines the build's local proxy
                    authenticates Code Insights calls for you; set a repository access
                    token (scope: pullrequest + repository) only when that proxy is not
                    there, e.g. on a self-hosted runner.

Exit code: 0 when every path passes the gate, 1 when any fails it, 2 when a scan
could not run. Code Insights problems are logged as warnings and never fail the build.
Nothing but the Code Insights report leaves the runner; the scan itself is offline.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from src.scanner import local_scan

_PROXY = "http://localhost:29418"
_BATCH = 100  # annotations per POST (Bitbucket's limit)


def _truthy(v: str | None, default: bool = True) -> bool:
    if v is None or v.strip() == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _slug(path: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", path.strip("./")).strip("-").lower()
    return s or "root"


def scan_args(path: str, suffix: str, env: dict[str, str]) -> list[str]:
    """The ``agentavow scan`` argument list for one path, from the pipe's variables."""
    # --quiet: the Markdown summary (answer, both scores, gate, top findings, link) is
    # what the build log shows, printed by run(); the FAIL line still prints.
    repo = (env.get("BITBUCKET_REPO_SLUG") or "").strip()
    if repo:
        name = repo if path.strip("./") == "" else f"{repo}/{path.strip('./')}"
        extra = ["--name", name]
    else:
        extra = []
    args = ["scan", path, "--quiet", *extra,
            "--json", f"agentavow-scan{suffix}.json",
            "--markdown", f"agentavow-summary{suffix}.md",
            "--bitbucket-insights", f"agentavow-insights{suffix}.json"]
    fail_on = (env.get("FAIL_ON") or "do_not_connect").strip()
    if fail_on != "none":
        args += ["--fail-on", fail_on]
    findings = (env.get("FAIL_ON_FINDINGS") or "none").strip()
    if findings != "none":
        args += ["--fail-on", findings]
    min_score = (env.get("MIN_SCORE") or "0").strip()
    if min_score not in ("", "0"):
        args += ["--min-score", min_score]
    return args


def _client(token: str | None):
    import httpx

    if token:
        return httpx.Client(headers={"Authorization": f"Bearer {token}"}, timeout=20)
    try:
        return httpx.Client(proxy=_PROXY, timeout=20)
    except TypeError:  # httpx < 0.26
        return httpx.Client(proxies=_PROXY, timeout=20)


def post_insights(insights: dict, report_id: str, env: dict[str, str]) -> bool:
    """PUT the report, then POST the annotations in batches. Returns True on success."""
    ws, repo, commit = (env.get("BITBUCKET_WORKSPACE"), env.get("BITBUCKET_REPO_SLUG"),
                        env.get("BITBUCKET_COMMIT"))
    if not (ws and repo and commit):
        print("agentavow: not running in Bitbucket Pipelines; skipping Code Insights",
              file=sys.stderr)
        return False
    token = env.get("BITBUCKET_ACCESS_TOKEN") or None
    base = "https://api.bitbucket.org/2.0" if token else "http://api.bitbucket.org/2.0"
    url = f"{base}/repositories/{ws}/{repo}/commit/{commit}/reports/{report_id}"
    try:
        with _client(token) as client:
            client.put(url, json=insights["report"]).raise_for_status()
            notes = insights.get("annotations") or []
            for i in range(0, len(notes), _BATCH):
                client.post(f"{url}/annotations",
                            json=notes[i:i + _BATCH]).raise_for_status()
    except Exception as exc:  # never fail the build on the report upload
        print(f"agentavow: warning: Code Insights upload failed ({exc})", file=sys.stderr)
        return False
    return True


def run(env: dict[str, str] | None = None) -> int:
    env = dict(os.environ if env is None else env)
    root = env.get("BITBUCKET_CLONE_DIR")
    if root and Path(root).is_dir():
        os.chdir(root)
    paths = (env.get("SCAN_PATHS") or ".").split()
    insights_on = _truthy(env.get("CODE_INSIGHTS"))
    worst = 0
    for path in paths:
        suffix = "" if len(paths) == 1 else f"-{_slug(path)}"
        rc = local_scan.main(scan_args(path, suffix, env))
        if rc == 2:
            worst = 2
            continue
        worst = max(worst, rc)
        summary = Path(f"agentavow-summary{suffix}.md")
        if summary.is_file():
            print(summary.read_text(encoding="utf-8"), file=sys.stderr)
        report = Path(f"agentavow-insights{suffix}.json")
        if insights_on and report.is_file():
            report_id = "agentavow" + suffix
            if post_insights(json.loads(report.read_text(encoding="utf-8")), report_id, env):
                print(f"agentavow: Code Insights report '{report_id}' posted", file=sys.stderr)
    return worst


if __name__ == "__main__":
    raise SystemExit(run())
