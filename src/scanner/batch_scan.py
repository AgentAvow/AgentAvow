"""Batch scan MCP server repos.

Can scan from:
  1. The recruitment_prospects DB table (production)
  2. GitHub search API directly (no DB needed)

Usage:
    python3 -m src.scanner.batch_scan [--limit N] [--output report.json]
    python3 -m src.scanner.batch_scan --from-github [--limit N]
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

import httpx

from src.config import settings
from src.scanner.scan import ScanResult, scan_repo

logger = logging.getLogger(__name__)


def _result_to_dict(r: ScanResult) -> dict:
    """Convert ScanResult to a JSON-serializable dict."""
    d = {
        "repo": r.repo,
        "stars": r.stars,
        "description": r.description,
        "framework": r.framework,
        "primary_language": r.primary_language,
        "files_scanned": r.files_scanned,
        "has_readme": r.has_readme,
        "has_license": r.has_license,
        "has_tests": r.has_tests,
        "trust_score": r.trust_score,
        "error": r.error,
        "findings_count": len(r.findings),
        "critical_count": r.critical_count,
        "high_count": r.high_count,
        "medium_count": r.medium_count,
        "positive_signals": list(set(r.positive_signals)),
        "findings": [
            {
                "category": f.category,
                "name": f.name,
                "severity": f.severity,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "snippet": f.snippet,
            }
            for f in r.findings
        ],
    }
    return d


def _generate_summary(results: list[ScanResult]) -> dict:
    """Generate aggregate stats from scan results."""
    scanned = [r for r in results if r.error is None]
    errored = [r for r in results if r.error is not None]

    total_findings = sum(len(r.findings) for r in scanned)
    repos_with_secrets = sum(
        1 for r in scanned
        if any(f.category == "secret" for f in r.findings)
    )
    repos_with_unsafe_exec = sum(
        1 for r in scanned
        if any(f.category == "unsafe_exec" for f in r.findings)
    )
    repos_with_fs_access = sum(
        1 for r in scanned
        if any(f.category == "fs_access" for f in r.findings)
    )
    repos_with_critical = sum(1 for r in scanned if r.critical_count > 0)
    repos_with_auth = sum(
        1 for r in scanned
        if "Authentication check" in r.positive_signals
        or "Authorization check" in r.positive_signals
    )
    repos_with_validation = sum(
        1 for r in scanned
        if "Input validation" in r.positive_signals
    )
    repos_with_tests = sum(1 for r in scanned if r.has_tests)
    repos_with_license = sum(1 for r in scanned if r.has_license)

    avg_trust = (
        sum(r.trust_score for r in scanned) / len(scanned)
        if scanned else 0
    )

    # Severity breakdown across all findings
    all_findings = [f for r in scanned for f in r.findings]
    severity_counts = {}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    # Category breakdown
    category_counts = {}
    for f in all_findings:
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    # Most common finding types
    finding_type_counts: dict[str, int] = {}
    for f in all_findings:
        finding_type_counts[f.name] = finding_type_counts.get(f.name, 0) + 1
    top_finding_types = sorted(
        finding_type_counts.items(), key=lambda x: x[1], reverse=True,
    )[:10]

    # Language breakdown
    lang_counts: dict[str, int] = {}
    for r in scanned:
        lang = r.primary_language or "unknown"
        lang_counts[lang] = lang_counts.get(lang, 0) + 1

    # Score distribution
    score_buckets = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}
    for r in scanned:
        s = r.trust_score
        if s <= 20:
            score_buckets["0-20"] += 1
        elif s <= 40:
            score_buckets["21-40"] += 1
        elif s <= 60:
            score_buckets["41-60"] += 1
        elif s <= 80:
            score_buckets["61-80"] += 1
        else:
            score_buckets["81-100"] += 1

    return {
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "total_repos": len(results),
        "successfully_scanned": len(scanned),
        "errors": len(errored),
        "total_findings": total_findings,
        "average_trust_score": round(avg_trust, 1),
        "repos_with_critical_findings": repos_with_critical,
        "repos_with_hardcoded_secrets": repos_with_secrets,
        "repos_with_unsafe_exec": repos_with_unsafe_exec,
        "repos_with_fs_access": repos_with_fs_access,
        "repos_with_auth": repos_with_auth,
        "repos_with_input_validation": repos_with_validation,
        "repos_with_tests": repos_with_tests,
        "repos_with_license": repos_with_license,
        "pct_with_secrets": round(repos_with_secrets / max(1, len(scanned)) * 100, 1),
        "pct_with_unsafe_exec": round(repos_with_unsafe_exec / max(1, len(scanned)) * 100, 1),
        "pct_with_auth": round(repos_with_auth / max(1, len(scanned)) * 100, 1),
        "pct_with_tests": round(repos_with_tests / max(1, len(scanned)) * 100, 1),
        "severity_breakdown": severity_counts,
        "category_breakdown": category_counts,
        "top_finding_types": top_finding_types,
        "language_breakdown": lang_counts,
        "score_distribution": score_buckets,
    }


_GITHUB_SEARCH_QUERIES = [
    # MCP ecosystem
    ("topic:mcp-server", 2),
    ("topic:mcp topic:server", 2),
    ('"model context protocol" in:readme', 5),
    ("topic:mcp topic:tools", 2),
    # Agent frameworks
    ("topic:crewai", 1),
    ("topic:autogen", 2),
    ("topic:langchain topic:agent", 5),
    ("topic:llama-index topic:agent", 5),
    ("topic:ai-agent", 30),
    ("topic:llm-agent", 15),
    ("topic:autonomous-agents", 15),
    # Skill / plugin marketplaces + protocols
    ("topic:openclaw OR topic:open-claw", 1),
    ("topic:agent-protocol OR topic:a2a", 2),
    ("topic:x402 OR topic:agent-payments", 1),
]

_MAX_STARS = 10000  # scan wider range than outreach — we want data


def _load_skip_set(skip_file: str | None) -> set[str]:
    """Load already-scanned repo full_names so recurring runs cover new ground."""
    if not skip_file:
        return set()
    try:
        with open(skip_file) as f:
            return {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def _append_skip_set(skip_file: str | None, names: list[str]) -> None:
    if not skip_file or not names:
        return
    with open(skip_file, "a") as f:
        for n in names:
            f.write(n + "\n")


async def _discover_from_github(
    token: str | None, limit: int, skip: set[str] | None = None,
) -> list[dict]:
    """Discover MCP/agent repos from GitHub search, skipping already-scanned ones."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    seen: set[str] = set(skip or set())  # pre-seed with already-scanned
    repos: list[dict] = []

    async with httpx.AsyncClient(timeout=20) as client:
        for query, min_stars in _GITHUB_SEARCH_QUERIES:
            q = f"{query} stars:>={min_stars} stars:<={_MAX_STARS}"
            resp = await client.get(
                "https://api.github.com/search/repositories",
                headers=headers,
                params={
                    "q": q, "sort": "stars", "order": "desc",
                    "per_page": 100,
                },
            )
            if resp.status_code != 200:
                logger.warning(
                    "GitHub search %d for: %s", resp.status_code, query,
                )
                continue

            for item in resp.json().get("items", []):
                full_name = item["full_name"]
                if full_name in seen or item.get("fork", False):
                    continue
                seen.add(full_name)
                repos.append({
                    "full_name": full_name,
                    "stars": item.get("stargazers_count", 0),
                    "description": (item.get("description") or "")[:500],
                    "framework": "mcp",
                })
                if 0 < limit <= len(repos):
                    return repos

    logger.info("Discovered %d repos from GitHub search", len(repos))
    return repos


async def _scan_repos(
    repos: list[dict],
    token: str | None,
    output_path: str,
    skip_file: str | None = None,
) -> dict:
    """Scan a list of repos and write the report.

    Successfully-scanned repo names are appended to ``skip_file`` (if given) so
    the next scheduled run covers new repos instead of repeating these.
    """
    results: list[ScanResult] = []
    total = len(repos)

    for i, repo in enumerate(repos):
        logger.info(
            "[%d/%d] Scanning %s (%d stars)...",
            i + 1, total, repo["full_name"], repo.get("stars", 0),
        )
        result = await scan_repo(
            full_name=repo["full_name"],
            stars=repo.get("stars", 0),
            description=repo.get("description", ""),
            framework=repo.get("framework", ""),
            token=token,
        )
        results.append(result)

        if result.error:
            logger.warning("  Error: %s", result.error)
        else:
            logger.info(
                "  Score: %d | Findings: %d (crit=%d, high=%d) | "
                "Files: %d",
                result.trust_score, len(result.findings),
                result.critical_count, result.high_count,
                result.files_scanned,
            )

        # Rate limit pause every 10 repos
        if (i + 1) % 10 == 0:
            logger.info("  [pausing 2s for rate limit]")
            await asyncio.sleep(2)

    # Record successfully-scanned repos so recurring runs don't repeat them.
    _append_skip_set(
        skip_file,
        [repos[i]["full_name"] for i, r in enumerate(results) if not r.error],
    )

    summary = _generate_summary(results)

    report = {
        "summary": summary,
        "repos": [_result_to_dict(r) for r in results],
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    logger.info("Report written to %s", output_path)
    logger.info("Summary:")
    logger.info("  Scanned: %d repos", summary["successfully_scanned"])
    logger.info("  Avg trust score: %.1f", summary["average_trust_score"])
    logger.info(
        "  Secrets: %d (%.1f%%)",
        summary["repos_with_hardcoded_secrets"],
        summary["pct_with_secrets"],
    )
    logger.info(
        "  Unsafe exec: %d (%.1f%%)",
        summary["repos_with_unsafe_exec"],
        summary["pct_with_unsafe_exec"],
    )
    logger.info(
        "  Auth: %d (%.1f%%)",
        summary["repos_with_auth"],
        summary["pct_with_auth"],
    )

    return summary


async def run_batch_scan(
    limit: int = 0,
    output_path: str = "data/mcp_scan_report.json",
    from_github: bool = False,
    skip_file: str | None = None,
) -> dict:
    """Run scan against MCP server repos.

    Args:
        limit: max repos to scan (0 = all)
        output_path: where to write the JSON report
        from_github: if True, discover repos via GitHub API.
                     If False, read from DB.
    """
    from src.github_auth import get_github_token
    token = await get_github_token()

    if from_github:
        skip = _load_skip_set(skip_file)
        repos = await _discover_from_github(token, limit, skip=skip)
    else:
        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import (
            AsyncSession,
            create_async_engine,
        )
        from sqlalchemy.orm import sessionmaker

        from src.models import RecruitmentProspect

        engine = create_async_engine(settings.database_url)
        factory = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False,
        )
        async with factory() as db:
            query = (
                select(RecruitmentProspect)
                .where(RecruitmentProspect.platform == "github")
                .order_by(RecruitmentProspect.stars.desc())
            )
            if limit > 0:
                query = query.limit(limit)
            rows = (await db.scalars(query)).all()
        await engine.dispose()

        repos = [
            {
                "full_name": r.platform_id,
                "stars": r.stars or 0,
                "description": r.description or "",
                "framework": r.framework_detected or "",
            }
            for r in rows
        ]

    logger.info("Total repos to scan: %d", len(repos))
    return await _scan_repos(repos, token, output_path, skip_file=skip_file)


if __name__ == "__main__":
    import argparse

    from src.observability import setup_logging

    setup_logging()

    parser = argparse.ArgumentParser(
        description="Batch scan MCP server repos",
    )
    parser.add_argument(
        "--limit", type=int, default=0, help="Max repos (0=all)",
    )
    parser.add_argument(
        "--output", default="data/mcp_scan_report.json",
        help="Output JSON path",
    )
    parser.add_argument(
        "--from-github", action="store_true",
        help="Discover repos from GitHub API instead of DB",
    )
    parser.add_argument(
        "--skip-file", default=None,
        help="Path to a newline-delimited set of already-scanned repo names; "
             "discovery skips these and appends newly-scanned ones (lets "
             "recurring runs accumulate coverage instead of repeating).",
    )
    args = parser.parse_args()

    asyncio.run(run_batch_scan(
        limit=args.limit,
        output_path=args.output,
        from_github=args.from_github,
        skip_file=args.skip_file,
    ))
