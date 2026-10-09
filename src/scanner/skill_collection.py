"""Multi-skill repos: grade every skill, report the worst.

A skills repo such as ``anthropics/skills`` holds many ``SKILL.md`` files, each its own
installable skill. Grading only the shallowest one (the old behaviour) told a user
nothing about the other skills they might install. Here every real skill is graded
(capped by count and wall time), and the repo-level result is the WORST skill's
result, with every skill's answer listed in ``artifact_scan.skills`` so the page can
link each one to its own result (``/check/skill/<owner>/<repo>/<skill dir>``).
"""
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import re
from collections.abc import Awaitable, Callable

# A collection bigger than this is graded on its first MAX_SKILLS skills (by path),
# and the page says how many were left out.
MAX_SKILLS = 40
# Wall-time budget for the whole collection; skills not done by then are left out
# (and counted) rather than failing the scan. Sits inside the endpoint's 60 s timeout.
COLLECTION_DEADLINE_S = 40.0
CONCURRENCY = 6

# Template / example / test skeletons are not real skills (kept only if that's all
# there is) — the same filter the single-skill scan has always used.
_SKELETON = re.compile(r"(?:^|/)(template|example|sample|demo|starter|_?tests?)s?/", re.I)
_SKILL_ARG = re.compile(r"^[\w.\-/]+$")


def skill_dir(skill_md_path: str) -> str:
    """The directory a SKILL.md lives in (``""`` for a root SKILL.md)."""
    return skill_md_path.rsplit("/", 1)[0] if "/" in skill_md_path else ""


def real_skill_mds(skill_mds: list[str]) -> list[str]:
    """Real skills (skeletons dropped), in a stable path order."""
    return sorted((p for p in skill_mds if not _SKELETON.search(p)), key=str.lower)


def resolve_skill_md(skill_mds: list[str], skill: str) -> str | None:
    """The SKILL.md a ``skill`` argument names: its directory (``skills/pdf``) or, if
    unambiguous, its folder name (``pdf``). None for a bad or unknown name."""
    skill = (skill or "").strip().strip("/")
    if not skill or ".." in skill or not _SKILL_ARG.match(skill):
        return None
    by_dir = {skill_dir(p).lower(): p for p in skill_mds}
    if skill.lower() in by_dir:
        return by_dir[skill.lower()]
    named = [p for p in skill_mds if skill_dir(p).rsplit("/", 1)[-1].lower() == skill.lower()]
    return named[0] if len(named) == 1 else None


def _rank(r) -> tuple:
    """Higher = worse: a critical beats a high beats a lower score."""
    return (r.critical_count > 0, r.high_count > 0, -(r.trust_score or 0))


async def grade_skills(
    skill_mds: list[str], grade: Callable[[str], Awaitable],
) -> tuple[list[tuple[str, object]], int]:
    """Grade up to MAX_SKILLS skills concurrently within COLLECTION_DEADLINE_S.
    Returns ([(skill_md_path, ScanResult), ...] for the skills that finished without
    error, in path order) and the total number of real skills in the repo."""
    total = len(skill_mds)
    todo = skill_mds[:MAX_SKILLS]
    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(md: str):
        async with sem:
            return md, await grade(md)

    tasks = [asyncio.ensure_future(one(md)) for md in todo]
    done, pending = await asyncio.wait(tasks, timeout=COLLECTION_DEADLINE_S)
    for t in pending:
        t.cancel()
    out = []
    for t in done:
        if t.cancelled() or t.exception() is not None:
            continue
        md, res = t.result()
        if not getattr(res, "error", None):
            out.append((md, res))
    out.sort(key=lambda pair: pair[0].lower())
    return out, total


def build_collection_result(repo_id: str, graded: list[tuple[str, object]], total: int):
    """The repo-level result: a copy of the worst skill's result, plus the list of
    every graded skill and a combined digest over all of them (so a change to ANY
    skill shows as definition drift on the repo)."""
    from src.scanner.verdict import decide

    worst_md, worst = max(graded, key=lambda pair: _rank(pair[1]))
    skills = []
    for md, r in graded:
        d = decide({
            "trust_score": r.trust_score,
            "findings": {"items": [dataclasses.asdict(f) if dataclasses.is_dataclass(f)
                                   else dict(f) for f in (r.findings or [])]},
            "deprecation": getattr(r, "deprecation", None),
            "metadata": {"files_scanned": r.files_scanned},
        })
        skills.append({
            "path": skill_dir(md),
            "name": (r.artifact_scan or {}).get("skill_name") or skill_dir(md).rsplit("/", 1)[-1],
            "trust_score": r.trust_score,
            "decision": d.decision,
            "critical": r.critical_count,
            "high": r.high_count,
            "files_scanned": r.files_scanned,
        })
    combined = hashlib.sha256("\n".join(
        f"{s['path']}:{(r.tool_manifest_digest or '')}"
        for s, (_md, r) in zip(skills, graded)).encode()).hexdigest()

    result = dataclasses.replace(worst)
    result.repo = repo_id
    result.tool_manifest_digest = combined
    result.files_scanned = sum(r.files_scanned for _md, r in graded)
    result.total_scannable_files = result.files_scanned
    result.artifact_scan = {
        **(worst.artifact_scan or {}),
        "collection": True,
        "worst_skill": skill_dir(worst_md),
        "skills": skills,
        "skills_total": total,
        "skills_graded": len(graded),
        "tree_digest": combined,
    }
    result.per_skill = {skill_dir(md): r for md, r in graded}
    return result
