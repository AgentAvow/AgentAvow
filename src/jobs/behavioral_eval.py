"""Scheduled behavioral-tier eval: run the sandbox eval corpus, keep the reports, diff
them, and raise an alarm when the graders regress.

What runs (in-process, through ``scripts/sandbox/eval/run_eval.py``):

  * every fixture (MCP servers + fixture skills) INTO the real sandbox — each one has
    the exact rules the graders must and must not raise;
  * every known-good package and skill — a finding on one of these is a false
    positive until a human says otherwise (``expect_rules`` marks the true ones).

Everything is serialized and holds ONE behavioral slot at a time (acquired and
released around each item), so a live scan always has the other slot.

The corpus = the file entries merged with admin overrides kept in Redis:
``ag:eval:corpus:add`` (JSON list of extra known_good entries) and
``ag:eval:corpus:remove`` (JSON list of ``"surface:name"`` / ``"skill:owner/repo"``
keys to skip). Reports go to ``ag:eval:behavioral:latest`` and the newest-first list
``ag:eval:behavioral:history`` (trimmed to 26 ≈ half a year of weekly runs).

A report carries a ``diff`` against the previous one; when it shows a fixture
failure, a new false positive, or an exercised count that dropped by 2 or more, the
admins get a notification and — if the admin account has an alert webhook — the same
HMAC-signed webhook the watch alerts use. The first-ever run never alerts.
"""
from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import json
import logging
import pathlib
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

LATEST_KEY = "ag:eval:behavioral:latest"
HISTORY_KEY = "ag:eval:behavioral:history"
RUNNING_KEY = "ag:eval:behavioral:running"
CORPUS_ADD_KEY = "ag:eval:corpus:add"
CORPUS_REMOVE_KEY = "ag:eval:corpus:remove"
HISTORY_MAX = 26
RUNNING_TTL = 2 * 60 * 60
EXERCISED_DROP_ALERT = 2  # exercised count dropped by this many vs the previous report
ALERT_LOG_PREFIX = "BEHAVIORAL-EVAL REGRESSION:"
NOTIFICATION_KIND = "ops_alert"
WEBHOOK_TYPE = "agentavow.ops.behavioral_eval_regression"

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUN_EVAL_PATH = ROOT / "scripts" / "sandbox" / "eval" / "run_eval.py"
_run_eval_module = None


class EvalAlreadyRunningError(RuntimeError):
    """Another eval holds ``ag:eval:behavioral:running``."""


class NoSandboxSlotError(RuntimeError):
    """No behavioral slot came free within the wait budget."""


def load_run_eval():
    """The eval script as a module (it is a script, not a package — same trick as
    tests/test_behavioral_eval.py). Imported once."""
    global _run_eval_module
    if _run_eval_module is None:
        spec = importlib.util.spec_from_file_location("agentavow_run_eval", RUN_EVAL_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        _run_eval_module = mod
    return _run_eval_module


# ---------------------------------------------------------------------------
# corpus: file entries + admin overrides
# ---------------------------------------------------------------------------

def corpus_key(entry: dict) -> str:
    """``surface:name`` for a package, ``skill:owner/repo`` for a skill."""
    if "repo" in entry and not entry.get("name"):
        return f"skill:{entry['repo']}"
    return f"{entry.get('surface', 'skill')}:{entry.get('name') or entry.get('repo', '')}"


def _normalize(entry: dict, source: str) -> dict | None:
    """One known-good entry in the shape ``run_known_good`` wants, plus ``source``/``key``.
    Returns None for an entry that cannot be run."""
    if not isinstance(entry, dict):
        return None
    repo = entry.get("repo")
    surface = (entry.get("surface") or ("skill" if repo else "")).strip().lower()
    name = (entry.get("name") or repo or "").strip()
    if not surface or not name:
        return None
    if surface == "skill" and name.count("/") != 1:
        return None
    if surface not in ("npm", "pypi", "skill"):
        return None
    rules = [str(r) for r in (entry.get("expect_rules") or []) if r]
    out = {"surface": surface, "name": name, "expect_rules": rules, "source": source}
    if surface == "skill":
        out["repo"] = name
    if entry.get("note"):
        out["note"] = str(entry["note"])[:300]
    out["key"] = corpus_key(out)
    return out


def file_known_good(corpus: dict | None = None) -> list[dict]:
    corpus = corpus if corpus is not None else load_run_eval().load_corpus()
    out = []
    for e in corpus.get("known_good", []):
        n = _normalize(e, "file")
        if n:
            out.append(n)
    for e in corpus.get("known_good_skills", []):
        n = _normalize(dict(e, surface="skill"), "file")
        if n:
            out.append(n)
    return out


async def _redis_json(key: str, default):
    try:
        from src.redis_client import get_redis

        raw = await get_redis().get(key)
    except Exception:
        return default
    if raw is None:
        return default
    try:
        if isinstance(raw, bytes):
            raw = raw.decode()
        val = json.loads(raw)
    except (ValueError, TypeError):
        return default
    return val if isinstance(val, type(default)) else default


async def read_overrides() -> tuple[list[dict], list[str]]:
    """``(add, remove)`` as the admin left them; malformed or missing reads as empty."""
    add = [e for e in await _redis_json(CORPUS_ADD_KEY, []) if isinstance(e, dict)]
    remove = [str(k) for k in await _redis_json(CORPUS_REMOVE_KEY, []) if k]
    return add, remove


async def write_overrides(add: list[dict], remove: list[str]) -> None:
    from src.redis_client import get_redis

    r = get_redis()
    await r.set(CORPUS_ADD_KEY, json.dumps(add, separators=(",", ":")))
    await r.set(CORPUS_REMOVE_KEY, json.dumps(remove, separators=(",", ":")))


async def merged_corpus(corpus: dict | None = None) -> list[dict]:
    """File entries + admin additions, minus admin removals. An admin entry with the
    same key as a file entry replaces it (so expect_rules can be overridden)."""
    add, remove = await read_overrides()
    rows: dict[str, dict] = {}
    for e in file_known_good(corpus):
        rows[e["key"]] = e
    for e in add:
        n = _normalize(e, "admin")
        if n:
            rows[n["key"]] = n
    removed = set(remove)
    return [e for e in rows.values() if e["key"] not in removed]


async def corpus_view(corpus: dict | None = None) -> list[dict]:
    """The merged corpus for the admin API, with removed file entries shown as
    ``removed`` so they can be restored."""
    add, remove = await read_overrides()
    merged = await merged_corpus(corpus)
    out = [dict(e, removed=False) for e in merged]
    removed = set(remove)
    for e in file_known_good(corpus):
        if e["key"] in removed:
            out.append(dict(e, removed=True))
    return out


async def apply_corpus_edit(
    action: str, surface: str, name: str, expect_rules: list[str] | None = None,
) -> list[dict]:
    """``add`` puts an entry in the admin additions (and un-removes it); ``remove``
    drops an admin addition or marks a file entry removed. Returns the corpus view."""
    entry = _normalize({"surface": surface, "name": name, "expect_rules": expect_rules or []},
                       "admin")
    if entry is None:
        raise ValueError("surface must be npm, pypi or skill (skill name is owner/repo)")
    key = entry["key"]
    add, remove = await read_overrides()
    if action == "add":
        add = [e for e in add if corpus_key(e) != key] + [
            {k: entry[k] for k in ("surface", "name", "expect_rules") if k in entry}]
        remove = [k for k in remove if k != key]
    elif action == "remove":
        add = [e for e in add if corpus_key(e) != key]
        if key in {e["key"] for e in file_known_good()} and key not in remove:
            remove = remove + [key]
    else:
        raise ValueError("action must be add or remove")
    await write_overrides(add, remove)
    return await corpus_view()


# ---------------------------------------------------------------------------
# one behavioral slot at a time
# ---------------------------------------------------------------------------

@contextlib.asynccontextmanager
async def hold_slot(*, wait_s: float | None = None, poll_s: float = 10.0):
    """Acquire one of the global sandbox slots (the same counter the public scan path
    uses), waiting up to ``wait_s`` for one to free up. Released on exit."""
    from src.api.public_scan_router import _acquire_behavioral_slot, _release_behavioral_slot
    from src.config import settings

    budget = float(wait_s if wait_s is not None
                   else getattr(settings, "behavioral_eval_slot_wait_sec", 600))
    deadline = time.monotonic() + budget
    while not (lease := await _acquire_behavioral_slot()):
        if time.monotonic() >= deadline:
            raise NoSandboxSlotError(f"no sandbox slot within {budget:.0f}s")
        await asyncio.sleep(poll_s)
    try:
        yield
    finally:
        await _release_behavioral_slot(lease)


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------

async def mark_running() -> bool:
    """``SET NX`` the running flag. True when this caller now owns the run. Fails open
    (no Redis = no other worker to collide with)."""
    try:
        from src.redis_client import get_redis

        return bool(await get_redis().set(RUNNING_KEY, "1", nx=True, ex=RUNNING_TTL))
    except Exception:
        return True


async def clear_running() -> None:
    try:
        from src.redis_client import get_redis

        await get_redis().delete(RUNNING_KEY)
    except Exception:
        pass


async def is_running() -> bool:
    try:
        from src.redis_client import get_redis

        return bool(await get_redis().get(RUNNING_KEY))
    except Exception:
        return False


async def _run_fixture(run_eval, entry: dict) -> dict:
    name = entry.get("file") or entry.get("dir", "")
    row = {"kind": "fixture", "label": entry.get("label", name), "file": name,
           "ok": False, "failures": [], "rules": [], "seconds": 0.0}
    started = time.monotonic()
    try:
        async with hold_slot():
            res = await run_eval.run_fixture_entry_sandbox(entry)
        rules = sorted({f.rule for f in run_eval.grade(res)})
        failures = (run_eval.check_expectations(entry, res) if res.ran
                    else [f"did not run: {res.error}"])
        row.update(rules=rules, failures=failures, ok=not failures)
    except NoSandboxSlotError as e:
        row["failures"] = [f"skipped: {e}"]
    except Exception as e:  # noqa: BLE001 — one bad fixture must not sink the run
        logger.exception("behavioral eval: fixture %s crashed", name)
        row["failures"] = [f"crashed: {type(e).__name__}: {e}"[:300]]
    row["seconds"] = round(time.monotonic() - started, 1)
    return row


async def _run_known_good(run_eval, pkg: dict) -> dict:
    row = {"kind": "known_good", "surface": pkg["surface"], "name": pkg["name"],
           "source": pkg.get("source", "file"), "expect_rules": pkg.get("expect_rules", []),
           "ran": False, "error": None, "launch_ok": False, "start_reason": "unknown",
           "tools_called": 0, "rules": [], "false_positives": [], "seconds": 0.0}
    started = time.monotonic()
    try:
        async with hold_slot():
            full = await run_eval.run_known_good(pkg)
        s = full.get("summary") or {}
        row.update(
            ran=bool(full.get("ran")), error=full.get("error"),
            launch_ok=bool(s.get("launch_ok")),
            start_reason=str(s.get("start_reason") or "unknown"),
            tools_called=int(s.get("tools_called") or 0),
            rules=sorted({f["rule"] for f in full.get("findings") or [] if f.get("rule")}),
            false_positives=sorted(set(full.get("false_positives") or [])),
        )
    except NoSandboxSlotError as e:
        row["error"] = f"skipped: {e}"
        row["start_reason"] = "no_slot"
    except Exception as e:  # noqa: BLE001
        logger.exception("behavioral eval: known-good %s crashed", pkg["name"])
        row["error"] = f"crashed: {type(e).__name__}: {e}"[:300]
        row["start_reason"] = "crashed"
    row["seconds"] = round(time.monotonic() - started, 1)
    return row


def build_report(rows: list[dict], *, reason: str, ran_at: str, duration_s: float) -> dict:
    fixtures = [r for r in rows if r["kind"] == "fixture"]
    kg = [r for r in rows if r["kind"] == "known_good"]
    return {
        "ran_at": ran_at,
        "reason": reason,
        "duration_s": round(duration_s, 1),
        "fixtures": {
            "total": len(fixtures),
            "passed": sum(1 for r in fixtures if r["ok"]),
            "failed": [r["label"] for r in fixtures if not r["ok"]],
        },
        "known_good": {
            "total": len(kg),
            "ran": sum(1 for r in kg if r["ran"]),
            "exercised": sum(1 for r in kg if r["launch_ok"]),
            "false_positives": [
                {"surface": r["surface"], "name": r["name"], "rules": r["false_positives"]}
                for r in kg if r["false_positives"]],
            "expected_findings": sum(1 for r in kg if r["rules"] and not r["false_positives"]),
            "not_started": [{"name": r["name"], "start_reason": r["start_reason"]}
                            for r in kg if not r["launch_ok"]],
        },
        "rows": rows,
    }


# ---------------------------------------------------------------------------
# diff + alerting
# ---------------------------------------------------------------------------

def _fp_map(report: dict) -> dict[str, set[str]]:
    return {f"{f['surface']}:{f['name']}": set(f.get("rules") or [])
            for f in (report.get("known_good") or {}).get("false_positives") or []}


def _exercised_names(report: dict) -> set[str]:
    return {f"{r['surface']}:{r['name']}" for r in report.get("rows") or []
            if r.get("kind") == "known_good" and r.get("launch_ok")}


def _failed_fixtures(report: dict) -> set[str]:
    return set((report.get("fixtures") or {}).get("failed") or [])


def _kg_rows(report: dict) -> dict[str, dict]:
    return {f"{r['surface']}:{r['name']}": r for r in report.get("rows") or []
            if r.get("kind") == "known_good"}


def _lost_expected(previous: dict, current: dict) -> list[dict]:
    """Known-good packages that produced an EXPECTED finding last time, ran this time,
    and no longer produce it. That is the sandbox going blind, not the package getting
    safer: on 2026-10-08 a full scratch disk truncated every capture, the tiny fixtures
    still passed, and mcp-server-fetch silently lost ssrf_internal_fetch."""
    prev_rows, out = _kg_rows(previous), []
    for key, row in sorted(_kg_rows(current).items()):
        if not row.get("ran") or row.get("error"):
            continue
        expected = set(row.get("expect_rules") or [])
        before = set((prev_rows.get(key) or {}).get("rules") or []) & expected
        lost = sorted(before - set(row.get("rules") or []))
        if lost:
            surface, _, name = key.partition(":")
            out.append({"surface": surface, "name": name, "rules": lost})
    return out


def compute_diff(previous: dict | None, current: dict) -> dict:
    """What changed since the last report. ``regression`` is the alert condition; it is
    never set on the first-ever run."""
    cur_fp = _fp_map(current)
    cur_failed = sorted(_failed_fixtures(current))
    cur_ex = (current.get("known_good") or {}).get("exercised") or 0
    diff = {
        "first_run": previous is None,
        "previous_ran_at": (previous or {}).get("ran_at"),
        "fixture_failures": cur_failed,
        "fixture_regressions": [],
        "fixture_fixed": [],
        "new_false_positives": [],
        "cleared_false_positives": [],
        "newly_not_exercised": [],
        "newly_exercised": [],
        "exercised_delta": 0,
        "lost_expected_findings": [],
        "regression": False,
    }
    if previous is None:
        return diff
    diff["lost_expected_findings"] = _lost_expected(previous, current)
    prev_fp = _fp_map(previous)
    prev_failed = _failed_fixtures(previous)
    diff["fixture_regressions"] = sorted(set(cur_failed) - prev_failed)
    diff["fixture_fixed"] = sorted(prev_failed - set(cur_failed))
    for key, rules in sorted(cur_fp.items()):
        new_rules = sorted(rules - prev_fp.get(key, set()))
        if new_rules:
            surface, _, name = key.partition(":")
            diff["new_false_positives"].append(
                {"surface": surface, "name": name, "rules": new_rules})
    diff["cleared_false_positives"] = sorted(set(prev_fp) - set(cur_fp))
    prev_ex, cur_ex_names = _exercised_names(previous), _exercised_names(current)
    diff["newly_not_exercised"] = sorted(prev_ex - cur_ex_names)
    diff["newly_exercised"] = sorted(cur_ex_names - prev_ex)
    prev_count = (previous.get("known_good") or {}).get("exercised") or 0
    diff["exercised_delta"] = int(cur_ex) - int(prev_count)
    diff["regression"] = bool(
        cur_failed or diff["new_false_positives"] or diff["lost_expected_findings"]
        or diff["exercised_delta"] <= -EXERCISED_DROP_ALERT)
    return diff


def summarize_regression(report: dict) -> tuple[str, str]:
    """(title, body) for the notification / webhook / log line."""
    d = report.get("diff") or {}
    parts = []
    if d.get("fixture_failures"):
        parts.append("fixtures failing: " + ", ".join(d["fixture_failures"]))
    if d.get("new_false_positives"):
        parts.append("new false positives: " + ", ".join(
            f"{f['surface']}:{f['name']} ({', '.join(f['rules'])})"
            for f in d["new_false_positives"]))
    if d.get("lost_expected_findings"):
        parts.append("sandbox stopped catching known findings (check capture health on "
                     "the box): " + ", ".join(
                         f"{f['surface']}:{f['name']} ({', '.join(f['rules'])})"
                         for f in d["lost_expected_findings"]))
    if (d.get("exercised_delta") or 0) <= -EXERCISED_DROP_ALERT:
        parts.append(f"exercised dropped by {-d['exercised_delta']} "
                     f"({', '.join(d.get('newly_not_exercised') or []) or 'see report'})")
    fx, kg = report.get("fixtures") or {}, report.get("known_good") or {}
    title = "Behavioral eval regressed"
    body = (f"Weekly sandbox eval ({report.get('ran_at')}): "
            f"fixtures {fx.get('passed', 0)}/{fx.get('total', 0)} passed, "
            f"{kg.get('exercised', 0)}/{kg.get('total', 0)} known-good exercised, "
            f"{len(kg.get('false_positives') or [])} with false positives. "
            + "; ".join(parts) + ".")
    return title, body


async def _admin_entities(db):
    from sqlalchemy import or_, select

    from src.config import settings
    from src.models import Entity

    return list((await db.execute(
        select(Entity).where(or_(Entity.is_admin.is_(True),
                                 Entity.email == settings.admin_email))
    )).scalars().all())


async def alert_regression(report: dict) -> dict:
    """Notify every admin account and deliver to the admin's alert webhook (the same
    HMAC-signed path watch alerts use). Returns what was delivered; never raises."""
    title, body = summarize_regression(report)
    logger.warning("%s %s — %s", ALERT_LOG_PREFIX, title, body)
    out = {"notified": 0, "webhooks": 0}
    try:
        from src.api.notification_router import create_notification
        from src.database import async_session

        async with async_session() as db:
            admins = await _admin_entities(db)
            if not admins:
                logger.warning("%s no admin account to notify (set an is_admin entity "
                               "or admin_email)", ALERT_LOG_PREFIX)
            for admin in admins:
                try:
                    await create_notification(db, admin.id, NOTIFICATION_KIND, title, body,
                                              reference_id="behavioral-eval")
                    out["notified"] += 1
                except Exception:
                    logger.exception("%s notification to %s failed",
                                     ALERT_LOG_PREFIX, admin.id)
            await db.commit()
            for admin in admins:
                try:
                    from src.api.account_webhook_router import deliver_to_hook
                    from src.jobs.scheduler import _watcher_hook

                    hook = await _watcher_hook(db, admin.id)
                    if hook is None:
                        continue
                    hook.last_status = await deliver_to_hook(hook, {
                        "type": WEBHOOK_TYPE, "event": "behavioral_eval_regression",
                        "title": title, "body": body, "ran_at": report.get("ran_at"),
                        "fixtures": report.get("fixtures"),
                        "known_good": {k: v for k, v in (report.get("known_good") or {}).items()
                                       if k != "not_started"},
                        "diff": report.get("diff"),
                    })
                    hook.last_delivery_at = datetime.now(timezone.utc)
                    out["webhooks"] += 1
                except Exception:
                    logger.exception("%s webhook to %s failed", ALERT_LOG_PREFIX, admin.id)
            await db.commit()
    except Exception:
        logger.exception("%s could not deliver the alert", ALERT_LOG_PREFIX)
    return out


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------

async def read_latest() -> dict | None:
    val = await _redis_json(LATEST_KEY, {})
    return val or None


async def read_history(limit: int = HISTORY_MAX) -> list[dict]:
    try:
        from src.redis_client import get_redis

        raw = await get_redis().lrange(HISTORY_KEY, 0, max(limit - 1, 0))
    except Exception:
        return []
    out = []
    for item in raw or []:
        try:
            if isinstance(item, bytes):
                item = item.decode()
            val = json.loads(item)
            if isinstance(val, dict):
                out.append(val)
        except (ValueError, TypeError):
            continue
    return out


async def store_report(report: dict) -> None:
    from src.redis_client import get_redis

    r = get_redis()
    blob = json.dumps(report, separators=(",", ":"), default=str)
    await r.set(LATEST_KEY, blob)
    await r.lpush(HISTORY_KEY, blob)
    await r.ltrim(HISTORY_KEY, 0, HISTORY_MAX - 1)


def report_summary(report: dict | None) -> dict | None:
    """The report minus its rows, for the dashboard."""
    if not report:
        return None
    return {k: v for k, v in report.items() if k != "rows"}


# ---------------------------------------------------------------------------

async def run_behavioral_eval(*, reason: str = "scheduled", _already_marked: bool = False,
                              ) -> dict:
    """Run the whole corpus, store the report, diff it against the previous one, alert
    on a regression. Raises ``EvalAlreadyRunningError`` when another run holds the flag."""
    if not _already_marked and not await mark_running():
        raise EvalAlreadyRunningError("a behavioral eval is already running")
    started = time.monotonic()
    ran_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    logger.info("behavioral eval started (reason=%s)", reason)
    try:
        run_eval = load_run_eval()
        corpus = run_eval.load_corpus()
        rows: list[dict] = []
        for entry in list(corpus.get("fixtures", [])) + list(corpus.get("skill_fixtures", [])):
            rows.append(await _run_fixture(run_eval, entry))
        for pkg in await merged_corpus(corpus):
            rows.append(await _run_known_good(run_eval, pkg))
        report = build_report(rows, reason=reason, ran_at=ran_at,
                              duration_s=time.monotonic() - started)
        previous = await read_latest()
        report["diff"] = compute_diff(previous, report)
        try:
            await store_report(report)
        except Exception:
            logger.exception("behavioral eval: could not store the report")
        if report["diff"]["regression"]:
            report["alert"] = await alert_regression(report)
        logger.info(
            "behavioral eval finished in %.0fs: fixtures %d/%d, known-good %d/%d exercised, "
            "%d false positives, regression=%s",
            report["duration_s"], report["fixtures"]["passed"], report["fixtures"]["total"],
            report["known_good"]["exercised"], report["known_good"]["total"],
            len(report["known_good"]["false_positives"]), report["diff"]["regression"],
        )
        return report
    finally:
        await clear_running()
