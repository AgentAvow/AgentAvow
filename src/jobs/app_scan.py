"""Scheduled PRIVATE-repo scanning for connected GitHub App installations.

When an owner installs the AgentAvow GitHub App (see ``github_app_router.connect``),
the install itself is proof they control those repos. This module turns that
install into something that actually DOES work:

  1. mint a short-lived installation token (never persisted — GitHub rotates it),
  2. list the repos the installation can access (reusing ``_installation_repos``),
  3. scan each repo (capped, fail-open per-repo),
  4. upsert an owner-scoped ``PrivateScanResult`` (never public/catalog),
  5. ensure a VERIFIED ``RepoClaim`` for each repo — the App install IS the
     ownership proof, so no topic/token dance is needed,
  6. fire grade-change alerts with the SAME rules as the watch re-scan loop
     (``src/jobs/scheduler.py``): a score drop, digest drift, a worse answer or a lost
     Certified mark → one ``watch_alert`` plus the ``grade_change`` webhook carrying
     every reason; a score rise, a better answer or a new Certified mark →
     ``watch_good_news`` (in-app, no webhook).

Fail-open throughout: a per-repo failure is swallowed so one bad repo can't sink
the whole installation, and token/list failures return an empty summary rather
than raising — this must never break the connect flow or a scheduler tick.

The caller owns the transaction: this function ``flush``es its writes but does
NOT ``commit`` (so it composes with a test's transactional session). Real callers
(the connect background task and the scheduler loop) wrap it in their own
``async_session()`` and commit.
"""
from __future__ import annotations

import logging
import secrets

logger = logging.getLogger(__name__)

# Per-install repo cap — a heavy org install shouldn't scan hundreds of repos in
# one tick and drain the GitHub budget. Matches the ~25 the task calls for.
_MAX_REPOS_PER_INSTALL = 25

# Score-change thresholds (mirror _run_watch_rescan's +/-5 band).
_CHANGE_THRESHOLD = 5


async def scan_installation(db, installation) -> dict:
    """Scan every repo a connected GitHub App installation can access, store each
    result, verify-claim each repo, and fire grade-change alerts.

    ``db``           an ``AsyncSession`` owned by the caller (NOT committed here).
    ``installation`` a ``GitHubAppInstallation`` row (needs ``installation_id`` +
                     ``entity_id`` loaded).

    Returns a small summary dict. Fail-open — never raises for a scan/network
    failure.
    """
    from src.api.github_app_router import _installation_repos
    from src.github_auth import mint_installation_token

    entity_id = installation.entity_id
    inst_id = installation.installation_id
    summary: dict = {
        "installation_id": inst_id,
        "entity_id": str(entity_id),
        "scanned": 0,
        "failed": 0,
        "alerts": 0,
        "repos": [],
    }

    # Mint a token for THIS installation (fail-open — no token, nothing to do).
    try:
        token = await mint_installation_token(inst_id)
    except Exception:
        logger.warning(
            "app_scan: could not mint token for installation %s", inst_id, exc_info=True
        )
        summary["error"] = "token_mint_failed"
        return summary

    # List the repos this installation can access (reuses the app router query).
    try:
        repos = await _installation_repos(inst_id)
    except Exception:
        logger.warning(
            "app_scan: could not list repos for installation %s", inst_id, exc_info=True
        )
        summary["error"] = "repo_list_failed"
        return summary

    from sqlalchemy import select

    from src.models import RepoClaim

    for r in repos[:_MAX_REPOS_PER_INSTALL]:
        full_name = (r or {}).get("full_name")
        if not full_name or "/" not in full_name:
            continue
        owner, repo = full_name.split("/", 1)
        # Only RE-scan repos the owner has EXPLICITLY claimed — never auto-claim a
        # whole installation. Claiming is a per-repo action (POST /claim-repo).
        claimed = (await db.execute(
            select(RepoClaim).where(
                RepoClaim.entity_id == entity_id,
                RepoClaim.owner == owner,
                RepoClaim.repo == repo,
                RepoClaim.status == "verified",
            )
        )).scalar_one_or_none()
        if claimed is None:
            continue
        try:
            fired = await _scan_and_store(db, entity_id, owner, repo, full_name, token)
            summary["scanned"] += 1
            summary["alerts"] += fired
            summary["repos"].append(full_name)
        except Exception:
            summary["failed"] += 1
            logger.warning("app_scan: repo scan failed for %s", full_name, exc_info=True)

    return summary


async def scan_one_repo(db, installation_id: str, entity_id, owner: str, repo: str) -> int:
    """Scan a SINGLE claimed repo (the per-repo claim flow) — mint a token, scan,
    store the result, refresh the verified claim, and fire alerts. Fail-open."""
    from src.github_auth import mint_installation_token

    try:
        token = await mint_installation_token(installation_id)
    except Exception:
        logger.warning("scan_one_repo: token mint failed for %s", installation_id)
        return 0
    try:
        return await _scan_and_store(db, entity_id, owner, repo, f"{owner}/{repo}", token)
    except Exception:
        logger.warning("scan_one_repo failed for %s/%s", owner, repo, exc_info=True)
        return 0


async def _scan_and_store(db, entity_id, owner: str, repo: str, full_name: str, token: str) -> int:
    """Scan one repo, upsert its PrivateScanResult, ensure a verified RepoClaim,
    and fire grade-change notifications. Returns the number of alerts fired (0/1).

    Any DB writes are flushed (not committed) — the caller owns the transaction.
    """
    from sqlalchemy import func as safunc
    from sqlalchemy import select

    from src.api.public_scan_router import _grade_from_score, _scan_result_to_dict
    from src.models import PrivateScanResult
    from src.scanner.scan import scan_repo

    # Scan with the installation token (private-repo capable).
    result = await scan_repo(full_name, token=token)
    if getattr(result, "error", None):
        raise RuntimeError(result.error)

    data = _scan_result_to_dict(result)
    new_score = data.get("trust_score")
    grade = _grade_from_score(new_score) if new_score is not None else None

    # --- Upsert the owner-scoped PrivateScanResult ---------------------------
    existing = (
        await db.execute(
            select(PrivateScanResult).where(
                PrivateScanResult.entity_id == entity_id,
                PrivateScanResult.owner == owner,
                PrivateScanResult.repo == repo,
            )
        )
    ).scalar_one_or_none()

    prev_score = existing.trust_score if existing is not None else None
    old_json = existing.result_json if existing is not None else None
    last_decision = existing.last_decision if existing is not None else None
    last_certified = existing.last_certified if existing is not None else None

    if existing is not None:
        row = existing
        existing.prev_score = prev_score
        existing.trust_score = new_score
        existing.grade = grade
        existing.result_json = data
        existing.source = "app"
        existing.scanned_at = safunc.now()
    else:
        row = PrivateScanResult(
            entity_id=entity_id,
            owner=owner,
            repo=repo,
            full_name=full_name,
            trust_score=new_score,
            grade=grade,
            result_json=data,
            prev_score=None,
            source="app",
        )
        db.add(row)
    await db.flush()

    # --- Ensure a VERIFIED RepoClaim (the App install IS the ownership proof) -
    await _ensure_verified_claim(db, entity_id, owner, repo, full_name)

    # --- Fire grade-change alerts (same rules as _run_watch_rescan) -----------
    fired, answer = await _maybe_notify(
        db, entity_id, owner, repo, full_name, prev_score, new_score, old_json, data,
        last_decision=last_decision, last_certified=last_certified,
    )
    # The answer baseline moves every re-scan (a first scan seeds it silently).
    row.last_decision = answer.decision_baseline
    row.last_certified = answer.certified_baseline
    await db.flush()
    return fired


async def _ensure_verified_claim(
    db, entity_id, owner: str, repo: str, full_name: str, is_private: bool | None = None
) -> None:
    """Ensure a verified RepoClaim exists for (entity, owner, repo). Idempotent —
    if one already exists it's just marked verified; otherwise a verified claim is
    created. The App install proves ownership, so no topic/token check is needed.

    ``is_private`` (when provided) is recorded authoritatively — it drives the
    publish-to-search affordance. Passed by the App claim path (which knows the
    repo's visibility); left None by re-scans so an existing flag is never lost."""
    from sqlalchemy import func as safunc
    from sqlalchemy import select

    from src.models import RepoClaim

    claim = (
        await db.execute(
            select(RepoClaim).where(
                RepoClaim.entity_id == entity_id,
                RepoClaim.owner == owner,
                RepoClaim.repo == repo,
            )
        )
    ).scalar_one_or_none()

    if claim is not None:
        changed = False
        if claim.status != "verified":
            claim.status = "verified"
            claim.verified_at = safunc.now()
            changed = True
        if is_private is not None and bool(claim.is_private) != bool(is_private):
            claim.is_private = bool(is_private)
            changed = True
        if changed:
            await db.flush()
        return

    db.add(
        RepoClaim(
            entity_id=entity_id,
            owner=owner,
            repo=repo,
            full_name=full_name,
            status="verified",
            verify_code=secrets.token_hex(8),  # NOT NULL — unused for App-proof claims
            is_private=bool(is_private) if is_private is not None else False,
            verified_at=safunc.now(),
        )
    )
    await db.flush()


async def _maybe_notify(
    db, entity_id, owner: str, repo: str, full_name: str,
    prev_score, new_score, old_json, new_json,
    last_decision: str | None = None, last_certified: bool | None = None,
):
    """Compare the new scan to the previous one and alert with the watch loop's rules
    (``src/jobs/scheduler.py``): a score drop, signed-definition (tool-manifest) drift,
    a worse answer or a lost Certified mark send ONE ``watch_alert`` naming every
    reason, plus the ``grade_change`` webhook (``triggers[]``, ``reasons[]``,
    ``old_decision``, ``old_certified_mark``) to the owner's alert webhook. A score
    rise, a better answer or a newly earned mark send ``watch_good_news`` (in-app,
    never the webhook).

    Returns ``(alerts fired: 0 or 1, AnswerChange)``; the caller stores the
    AnswerChange baseline. No stored answer yet (a first scan, or a row from before
    the columns) sets the baseline silently.
    """
    from datetime import datetime, timezone

    from src.api.notification_router import create_notification
    from src.jobs.scheduler import (
        AnswerChange,
        _answer_phrase,
        _watch_decision,
        _watcher_hook,
        alert_extra_reasons,
        alert_triggers,
        grade_change_payload,
        w_decision_phrase,
    )

    dropped = (
        prev_score is not None and new_score is not None
        and new_score < prev_score - _CHANGE_THRESHOLD
    )
    improved = (
        prev_score is not None and new_score is not None
        and new_score > prev_score + _CHANGE_THRESHOLD
    )
    # A private repo has no sandbox block: the answer is decide() over the scan.
    decision = _watch_decision(new_json, None)
    answer = AnswerChange(last_decision, last_certified, decision)

    if dropped or improved or answer.moved:
        # A planned catalog re-score holds back score-change alerts (the formula moved,
        # not the repo), and answer moves with them. Definition drift below still alerts.
        from src.jobs.watch_alert_hold import score_alerts_held

        if await score_alerts_held():
            dropped = improved = False
            answer.absorb()

    old_digest = (old_json or {}).get("tool_manifest_digest") if old_json else None
    new_digest = (new_json or {}).get("tool_manifest_digest")
    drift = bool(old_digest and new_digest and old_digest != new_digest)

    old_phrase = _answer_phrase(last_decision, last_certified)
    triggers = alert_triggers(dropped, drift, answer)
    answer_alert = answer.worse or answer.certified_lost
    ref = full_name
    try:
        if triggers:
            reason = triggers[0][1]
            title = f"{owner}/{repo} — {reason}"
            body = (
                f"A private repo you connected changed: {reason}"
                + (f" ({prev_score} -> {new_score})" if dropped else "")
                + alert_extra_reasons(triggers)
                + (f" (was: {old_phrase})" if answer_alert else "")
                + f". Now: {w_decision_phrase(decision)}."
                + " Review it before your agents keep using it."
            )
            await create_notification(
                db, entity_id, "watch_alert", title, body, reference_id=ref,
            )
            # Webhook alert delivery, the same body as a watched tool's grade_change.
            try:
                hook = await _watcher_hook(db, entity_id)
                if hook is not None:
                    from src.api.account_webhook_router import deliver_to_hook

                    hook.last_status = await deliver_to_hook(hook, grade_change_payload(
                        owner, repo, prev_score, new_score, reason, triggers, decision,
                        last_decision, last_certified))
                    hook.last_delivery_at = datetime.now(timezone.utc)
            except Exception:
                logger.debug("app_scan: webhook alert delivery failed for %s", full_name)
            return 1, answer
        if improved or answer.better or answer.certified_gained:
            answer_up = answer.better or answer.certified_gained
            if improved:
                title = f"{owner}/{repo} — score improved 🎉"
                body = (
                    f"Good news: a private repo you connected improved "
                    f"({prev_score} → {new_score}/100). "
                    + (f"Was: {old_phrase}. " if answer_up else "")
                    + f"Now: {w_decision_phrase(decision)}."
                )
            else:
                what = "answer improved" if answer.better else "earned the Certified mark"
                title = f"{owner}/{repo} — {what} 🎉"
                body = (
                    f"Good news: a private repo you connected improved. Was: {old_phrase}. "
                    f"Now: {w_decision_phrase(decision)}."
                )
            await create_notification(
                db, entity_id, "watch_good_news", title, body, reference_id=ref,
            )
            return 1, answer
    except Exception:
        logger.warning(
            "app_scan: notification failed for %s", full_name, exc_info=True
        )
    return 0, answer


__all__ = ["scan_installation", "scan_one_repo"]
