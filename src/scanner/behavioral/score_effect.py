"""How a signed sandbox observation moves the trust score — deterministic, recomputable.

The trust score is recomputable from evidence. Before this, the evidence was only the
code + registry data, so the sandbox result sat BESIDE the score. Now the score also
takes the signed ``BehavioralObservation`` as an input: given the static score and the
observation (both recorded in the score attestation as ``behavioralEvidence``), anyone
recomputes the same number with :func:`behavioral_score_effect`.

Rules (applied to the static score, in this order):
  * a canary credential left the sandbox, or any CRITICAL behavioral finding
      → hard ceiling 45 (same as a shipped critical in code): caught in the act
  * any HIGH behavioral finding (undeclared egress, a read-only tool that wrote files)
      → −10 and a ceiling of 70, i.e. always "needs review"
  * MEDIUM findings only → −5;  LOW findings → no change (a crash is not a security fact)
  * a clean, full exercise (server started, ≥1 tool called, no findings, no canary leak)
      → +3 evidence bonus (we watched it run), capped at 100
  * anything else (pending, not run, not started, install-only clean, unsigned) → no effect
"""
from __future__ import annotations

import hashlib

CRITICAL_CEILING = 45
HIGH_CEILING = 70
HIGH_PENALTY = 10
MEDIUM_PENALTY = 5
CLEAN_EXERCISE_BONUS = 3
RULES_VERSION = "behavioral-score-v1"


def behavioral_score_effect(static_score: int, block: dict | None) -> dict:
    """{"applied", "static_score", "score", "delta", "reason", "evidence"} for ``block``
    (the public behavioral block incl. its ``attestation``). Pure; never raises."""
    base = int(static_score or 0)
    none = {"applied": False, "static_score": base, "score": base, "delta": 0,
            "reason": "", "evidence": None}
    try:
        if not isinstance(block, dict) or not block.get("ran") or block.get("pending"):
            return none
        att = block.get("attestation") or {}
        jws = att.get("jws") if isinstance(att, dict) else None
        if not jws:
            return none  # only a SIGNED observation may move a signed score
        findings = [f for f in (block.get("findings") or []) if isinstance(f, dict)]
        sev = {str(f.get("severity") or "").lower() for f in findings}
        exfil = bool(block.get("canary_exfil"))
        ex = block.get("exercise") if isinstance(block.get("exercise"), dict) else {}
        calls = len(ex.get("calls") or []) if ex else 0
        score, reason = base, ""
        names = ", ".join(sorted({str(f.get("rule") or f.get("name") or "")
                                  for f in findings if f.get("severity") in
                                  ("critical", "high")}))[:120]
        if exfil or "critical" in sev:
            score = min(score, CRITICAL_CEILING)
            reason = ("caught in the sandbox: a canary credential left the machine" if exfil
                      else f"caught in the sandbox: {names}")
        elif "high" in sev:
            score = min(score - HIGH_PENALTY, HIGH_CEILING)
            reason = f"sandbox finding: {names}"
        elif "medium" in sev:
            score = score - MEDIUM_PENALTY
            reason = "sandbox: medium behavioral finding(s)"
        elif not findings and ex and ex.get("launch_ok") and calls >= 1:
            score = min(100, score + CLEAN_EXERCISE_BONUS)
            reason = f"sandbox: clean run, {calls} tool(s) exercised"
        score = max(0, score)
        evidence = {
            "rules": RULES_VERSION,
            "observationSha256": hashlib.sha256(jws.encode("ascii")).hexdigest(),
            "observedAt": att.get("observed_at"),
            "plan": block.get("plan") or "",
            "launchOk": bool(ex.get("launch_ok")) if ex else False,
            "toolsCalled": calls,
            "canaryExfil": exfil,
            "findings": sorted([{"rule": str(f.get("rule") or ""),
                                 "severity": str(f.get("severity") or "")} for f in findings],
                               key=lambda x: (x["rule"], x["severity"])),
            "staticScore": base,
            "delta": score - base,
        }
        return {"applied": score != base, "static_score": base, "score": score,
                "delta": score - base, "reason": reason if score != base else "",
                "evidence": evidence}
    except Exception:  # noqa: BLE001
        return none
