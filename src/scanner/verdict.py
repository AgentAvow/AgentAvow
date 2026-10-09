"""Shared safe / needs-review verdict derivation.

ONE source of truth for the binary verdict and its machine-readable reason, so the
public API JSON (`PublicScanResponse`) and the MCP connector (`mcp_streamable`) can
never disagree about whether a target is "safe to connect" or why.

Pure functions over a scan-result dict — no imports, no I/O, no side effects. The dict
shape is the same whether it comes straight from the scanner (API) or round-trips
through the public JSON (MCP), so both callers get identical answers.

Hard rule: adoption/popularity is NEVER a verdict input (popular != safe). The verdict
is code-analysis only, matching the signed trust_score.
"""
from __future__ import annotations

SAFE_BAR = 81  # A/A+ floor for the binary "safe" call (matches the site verdict)


def is_safe(data: dict) -> bool:
    """True iff the three-way decision is Safe to connect (``decide(data)``).

    Since 2026-10-08 the binary ``verdict`` follows ``decide()`` on every surface (Kenne:
    "make everything the same across the board"), so a result never reads ``safe`` in
    one field and Review in another (e.g. a deprecated package scoring 84, or a clean
    thin-coverage 74). The old score-bar rule survives as ``is_safe_legacy``.
    """
    return decide(data).decision == DECISION_SAFE


def is_safe_legacy(data: dict) -> bool:
    """The pre-2026-10-08 binary rule: trust_score >= SAFE_BAR AND no critical/high finding.

    Prefers the authoritative ``certified.checks.no_critical_or_high`` flag; falls back
    to scanning the (severity-sorted) findings items when that flag is absent.
    """
    score = int(data.get("trust_score") or 0)
    items = (data.get("findings") or {}).get("items") or []
    checks = (data.get("certified") or {}).get("checks") or {}
    no_blocking = checks.get("no_critical_or_high")
    if not isinstance(no_blocking, bool):
        no_blocking = not any(i.get("severity") in ("critical", "high") for i in items)
    return score >= SAFE_BAR and bool(no_blocking) and not sandbox_alarm(data)


def sandbox_alarm(data: dict) -> bool:
    """True when the behavioral sandbox caught something that must block a 'safe' call:
    a leaked canary credential, or a high/critical behavioral finding. Reads the public
    ``behavioral`` block (absent/pending → False)."""
    b = data.get("behavioral")
    if not isinstance(b, dict) or not b.get("ran"):
        return False
    if is_advisory_block(b):
        return False
    if b.get("canary_exfil"):
        return True
    return any(str(f.get("severity")) in ("critical", "high")
               for f in (b.get("findings") or []) if isinstance(f, dict))


def is_advisory_block(b: dict) -> bool:
    """True for a ``behavioral`` block that is advisory only — the opt-in live probe of a
    remote MCP server (``plan == "live-probe"``). Its findings are reported, never a
    verdict input: nobody can reproduce a live server's answers."""
    return isinstance(b, dict) and (b.get("plan") == "live-probe" or b.get("advisory") is True)


def verdict_reason(data: dict, safe: bool | None = None) -> str:
    """Machine-readable 'why' behind the verdict:

    - ``clean``             — safe.
    - ``blocking_findings`` — held back by a critical/high finding (real risk).
    - ``sandbox_finding``   — the behavioral sandbox caught it (undeclared egress,
                              a read-only tool that wrote, a leaked canary credential).
    - ``known_vulnerability`` — a published advisory (GHSA/CVE) affects this version.
    - ``deprecated``        — no risk found; the maintainer retired the package.
    - ``thin_coverage``     — no risk found, but too little code to inspect (<8 files).
    - ``low_signals``       — no risk found, held down by non-finding signals
                              (maintainer/provenance/adoption), not detected risk.

    Pass ``safe`` if already computed to avoid recomputing it.
    """
    if safe is None:
        safe = is_safe(data)
    if safe:
        return "clean"
    items = (data.get("findings") or {}).get("items") or []
    if any(i.get("severity") in ("critical", "high") for i in items):
        return "blocking_findings"
    if sandbox_alarm(data):
        return "sandbox_finding"
    if any(i.get("category") == "known_vulnerability" for i in items) or any(
            a.get("affects_scanned_version") for a in (data.get("advisories") or [])
            if isinstance(a, dict)):
        return "known_vulnerability"
    dep = data.get("deprecation")
    if isinstance(dep, str) and dep.strip():
        return "deprecated"
    files = (data.get("metadata") or {}).get("files_scanned")
    return "thin_coverage" if isinstance(files, int) and 0 < files < 8 else "low_signals"


def verdict_label(safe: bool) -> str:
    """The stable public string for the binary state."""
    return "safe" if safe else "needs_review"


# ── The three-phrase decision ─────────────────────────────────────────────────────
# ONE rule for what every surface leads with (enterprise plan, LOCKED 2026-10-07):
#
#   do_not_connect  "Do not connect"            a blocking critical defect (static), a
#                                               planted credential leaving the sandbox or
#                                               any other critical sandbox finding, a
#                                               known-malicious dependency / OpenSSF MAL
#                                               advisory on this version
#   review          "Review before you connect" a blocking high defect (static or
#                                               sandbox), a published advisory affecting
#                                               the scanned version, deprecation, a score
#                                               under 51
#   safe            "Safe to connect"           otherwise, including thin static
#                                               coverage with nothing found (the reason
#                                               says so; decided 2026-10-08, #19)
#
# Derived from the APPLIED data (after ``_apply_behavioral_score``; ``behavioral`` is the
# block as returned to users) so the phrase and the score agree. Adoption is never an
# input. Advisory sandbox results never count: a live probe of a remote server
# (``is_advisory_block``), a run that did not happen, needed credentials or timed out
# contributes no finding. A capability (``kind == "capability"``) is never a defect.
# While ``behavioral.pending`` is true the decision is provisional (``final=False``) and
# the reason says the sandbox is still running (or, ``state == "queued"``, waiting for a
# slot). The API stops saying pending after a while (``slots.PENDING_MAX_AGE``), so a
# busy or down sandbox can't keep a decision provisional for hours.
#
# UNSIGNED: the decision rides beside the signed verdict; it is not in the JWS.
# TS twin: ``decide()`` in ``web/src/components/trust/gradeSystem.ts`` — the two must
# produce byte-identical output (``tests/test_decision.py`` runs both on one table).

DECISION_SAFE = "safe"
DECISION_REVIEW = "review"
DECISION_DO_NOT_CONNECT = "do_not_connect"
DECISION_VALUES = (DECISION_SAFE, DECISION_REVIEW, DECISION_DO_NOT_CONNECT)

REVIEW_SCORE_FLOOR = 51  # below this, accumulated findings alone mean "review"
THIN_COVERAGE_FILES = 8  # fewer static files than this, with nothing found = thin
PENDING_SUFFIX = "; sandbox still running"
# Pending because every sandbox slot is busy (``behavioral.state == "queued"``), not
# because a run is going. Past the pending age limit the API stops saying pending.
QUEUED_SUFFIX = "; waiting for a sandbox slot"
THIN_REASON = "nothing found; little code to inspect"
# A live MCP server scan reads the served tool definitions only (files = tools).
THIN_REASON_REMOTE_MCP = "tool definitions clean; server code not inspected"

# Human names for the sandbox rules a reason can cite.
_BEHAVIORAL_LABELS = {
    "behavioral_undeclared_egress": "undeclared network call",
    "ssrf_internal_fetch": "fetched an internal network address",
    "annotation_readonly_violated": "a read-only tool wrote files",
    "credential_canary_exfiltrated": "a planted credential left the sandbox",
}


class Decision:
    """The three-phrase decision: ``decision`` (safe | review | do_not_connect),
    ``final`` (False while the sandbox is still running), ``reason`` (one short
    sentence naming the single triggering condition)."""

    __slots__ = ("decision", "final", "reason")

    def __init__(self, decision: str, final: bool, reason: str) -> None:
        self.decision = decision
        self.final = final
        self.reason = reason

    def as_dict(self) -> dict:
        """The three unsigned API fields."""
        return {"decision": self.decision, "decision_final": self.final,
                "decision_reason": self.reason}

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Decision) and self.as_dict() == other.as_dict()

    def __repr__(self) -> str:
        return f"Decision({self.decision!r}, final={self.final!r}, reason={self.reason!r})"


def _int(v: object) -> int:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)):
        try:
            return int(v)
        except (ValueError, OverflowError):
            return 0
    if isinstance(v, str):
        try:
            return int(float(v.strip()))
        except (ValueError, OverflowError):
            return 0
    return 0


def _label(name: object) -> str:
    """A finding name as reason text: trimmed to 70 chars, first letter lowered unless
    it starts an acronym (``API key`` stays, ``Hardcoded`` -> ``hardcoded``)."""
    s = " ".join(str(name or "").split())
    if not s:
        return "unnamed finding"
    if len(s) > 70:
        s = s[:69].rstrip() + "…"
    if len(s) > 1 and s[0].isupper() and not s[1].isupper():
        s = s[0].lower() + s[1:]
    return s


def _strip_mal_prefix(name: object) -> str:
    """``Known-malicious package: evil@1.0 (MAL-1)`` -> ``evil@1.0 (MAL-1)``."""
    s = str(name or "")
    if s.lower().startswith("known-malicious package:"):
        s = s.split(":", 1)[1]
    return s


def _is_malicious_item(i: dict) -> bool:
    return (i.get("kind") != "capability"
            and "malicious" in str(i.get("name") or "").lower())


def _is_blocking_item(i: dict) -> bool:
    """Item-level mirror of ``scan._finding_is_blocking`` for shapes that carry only
    the public items (the authoritative headline counts are preferred when present)."""
    if _is_malicious_item(i):
        return True
    if i.get("kind") == "capability" or i.get("installed") is False:
        return False
    cat = i.get("category")
    if cat == "install_hook":
        return True
    if cat == "dependency":
        return False
    return i.get("shipped") is not False


def _is_remote_mcp(data: dict) -> bool:
    """A live MCP server scan (``scan_mcp``): only the served tool definitions were
    read, no server code. Marked ``coverage.surface == "mcp"`` (or the same in
    ``surface_detail``); a stdio MCP package scanned from npm/PyPI is not this."""
    for key in ("coverage", "surface_detail"):
        block = data.get(key)
        if isinstance(block, dict) and block.get("surface") == "mcp":
            return True
    return False


def _count_phrase(n: int, severity: str, label: str | None, where: str = "") -> str:
    if n == 1:
        return f"one {severity} finding{where}" + (f": {label}" if label else "")
    return f"{n} {severity} findings{where}" + (f", including {label}" if label else "")


def finding_decides(i: dict) -> bool:
    """Whether a listed finding is an input to the decision: a blocking critical/high
    (static code, install hook, known-malicious dependency, own advisory) or a sandbox
    critical/high (``sandbox: True``). Dependency advisories, mediums, lows and
    capabilities are not. Used to list the findings that decided the answer first."""
    if not isinstance(i, dict):
        return False
    if str(i.get("severity") or "").lower() not in ("critical", "high"):
        return False
    return bool(i.get("sandbox")) or _is_blocking_item(i)


def _is_dependency_advisory(i: dict) -> bool:
    """A vulnerable-dependency finding (``category == "dependency"``): reported and
    counted in the totals, never a decision input (a known-malicious one is)."""
    return (i.get("category") == "dependency" and i.get("kind") != "capability"
            and not _is_malicious_item(i))


def _dependency_counts(data: dict, items: list) -> tuple[int, int]:
    """(critical, high) dependency advisories, as the totals beside the reason count
    them: the larger of the listed items and the scored supply-chain counts (the item
    list is capped)."""
    crit = sum(1 for i in items if _is_dependency_advisory(i)
               and str(i.get("severity") or "").lower() == "critical")
    high = sum(1 for i in items if _is_dependency_advisory(i)
               and str(i.get("severity") or "").lower() == "high")
    sc = data.get("supply_chain") if isinstance(data.get("supply_chain"), dict) else {}
    counts = sc.get("counts")
    if sc.get("scored") is True and isinstance(counts, dict):
        crit = max(crit, _int(counts.get("critical")))
        high = max(high, _int(counts.get("high")))
    return crit, high


def _dependency_phrase(crit: int, high: int) -> str:
    """``6 critical and 43 high`` (empty when neither)."""
    parts = []
    if crit > 0:
        parts.append(f"{crit} critical")
    if high > 0:
        parts.append(f"{high} high")
    return " and ".join(parts)


def _first(items: list, pred) -> dict | None:
    for i in items:
        if pred(i):
            return i
    return None


def decide(data: dict) -> Decision:
    """The three-phrase decision for a scan result (see the table above). Pure; never
    raises on odd shapes (an unreadable field reads as absent)."""
    data = data if isinstance(data, dict) else {}
    score = _int(data.get("trust_score"))
    findings = data.get("findings") if isinstance(data.get("findings"), dict) else {}
    items = [i for i in (findings.get("items") or []) if isinstance(i, dict)]
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    files = meta.get("files_scanned")
    files = files if isinstance(files, int) and not isinstance(files, bool) else 0

    b = data.get("behavioral")
    b = b if isinstance(b, dict) else None
    pending = bool(b and b.get("pending"))
    b_live = bool(b and b.get("ran") and not b.get("pending") and not is_advisory_block(b))
    b_findings = [f for f in ((b or {}).get("findings") or []) if isinstance(f, dict)] \
        if b_live else []

    suffix = "" if not pending else (
        QUEUED_SUFFIX if b and b.get("state") == "queued" else PENDING_SUFFIX)

    def done(decision: str, reason: str) -> Decision:
        return Decision(decision, not pending, reason + suffix)

    # Dependency advisories are never decision inputs, but the totals beside the reason
    # count them; a reason that counts findings names them too, so the two never seem
    # to disagree ("5 high findings in its code; plus 6 critical and 43 high in
    # dependencies"). Wording only: nothing here changes the decision.
    dep_c, dep_h = _dependency_counts(data, items)
    deps = _dependency_phrase(dep_c, dep_h)
    in_code = " in its code" if deps else ""
    in_sandbox = " in the sandbox" if deps else ""
    plus_deps = f"; plus {deps} in dependencies" if deps else ""

    def sev(i: dict) -> str:
        return str(i.get("severity") or "").lower()

    # ── do_not_connect ────────────────────────────────────────────────────────────
    canary = b_live and (bool(b.get("canary_exfil")) or any(
        f.get("rule") == "credential_canary_exfiltrated" for f in b_findings))
    if canary:
        return done(DECISION_DO_NOT_CONNECT, "a planted credential left the sandbox")
    inc = data.get("incident_history") if isinstance(data.get("incident_history"), dict) \
        else {}
    if inc.get("current_version_affected") is True:
        return done(DECISION_DO_NOT_CONNECT,
                    "this version is listed as malicious (OpenSSF MAL advisory)")
    mal = _first(items, _is_malicious_item)
    sc = data.get("supply_chain") if isinstance(data.get("supply_chain"), dict) else {}
    sc_mal = sc.get("malicious")
    if mal is not None or (isinstance(sc_mal, list) and sc_mal):
        what = _label(_strip_mal_prefix(mal.get("name"))) if mal is not None \
            else str(sc_mal[0])
        return done(DECISION_DO_NOT_CONNECT, f"a known-malicious dependency: {what}")

    def is_advisory(i: dict) -> bool:
        return i.get("category") == "known_vulnerability" and i.get("kind") != "capability"

    def defect(severity: str):
        """(count, first item) of blocking static defects at ``severity``; an own
        advisory is not a defect here (it reads as review below)."""
        hits = [i for i in items if sev(i) == severity and _is_blocking_item(i)
                and not is_advisory(i)]
        headline = findings.get(severity)
        if isinstance(headline, int) and not isinstance(headline, bool):
            adv = sum(1 for i in items if sev(i) == severity and is_advisory(i))
            n = max(headline - adv, 0)
        else:
            n = len(hits)
        if n and not hits:
            hits = [i for i in items if sev(i) == severity and i.get("kind") != "capability"
                    and i.get("installed") is not False and not is_advisory(i)]
        return n, (hits[0] if hits else None)

    n_crit, crit = defect("critical")
    if n_crit:
        return done(DECISION_DO_NOT_CONNECT, _count_phrase(
            n_crit, "critical", _label(crit.get("name")) if crit else None, in_code)
            + plus_deps)
    b_crit = [f for f in b_findings if sev(f) == "critical"]
    if b_crit:
        f = b_crit[0]
        label = _BEHAVIORAL_LABELS.get(str(f.get("rule") or "")) or _label(f.get("name"))
        return done(DECISION_DO_NOT_CONNECT,
                    f"the sandbox caught a critical behavior: {label}" + plus_deps)

    # ── review ────────────────────────────────────────────────────────────────────
    n_high, high = defect("high")
    if n_high:
        return done(DECISION_REVIEW, _count_phrase(
            n_high, "high", _label(high.get("name")) if high else None, in_code)
            + plus_deps)
    b_high = [f for f in b_findings if sev(f) == "high"]
    if b_high:
        f = b_high[0]
        label = _BEHAVIORAL_LABELS.get(str(f.get("rule") or "")) or _label(f.get("name"))
        return done(DECISION_REVIEW,
                    _count_phrase(len(b_high), "high", label, in_sandbox) + plus_deps)

    raw_adv = data.get("advisories")
    if not (isinstance(raw_adv, list) and raw_adv):
        raw_adv = inc.get("advisories")
    advisories = [a for a in (raw_adv if isinstance(raw_adv, list) else [])
                  if isinstance(a, dict) and a.get("affects_scanned_version") is True]
    affecting = data.get("advisories_affecting_version")
    if isinstance(affecting, list):
        advisories += [a for a in affecting if isinstance(a, dict)]
    adv_item = _first(items, is_advisory)
    if advisories or adv_item is not None:
        aid = str((advisories[0].get("id") if advisories else "") or "")
        return done(DECISION_REVIEW, "a published advisory affects this version"
                    + (f" ({aid})" if aid else ""))
    dep = data.get("deprecation")
    if isinstance(dep, str) and dep.strip():
        return done(DECISION_REVIEW, "the maintainer has deprecated this package")
    if score < REVIEW_SCORE_FLOOR:
        return done(DECISION_REVIEW, f"trust score {score}/100 is under {REVIEW_SCORE_FLOOR}")

    found = any(sev(i) in ("critical", "high", "medium") and i.get("kind") != "capability"
                and i.get("installed") is not False for i in items)

    # ── safe ──────────────────────────────────────────────────────────────────────
    if deps:
        noun = "advisory" if dep_c + dep_h == 1 else "advisories"
        return done(DECISION_SAFE,
                    f"no critical or high findings in its code (dependencies: {deps} {noun})")
    # Thin coverage (0 < files < 8, nothing found) reads Safe and says so in the reason
    # (Kenne, 2026-10-08, #19). The 74 / 82 evidence cap on the score still shows it.
    if 0 < files < THIN_COVERAGE_FILES and not found:
        return done(DECISION_SAFE, THIN_REASON_REMOTE_MCP if _is_remote_mcp(data)
                    else THIN_REASON)
    if files > 0:
        n = f"{files:,}"
        unit = "file" if files == 1 else "files"
        reason = (f"no critical or high findings in {n} {unit}" if found
                  else f"nothing found in {n} {unit}")
    else:
        reason = "no critical or high findings" if found else "nothing found"
    return done(DECISION_SAFE, reason)


# ── The Certified mark (display rule) ─────────────────────────────────────────────
# ``certified.eligible`` is the signed six-check provenance gate (safety model §8) and
# never changes here. The MARK ("✓ Certified <score>") is a display rule on top of it
# (§10, Kenne 2026-10-08): it sits only beside Safe to connect, once the sandbox result
# is final, at a score of 81 or above, and never on thin coverage. Every surface reads
# this one function (or the API's ``certified_mark`` field); fail closed on anything
# missing. TS twin: ``certifiedMarkStatus()`` in gradeSystem.ts (byte-identical; the
# equivalence table is in tests/test_decision.py).

CERTIFIED_MARK_MIN_SCORE = 81

MARK_NOT_SAFE = "not_safe"
MARK_PENDING = "sandbox_pending"
MARK_SCORE = "score_below_81"
MARK_THIN = "thin_coverage"


def certified_mark_status(data: dict, decision: Decision | None = None) -> tuple[bool, str]:
    """(mark, why_not). ``why_not`` is "" when the mark shows or when the tool is not
    eligible at all (nothing to explain); otherwise the one condition that suppressed
    an earned eligibility. ``decision`` defaults to ``decide(data)``; pass the applied
    one (sandbox block + adjusted score) when the caller already has it."""
    data = data if isinstance(data, dict) else {}
    cert = data.get("certified")
    if not (isinstance(cert, dict) and cert.get("eligible") is True):
        return False, ""
    d = decision if isinstance(decision, Decision) else decide(data)
    if d.decision != DECISION_SAFE:
        return False, MARK_NOT_SAFE
    if not d.final:
        return False, MARK_PENDING
    if _int(data.get("trust_score")) < CERTIFIED_MARK_MIN_SCORE:
        return False, MARK_SCORE
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    files = meta.get("files_scanned")
    files = files if isinstance(files, int) and not isinstance(files, bool) else 0
    if files < THIN_COVERAGE_FILES:
        return False, MARK_THIN
    return True, ""


def certified_mark(data: dict, decision: Decision | None = None) -> bool:
    """Whether a result shows the Certified mark (see ``certified_mark_status``)."""
    return certified_mark_status(data, decision)[0]
