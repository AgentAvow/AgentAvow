"""A sandbox result belongs to the code that ran, and a run that observed nothing is not
a clean run (2026-11-06, gadgethumans-mcp).

* A version-pinned scan never takes the sandbox block of another version. The sandbox
  runs the latest release under an unversioned key; folding that into a pinned report put
  one version's observation under another version's signed score.
* A sandbox that could not start the tool, or did not run, is disclosed: ``not_checked``
  says so, signed as ``scan.coverageGaps``. The decision and score do not move, and
  ``decision_final`` stays true: nothing further is coming, which is all it means.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import src.api.public_scan_router as psr
from src.database import get_db
from src.main import app
from src.scanner.verdict import coverage_gap_notes

URL = "/api/v1/public/scan/package/npm/left-pad"
NOT_THIS_VERSION = "the sandbox has not run this version"


def _scan_dict(score: int = 82) -> dict:
    return {
        "trust_score": score, "trust_tier": "standard", "scan_result": "clean",
        "recommended_limits": {"requests_per_minute": 60, "max_tokens_per_call": 4000,
                               "require_user_confirmation": False},
        "findings": {"critical": 0, "high": 0, "medium": 0, "total": 0, "categories": {},
                     "suppressed_lines": 0},
        "positive_signals": [], "category_scores": {},
        "metadata": {"files_scanned": 12, "primary_language": "javascript", "has_readme": True,
                     "has_license": True, "has_tests": False, "is_mcp_server": True},
        "artifact_scan": {"is_mcp_server": True},
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


def _block(*, launch_ok: bool = True, findings: list | None = None,
           start_reason: str = "started", failed: bool | None = None) -> dict:
    return {
        "ran": True, "plan": "npm-mcp", "findings": findings or [], "canary_exfil": [],
        "exercise": {"launch_ok": launch_ok,
                     "calls": [{"tool": "t", "ok": True}] if launch_ok else [],
                     "tools": []},
        "grade_summary": {"launch_ok": launch_ok, "start_reason": start_reason,
                          "server_failed_to_start": (not launch_ok) if failed is None
                          else failed},
        "attestation": {"jws": "aaa.bbb.ccc", "observed_at": "2026-11-07T01:15:42+00:00"},
    }


CAUGHT = [{"rule": "credential_canary_exfiltrated", "severity": "critical", "name": "leak"}]


def _signed(body: dict) -> dict:
    return json.loads(base64.urlsafe_b64decode(body["jws"].split(".")[1] + "==="))


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture
def scanner_on():
    with patch("src.config.settings.scanner_behavioral_enabled", True):
        yield


async def _get(client, params: dict, block: dict | None):
    """The route over a cached static scan, with ``block`` in the sandbox cache."""
    with patch.object(psr, "_get_cached", new=AsyncMock(return_value=_scan_dict())), \
         patch.object(psr, "_get_cached_behavioral", new=AsyncMock(return_value=block)), \
         patch.object(psr, "_start_behavioral_payload",
                      new=AsyncMock(return_value="started")) as start:
        r = await client.get(URL, params=params)
    assert r.status_code == 200
    return r.json(), start


@pytest.mark.asyncio
async def test_clean_latest_run_gives_a_pinned_version_no_bonus(client, scanner_on):
    body, _ = await _get(client, {"version": "1.0.9"}, _block())
    assert body["trust_score"] == 82
    assert body["behavioral_score_effect"]["applied"] is False
    assert "behavioralEvidence" not in _signed(body)["scan"]


@pytest.mark.asyncio
async def test_latest_caught_in_the_act_does_not_move_a_pinned_version(client, scanner_on):
    body, _ = await _get(client, {"version": "1.0.9"}, _block(findings=CAUGHT))
    assert body["trust_score"] == 82
    assert body["decision"] != "do_not_connect"
    assert "behavioralEvidence" not in _signed(body)["scan"]


@pytest.mark.asyncio
async def test_pinned_report_shows_no_observation_and_says_so(client, scanner_on):
    body, _ = await _get(client, {"version": "1.0.9"}, _block())
    b = body["behavioral"]
    assert b["ran"] is False and b["pending"] is False and "attestation" not in b
    assert NOT_THIS_VERSION in body["not_checked"]
    assert _signed(body)["scan"]["coverageGaps"]["sandbox_not_observed"] == "other_version"


@pytest.mark.asyncio
async def test_pinned_lookup_starts_no_sandbox_run(client, scanner_on):
    _body, start = await _get(client, {"version": "1.0.9"}, None)
    start.assert_not_awaited()


@pytest.mark.asyncio
async def test_unpinned_scan_keeps_its_block_and_bonus(client, scanner_on):
    body, _ = await _get(client, {}, _block())
    assert body["trust_score"] == 85
    assert body["behavioral"]["ran"] is True
    assert body["not_checked"] == []
    assert _signed(body)["scan"]["behavioralEvidence"]["launchOk"] is True


@pytest.mark.asyncio
async def test_server_that_never_started_is_disclosed_not_clean(client, scanner_on):
    body, _ = await _get(client, {}, _block(launch_ok=False, start_reason="crashed"))
    note = "the sandbox could not start the tool (crashed), so its behavior was not observed"
    assert body["not_checked"] == [note]
    assert note in body["decision_reason"]
    assert _signed(body)["scan"]["coverageGaps"]["sandbox_not_observed"] == "crashed"
    # Disclosure only: no score move, nothing more is coming.
    assert body["trust_score"] == 82
    assert body["decision"] == "safe" and body["decision_final"] is True


def _gap(block):
    return psr._apply_behavioral_score(_scan_dict(), block).get("coverage_gaps") or {}


def test_needs_credentials_reads_in_plain_words():
    gaps = _gap(_block(launch_ok=False, start_reason="needs_credentials"))
    assert gaps == {"sandbox_not_observed": "needs credentials"}


def test_existing_gaps_are_kept_and_the_cached_scan_is_not_touched():
    scan = {**_scan_dict(), "coverage_gaps": {"oversized_files": 1}}
    out = psr._apply_behavioral_score(scan, _block(launch_ok=False, start_reason="crashed"))
    assert out["coverage_gaps"] == {"oversized_files": 1, "sandbox_not_observed": "crashed"}
    assert scan["coverage_gaps"] == {"oversized_files": 1}


@pytest.mark.parametrize("block", [
    None,
    _block(),                                                     # started and exercised
    {"ran": False, "pending": True, "state": "running"},          # still going: not a gap
    {"ran": False, "pending": True, "state": "queued"},
    _block(launch_ok=False, start_reason="not_applicable", failed=False),  # install-only plan
    {**_block(launch_ok=False, start_reason="crashed"), "plan": "live-probe"},  # advisory
    {"ran": False, "reason": "nothing the sandbox can install"},  # no target: nothing to run
])
def test_no_gap_when_there_was_nothing_to_observe_or_it_is_still_coming(block):
    assert _gap(block) == {}


@pytest.mark.parametrize("block", [
    {"ran": False, "pending": False, "state": "unavailable", "reason": "sandbox unavailable"},
    {"ran": False, "error": "sandbox_disk_low", "reason": "x"},
])
def test_a_run_that_did_not_happen_is_a_gap(block):
    assert _gap(block) == {"sandbox_not_observed": "unavailable"}
    note = "the sandbox could not start the tool (unavailable), so its behavior was not observed"
    assert coverage_gap_notes({"coverage_gaps": _gap(block)}) == [note]
