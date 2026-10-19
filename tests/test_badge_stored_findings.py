"""Entity badges decide from the STORED scan, the same way the report does (P8).

``FrameworkSecurityScan.vulnerabilities`` is a dict for scanner rows (findings under
``"findings"``) and a list for framework bridge imports. The trust badge and the embed
badge used to read it as a list only, so every scanner finding was dropped and the
badge could read Safe over a report that said Review or Do not connect.
"""
from __future__ import annotations

import re
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.database import get_db
from src.main import app
from src.models import Entity, EntityType, FrameworkSecurityScan, TrustScore
from src.scanner.scan import Finding, ScanResult
from src.scanner.service import (
    decide_stored_scan,
    run_security_scan,
    stored_scan_decision_input,
)
from src.scanner.verdict import decide


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


async def _make_entity(db, entity_score: float = 0.9) -> Entity:
    suffix = uuid.uuid4().hex[:8]
    entity = Entity(
        type=EntityType.AGENT,
        display_name=f"badge-{suffix}",
        did_web=f"did:web:test-badge-{suffix}",
        source_url=f"https://github.com/badge-owner/repo-{suffix}",
        source_type="github",
        framework_source="mcp",
        is_active=True,
    )
    db.add(entity)
    await db.flush()
    db.add(TrustScore(entity_id=entity.id, score=entity_score, components={}))
    await db.flush()
    return entity


def _finding(severity: str, path: str, name: str, category: str = "unsafe_exec"):
    return Finding(category=category, name=name, severity=severity, file_path=path,
                   line_number=10, snippet="")


def _result(findings: list, score: int) -> ScanResult:
    return ScanResult(repo="badge-owner/repo", stars=0, description="", framework="mcp",
                      findings=findings, files_scanned=40, total_scannable_files=40,
                      trust_score=score)


async def _store_via_writer(db, monkeypatch, entity: Entity, result: ScanResult):
    """Store ``result`` the way production does (run_security_scan's writer)."""
    async def fake_scan_repo(**_kw):
        return result

    async def fake_token():
        return None

    monkeypatch.setattr("src.scanner.scan.scan_repo", fake_scan_repo)
    monkeypatch.setattr("src.github_auth.get_github_token", fake_token)
    row = await run_security_scan(db, entity.id, force=True)
    assert isinstance(row.vulnerabilities, dict)
    return row


def _report_decision(result: ScanResult) -> str:
    """The decision the public report reaches for the same scan result."""
    from src.api.public_scan_router import _scan_result_to_dict
    return decide(_scan_result_to_dict(result)).decision


async def _surfaces(client, entity_id) -> dict[str, str | None]:
    svg = await client.get(f"/api/v1/badges/trust/{entity_id}.svg")
    assert svg.status_code == 200
    m = re.search(r"<title>[^<]* scan: ([a-z_]+)</title>", svg.text)
    embed = await client.get(f"/api/v1/badges/embed/{entity_id}?format=json")
    assert embed.status_code == 200
    report = await client.get(f"/api/v1/bots/{entity_id}/security-scan")
    assert report.status_code == 200
    return {
        "badge": m.group(1) if m else None,
        "embed": embed.json()["decision"],
        "report": report.json()["decision"],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("findings,score,expected", [
    # A shipped critical and a shipped high: Do not connect.
    ([_finding("critical", "src/server.py", "eval of user input", "unsafe_exec"),
      _finding("high", "src/tool.py", "Shell command from user input")], 40,
     "do_not_connect"),
    # A hardcoded credential alone exposes the vendor, not the user: Review.
    ([_finding("critical", "src/server.py", "Hardcoded API key", "secret")], 45, "review"),
    # A hardcoded credential beside another shipped critical: still Do not connect.
    ([_finding("critical", "src/server.py", "Hardcoded API key", "secret"),
      _finding("critical", "src/tool.py", "eval of user input", "unsafe_exec")], 30,
     "do_not_connect"),
    # A shipped high only: Review.
    ([_finding("high", "src/tool.py", "Shell command from user input")], 70, "review"),
    # A critical in a test file only: not blocking, the report reads Safe.
    ([_finding("critical", "tests/test_tool.py", "eval of input")], 85, "safe"),
])
async def test_badges_match_report_for_stored_scan(
    client, db, monkeypatch, findings, score, expected,
):
    # The entity score (90) is far above the scan's own; the old badge read it plus an
    # empty findings list and answered Safe.
    entity = await _make_entity(db, entity_score=0.9)
    result = _result(findings, score)
    row = await _store_via_writer(db, monkeypatch, entity, result)

    assert _report_decision(result) == expected
    assert decide_stored_scan(row, fallback_score=90).decision == expected
    assert await _surfaces(client, entity.id) == {
        "badge": expected, "embed": expected, "report": expected,
    }


@pytest.mark.asyncio
async def test_pre_tag_dict_row_still_blocks(client, db):
    """A dict row written before items carried ``shipped`` / shipped counts."""
    entity = await _make_entity(db, entity_score=0.95)
    db.add(FrameworkSecurityScan(
        entity_id=entity.id, framework="mcp", scan_result="critical",
        vulnerabilities={
            "trust_score": 42, "files_scanned": 30, "critical_count": 1,
            "high_count": 1, "total_findings": 3,
            "findings": [
                {"category": "unsafe_exec", "name": "eval of input", "severity": "critical",
                 "file_path": "src/server.py", "line_number": 3},
                {"category": "unsafe_exec", "name": "Shell from input", "severity": "high",
                 "file_path": "src/tool.py", "line_number": 9},
                {"category": "unsafe_exec", "name": "eval", "severity": "critical",
                 "file_path": "tests/test_x.py", "line_number": 1},
            ],
        },
    ))
    await db.flush()
    assert await _surfaces(client, entity.id) == {
        "badge": "do_not_connect", "embed": "do_not_connect", "report": "do_not_connect",
    }


@pytest.mark.asyncio
async def test_empty_dict_row_uses_scan_score(client, db):
    entity = await _make_entity(db, entity_score=0.9)
    db.add(FrameworkSecurityScan(
        entity_id=entity.id, framework="mcp", scan_result="clean",
        vulnerabilities={},
    ))
    await db.flush()
    # No findings and no scan score: the entity score (90) decides, Safe.
    assert await _surfaces(client, entity.id) == {
        "badge": "safe", "embed": "safe", "report": "safe",
    }


@pytest.mark.asyncio
async def test_bridge_list_row(client, db):
    """Framework bridge imports store a list of {pattern, severity, location, match}."""
    entity = await _make_entity(db, entity_score=0.9)
    db.add(FrameworkSecurityScan(
        entity_id=entity.id, framework="openclaw", scan_result="critical",
        vulnerabilities=[{"pattern": "command_injection_os_system", "severity": "critical",
                          "location": "skill code", "match": "os.system("}],
    ))
    await db.flush()
    assert await _surfaces(client, entity.id) == {
        "badge": "do_not_connect", "embed": "do_not_connect", "report": "do_not_connect",
    }


@pytest.mark.asyncio
async def test_null_vulnerabilities_row(client, db):
    entity = await _make_entity(db, entity_score=0.3)
    db.add(FrameworkSecurityScan(
        entity_id=entity.id, framework="mcp", scan_result="clean", vulnerabilities=None,
    ))
    await db.flush()
    # Entity score 30 < 51: Review on every surface.
    assert await _surfaces(client, entity.id) == {
        "badge": "review", "embed": "review", "report": "review",
    }


@pytest.mark.asyncio
async def test_error_row(client, db):
    entity = await _make_entity(db, entity_score=0.9)
    db.add(FrameworkSecurityScan(
        entity_id=entity.id, framework="mcp", scan_result="error",
        vulnerabilities={"error": "boom"},
    ))
    await db.flush()
    s = await _surfaces(client, entity.id)
    assert s["badge"] == "error"
    assert s["report"] is None


def test_decision_input_shapes():
    assert stored_scan_decision_input(None, 77) == {
        "trust_score": 77, "findings": {"items": []}}
    assert stored_scan_decision_input({}, 77)["trust_score"] == 77
    assert stored_scan_decision_input("junk", None)["trust_score"] == 0
    listed = stored_scan_decision_input(
        [{"pattern": "p", "severity": "High", "location": "x"}, "junk"], 60)
    assert listed["findings"]["items"] == [
        {"category": "bridge", "name": "p", "severity": "high", "file_path": "x"}]
    stored = stored_scan_decision_input({
        "trust_score": 55, "shipped_critical_count": 0, "shipped_high_count": 2,
        "findings": [{"severity": "high", "file_path": "docs/a.py"}],
    }, 99)
    assert stored["trust_score"] == 55
    assert stored["findings"]["critical"] == 0 and stored["findings"]["high"] == 2
    # A stored ``shipped`` tag wins; an untagged one is inferred from the path.
    assert stored["findings"]["items"][0]["shipped"] is False
