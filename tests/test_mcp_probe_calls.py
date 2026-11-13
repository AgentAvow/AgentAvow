"""A tool name we do not serve is a monitor probe: counted on its own, never as usage."""
import pytest

from src.bridges import mcp_streamable as ms


@pytest.mark.asyncio
async def test_unknown_tool_is_a_probe_not_usage(monkeypatch):
    bumped: list[str] = []

    async def fake_bump(metric: str) -> None:
        bumped.append(metric)

    async def no_caller() -> None:
        bumped.append("caller")

    monkeypatch.setattr(ms, "_bump", fake_bump)
    monkeypatch.setattr(ms, "_record_caller", no_caller)
    out = await ms._run_tool("__verifymcp_auth_probe_19df9db3007f77a7__", {})
    text = out[0] if isinstance(out, tuple) else out
    assert "Unknown tool" in text[0].text
    assert bumped == ["probe:unknown_tool"]


def test_every_served_tool_counts_as_usage():
    assert {t.name for t in ms._TOOLS} == ms._TOOL_NAMES
    assert "about_agentavow" in ms._TOOL_NAMES and "scan_repo" in ms._TOOL_NAMES
