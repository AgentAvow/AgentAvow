"""Smoke test against the real ``litellm`` package and the live AgentAvow API.

No model calls and no LiteLLM proxy process: it loads the guardrail the way the
proxy does (``get_instance_fn`` on ``agentavow_guardrail.AgentAvowGuardrail`` with the
``litellm_params`` from config.yaml), checks it is a real ``CustomGuardrail`` that
registers for ``pre_mcp_call``, then runs LiteLLM's MCP pre-call hook on a Safe and a
Do not connect server.

    python -m venv /tmp/ll && /tmp/ll/bin/pip install "litellm[proxy]==1.105.0"
    AGENTAVOW_REPO=$PWD /tmp/ll/bin/python integrations/litellm/smoke_test.py
"""
from __future__ import annotations

import asyncio
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(HERE, "config.yaml")


def main() -> int:
    import litellm
    import yaml
    from litellm.integrations.custom_guardrail import CustomGuardrail
    from litellm.proxy.types_utils.utils import get_instance_fn
    from litellm.types.guardrails import GuardrailEventHooks, LitellmParams

    print("litellm", getattr(litellm, "version", None) or _pkg_version("litellm"))
    with open(CONFIG) as f:
        cfg = yaml.safe_load(f)
    entry = cfg["guardrails"][0]
    params = LitellmParams(**entry["litellm_params"])
    cls = get_instance_fn(params.guardrail, config_file_path=CONFIG)
    extra = params.model_dump(exclude_none=True)
    for key in ("guardrail", "mode", "default_on"):
        extra.pop(key, None)
    # deepwiki is resolved from LiteLLM's MCP registry in the proxy; here, with no
    # proxy running, map it explicitly.
    extra.setdefault("servers", {})
    extra["servers"]["deepwiki"] = "https://mcp.deepwiki.com/mcp"
    extra["servers"]["serena"] = "oraios/serena"
    guard = cls(guardrail_name=entry["guardrail_name"], event_hook=params.mode,
                default_on=params.default_on, **extra)

    assert isinstance(guard, CustomGuardrail), type(guard).__mro__
    assert guard.get_supported_event_hooks() == [GuardrailEventHooks.pre_mcp_call]
    print("loaded:", type(guard).__name__, "fail_on =", guard.fail_on)

    async def hook(server: str, tool: str):
        data = {"mcp_tool_name": tool, "mcp_server_name": server,
                "mcp_arguments": {}, "metadata": {}}
        return await guard.async_pre_call_hook(None, None, data, "call_mcp_tool")

    out = asyncio.run(hook("deepwiki", "read_wiki_structure"))
    assert out["mcp_tool_name"] == "read_wiki_structure"
    print("deepwiki read_wiki_structure: allowed")

    try:
        asyncio.run(hook("serena", "find_symbol"))
    except Exception as e:  # noqa: BLE001
        detail = getattr(e, "detail", e)
        status = getattr(e, "status_code", "")
        print("serena find_symbol: refused ->", type(e).__name__, status, detail)
    else:
        raise AssertionError("serena (Do not connect) was not refused")

    # The drift check against deepwiki's live tools/list: the served definition must
    # recompute to the digest signed into the scan.
    d = asyncio.run(guard.check_call("deepwiki", "read_wiki_structure"))
    assert d.allow and "matches the signed digest" in d.reason, d.reason
    print("deepwiki drift check:", d.reason)
    print("OK")
    return 0


def _pkg_version(name: str) -> str:
    from importlib.metadata import version
    return version(name)


if __name__ == "__main__":
    sys.exit(main())
