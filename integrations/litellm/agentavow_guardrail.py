"""LiteLLM loads this file by the name in config.yaml
(``guardrail: agentavow_guardrail.AgentAvowGuardrail``); keep it next to the config.

The guardrail lives in the AgentAvow repository (``src/bridges/litellm``). Point
``AGENTAVOW_REPO`` at a checkout, or keep this file inside one
(``integrations/litellm/``), and it is found from here.
"""
from __future__ import annotations

import os
import sys

_repo = os.environ.get("AGENTAVOW_REPO") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", ".."))
if _repo not in sys.path:
    sys.path.insert(0, _repo)

from src.bridges.litellm.guardrail import AgentAvowGuardrail  # noqa: E402

__all__ = ["AgentAvowGuardrail"]
