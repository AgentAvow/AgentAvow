"""AgentAvow's own ERC-8004 registration file (design:
docs/internal/erc8004-self-registration-design-2026-11-11.md).

The on-chain agentURI on Base points at https://agentavow.com/.well-known/agent-
registration.json, so the file must stay in step with what we actually serve: its MCP
and A2A endpoints are our real MCP mount and our signed agent card, our own reader sees
exactly those two as checkable tools, and nginx serves it as cacheable JSON."""
from __future__ import annotations

import json
import re
from pathlib import Path

from src.scanner import erc8004_agent as ea

ROOT = Path(__file__).resolve().parent.parent
REG = ROOT / "web" / "public" / ".well-known" / "agent-registration.json"
CARD = ROOT / "web" / "public" / ".well-known" / "agent-card.json"
NGINX = (ROOT / "nginx" / "nginx.conf").read_text()
DOC = json.loads(REG.read_text())
REGISTRY = "eip155:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432"


def test_registration_v1_shape():
    assert DOC["type"] == "https://eips.ethereum.org/EIPS/eip-8004#registration-v1"
    assert DOC["name"] == "AgentAvow" and DOC["active"] is True
    assert DOC["x402Support"] is False
    assert "supportedTrust" not in DOC   # no on-chain trust claims
    # Minted 2026-11-11, tx 0xa91945e9…60f1f2 on Base: exactly ours.
    assert DOC["registrations"] == [{"agentId": 1178486, "agentRegistry": REGISTRY}]


def test_our_reader_sees_exactly_our_two_tools():
    reg = ea.parse_registration(REG.read_bytes())
    tools = [(s.kind, s.endpoint) for s in reg.services if s.kind]
    assert tools == [("mcp", "https://agentavow.com/mcp"),
                     ("a2a", "https://agentavow.com/.well-known/agent-card.json")]
    assert ea.file_findings(reg) == []
    assert ea.headline([{"decision": "safe"}, {"decision": "safe"}], [])["decision"] == "safe"


def test_endpoints_match_what_we_serve():
    services = {s["name"]: s["endpoint"] for s in DOC["services"]}
    # the MCP server is mounted at /mcp (src/main.py)
    assert re.search(r'app\.mount\("/mcp"', (ROOT / "src" / "main.py").read_text())
    assert services["MCP"] == "https://agentavow.com/mcp"
    # the A2A card we serve and sign, and the trust-verdict extension points at it
    card = json.loads(CARD.read_text())
    assert services["A2A"] == "https://agentavow.com/.well-known/agent-card.json"
    assert card["name"] == "AgentAvow"
    assert services["DID"] == "did:web:agentgraph.co"


def test_nginx_serves_it_as_cacheable_json():
    m = re.search(r"location = /\.well-known/agent-registration\.json \{(.*?)\n        \}",
                  NGINX, re.S)
    assert m, "exact nginx location missing"
    block = m.group(1)
    assert "default_type application/json" in block
    assert 'Cache-Control "public, max-age=300"' in block
    assert 'Access-Control-Allow-Origin "*"' in block


def test_image_and_text_are_plain():
    assert DOC["image"].startswith("https://agentavow.com/")
    assert "<" not in DOC["description"] and len(DOC["description"]) <= 300
