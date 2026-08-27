"""Prototype: map an AgentAvow scan → an ATD Trust Index `trustmodel.safety.score`
observation for the generic {score, riskCodes, explanation} container (agent-trust-
discovery #10), carrying the Ed25519/JWS attestation in the observation's `provenance`
envelope so a consumer can recompute the verdict offline instead of trusting the score.

Usage: python scripts/atd_safety_observation.py <owner>/<repo>
"""
from __future__ import annotations

import json
import sys
import urllib.request

# AgentAvow scan category → ATD `SAFETY_` risk code (core stays opinion-free; these are
# the risk codes that ride the generic container alongside the 0-100 score).
_CATEGORY_TO_RISK: dict[str, str] = {
    "unsafe_exec": "SAFETY_UNSAFE_EXEC",
    "code_safety": "SAFETY_UNSAFE_EXEC",
    "exfiltration": "SAFETY_EXFILTRATION",
    "data_handling": "SAFETY_EXFILTRATION",
    "prompt_injection": "SAFETY_PROMPT_INJECTION",
    "secret_hygiene": "SAFETY_SECRET_EXPOSURE",
    "secret": "SAFETY_SECRET_EXPOSURE",
    "dynamic_remote_load": "SAFETY_DYNAMIC_REMOTE_LOAD",
    "dependency": "SAFETY_VULNERABLE_DEPENDENCY",
    "obfuscation": "SAFETY_OBFUSCATION",
    "hidden_unicode": "SAFETY_HIDDEN_UNICODE",
    "install_hook": "SAFETY_INSTALL_HOOK",
    "fs_access": "SAFETY_FS_ACCESS",
    "lethal_trifecta": "SAFETY_LETHAL_TRIFECTA",
    "insecure_deserialization": "SAFETY_INSECURE_DESERIALIZATION",
    "annotation_lie": "SAFETY_ANNOTATION_LIE",
    "schema_risk": "SAFETY_SCHEMA_RISK",
    "toxic_flow": "SAFETY_TOXIC_FLOW",
    "artifact_drift": "SAFETY_ARTIFACT_DRIFT",
}


def to_observation(scan: dict) -> dict:
    score = scan.get("trust_score")
    findings = scan.get("findings") or {}
    items = findings.get("items") or []
    risk_codes = sorted(
        {_CATEGORY_TO_RISK.get(it.get("category"), "SAFETY_OTHER") for it in items}
    )
    tier = scan.get("tier")
    total = findings.get("total", len(items))
    n_crit = findings.get("critical", 0)
    n_high = findings.get("high", 0)
    explanation = (
        f"AgentAvow static-analysis safety score {score}/100 ({tier}). "
        f"{total} findings ({n_crit} critical, {n_high} high) across "
        f"{len(risk_codes)} risk categories; scores the TOOL/MCP server, not the agent."
    )
    att = scan.get("attestation") or {}
    return {
        "signal": "trustmodel.safety.score",
        "subject": scan.get("repo") or scan.get("target"),
        "container": {"score": score, "riskCodes": risk_codes, "explanation": explanation},
        "provenance": {
            "aimId": "did:web:agentgraph.co",
            "evidence": {
                "type": "ed25519-jws",
                "jws": att.get("jws", "<Ed25519/JWS attestation over the JCS-canonical verdict>"),
                "kid": att.get("key_id"),
                "jwks_url": att.get("jwks_url", "https://agentgraph.co/.well-known/jwks.json"),
                "recomputable": True,  # verifier re-derives the verdict offline, no trust in AgentAvow
            },
        },
    }


def _fetch(owner_repo: str) -> dict:
    url = f"https://agentavow.com/api/v1/public/scan/{owner_repo}?force=false"
    with urllib.request.urlopen(url, timeout=90) as r:  # noqa: S310 — fixed https host
        return json.load(r)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "modelcontextprotocol/servers"
    print(json.dumps(to_observation(_fetch(target)), indent=2))
