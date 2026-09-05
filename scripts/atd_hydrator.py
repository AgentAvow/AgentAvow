"""ATD hydrator — push an AgentAvow scan into the Agent Trust Discovery import
path as an `agentgraph.safety.score` observation.

Targets the shapes that landed in agent-trust-discovery:
  - #15 (MERGED): the neutral score container `{score, riskCodes, explanation,
    subject}`. `score` is an int (the container uses `*int` + DisallowUnknownFields,
    so only these fields, and never a null/absent score decoding to 0). `riskCodes`
    are prefixed for the dimension (`SAFETY_*`). `subject` is the subject class the
    engine buckets on so a tool score is never averaged with an agent score.
  - #16 (config-driven registration, pending merge): the provider registers via a
    config entry (see CONFIG_ENTRY below) whose `signals.path` resolves against the
    config-file dir; `threshold` is `*int` (omit for the default 70).

The attestation rides `provenance.evidence` so a consumer re-derives the verdict
offline (RFC 8785 JCS + Ed25519 against the public JWKS) rather than trusting the
score. Live scan attestations are now JCS-canonical, so this is recomputable.

Usage:
  python scripts/atd_hydrator.py <owner>/<repo>              # dry-run: print the observation
  python scripts/atd_hydrator.py <owner>/<repo> --post URL   # POST to the ATD import path
"""
from __future__ import annotations

import json
import sys
import urllib.request

# AgentAvow scan category -> ATD SAFETY_ risk code (prefixed for the `safety`
# dimension, per the #15 validator: a code not prefixed for the dimension is
# rejected at import rather than silently dropped).
_CATEGORY_TO_RISK: dict[str, str] = {
    "unsafe_exec": "SAFETY_UNSAFE_EXEC", "code_safety": "SAFETY_UNSAFE_EXEC",
    "exfiltration": "SAFETY_EXFILTRATION", "data_handling": "SAFETY_EXFILTRATION",
    "prompt_injection": "SAFETY_PROMPT_INJECTION",
    "secret_hygiene": "SAFETY_SECRET_EXPOSURE", "secret": "SAFETY_SECRET_EXPOSURE",
    "dynamic_remote_load": "SAFETY_DYNAMIC_REMOTE_LOAD",
    "dependency": "SAFETY_VULNERABLE_DEPENDENCY", "obfuscation": "SAFETY_OBFUSCATION",
    "hidden_unicode": "SAFETY_HIDDEN_UNICODE", "install_hook": "SAFETY_INSTALL_HOOK",
    "fs_access": "SAFETY_FS_ACCESS", "lethal_trifecta": "SAFETY_LETHAL_TRIFECTA",
    "insecure_deserialization": "SAFETY_INSECURE_DESERIALIZATION",
    "annotation_lie": "SAFETY_ANNOTATION_LIE", "schema_risk": "SAFETY_SCHEMA_RISK",
    "toxic_flow": "SAFETY_TOXIC_FLOW", "artifact_drift": "SAFETY_ARTIFACT_DRIFT",
}

SIGNAL_ID = "agentgraph.safety.score"
DIMENSION = "safety"
SUBJECT_CLASS = "tool"  # scores the tool / MCP server, not the agent that mounts it

# The #16 provider registration entry (goes in the ATD server's score-signals config).
CONFIG_ENTRY = {"id": SIGNAL_ID, "dimension": DIMENSION, "threshold": 70, "subject": SUBJECT_CLASS}


def to_observation(scan: dict) -> dict:
    score = scan.get("trust_score")
    if not isinstance(score, int):
        raise ValueError(f"scan trust_score must be an int for the #15 container, got {score!r}")
    findings = scan.get("findings") or {}
    items = findings.get("items") or []
    risk_codes = sorted({_CATEGORY_TO_RISK.get(it.get("category"), "SAFETY_OTHER") for it in items})
    tier = scan.get("trust_tier") or scan.get("tier")
    grade = scan.get("grade")
    total = findings.get("total", len(items))
    tier_str = f"{tier}" + (f", grade {grade}" if grade else "")
    explanation = (
        f"AgentAvow static-analysis safety score {score}/100 ({tier_str}). "
        f"{total} findings ({findings.get('critical', 0)} critical, {findings.get('high', 0)} high) "
        f"across {len(risk_codes)} risk categories; scores the TOOL/MCP server, not the agent."
    )
    return {
        "signal": SIGNAL_ID,
        "subjectId": scan.get("repo") or scan.get("target"),  # the observed entity
        "container": {
            "score": score,
            "riskCodes": risk_codes,
            "explanation": explanation,
            "subject": SUBJECT_CLASS,          # #15/#16 bucket key: tool vs agent vs org
        },
        "provenance": {
            "aimId": "did:web:agentgraph.co",
            "evidence": {
                "type": "ed25519-jws",
                "algorithm": scan.get("algorithm", "EdDSA"),
                "jws": scan.get("jws"),
                "kid": scan.get("key_id"),
                "jwks_url": scan.get("jwks_url", "https://agentgraph.co/.well-known/jwks.json"),
                "recomputable": True,  # JCS-canonical payload; verifier re-derives offline
            },
        },
    }


def _fetch(owner_repo: str) -> dict:
    url = f"https://agentavow.com/api/v1/public/scan/{owner_repo}?force=false"
    with urllib.request.urlopen(url, timeout=90) as r:  # noqa: S310 — fixed https host
        return json.load(r)


def _post(import_url: str, observation: dict) -> int:
    body = json.dumps(observation).encode()
    req = urllib.request.Request(import_url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310
        return r.status


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    target = args[0] if args else "modelcontextprotocol/servers"
    obs = to_observation(_fetch(target))
    if "--post" in sys.argv:
        url = sys.argv[sys.argv.index("--post") + 1]
        print(f"POST {url} -> {_post(url, obs)}")
    else:
        print("# config entry (#16):", json.dumps(CONFIG_ENTRY))
        print(json.dumps(obs, indent=2))
