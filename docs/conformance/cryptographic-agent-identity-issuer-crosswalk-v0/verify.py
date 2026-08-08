#!/usr/bin/env python3
"""Verify the cryptographic-agent-identity issuer/project crosswalk (A2A#1786).

Asserts the dual-carry invariant: the AgentGraph -> AgentAvow rename moves no
wire values. Concretely:

  1. Both hosts (agentgraph.co, agentavow.com) serve /.well-known/
     cte-test-vectors.json byte-identically.
  2. Each of the four published vectors reproduces its pinned canonical SHA-256.
  3. The issuer (provider.id) is did:web:agentgraph.co in every vector — held,
     not rotated.
  4. The claim_type closed set and the two error codes are unchanged.

Stdlib only. Requires network access to both hosts. Exit 0 on full pass.
"""
from __future__ import annotations

import hashlib
import json
import sys
import urllib.request

PREVIOUS_HOST = "https://agentgraph.co/.well-known/cte-test-vectors.json"
CURRENT_HOST = "https://agentavow.com/.well-known/cte-test-vectors.json"

HELD_ISSUER = "did:web:agentgraph.co"
EXPECTED_CLAIM_TYPES = ["identity", "transport", "authority", "continuity"]
EXPECTED_ERROR_CODES = {"INVALID_CLAIM_SCOPE", "INVALID_COMPOSITION"}

PINNED_SHA256 = {
    "envelope_vector":
        "9e7b5031e46de38b5f90e895113a3f24f42a4128d8d99856a2d71e529b0f0d5c",
    "verdict_vector":
        "feb42dca4214fc46207138d676ec727d7b3d0caa1eda8c0390d2d6f6fbc28913",
    "scope_violation_vector":
        "e584f1cd0885dc938da5fc23ce7e528715a0086e5464c9ed0f3c1c82b364026f",
    "composition_failure_vector":
        "f9cd10bc4e8bf34ce3aa6a0e5df0d27989e54ff41c4333c69ae3ecfaf8de0cb5",
}


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def main() -> int:
    fails: list[str] = []

    prev_raw = _fetch(PREVIOUS_HOST)
    cur_raw = _fetch(CURRENT_HOST)

    # 1. Byte-identical across hosts.
    if prev_raw == cur_raw:
        print("PASS  both hosts serve byte-identical content")
    else:
        fails.append("host responses differ byte-for-byte")
        print("FAIL  host responses differ byte-for-byte")

    doc = json.loads(prev_raw)
    model = doc["claim_model"]

    # 2. Pinned canonical SHA-256 per vector.
    for name, pinned in PINNED_SHA256.items():
        vector = doc[name]
        got = hashlib.sha256(
            vector["canonical_bytes_utf8"].encode("utf-8")
        ).hexdigest()
        published = vector["canonical_sha256"]
        if got == pinned == published:
            print(f"PASS  {name} canonical SHA-256 == {pinned}")
        else:
            fails.append(f"{name} sha mismatch (got {got}, pinned {pinned})")
            print(f"FAIL  {name} sha mismatch: got {got}, pinned {pinned}, "
                  f"published {published}")

    # 3. Issuer held at did:web:agentgraph.co in every envelope vector.
    for name in ("envelope_vector", "scope_violation_vector",
                 "composition_failure_vector"):
        provider_id = doc[name]["input_object"]["provider"]["id"]
        if provider_id == HELD_ISSUER:
            print(f"PASS  {name} issuer held at {HELD_ISSUER}")
        else:
            fails.append(f"{name} issuer moved to {provider_id}")
            print(f"FAIL  {name} issuer is {provider_id}, expected {HELD_ISSUER}")

    # 4. claim_type closed set + error codes unchanged.
    closed_set = model["claim_type"]["closed_set"]
    if closed_set == EXPECTED_CLAIM_TYPES:
        print(f"PASS  claim_type closed set unchanged: {closed_set}")
    else:
        fails.append(f"claim_type closed set changed: {closed_set}")
        print(f"FAIL  claim_type closed set changed: {closed_set}")

    error_codes = set(doc["error_codes"].keys())
    if error_codes == EXPECTED_ERROR_CODES:
        print(f"PASS  error codes unchanged: {sorted(error_codes)}")
    else:
        fails.append(f"error codes changed: {sorted(error_codes)}")
        print(f"FAIL  error codes changed: {sorted(error_codes)}")

    if fails:
        print(f"\n{len(fails)} check(s) failed")
        return 1
    print("\nAll crosswalk invariants hold: rename carries no wire change.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
