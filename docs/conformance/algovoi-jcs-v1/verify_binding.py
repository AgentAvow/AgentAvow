#!/usr/bin/env python3
"""Recompute-binding verifier for the digest primitives the JCS runner leaves unbound.

`run_conformance.py` proves cross-substrate JCS *canonicalization agreement*, but it
only recomputes the digests wired into its INPUT_KEYS/hkey extraction. A 2026-07-28
mutation audit (`scripts/dev/mutation_test_vectors.py`) found it never independently
recomputes the top-level published `expected_action_ref` (the CTEF action_ref
primitive) nor the retention-chain refs — so those stored digests could be swapped and
the JCS runner still passed.

This verifier closes that gap by recomputing each such digest FROM ITS PREIMAGE and
requiring an exact match — a recompute-from-scratch check, so any tampered stored value
fails closed (100% of mutations to a bound field are caught, by construction).

Bound primitives:
  * action_ref       = "sha256:" + SHA-256(JCS({agent_id, action_type, scope, timestamp_ms}))
  * receipt_hash     = SHA-256(UTF-8(receipt_preimage))
  * retention_chain  = "sha256:" + SHA-256(JCS({chain_seq, issuer_id,
                       prev_receipt_hash, receipt_hash}))
  * row content hash = SHA-256(JCS(row))  (binds content_hash / prev_hash / row_number)

Scope note: action_ref is our (CTEF / draft-etcheverry-action-ref) primitive; the
retention-chain is AlgoVoi's (draft-hopley-x402-retention-chain). We bind both where the
published preimage is present. The receipt-row content_hash/prev_hash fields in the other
AlgoVoi receipt vectors remain AlgoVoi-spec-owned and are not bound here.

Exit 0 iff every bindable digest recomputes; nonzero (with a report) otherwise.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import sys

from src.signing import canonicalize_jcs_strict

VEC_DIR = os.environ.get(
    "VECTORS_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors"),
)


def _hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _norm(h: str) -> str:
    return str(h).split("sha256:")[-1]


def _bind(vecs, preimage_key, digest_key, recompute, out):
    n = 0
    for v in vecs:
        if isinstance(v, dict) and preimage_key in v and digest_key in v:
            n += 1
            got = recompute(v[preimage_key])
            want = _norm(v[digest_key])
            out.append((v.get("vector_id"), digest_key, got == want, got, want))
    return n


def main() -> int:
    bound = 0
    results = []
    for f in sorted(glob.glob(os.path.join(VEC_DIR, "*.json"))):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        vecs = d.get("vectors", [])
        rows = []
        # action_ref: recompute over the JCS-canonical preimage
        bound += _bind(vecs, "preimage", "expected_action_ref",
                       lambda p: _hex(canonicalize_jcs_strict(p)), rows)
        # retention receipt_hash: SHA-256 of the literal receipt_preimage string
        bound += _bind(vecs, "receipt_preimage", "receipt_hash",
                       lambda p: _hex(p.encode("utf-8")), rows)
        # retention chain ref: recompute over the four-field JCS preimage
        bound += _bind(vecs, "preimage", "expected_chain_ref",
                       lambda p: _hex(canonicalize_jcs_strict(p)), rows)
        # audit-chain row hash: expected_row_content_hash = SHA-256(JCS(row)).
        # Binding this catches any mutation inside `row` — content_hash, prev_hash,
        # receipt_content_hash, row_number — since each changes JCS(row).
        bound += _bind(vecs, "row", "expected_row_content_hash",
                       lambda r: _hex(canonicalize_jcs_strict(r)), rows)
        for vid, key, ok, got, want in rows:
            results.append((os.path.basename(f), vid, key, ok, got, want))

    failures = [r for r in results if not r[3]]
    print(f"verify_binding: {bound - len(failures)}/{bound} recompute-bound digests matched")
    for fname, vid, key, _ok, got, want in failures:
        print(f"  MISMATCH {fname} {vid} {key} {got[:12]} vs {want[:12]}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
