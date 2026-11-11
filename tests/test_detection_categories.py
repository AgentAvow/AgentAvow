"""The canonical detection-category list (src/scanner/categories.py).

Pins the list, and checks that every raw finding ``category`` a detector can emit maps
into exactly one detection category. The emitted set is read from the scanner's source
(every ``category=`` / ``"category":`` literal and every first argument to a helper whose
first parameter is ``category``), so a new detector key without a mapping fails here.
"""
from __future__ import annotations

import ast
import asyncio
from pathlib import Path

from src.scanner.categories import (
    DETECTION_CATEGORIES,
    DETECTION_CATEGORY_IDS,
    FINDING_CATEGORY_MAP,
    UNMAPPED,
    categories_public,
    detection_category_for,
)

SCANNER = Path(__file__).resolve().parent.parent / "src" / "scanner"

PINNED_IDS = (
    "secrets",
    "code_execution",
    "obfuscation",
    "prompt_injection",
    "remote_code_load",
    "data_exfiltration",
    "toxic_flow",
    "network_endpoints",
    "filesystem_access",
    "dependencies",
    "install_hooks",
    "tool_definition",
    "artifact_integrity",
    "runtime_robustness",
)


def _emitted_finding_categories() -> set[str]:
    trees = [ast.parse(p.read_text()) for p in sorted(SCANNER.rglob("*.py"))]
    out: set[str] = set()
    for t in trees:
        # Module-local helpers whose FIRST parameter is the category
        # (``_finding("secret", ...)``). A same-named helper elsewhere with ``category``
        # later (behavioral ``_finding(rule, *, category=...)``) is read through its
        # keyword instead.
        positional = {"Finding"} | {
            n.name for n in ast.walk(t)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.args.args and n.args.args[0].arg == "category"}
        for n in ast.walk(t):
            if isinstance(n, ast.Call):
                fn = getattr(n.func, "id", None) or getattr(n.func, "attr", None)
                for k in n.keywords:
                    if (k.arg == "category" and isinstance(k.value, ast.Constant)
                            and isinstance(k.value.value, str)):
                        out.add(k.value.value)
                if (fn in positional and n.args and isinstance(n.args[0], ast.Constant)
                        and isinstance(n.args[0].value, str)):
                    out.add(n.args[0].value)
            elif isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values):
                    if (isinstance(k, ast.Constant) and k.value == "category"
                            and isinstance(v, ast.Constant) and isinstance(v.value, str)):
                        out.add(v.value)
    # Categories held in tables rather than at the call site.
    from src.scanner.bytecode import CATEGORY
    from src.scanner.mcp_icons import _RULES
    out.add(CATEGORY)
    out.update(cat for cat, _sev, _rem in _RULES.values())
    return out


def test_canonical_list_is_pinned():
    assert DETECTION_CATEGORY_IDS == PINNED_IDS
    assert len(DETECTION_CATEGORIES) == 14
    assert sum(1 for c in DETECTION_CATEGORIES if c.static) == 13
    assert [c.id for c in DETECTION_CATEGORIES if not c.static] == ["runtime_robustness"]
    for c in DETECTION_CATEGORIES:
        assert c.name and c.description and c.finding_categories
        assert "\n" not in c.description


def test_each_raw_key_maps_to_exactly_one_category():
    seen: list[str] = [raw for c in DETECTION_CATEGORIES for raw in c.finding_categories]
    assert len(seen) == len(set(seen)), "a raw finding category is in two groups"
    assert set(FINDING_CATEGORY_MAP) == set(seen)


def test_every_emitted_finding_category_is_mapped():
    emitted = _emitted_finding_categories()
    # The scan must find the core pattern-table keys, or the AST walk is broken.
    assert {"secret", "unsafe_exec", "fs_access", "exfiltration", "obfuscation",
            "prompt_injection", "hidden_unicode", "dynamic_remote_load",
            "insecure_deserialization", "toxic_flow", "dependency",
            "install_hook"} <= emitted
    unmapped = sorted(emitted - set(FINDING_CATEGORY_MAP))
    assert not unmapped, f"finding categories with no detection category: {unmapped}"


def test_no_mapping_for_a_key_nothing_emits():
    stale = sorted(set(FINDING_CATEGORY_MAP) - _emitted_finding_categories())
    assert not stale, f"mapped keys no detector emits: {stale}"


def test_score_axis_keys_are_all_mapped():
    """Every raw key the sub-score axes read is in the canonical list."""
    import inspect

    from src.scanner import scan

    src = inspect.getsource(scan._calculate_category_scores)
    tree = ast.parse(src.lstrip())
    keys: set[str] = set()
    for n in ast.walk(tree):
        if (isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "category_map"
                and isinstance(n.value, ast.Dict)):
            keys = {k.value for k in n.value.keys}
    assert keys and keys <= set(FINDING_CATEGORY_MAP)
    assert set(scan._REMEDIATION_HINTS) <= set(FINDING_CATEGORY_MAP)


def test_detection_category_for():
    assert detection_category_for("secret") == "secrets"
    assert detection_category_for("lethal_trifecta") == "toxic_flow"
    assert detection_category_for("auth_scheme") == "network_endpoints"
    assert detection_category_for("robustness") == "runtime_robustness"
    assert detection_category_for("no_such_key") == UNMAPPED
    assert detection_category_for("") == UNMAPPED


def test_public_shape_and_endpoint():
    from src.api.public_scan_router import list_detection_categories

    body = asyncio.run(list_detection_categories())
    assert body["count"] == 14
    assert body["static_count"] == 13
    assert body["categories"] == categories_public()
    assert [c["id"] for c in body["categories"]] == list(PINNED_IDS)
    assert set(body["categories"][0]) == {
        "id", "name", "description", "finding_categories", "static"}


def test_scan_finding_carries_detection_category():
    from src.api.public_scan_router import ScanFinding

    f = ScanFinding(category="unsafe_exec", name="x", severity="high",
                    file_path="a.py", line_number=1)
    assert f.detection_category == "code_execution"
    # A cached item from before the field existed still gets it.
    g = ScanFinding.model_validate({"category": "ssrf", "name": "y", "severity": "high",
                                    "file_path": "b.py", "line_number": 2})
    assert g.model_dump()["detection_category"] == "network_endpoints"
