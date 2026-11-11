"""The detection categories: one canonical list of what the scanner checks.

Every finding carries a raw ``category`` key (``secret``, ``unsafe_exec``,
``lethal_trifecta``, ...). Detectors added over time grew that set to 28 keys, many of
them narrow variants of one check (an A2A card's plain-HTTP endpoint and its
private-address endpoint are both network findings). This module groups the raw keys
into the detection categories a person would name, each with an id, a display name and
a one-line description, and maps every raw key into exactly one of them.

Categorisation only. Nothing here feeds the trust score, the five ``category_scores``
sub-scores (``src/scanner/scan.py`` ``_calculate_category_scores``) or the answer
(``src/scanner/verdict.py`` ``decide()``); those still read the raw ``category`` key.

``static`` is False for a category only the behavioral sandbox tier can produce (it
needs the tool to run); the static engine never emits it.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionCategory:
    id: str
    name: str
    description: str
    # Raw finding ``category`` keys that roll up into this detection category.
    finding_categories: tuple[str, ...]
    static: bool = True


DETECTION_CATEGORIES: tuple[DetectionCategory, ...] = (
    DetectionCategory(
        "secrets", "Exposed secrets",
        "API keys, tokens, passwords or private keys written into the code or config.",
        ("secret",),
    ),
    DetectionCategory(
        "code_execution", "Unsafe code execution",
        "Shell or eval execution of input, unsafe deserialization, and git configs that"
        " run commands on ordinary git operations.",
        ("unsafe_exec", "insecure_deserialization", "git_autorun"),
    ),
    DetectionCategory(
        "obfuscation", "Obfuscated or hidden code",
        "Encoded, packed or bytecode-only code, and invisible or bidi Unicode that hides"
        " text from a human reviewer.",
        ("obfuscation", "hidden_unicode"),
    ),
    DetectionCategory(
        "prompt_injection", "Prompt injection",
        "Instruction-override or hidden-directive text in tool descriptions, metadata,"
        " skill prose or tool results, aimed at the model that reads it.",
        ("prompt_injection",),
    ),
    DetectionCategory(
        "remote_code_load", "Remote code loading (rug-pull)",
        "Code, config or tool definitions fetched from a mutable remote source that can"
        " change after you approved the tool.",
        ("dynamic_remote_load",),
    ),
    DetectionCategory(
        "data_exfiltration", "Data exfiltration",
        "Credentials or local data sent to an outbound endpoint.",
        ("exfiltration",),
    ),
    DetectionCategory(
        "toxic_flow", "Toxic flows (lethal trifecta)",
        "Private-data access, untrusted input and an outbound send combined in one tool,"
        " the prompt-injection-to-exfiltration chain.",
        ("toxic_flow", "lethal_trifecta"),
    ),
    DetectionCategory(
        "network_endpoints", "Network and endpoint safety",
        "Caller-supplied URLs fetched unchecked (SSRF), plain-HTTP or private-address"
        " endpoints, cross-site endpoints, and weak or missing auth schemes.",
        ("ssrf", "insecure_transport", "endpoint_origin", "auth_scheme", "data_handling",
         # x402 payment terms (src/scanner/x402_scan.py): who gets paid, on what network.
         "payment_terms"),
    ),
    DetectionCategory(
        "filesystem_access", "Filesystem access",
        "Unsandboxed reads and writes, path traversal, and recursive deletes.",
        ("fs_access",),
    ),
    DetectionCategory(
        "dependencies", "Dependencies and advisories",
        "Dependencies with known vulnerabilities, published advisories against the"
        " package itself, and deprecated or yanked releases.",
        ("dependency", "known_vulnerability", "maintenance"),
    ),
    DetectionCategory(
        "install_hooks", "Install and lifecycle hooks",
        "Scripts that run on install or around a skill's invocation without being"
        " called (npm pre/postinstall, skill hook manifests).",
        ("install_hook", "skill_hook"),
    ),
    DetectionCategory(
        "tool_definition", "Tool and skill definition",
        "Risky input schemas, annotations that misstate what a tool does, and skill"
        " permission grants that differ from what the shipped code does.",
        ("schema_risk", "annotation_lie", "skill_capability"),
    ),
    DetectionCategory(
        "artifact_integrity", "Artifact integrity",
        "A published package that differs from its source repo, and agent cards whose"
        " signature does not verify.",
        ("artifact_drift", "card_signature"),
    ),
    DetectionCategory(
        "runtime_robustness", "Runtime robustness",
        "A tool call that crashes the server or a read-only tool that fails on a read,"
        " seen only when the behavioral sandbox runs the tool.",
        ("robustness",),
        static=False,
    ),
)

DETECTION_CATEGORY_IDS: tuple[str, ...] = tuple(c.id for c in DETECTION_CATEGORIES)

# Raw finding category -> detection category id.
FINDING_CATEGORY_MAP: dict[str, str] = {
    raw: c.id for c in DETECTION_CATEGORIES for raw in c.finding_categories
}

# Fallback for a raw key no detector emits today (a new detector added without a
# mapping). The pinning test fails before that ships; this keeps the API from erroring.
UNMAPPED = "other"


def detection_category_for(finding_category: str) -> str:
    """The detection category id for a raw finding ``category`` key."""
    return FINDING_CATEGORY_MAP.get(finding_category or "", UNMAPPED)


def categories_public() -> list[dict]:
    """The canonical list as plain JSON, for the public API."""
    return [
        {
            "id": c.id,
            "name": c.name,
            "description": c.description,
            "finding_categories": list(c.finding_categories),
            "static": c.static,
        }
        for c in DETECTION_CATEGORIES
    ]
