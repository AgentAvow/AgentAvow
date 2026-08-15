"""Parse a tool's `.agentavow.yml` declared-scope manifest (spec:
docs/standards/agentavow-manifest-v0.md). A malformed or absent manifest yields an empty
DeclaredScope — never an error — so a bad manifest can't fail a scan.
"""
from __future__ import annotations

from dataclasses import dataclass, field

_CAP_VOCAB = {
    "filesystem:read", "filesystem:write", "network:egress", "process:spawn", "env:read",
}


@dataclass
class DeclaredScope:
    present: bool = False
    egress: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    note: str = ""

    def egress_set(self) -> set[str]:
        """Declared hosts as a set the behavioral tier can pass as expected_hosts. A leading
        '.' (subdomain wildcard) is normalized to the bare host — the egress classifier
        already treats an allowed host as covering its subdomains."""
        return {h.lstrip(".").lower() for h in self.egress if h and isinstance(h, str)}


def parse_manifest(text: str | None) -> DeclaredScope:
    """Parse `.agentavow.yml` text. Absent/blank/malformed → empty DeclaredScope."""
    if not text or not text.strip():
        return DeclaredScope()
    try:
        import yaml  # optional dep, imported lazily
        data = yaml.safe_load(text)
    except Exception:
        return DeclaredScope()
    if not isinstance(data, dict):
        return DeclaredScope()
    if data.get("version") != "agentavow-manifest-v0":
        # Unknown/again-absent version — treat as no usable declaration.
        return DeclaredScope()

    def _str_list(v: object) -> list[str]:
        if not isinstance(v, list):
            return []
        return [str(x).strip() for x in v if isinstance(x, (str, int)) and str(x).strip()]

    caps = [c for c in _str_list(data.get("capabilities")) if c in _CAP_VOCAB]
    note = data.get("note")
    return DeclaredScope(
        present=True,
        egress=_str_list(data.get("egress")),
        capabilities=caps,
        note=str(note).strip()[:280] if isinstance(note, str) else "",
    )
