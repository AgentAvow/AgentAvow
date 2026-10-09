"""Short adoption units — one mapping for every adoption display.

Every surface that shows an adoption count (badges, the website card, OG images, the
MCP trust card, the site) uses the short unit, so the same tool reads the same
everywhere: "867M dl/wk", "12k ★", "3.1M pulls". The full unit stays in accessible
titles and the API. The TypeScript twin is ``web/src/rebrand/lib/adoptionUnit.ts``
and the MCP trust card's ``shortUnit`` in ``src/bridges/mcp_app_view.py``; keep the
three tables identical.
"""
from __future__ import annotations

SHORT_UNITS: dict[str, str] = {
    "downloads/wk": "dl/wk",
    "downloads/mo": "dl/mo",
    "downloads/yr": "dl/yr",
    "downloads/90d": "dl/90d",
    "downloads": "dl",
    "stars": "★",
    "stars (linked repo)": "★",
    "pulls": "pulls",
    "dependents": "deps",
    "installs": "installs",
    "likes": "likes",
}


def short_unit(unit: str | None) -> str:
    """The short display form of an adoption unit ("downloads/wk" -> "dl/wk")."""
    u = (unit or "").strip()
    if not u:
        return ""
    return SHORT_UNITS.get(u.lower(), u.replace("downloads", "dl"))
