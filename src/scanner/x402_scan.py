"""x402 endpoints, read from their public Bazaar listing (design: docs/internal/
x402-scan-design-2026-11-11.md, reviewed by agentgraph-83 2026-11-11).

An agent that pays for an x402 endpoint decides what to call from the listing in
Coinbase's discovery directory: a description, a JSON Schema of the input and output
with a description per field, an output example, and the payment terms (``accepts[]``:
network, asset, amount, payTo). That is the same surface as an MCP tool definition, so
the listing goes through ``analyze_mcp`` unchanged (tool poisoning, hidden and encoded
instructions, exfiltration directives, invisible Unicode, capability taxonomy). Phase 1
adds factual checks on the payment terms. Nothing here calls the endpoint.

What the answer may say: we read the listing, never the code behind it. Every result
carries the ``x402_code_unread`` coverage gap, which withholds the Certified mark, and a
Safe reason says the code is not visible (``verdict.X402_CLEAN_REASON``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import urlsplit

X402_SURFACE = "x402"
X402_CODE_UNREAD_GAP = "x402_code_unread"
# The phase-2 live check's user agent lives in src/scanner/x402_live.py (USER_AGENT).
BAZAAR_RESOURCES_URL = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources"

# Raw finding category for the payment-term checks (maps to the data_handling axis).
PAYMENT_TERMS = "payment_terms"

# Disclosure ceiling, per design review: low, "costs more than $1 per call".
PRICE_CEILING_USD = Decimal("1")

# Known USD stablecoins by (CAIP-2 network, asset), lower-cased for EVM addresses. Six
# decimals each. Anything else is disclosed as "price in <asset>, not converted"; a
# token's self-declared name (``extra.name``) is never trusted for this.
_USDC6 = 6
KNOWN_STABLECOINS: dict[tuple[str, str], tuple[str, int]] = {
    ("eip155:1", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"): ("USDC", _USDC6),
    ("eip155:8453", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"): ("USDC", _USDC6),
    ("eip155:84532", "0x036cbd53842c5426634e7929541ec2318f3dcf7e"): ("USDC", _USDC6),
    ("eip155:42161", "0xaf88d065e77c8cc2239327c5edb3a432268e5831"): ("USDC", _USDC6),
    ("eip155:137", "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359"): ("USDC", _USDC6),
    ("eip155:10", "0x0b2c639c533813f4aa9d7837caf62653d097ff85"): ("USDC", _USDC6),
    ("eip155:43114", "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e"): ("USDC", _USDC6),
    ("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"):
        ("USDC", _USDC6),
}
# Test networks: a listing that settles on one cannot take real payment.
TESTNETS = frozenset({
    "eip155:84532",      # Base Sepolia
    "eip155:11155111",   # Ethereum Sepolia
    "eip155:421614",     # Arbitrum Sepolia
    "eip155:80002",      # Polygon Amoy
    "eip155:11155420",   # OP Sepolia
    "eip155:43113",      # Avalanche Fuji
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",  # Solana devnet
    "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z",  # Solana testnet
})
# Legacy (x402 v1) network names seen in older listings.
_LEGACY_NETWORKS = {"base": "eip155:8453", "base-sepolia": "eip155:84532",
                    "ethereum": "eip155:1", "polygon": "eip155:137",
                    "arbitrum": "eip155:42161", "optimism": "eip155:10",
                    "avalanche": "eip155:43114", "avalanche-fuji": "eip155:43113",
                    "solana": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                    "solana-devnet": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"}

_EVM_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_B58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

# Locations the scorer reads as plain metadata (never as a test or docs path).
_WHERE_LISTING = "x402:listing"
_WHERE_EXAMPLE = "x402:listing:output-example"
_WHERE_TERMS = "x402:payment-terms"


@dataclass
class X402ScanResult:
    findings: list = field(default_factory=list)
    resource: str = ""
    service_name: str = ""
    networks: list[str] = field(default_factory=list)
    pay_to: list[str] = field(default_factory=list)
    price_usd: str | None = None          # lowest known-stablecoin price, as a string
    price_unconverted: list[str] = field(default_factory=list)
    testnet_only: bool = False
    capabilities: dict[str, int] = field(default_factory=dict)
    coverage_gaps: dict = field(default_factory=dict)


def _finding(category: str, name: str, severity: str, where: str, remediation: str = ""):
    from src.scanner.scan import Finding
    return Finding(category=category, name=name, severity=severity, file_path=where,
                   line_number=0, snippet="", remediation=remediation)


def _clip(s: Any, n: int = 60) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def network_id(raw: Any) -> str:
    n = str(raw or "").strip()
    return _LEGACY_NETWORKS.get(n.lower(), n)


def _bazaar(rec: dict) -> dict:
    ext = rec.get("extensions") if isinstance(rec.get("extensions"), dict) else {}
    baz = ext.get("bazaar") if isinstance(ext.get("bazaar"), dict) else {}
    return baz


def _schema_part(rec: dict, part: str) -> dict:
    """``input`` / ``output`` JSON Schema from the bazaar extension (v2), or the older
    top-level ``input_schema`` / ``output_schema`` fields of an x402 v1 listing."""
    schema = _bazaar(rec).get("schema")
    if isinstance(schema, dict):
        props = schema.get("properties")
        if isinstance(props, dict) and isinstance(props.get(part), dict):
            return props[part]
    legacy = rec.get(f"{part}_schema") or rec.get(f"{part}Schema")
    return legacy if isinstance(legacy, dict) else {}


def _flat_props(schema: Any, prefix: str = "", depth: int = 0,
                out: dict | None = None) -> dict:
    """Leaf properties of a nested JSON Schema as ``{"query.city": spec}``. x402 nests
    fields under ``queryParams`` / ``body`` / ``pathParams`` / ``headers``, while
    ``analyze_mcp`` reads parameters one level deep; flattening gives every field the
    same per-parameter checks as an MCP tool parameter."""
    out = {} if out is None else out
    if not isinstance(schema, dict) or depth > 5 or len(out) >= 200:
        return out
    props = schema.get("properties")
    if not isinstance(props, dict):
        return out
    for k, spec in props.items():
        if not isinstance(spec, dict):
            continue
        path = f"{prefix}{k}"
        nested = spec.get("properties")
        if isinstance(nested, dict) and nested:
            if spec.get("description") or spec.get("title"):
                out[path] = {kk: spec[kk] for kk in ("type", "description", "title")
                             if kk in spec}
            _flat_props(spec, f"{path}.", depth + 1, out)
        else:
            out[path] = spec
    return out


def listing_as_tool(rec: dict) -> dict:
    """The listing in the shape ``analyze_mcp`` reads for one tool definition."""
    resource = str(rec.get("resource") or rec.get("endpoint_url") or "")
    name = str(rec.get("serviceName") or rec.get("service_name") or "").strip()
    if not name:
        path = urlsplit(resource).path.strip("/") if resource else ""
        name = path.rsplit("/", 1)[-1] or (urlsplit(resource).hostname or "x402 endpoint")
    return {
        "name": name[:120],
        "description": str(rec.get("description") or ""),
        "inputSchema": {"type": "object",
                        "properties": _flat_props(_schema_part(rec, "input"))},
        "outputSchema": _schema_part(rec, "output"),
    }


def _output_schema_findings(tool: dict) -> list:
    """Field descriptions of the output schema are text an agent reads too: the same
    injection check as an input parameter, at full weight."""
    from src.scanner.mcp_scan import _scan_text_for_injection
    found: list = []
    for path, spec in _flat_props(tool.get("outputSchema") or {}).items():
        for key in ("description", "title"):
            text = spec.get(key) if isinstance(spec, dict) else None
            if text:
                found.extend(_scan_text_for_injection(
                    str(text), f"{_WHERE_LISTING}:output:{path}"))
    return found


def _example_strings(obj: Any, out: list[str], budget: list[int]) -> None:
    """Every string value in the output example, bounded (64 KB of text)."""
    if budget[0] <= 0:
        return
    if isinstance(obj, str):
        s = obj[: budget[0]]
        budget[0] -= len(s)
        if s.strip():
            out.append(s)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _example_strings(str(k), out, budget)
            _example_strings(v, out, budget)
    elif isinstance(obj, list):
        for v in obj:
            _example_strings(v, out, budget)


_ONE_STEP_DOWN = {"critical": "high", "high": "medium", "medium": "low",
                  "low": "low", "info": "info"}


def _example_findings(rec: dict) -> list:
    """Injection in the output example: what an agent would ingest, but an example,
    not an observed response. One severity step down, never critical (design review
    2026-11-11). The same text in the description or schema keeps full weight there."""
    info = _bazaar(rec).get("info")
    out_ex = (info or {}).get("output") if isinstance(info, dict) else None
    example = out_ex.get("example") if isinstance(out_ex, dict) else None
    if example is None:
        return []
    texts: list[str] = []
    _example_strings(example, texts, [64 * 1024])
    if not texts:
        return []
    from src.scanner.mcp_scan import _scan_text_for_injection
    found = _scan_text_for_injection("\n".join(texts), _WHERE_EXAMPLE)
    for f in found:
        f.severity = _ONE_STEP_DOWN.get(f.severity, f.severity)
        if f.severity == "critical":  # defensive: never critical from an example
            f.severity = "high"
        f.name = f"{f.name} (in the output example)"
    return found


def _price(amount: Any, decimals: int) -> Decimal | None:
    try:
        return Decimal(str(amount)) / (Decimal(10) ** decimals)
    except (InvalidOperation, ValueError):
        return None


def _valid_pay_to(network: str, pay_to: str) -> bool:
    if network.startswith("eip155:"):
        return bool(_EVM_ADDR_RE.match(pay_to))
    if network.startswith("solana:"):
        return bool(_B58_RE.match(pay_to))
    return bool(pay_to.strip())


def _terms_findings(rec: dict, res: X402ScanResult) -> list:
    out: list = []
    resource = str(rec.get("resource") or rec.get("endpoint_url") or "").strip()
    accepts = [a for a in (rec.get("accepts") or []) if isinstance(a, dict)]

    # Transport: the payment authorization header travels with the request.
    scheme = (urlsplit(resource).scheme or "").lower() if resource else ""
    host = (urlsplit(resource).hostname or "").lower() if resource else ""
    if scheme == "http":
        out.append(_finding(
            "insecure_transport", f"the paid endpoint uses plain http:// ({_clip(resource)})",
            "high", _WHERE_LISTING,
            "Serve it over https. The signed payment authorization and the response "
            "travel in cleartext, so anyone on the path can read or replay them."))
    elif scheme and scheme != "https":
        out.append(_finding(
            "insecure_transport", f"the paid endpoint uses an unexpected scheme {scheme}://",
            "medium", _WHERE_LISTING, "Use an https:// URL."))

    # Recipients: one payee per address family. An EVM wallet and a Solana wallet are
    # necessarily different addresses, so a listing that settles on both chains names
    # two payTo values by design; two different EVM wallets (or two Solana wallets)
    # for one resource is the finding (first full-listing run, 2026-11-11: 12,519 rows
    # were EVM + Solana pairs).
    payees = sorted({str(a.get("payTo") or "").strip() for a in accepts
                     if str(a.get("payTo") or "").strip()})
    res.pay_to = payees
    per_net: dict[str, set[str]] = {}
    families: dict[str, set[str]] = {}
    for a in accepts:
        pt = str(a.get("payTo") or "").strip()
        if not pt:
            continue
        net = network_id(a.get("network"))
        fam = net.split(":", 1)[0] if ":" in net else (net or "unknown")
        norm = pt.lower() if fam == "eip155" else pt
        per_net.setdefault(net, set()).add(norm)
        families.setdefault(fam, set()).add(norm)
    same_net = {n: v for n, v in per_net.items() if len(v) > 1}
    if same_net:
        # Two wallets on one network: an agent paying there can be sent to either
        # (api.exa.ai: two Base wallets).
        net, v = max(same_net.items(), key=lambda kv: len(kv[1]))
        out.append(_finding(
            "payment_terms",
            f"the listing names {len(v)} different recipients on {net}",
            "medium", _WHERE_TERMS,
            "An agent paying on this network may be sent to either wallet. Use one "
            "recipient per network, or say in the description which wallet is which."))
    else:
        multi = {fam: v for fam, v in families.items() if len(v) > 1}
        if multi:
            # Different wallets on different chains of one family: often one wallet per
            # deployment. Disclosure only.
            fam, v = max(multi.items(), key=lambda kv: len(kv[1]))
            label = {"eip155": "EVM", "solana": "Solana"}.get(fam, fam)
            out.append(_finding(
                "payment_terms",
                f"a different {label} recipient on each network ({len(v)} payTo addresses)",
                "low", _WHERE_TERMS,
                "Different chains pay different wallets. If they are not all yours, say "
                "so in the description."))
    for a in accepts:
        net = network_id(a.get("network"))
        pay_to = str(a.get("payTo") or "").strip()
        if pay_to and not _valid_pay_to(net, pay_to):
            out.append(_finding(
                "payment_terms", f"payTo is not a valid address for {net or 'its network'} "
                f"({_clip(pay_to, 24)})", "medium", _WHERE_TERMS,
                "A malformed recipient means a payment that fails or goes somewhere "
                "unintended."))
        a_res = str(a.get("resource") or "").strip()
        a_host = (urlsplit(a_res).hostname or "").lower() if a_res else ""
        if a_host and host and a_host != host:
            # The payee-swap shape: the listing an agent reads names one host, the
            # resource it pays for names another (api.aidress.ai listings paying for
            # api.printmoneylab.com, 2026-11-11). High (Review): the agent should know
            # who it really pays, even when a reseller is legitimate.
            out.append(_finding(
                "endpoint_origin",
                f"the payment terms name a different host ({a_host}) than the listing "
                f"({host})", "high", _WHERE_TERMS,
                "An agent calls one host and pays for a resource on another. If this is "
                "a reseller or proxy, say so in the description and name the provider."))

    # Networks and price.
    nets = sorted({network_id(a.get("network")) for a in accepts if a.get("network")})
    res.networks = nets
    if nets and all(n in TESTNETS for n in nets):
        res.testnet_only = True
        out.append(_finding(
            "payment_terms", "settles on a test network only (" + ", ".join(nets) + ")",
            "info", _WHERE_TERMS, "A test-network listing cannot take real payment."))
    prices: list[Decimal] = []
    for a in accepts:
        net = network_id(a.get("network"))
        asset = str(a.get("asset") or "").strip()
        key = (net, asset.lower() if asset.startswith("0x") else asset)
        known = KNOWN_STABLECOINS.get(key)
        if known:
            p = _price(a.get("amount"), known[1])
            if p is not None:
                prices.append(p)
        elif asset:
            label = f"{_clip(asset, 14)} on {net}" if net else _clip(asset, 14)
            if label not in res.price_unconverted:
                res.price_unconverted.append(label)
    if prices:
        low = min(prices)
        res.price_usd = format(low.normalize(), "f")
        if low > PRICE_CEILING_USD:
            out.append(_finding(
                "payment_terms", "costs more than $1 per call", "low", _WHERE_TERMS,
                f"The cheapest listed option is ${res.price_usd} per call."))
    elif res.price_unconverted:
        out.append(_finding(
            "payment_terms", f"price in {res.price_unconverted[0]}, not converted", "info",
            _WHERE_TERMS, "The asset is not a stablecoin we know, so no USD price is shown."))
    return out


def analyze_x402_listing(rec: dict) -> X402ScanResult:
    """Score one Bazaar listing record. Pure: nothing is fetched."""
    from src.scanner.mcp_scan import analyze_mcp

    tool = listing_as_tool(rec)
    res = X402ScanResult(
        resource=str(rec.get("resource") or rec.get("endpoint_url") or ""),
        service_name=tool["name"])
    mcp = analyze_mcp([tool])
    for f in mcp.findings:
        # The lethal trifecta is about the set of tools one agent session holds; a
        # single remote API's listing cannot form it. On security-audit APIs it read
        # their own capability prose as a critical (first full-listing run: 6 rows).
        if f.category == "lethal_trifecta":
            continue
        # analyze_mcp locates findings as "tool:<name>[...]"; anything else (server-level
        # findings) is the listing too. Never "in its code".
        path = str(f.file_path or "")
        prefix = f"tool:{tool['name']}"
        f.file_path = (_WHERE_LISTING + path[len(prefix):] if path.startswith(prefix)
                       else _WHERE_LISTING)
        res.findings.append(f)
    res.findings.extend(_output_schema_findings(tool))
    res.capabilities = dict(mcp.capabilities)
    res.findings.extend(_example_findings(rec))
    res.findings.extend(_terms_findings(rec, res))
    res.coverage_gaps = dict(mcp.coverage_gaps)
    res.coverage_gaps[X402_CODE_UNREAD_GAP] = True
    return res


def scan_result_from_listing(rec: dict, live: dict | None = None):
    """A signed-shape ``ScanResult`` for one listing (no network). ``live`` is that
    endpoint's phase-2 reply (``x402_live.read_reply``) when a live check ran: its
    findings join the listing's and ``artifact_scan.live_check`` records it."""
    from src.scanner.coverage import SCAN_DEPTH_ARTIFACT_LIVE, build_coverage
    from src.scanner.scan import (
        ScanResult,
        _calculate_category_scores,
        _calculate_trust_score,
        _certified_status,
    )

    x = analyze_x402_listing(rec)
    live_record = None
    if isinstance(live, dict):
        from src.scanner.x402_live import live_findings
        extra, live_record = live_findings(rec, live)
        live_record["checked_at"] = live.get("checked_at")
        x.findings.extend(extra)
    result = ScanResult(repo=f"x402:{x.resource}", stars=0, description="",
                        framework="x402")
    result.findings = x.findings
    result.files_scanned = 1
    result.total_scannable_files = 1
    result.primary_language = "x402"
    price = f" · ${x.price_usd}/call" if x.price_usd else ""
    result.description = f"{x.service_name} — x402 endpoint{price}"
    result.artifact_scan = {
        "surface": X402_SURFACE, "resource": x.resource, "service_name": x.service_name,
        "networks": x.networks, "pay_to": x.pay_to, "price_usd": x.price_usd,
        "price_unconverted": x.price_unconverted, "testnet_only": x.testnet_only,
        "capabilities": x.capabilities,
        "last_updated": rec.get("lastUpdated") or rec.get("last_updated"),
    }
    if live_record is not None:
        result.artifact_scan["live_check"] = live_record
    result.coverage = build_coverage(
        surface=X402_SURFACE, scan_depth=SCAN_DEPTH_ARTIFACT_LIVE, live_observed=False)
    result.coverage_gaps = dict(x.coverage_gaps)
    result.trust_score = _calculate_trust_score(result)
    result.category_scores = _calculate_category_scores(result)
    result.certified = _certified_status(result)
    return result
