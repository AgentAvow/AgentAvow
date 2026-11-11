"""Grade an A2A (Agent2Agent) Agent Card for the public check.

The card is the contract a client acts on when it delegates work to a remote agent:
which URLs it will send tasks (and credentials) to, which auth it must present, and
the skill text an orchestrating model reads to decide what to delegate. This module
reads that contract and nothing else; the agent's own code is never seen.

Findings, by where they sit (``file_path`` starts with ``card:``):

- interfaces: a non-https URL (``insecure_transport``), a private, loopback or
  link-local host (``ssrf``: the card would steer a client into its own network),
  an interface on a different site from the card (``endpoint_origin``), none at all;
- auth (``auth_scheme``): no scheme while a skill says it can run code, write files
  or data, read secrets or move money; HTTP Basic; an API key in the query string;
  the deprecated implicit / password OAuth flows; non-https OAuth / OIDC URLs; a
  requirement naming an undeclared scheme; an extended card with no scheme;
- text an agent reads: the metadata prompt-injection matcher and the encoded-
  instruction decoder (``src.scanner.encoded_instructions``) over the card and skill
  descriptions, skill names, tags and examples, and extension and scheme text;
- the card's own signature (``card_signature``): a signature we could not verify is
  a medium finding and the coverage gap ``card_signature_unverified``, which reads
  Review. Never Do not connect: A2A 1.0 §8.4.1 says explicitly set optional fields
  are kept while §8.4.2/§8.4.3 say default-valued properties are removed, so honest
  verifiers disagree at the edges.

``analyze_a2a_card`` is pure: card JSON + the URL it was served from + the pinned
signature result. The card's RFC 8785 digest is signed into the attestation, so a
verifier holding the card recomputes the same findings and score offline.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import rfc8785

logger = logging.getLogger(__name__)

A2A_CARD_DIGEST_PROFILE = "agentavow.a2a-agent-card.v1"
A2A_SKILL_DIGEST_PROFILE = "agentavow.a2a-skill.v1"
SIGNATURE_UNVERIFIED_GAP = "card_signature_unverified"

SIG_VERIFIED = "verified"
SIG_UNVERIFIED = "unverified"
SIG_ABSENT = "absent"

_MAX_SIGNATURES = 5
_MAX_JWKS_BYTES = 64 * 1024

# Capabilities (``src.scanner.mcp_scan`` taxonomy, plus ``payments``) that make an
# unauthenticated skill a finding: anyone who can reach the agent can make it do these.
# ``secrets`` is reported but is not one of them: on a card it is read from prose alone,
# and a skill that explains how to store a credential mentions credentials too.
_SENSITIVE_CAPS = frozenset({"exec", "fs_write", "db_write"})
_CAP_PHRASE = {
    "exec": "run code or commands", "fs_write": "write or delete files",
    "db_write": "write to a database", "secrets": "read secrets or credentials",
    "payments": "move money",
}
_PAYMENTS = re.compile(
    r"\b(?:transfer|send|move|withdraw|wire|spend)s?\s+(?:the\s+|your\s+)?"
    r"(?:funds|money|payments?|crypto|tokens|usdc|eth|btc|sol)\b"
    r"|\b(?:make|makes|execute|executes|initiate|initiates|place|places)\s+"
    r"(?:an?\s+)?(?:payments?|purchases?|trades?|orders?)\b"
    r"|\b(?:buy|sell|swap)s?\s+(?:crypto|tokens|stocks?|shares)\b",
    re.I)

_SECURE_SCHEMES = frozenset({"https", "wss", "grpcs"})
_PLAINTEXT_SCHEMES = frozenset({"http", "ws"})


@dataclass
class A2aScanResult:
    findings: list = field(default_factory=list)
    skill_count: int = 0
    interface_count: int = 0
    capabilities: dict[str, int] = field(default_factory=dict)
    skills: list[dict] = field(default_factory=list)
    auth: dict = field(default_factory=dict)
    positive_signals: list[str] = field(default_factory=list)
    coverage_gaps: dict = field(default_factory=dict)
    card: dict = field(default_factory=dict)  # the normalized card


# ── digests ─────────────────────────────────────────────────────────────────────

def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canon_digest(profile: str, key: str, obj: Any) -> str:
    """SHA-256 over JCS bytes of ``{"profile": …, key: obj}``. Never raises: a value JCS
    cannot represent gets a digest under a distinct ``.noncanonical`` label."""
    from src.scanner.mcp_scan import _as_ijson
    try:
        return _sha256(rfc8785.dumps({"profile": profile, key: _as_ijson(obj)}))
    except Exception:  # noqa: BLE001
        pass
    try:
        return _sha256((profile + ".noncanonical\n" + json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            default=str)).encode("utf-8"))
    except Exception:  # noqa: BLE001
        return _sha256((profile + ".unhashable").encode())


def card_digest(card: dict) -> str:
    """The pinned digest of the card exactly as served (signatures included: a card
    re-signed with a new key is a change a watcher should see)."""
    return _canon_digest(A2A_CARD_DIGEST_PROFILE, "card", card)


def skill_digest_key(skill_id: str) -> str:
    from src.scanner.mcp_scan import tool_digest_key
    return "skill:" + tool_digest_key(skill_id)[len("tool:"):]


def compute_card_digests(card: dict) -> dict[str, str]:
    """``{"card": …, "skill:<id>": …}``: the whole card, plus one digest per skill so
    drift names the skill that changed. Skills sharing an id fold into one entry."""
    out: dict[str, str] = {"card": card_digest(card)}
    by_key: dict[str, list[str]] = {}
    skills = card.get("skills") if isinstance(card, dict) else None
    for sk in skills if isinstance(skills, list) else []:
        if not isinstance(sk, dict):
            continue
        sid = str(sk.get("id") or sk.get("name") or "unnamed")
        by_key.setdefault(skill_digest_key(sid), []).append(
            _canon_digest(A2A_SKILL_DIGEST_PROFILE, "skill", sk))
    for k, ds in list(by_key.items())[:500]:
        out[k] = ds[0] if len(ds) == 1 else _sha256(
            (A2A_SKILL_DIGEST_PROFILE + ".duplicates\n" + "\n".join(sorted(ds))).encode())
    return out


# ── signatures (A2A 1.0 §8.4) ─────────────────────────────────────────────────────

# Fields A2A 1.0 marks ``optional`` or REQUIRED: kept when present, even at their
# default value (§8.4.1). Keyed by the path of the object that holds them; list items
# share their list's path.
_KEEP_FIELDS = {
    (): {"name", "description", "supportedInterfaces", "version", "capabilities",
         "defaultInputModes", "defaultOutputModes", "skills", "documentationUrl",
         "iconUrl"},
    ("capabilities",): {"streaming", "pushNotifications", "extendedAgentCard"},
    ("skills",): {"id", "name", "description", "tags"},
    ("supportedInterfaces",): {"url", "protocolBinding", "protocolVersion"},
    ("provider",): {"url", "organization"},
}


def _is_default(v: Any) -> bool:
    if v is None or v is False or v == "" or v == [] or v == {}:
        return True
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v == 0


def _drop_defaults(obj: Any, path: tuple = (), keep_presence: bool = True) -> Any:
    """Remove default-valued properties (``""``, ``0``, ``false``, ``[]``, ``{}``).
    With ``keep_presence`` the REQUIRED and ``optional`` fields stay when present
    (§8.4.1); without it every default goes (the plain §8.4.2 / §8.4.3 reading)."""
    if isinstance(obj, dict):
        keep = _KEEP_FIELDS.get(path, set()) if keep_presence else set()
        out = {}
        for k, v in obj.items():
            child = _drop_defaults(v, path + (k,), keep_presence)
            if k in keep or not _is_default(child):
                out[k] = child
        return out
    if isinstance(obj, list):
        return [_drop_defaults(v, path, keep_presence) for v in obj]
    return obj


def signing_payload_variants(card: dict) -> list[tuple[str, bytes]]:
    """The payloads a signer may have meant, as JCS bytes, most literal first:
    ``as_served`` (signatures removed, nothing else), ``presence`` (§8.4.1: defaults
    removed, explicitly set optional fields kept), ``no_defaults`` (§8.4.2: every
    default removed). Duplicates are dropped."""
    from src.scanner.mcp_scan import _as_ijson
    base = {k: v for k, v in card.items() if k != "signatures"}
    out: list[tuple[str, bytes]] = []
    for label, body in (
        ("as_served", base),
        ("presence", _drop_defaults(base, (), True)),
        ("no_defaults", _drop_defaults(base, (), False)),
    ):
        try:
            b = rfc8785.dumps(_as_ijson(body))
        except Exception:  # noqa: BLE001
            continue
        if all(b != prev for _l, prev in out):
            out.append((label, b))
    return out


def _b64url_decode(s: str) -> bytes:
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


_ASYMMETRIC_ALGS = frozenset({
    "EdDSA", "Ed25519", "ES256", "ES384", "ES512", "ES256K",
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
})


def verify_with_jwk(alg: str, jwk: dict, signing_input: bytes, signature: bytes) -> bool:
    """Verify one JWS signature with a public JWK. Asymmetric algorithms only: ``none``
    and HMAC are refused (a card's key is public, so an HMAC "signature" proves nothing)."""
    if alg not in _ASYMMETRIC_ALGS or not isinstance(jwk, dict):
        return False
    if any(k in jwk for k in ("d", "p", "q", "k")):  # a private or symmetric key
        return False
    try:
        from jwt.algorithms import get_default_algorithms
        algs = get_default_algorithms()
        impl = algs.get("EdDSA" if alg == "Ed25519" else alg)
        if impl is None:
            return False
        key = impl.from_jwk(json.dumps(jwk))
        return bool(impl.verify(signing_input, key, signature))
    except Exception:  # noqa: BLE001
        return False


def _select_key(jwks: Any, kid: str | None, alg: str) -> dict | None:
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        return None
    keys = [k for k in keys if isinstance(k, dict)]
    if kid:
        match = [k for k in keys if k.get("kid") == kid]
        return match[0] if match else None
    return keys[0] if len(keys) == 1 else None


def check_signatures(card: dict, jwks_by_url: dict[str, Any]) -> dict:
    """The signature result for ``card`` given JWKS documents already fetched
    (``{jku: parsed JSON}``). Pure, so a verifier with the same inputs agrees.

    ``state`` is ``verified`` when one signature verifies against the key its ``jku``
    names, ``unverified`` when signatures exist but none does, ``absent`` otherwise."""
    sigs = card.get("signatures") if isinstance(card, dict) else None
    if not isinstance(sigs, list) or not sigs:
        return {"state": SIG_ABSENT, "count": 0}
    variants = signing_payload_variants(card)
    reasons: list[str] = []
    first: dict = {}
    for sig in [s for s in sigs if isinstance(s, dict)][:_MAX_SIGNATURES]:
        prot, value = sig.get("protected"), sig.get("signature")
        if not isinstance(prot, str) or not isinstance(value, str):
            reasons.append("a signature entry is missing its protected header or value")
            continue
        try:
            header = json.loads(_b64url_decode(prot))
            raw_sig = _b64url_decode(value)
        except Exception:  # noqa: BLE001
            reasons.append("a signature's protected header is not base64url JSON")
            continue
        if not isinstance(header, dict):
            reasons.append("a signature's protected header is not a JSON object")
            continue
        alg = str(header.get("alg") or "")
        kid = header.get("kid") if isinstance(header.get("kid"), str) else None
        jku = header.get("jku") if isinstance(header.get("jku"), str) else None
        info = {"alg": alg, "kid": kid, "jku": jku}
        first = first or info
        if alg not in _ASYMMETRIC_ALGS:
            reasons.append(f"algorithm {alg or 'missing'} is not an accepted signing algorithm")
            continue
        if not jku:
            reasons.append("the signature names no jku, so its key cannot be retrieved"
                           " from the agent's site")
            continue
        jwks = jwks_by_url.get(jku)
        if not isinstance(jwks, dict):
            reasons.append("the key set at its jku could not be fetched")
            continue
        jwk = _select_key(jwks, kid, alg)
        if jwk is None:
            reasons.append("no key in the jku key set matches its kid")
            continue
        for label, payload in variants:
            signing_input = prot.encode("ascii") + b"." + _b64url(payload).encode("ascii")
            if verify_with_jwk(alg, jwk, signing_input, raw_sig):
                return {"state": SIG_VERIFIED, "count": len(sigs), **info,
                        "variant": label, "jwk_thumbprint": _jwk_thumbprint(jwk)}
        reasons.append("the signature does not match the card under any canonical form")
    return {"state": SIG_UNVERIFIED, "count": len(sigs), **first,
            "reason": reasons[0] if reasons else "no usable signature entry"}


def _jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint (SHA-256, base64url) of a public JWK."""
    req = {"OKP": ("crv", "kty", "x"), "EC": ("crv", "kty", "x", "y"), "RSA": ("e", "kty", "n")}
    fields = req.get(str(jwk.get("kty")), ())
    body = {k: jwk[k] for k in fields if k in jwk}
    try:
        return _b64url(hashlib.sha256(rfc8785.dumps(body)).digest())
    except Exception:  # noqa: BLE001
        return ""


async def fetch_signature_keys(card: dict) -> dict[str, Any]:
    """Fetch each signature's ``jku`` (https only, SSRF-pinned, 64 KiB cap, at most
    two distinct URLs). A fetch that fails is simply absent from the map."""
    from src.ssrf import ssrf_safe_async_client, validate_url_https

    sigs = card.get("signatures") if isinstance(card, dict) else None
    urls: list[str] = []
    for sig in [s for s in (sigs or []) if isinstance(s, dict)][:_MAX_SIGNATURES]:
        try:
            header = json.loads(_b64url_decode(str(sig.get("protected") or "")))
        except Exception:  # noqa: BLE001
            continue
        jku = header.get("jku") if isinstance(header, dict) else None
        if isinstance(jku, str) and jku not in urls:
            urls.append(jku)
    out: dict[str, Any] = {}
    if not urls:
        return out
    try:
        async with ssrf_safe_async_client(timeout=8, follow_redirects=False) as client:
            for url in urls[:2]:
                try:
                    validate_url_https(url, field_name="jku")
                    async with client.stream("GET", url) as resp:
                        if resp.status_code != 200:
                            continue
                        buf = bytearray()
                        async for chunk in resp.aiter_bytes():
                            buf += chunk
                            if len(buf) > _MAX_JWKS_BYTES:
                                break
                        if len(buf) > _MAX_JWKS_BYTES:
                            continue
                    out[url] = json.loads(bytes(buf).decode("utf-8"))
                    out[url + "#sha256"] = _sha256(bytes(buf))
                except Exception:  # noqa: BLE001 — an unreachable key is "unverified"
                    continue
    except Exception:  # noqa: BLE001
        pass
    return out


async def verify_card_signature(card: dict) -> dict:
    """Fetch the keys and check the signatures. The result is pinned into the signed
    verdict (``jwks_digest`` names the exact key set that was used)."""
    sigs = card.get("signatures") if isinstance(card, dict) else None
    if not isinstance(sigs, list) or not sigs:
        return {"state": SIG_ABSENT, "count": 0}
    keys = await fetch_signature_keys(card)
    result = check_signatures(card, {k: v for k, v in keys.items() if "#sha256" not in k})
    jku = result.get("jku")
    if jku and keys.get(jku + "#sha256"):
        result["jwks_digest"] = keys[jku + "#sha256"]
    return result


# ── findings ─────────────────────────────────────────────────────────────────────

def _finding(category: str, name: str, severity: str, where: str, remediation: str = ""):
    from src.scanner.scan import Finding
    return Finding(category=category, name=name, severity=severity, file_path=where,
                   line_number=0, snippet="", remediation=remediation)


_LOC_UNSAFE = re.compile(r"[^A-Za-z0-9-]+")


def _loc(kind: str, index: int, ident: str = "") -> str:
    """``card:skill:3:route-optimizer``. The id is reduced to letters, digits and
    hyphens: a skill id must never shape the location into a path the scorer reads
    as a test or docs file (``tests/x``, ``a.test.js``), which is weighted down."""
    safe = _LOC_UNSAFE.sub("-", ident).strip("-")[:40]
    return f"card:{kind}:{index}" + (f":{safe}" if safe else "")


def _clip(s: str, n: int = 60) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _host(url: str) -> str:
    from src.scanner.mcp_icons import _host_of
    return _host_of(url)


TRUST_VERDICT_EXT_URI = "https://agentavow.com/ext/trust-verdict/v1"
_VERDICT_PATH = "/api/v1/public/scan/a2a"


def _card_identity(url: str) -> str | None:
    try:
        from src.ssrf import mcp_endpoint_identity
        return mcp_endpoint_identity(str(url).strip())
    except Exception:  # noqa: BLE001
        return None


def trust_verdict_url_ok(verdict_url: Any, card_url: str) -> bool:
    """``verdict_url`` is AgentAvow's verdict endpoint for exactly ``card_url``: https,
    host agentavow.com, path /api/v1/public/scan/a2a, one ``card`` query parameter that
    names the same card (after the same normalisation our A2A route applies)."""
    from urllib.parse import parse_qs
    if not isinstance(verdict_url, str) or not verdict_url.strip():
        return False
    try:
        parts = urlsplit(verdict_url.strip())
    except ValueError:
        return False
    if (parts.scheme != "https" or (parts.hostname or "").lower() != "agentavow.com"
            or parts.port not in (None, 443) or parts.username or parts.password
            or parts.path.rstrip("/") != _VERDICT_PATH or parts.fragment):
        return False
    q = parse_qs(parts.query, keep_blank_values=True)
    if set(q) != {"card"} or len(q["card"]) != 1:
        return False
    claimed, actual = _card_identity(q["card"][0]), _card_identity(card_url)
    return bool(claimed) and claimed == actual


def _url_findings(url: str, where: str, what: str, card_host: str) -> list:
    """Transport + private-host + origin findings for one URL the card tells a client
    to call (an interface, or an OAuth / OIDC / jku URL when ``what`` says so)."""
    from src.scanner.mcp_icons import _is_private_host, _same_site

    out: list = []
    u = url.strip()
    if not u:
        return out
    try:
        parts = urlsplit(u if "://" in u else "//" + u)
    except ValueError:
        return [_finding("insecure_transport", f"{what} URL cannot be parsed: {_clip(u)}",
                         "medium", where, "Publish a valid https:// URL.")]
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower().rstrip(".") if "://" in u or u.startswith("//") \
        else ""
    if not host:
        try:
            host = (urlsplit("//" + u).hostname or "").lower()
        except ValueError:
            host = ""
    if scheme in _PLAINTEXT_SCHEMES:
        out.append(_finding(
            "insecure_transport", f"{what} uses plain {scheme}:// ({_clip(u)})", "high",
            where, "Serve it over https (A2A 1.0 §13.4: production MUST use TLS). Tasks,"
                   " their data and any credentials the client sends travel in cleartext."))
    elif scheme == "grpc":
        out.append(_finding(
            "insecure_transport", f"{what} uses grpc:// with no TLS marker ({_clip(u)})",
            "medium", where, "Use a TLS gRPC endpoint and say so in the URL."))
    elif not scheme:
        out.append(_finding(
            "insecure_transport", f"{what} has no scheme, so TLS is not stated ({_clip(u)})",
            "low", where, "Give the full https:// URL."))
    elif scheme not in _SECURE_SCHEMES:
        out.append(_finding(
            "insecure_transport", f"{what} uses an unexpected scheme {scheme}://", "medium",
            where, "Interfaces should be https:// (or wss:// / TLS gRPC)."))
    if host and _is_private_host(host):
        out.append(_finding(
            "ssrf", f"{what} points at a private or local address ({host})", "high", where,
            "A public card must not send clients to loopback, private or link-local"
            " addresses: a client that follows it calls into its own network."))
    elif host and card_host and not _same_site(host, {card_host}):
        out.append(_finding(
            "endpoint_origin",
            f"{what} is on {host}, a different site from the card ({card_host})", "medium",
            where, "A client reads the card from one site and sends tasks to another."
                   " If that is intended, sign the card so the pairing is attested."))
    return out


def _auth_scheme_findings(name: str, s: dict, where: str, card_host: str) -> list:
    out: list = []
    kind = s.get("kind")
    if kind == "http" and s.get("scheme") == "basic":
        out.append(_finding(
            "auth_scheme", f"Scheme '{_clip(name, 40)}' is HTTP Basic auth", "medium", where,
            "Basic sends a reusable password with every request. Prefer OAuth 2 or a"
            " bearer token with a short life."))
    if kind == "apiKey" and s.get("location") == "query":
        out.append(_finding(
            "auth_scheme", f"Scheme '{_clip(name, 40)}' sends its API key in the URL query",
            "medium", where,
            "Keys in URLs end up in logs, proxies and browser history. Use a header."))
    if kind == "oauth2":
        for flow, urls in (s.get("flows") or {}).items():
            if flow in ("implicit", "password"):
                out.append(_finding(
                    "auth_scheme",
                    f"Scheme '{_clip(name, 40)}' uses the deprecated OAuth {flow} flow",
                    "medium", where,
                    "A2A 1.0 deprecates the implicit and password flows (OAuth 2.1 drops"
                    " them). Use authorization code with PKCE, or client credentials."))
            for k, u in urls.items():
                out.extend(f for f in _url_findings(u, where, f"OAuth {k}", "")
                           if f.category != "endpoint_origin")
        if s.get("metadataUrl"):
            out.extend(f for f in _url_findings(s["metadataUrl"], where, "OAuth metadata URL",
                                                "") if f.category != "endpoint_origin")
    if kind == "openIdConnect" and s.get("openIdConnectUrl"):
        out.extend(f for f in _url_findings(s["openIdConnectUrl"], where, "OpenID Connect URL",
                                            "") if f.category != "endpoint_origin")
    return out


def _sensitive_caps(skill: dict) -> set[str]:
    from src.scanner.mcp_scan import _affirmed, _classify_tool
    text = f"{skill.get('description', '')}\n" + "\n".join(skill.get("tags") or [])
    caps = _classify_tool(skill.get("name") or skill.get("id") or "", text)
    if _affirmed(_PAYMENTS, f"{skill.get('name', '')}. {text}"):
        caps = caps | {"payments"}
    return caps


class _TextBatch:
    """Every agent-facing text on the card, read by the metadata injection matcher in
    ONE ``_scan_content`` pass (its fixed cost per call is ~1 ms, and a 1 MiB card holds
    thousands of texts), then mapped back to where each line came from. Fields are
    separated by a blank line so a match cannot span two of them. The encoded-instruction
    decoder runs per text (its own budget bounds it)."""

    def __init__(self, budget) -> None:
        self.budget = budget
        self.lines: list[str] = []
        self.where_by_line: list[str] = []  # 1-based line -> location ("" = separator)
        self.encoded: list = []

    def add(self, text: str, where: str) -> None:
        from src.scanner.encoded_instructions import scan_text
        if not isinstance(text, str) or not text.strip():
            return
        for ln in text.split("\n"):
            self.lines.append(ln)
            self.where_by_line.append(where)
        self.lines.append("")
        self.where_by_line.append("")
        self.encoded.extend(scan_text(text, where, self.budget, lines=False))

    def findings(self) -> list:
        from src.scanner.scan import _scan_content
        if not self.lines:
            return list(self.encoded)
        try:
            found, _pos, _sup = _scan_content("\n".join(self.lines), "card",
                                              metadata_text=True)
        except Exception:  # noqa: BLE001 — a matcher bug must not fail the scan
            found = []
        out = []
        seen: set[tuple[str, str]] = set()
        for f in found:
            if f.category not in ("prompt_injection", "hidden_unicode"):
                continue
            i = (f.line_number or 1) - 1
            where = self.where_by_line[i] if 0 <= i < len(self.where_by_line) else ""
            if not where or (f.name, where) in seen:
                continue
            seen.add((f.name, where))
            f.file_path, f.line_number = where, 0
            out.append(f)
        return out + list(self.encoded)


def analyze_a2a_card(raw: dict, *, card_url: str, signature: dict | None = None
                     ) -> A2aScanResult:
    """Findings for one Agent Card. Pure and deterministic given its inputs."""
    from src.scanner.encoded_instructions import Budget
    from src.source_import.a2a_fetcher import parse_agent_card

    card = parse_agent_card(raw)
    res = A2aScanResult(card=card, skill_count=card["skill_count"],
                        interface_count=len(card["interfaces"]))
    card_host = _host(card_url)
    budget = Budget()
    texts = _TextBatch(budget)

    # 1. interfaces
    seen_urls: set[str] = set()
    for idx, iface in enumerate(card["interfaces"]):
        url = iface["url"]
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        label = "Interface" + (f" ({iface['binding']})" if iface["binding"] else "")
        res.findings.extend(_url_findings(url, _loc("interface", idx, iface["binding"]),
                                          label, card_host))
    if not seen_urls:
        res.findings.append(_finding(
            "endpoint_origin", "The card declares no interface URL", "low", "card:interfaces",
            "A2A 1.0 requires supportedInterfaces; a client has nowhere to send tasks."))

    # 2. auth
    schemes: dict[str, dict] = card["security_schemes"]
    reqs = card["security_requirements"]
    for name, s in schemes.items():
        res.findings.extend(_auth_scheme_findings(
            name, s, _loc("security", 0, name), card_host))
        if s.get("description"):
            texts.add(s["description"], _loc("security", 0, name))
    referenced = {n for r in reqs for n in r} | {
        n for sk in card["skills"] for r in sk["security_requirements"] for n in r}
    for n in sorted(referenced - set(schemes)):
        res.findings.append(_finding(
            "auth_scheme", f"A security requirement names '{_clip(n, 40)}', which the card"
                           " does not declare", "medium", "card:security",
            "Every scheme a requirement names must be declared in securitySchemes, or a"
            " client cannot tell what to send."))
    card_has_auth = bool(schemes) or bool(reqs)
    if card["capabilities"]["extended_agent_card"] and not schemes:
        res.findings.append(_finding(
            "auth_scheme", "The card offers an extended card but declares no auth scheme",
            "medium", "card:capabilities",
            "A2A 1.0 §13.3: the extended card MUST require authentication with a scheme"
            " declared in the public card."))

    # 3. skills: capabilities, auth on sensitive skills, injected text
    cap_counts: dict[str, int] = {}
    open_sensitive: list[tuple[dict, set[str]]] = []
    for idx, sk in enumerate(card["skills"]):
        where = _loc("skill", idx, sk["id"])
        caps = _sensitive_caps(sk)
        for c in caps:
            cap_counts[c] = cap_counts.get(c, 0) + 1
        authed = card_has_auth or sk["declares_security"]
        sensitive = caps & (_SENSITIVE_CAPS | {"payments"})
        if sensitive and not authed:
            open_sensitive.append((sk, sensitive))
        res.skills.append({
            "id": sk["id"], "name": sk["name"], "description": _clip(sk["description"], 240),
            "tags": sk["tags"][:10], "capabilities": sorted(caps),
            "authenticated": authed,
        })
        # Every skill and every example is read: a cap here is a place to hide the
        # payload (pad 25 noisy skills, put it in the 26th). The 1 MiB card cap and the
        # decode budget bound the cost.
        texts.add(f"{sk['name']}\n{sk['description']}", where)
        if sk["tags"]:
            texts.add(" ".join(sk["tags"]), where + ":tags")
        for n, ex in enumerate(sk["examples"]):
            texts.add(ex, f"{where}:example:{n}")
    if open_sensitive:
        sk, caps = open_sensitive[0]
        what = ", ".join(_CAP_PHRASE[c] for c in sorted(caps) if c in _CAP_PHRASE)
        more = f" (and {len(open_sensitive) - 1} more)" if len(open_sensitive) > 1 else ""
        res.findings.append(_finding(
            "auth_scheme",
            f"Skill '{_clip(sk['name'] or sk['id'], 40)}' says it can {what}, and the card"
            f" declares no authentication{more}", "high",
            _loc("skill", card["skills"].index(sk), sk["id"]),
            "Declare a security scheme and require it, on the card or on the skill: as"
            " published, anyone who can reach the agent can ask it to do this."))
    elif not card_has_auth and not any(sk["declares_security"] for sk in card["skills"]):
        res.findings.append(_finding(
            "auth_scheme", "The card declares no authentication", "low", "card:security",
            "Fine for a public read-only agent; declare a scheme before it does more."))

    # 3b. the AgentAvow trust-verdict extension (https://agentavow.com/ext/trust-verdict/v1):
    # a card that declares it must point at OUR verdict for THIS card. Anything else is
    # a borrowed or forged claim.
    for idx, ext in enumerate(card["capabilities"]["extensions"]):
        if ext.get("uri") != TRUST_VERDICT_EXT_URI:
            continue
        ok = trust_verdict_url_ok((ext.get("params") or {}).get("verdict_url"), card_url)
        if ok:
            res.positive_signals.append("The card links its own AgentAvow verdict")
        else:
            res.findings.append(_finding(
                "card_signature",
                "The card claims an AgentAvow verdict that is not this card's own",
                "medium", _loc("extension", idx),
                "The trust-verdict extension's verdict_url must be "
                "https://agentavow.com/api/v1/public/scan/a2a?card=<this card's URL>. "
                "A verdict for another card, or from another host, says nothing about "
                "this one."))

    # 4. card-level text an agent reads
    texts.add(f"{card['name']}\n{card['description']}", "card:description")
    for idx, ext in enumerate(card["capabilities"]["extensions"]):
        if ext["description"]:
            texts.add(ext["description"], _loc("extension", idx))
    res.findings.extend(texts.findings())

    # 5. the card's signature (pinned input)
    sig = signature or {"state": SIG_ABSENT, "count": 0}
    if sig.get("state") == SIG_UNVERIFIED:
        res.findings.append(_finding(
            "card_signature",
            "The card is signed, but the signature could not be verified: "
            + _clip(str(sig.get("reason") or "no usable signature"), 90), "medium",
            "card:signatures",
            "Publish the signing key at the jku the signature names, and sign the card's"
            " RFC 8785 form with the signatures field removed (A2A 1.0 §8.4)."))
        res.coverage_gaps[SIGNATURE_UNVERIFIED_GAP] = 1
    elif sig.get("state") == SIG_VERIFIED:
        res.positive_signals.append("Agent card signature verifies")
    else:
        # Most published cards are unsigned (48 of 55 in the 2026-11-07 sample), and
        # A2A 1.0 makes signing optional: a note only, never a score or decision input.
        res.findings.append(_finding(
            "card_signature", "The card is not signed", "info", "card:signatures",
            "Signing the card (A2A 1.0 §8.4) lets a client check it was not altered"
            " between your site and theirs."))

    res.coverage_gaps.update(budget.gaps())
    res.capabilities = cap_counts
    res.auth = {
        "schemes": {n: s.get("kind") for n, s in schemes.items()},
        "card_requires_auth": bool(reqs),
        "skills_with_own_requirements": sum(1 for s in card["skills"]
                                            if s["declares_security"]),
    }
    return res


# ── the scan ─────────────────────────────────────────────────────────────────────

A2A_FETCH_ERROR = ("Could not read an A2A Agent Card there. Give the card URL (for"
                   " example https://agent.example.com/.well-known/agent-card.json) or"
                   " the agent's base URL.")


async def scan_a2a(card_url: str):
    """Grade the A2A Agent Card at ``card_url`` (or at an agent base URL). Returns a
    ``ScanResult`` with ``.error`` set when no card could be read."""
    from src.scanner.coverage import SCAN_DEPTH_ARTIFACT_LIVE, build_coverage
    from src.scanner.scan import (
        ScanResult,
        _calculate_category_scores,
        _calculate_trust_score,
        _certified_status,
        _compute_manifest_digest,
    )
    from src.source_import.a2a_fetcher import fetch_agent_card
    from src.source_import.errors import SourceFetchError, SourceParseError

    result = ScanResult(repo=f"a2a:{card_url}", stars=0, description="", framework="a2a")
    try:
        fetched = await fetch_agent_card(card_url, https_only=True)
    except (SourceFetchError, SourceParseError) as exc:
        logger.info("A2A card fetch failed for %s: %s", card_url, exc)
        result.error = A2A_FETCH_ERROR
        return result
    raw = fetched.card
    if not isinstance(raw.get("name"), str) or not raw.get("name"):
        result.error = "That JSON is not an A2A Agent Card (it has no name)."
        return result

    signature = await verify_card_signature(raw)
    # CPU-bound on a large card (up to 1 MiB of text): off the event loop.
    import asyncio
    a2a = await asyncio.to_thread(
        analyze_a2a_card, raw, card_url=fetched.url, signature=signature)
    card = a2a.card

    result.findings = a2a.findings
    result.positive_signals.extend(a2a.positive_signals)
    result.tool_digests = compute_card_digests(raw)
    result.tool_manifest_digest = _compute_manifest_digest(result.tool_digests)
    result.files_scanned = a2a.skill_count
    result.total_scannable_files = a2a.skill_count
    result.primary_language = "A2A"
    n = a2a.skill_count
    name = card["name"].strip()
    result.description = f"{name} — A2A agent · {n} skill{'' if n == 1 else 's'}"
    result.a2a_card = {
        "url": fetched.url,
        "requestedUrl": fetched.requested_url,
        "legacyPath": fetched.legacy_path,
        "profile": A2A_CARD_DIGEST_PROFILE,
        "digest": result.tool_digests["card"],
        "signature": signature,
    }
    result.artifact_scan = {
        "surface": "a2a", "agent_name": name, "card_url": fetched.url,
        "legacy_path": fetched.legacy_path, "card_shape": card["shape"],
        "protocol_version": card["protocol_version"], "version": card["version"],
        "provider": card["provider"], "documentation_url": card["documentation_url"],
        "skill_count": n, "interface_count": a2a.interface_count,
        "interfaces": [{"url": i["url"], "binding": i["binding"]}
                       for i in card["interfaces"][:20]],
        "capabilities": a2a.capabilities,
        "streaming": card["capabilities"]["streaming"],
        "push_notifications": card["capabilities"]["push_notifications"],
        "extended_agent_card": card["capabilities"]["extended_agent_card"],
        "extensions": [{"uri": e["uri"], "required": e["required"]}
                       for e in card["capabilities"]["extensions"][:20]],
        "auth": a2a.auth,
        "skills": a2a.skills[:100],
        "signature": {k: v for k, v in signature.items()
                      if k in ("state", "count", "alg", "kid", "jku", "variant", "reason")},
        "card_digest": result.tool_digests["card"],
    }
    result.coverage = build_coverage(
        surface="a2a", scan_depth=SCAN_DEPTH_ARTIFACT_LIVE, live_observed=True)
    result.coverage_gaps = dict(a2a.coverage_gaps)
    result.trust_score = _calculate_trust_score(result)
    result.category_scores = _calculate_category_scores(result)
    result.certified = _certified_status(result)
    return result
