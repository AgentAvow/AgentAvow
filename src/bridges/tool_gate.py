"""Tool-call gate on the AgentAvow grade — the framework-agnostic core.

Before an agent runs a tool from an MCP server (or a package / repo it maps to),
look up the server's signed grade on AgentAvow and decide:

* **allow** — the tool's answer is Safe to connect (``fail_on="review"``, the
  default; ``fail_on="do_not_connect"`` also allows Review before you connect),
  the score is at or above ``min_score`` (default 51, the floor of Safe to
  connect), no finding carries a ``block_on`` severity (default critical / high),
  and — for a live MCP server — the definition the agent was served for this
  tool recomputes to the per-tool digest signed into the attestation.
* **fail** — anything else: an answer at or past ``fail_on``, a low score, a
  blocking finding, a definition that drifted since the grade (the rug-pull), a
  tool the grade never saw, or — when ``fail_closed`` is on (the default) — an
  AgentAvow API that could not answer.

Every message leads with the tool's three-phrase decision — "Safe to connect",
"Review before you connect" or "Do not connect" — and its one reason, read from the
API's ``decision`` / ``decision_reason`` (decided locally by the same rule when an older
response lacks them); the score and tier follow as evidence, and
``GateDecision.decision`` carries the value.

What a *fail* does is the framework adapter's job (``on_fail``: block, confirm,
warn or raise); this module only produces the :class:`GateDecision`. The
LangChain middleware (``src.bridges.langchain.middleware``) and the Google ADK
callback (``src.bridges.google_adk.gate``) are thin layers over :class:`ToolGate`.

This is client-side library code: it depends only on ``httpx``. The per-tool
digest is derived exactly as the attestation signs it
(``docs/standards/tool-manifest-digest-vectors-v1``): the server-side
implementation (``src.scanner.mcp_scan``) is used when importable, else the
pure-stdlib copy below, which is byte-identical to the Claude Code plugin gate's.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx

__version__ = "0.1.0"

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://agentavow.com/api/v1"
DEFAULT_MIN_SCORE = 51  # the floor of Safe to connect (81, Trusted, is the strict choice)
DEFAULT_FAIL_ON = "review"  # fail on Review before you connect or worse
FAIL_ON_MODES = ("review", "do_not_connect", "none")
DEFAULT_BLOCK_ON = ("critical", "high")
DEFAULT_CACHE_TTL = 3600.0  # the API caches a verdict for an hour
DEFAULT_TIMEOUT = 10.0
MAX_REDIRECTS = 3
WEB = "https://agentavow.com"
ON_FAIL_MODES = ("block", "confirm", "warn", "raise")
PACKAGE_SURFACES = ("npm", "pypi", "crates", "docker", "huggingface")

# Score floor of each tier (src/api/public_scan_router.py TRUST_TIERS).
TIER_FLOORS = {
    "blocked": 0, "restricted": 11, "minimal": 31, "standard": 51, "trusted": 81, "verified": 96,
}


# ── the per-tool digest, exactly as the attestation signs it ──────────────────

PROFILE = "agentavow.mcp-tool-definition.v1"
DIGEST_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
_MAX_SAFE_INT = 2**53 - 1
_MAX_KEY_NAME = 128
_MAX_TOOL_DIGESTS = 500  # beyond this the signed map is folded; the gate cannot compare


class UnhashableError(Exception):
    """A definition RFC 8785 cannot represent the way this gate implements it (a
    non-integer number, an integer beyond 2^53, a value that is not JSON)."""


# ── RFC 8785 (JCS) for JSON that came from json.loads ────────────────────────


def jcs(value: object) -> str:
    """Canonical JSON per RFC 8785: keys sorted by UTF-16 code units, no whitespace,
    strings escaped as JSON.stringify does, non-ASCII kept literal. Integers print
    as digits; an integral float prints as its integer (as ES6 does). Any other
    number raises UnhashableError rather than risk a digest that differs from the
    issuer's."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise UnhashableError("integer beyond 2^53")
        return str(value)
    if isinstance(value, float):
        if value.is_integer() and abs(value) <= _MAX_SAFE_INT:
            return str(int(value))  # 1.0 -> "1", -0.0 -> "0"
        raise UnhashableError("non-integer number")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise UnhashableError("non-string key")
        keys = sorted(value, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + jcs(value[k]) for k in keys) + "}"
    raise UnhashableError(type(value).__name__)


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def tool_key(name: str) -> str:
    """`tool:<name>`: everything outside printable ASCII, plus % and =, is
    percent-encoded as UTF-8 bytes; an overlong key is cut and suffixed."""
    out = []
    for ch in name:
        if "\x21" <= ch <= "\x7e" and ch not in "%=":
            out.append(ch)
        else:
            out.extend(f"%{b:02X}" for b in ch.encode("utf-8", "surrogatepass"))
    enc = "".join(out)
    if len(enc) > _MAX_KEY_NAME:
        enc = enc[:96] + "~" + hashlib.sha256(
            name.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return "tool:" + enc


def tool_digest(tool: dict) -> str:
    """`sha256:<hex>` over JCS({"profile": PROFILE, "tool": <restricted definition>}).
    A missing or null field is omitted; _meta and unknown fields are never hashed."""
    body = {f: tool[f] for f in DIGEST_FIELDS if tool.get(f) is not None}
    return _sha256(jcs({"profile": PROFILE, "tool": body}))


try:  # the issuer's own derivation, when this runs next to the server code
    from src.scanner.mcp_scan import tool_definition_digest as _issuer_tool_digest
    from src.scanner.mcp_scan import tool_digest_key as _issuer_tool_key
except Exception:  # pragma: no cover - depends on the install
    _issuer_tool_digest = None
    _issuer_tool_key = None


def served_tool_digest(definition: dict) -> str | None:
    """Digest of a served tool definition, or None when it cannot be hashed the
    way the issuer hashes it (then drift is not evaluated, and the gate says so)."""
    if _issuer_tool_digest is not None:
        try:
            return _issuer_tool_digest(definition)
        except Exception:
            return None
    try:
        return tool_digest(definition)
    except UnhashableError:
        return None


def served_tool_key(name: str) -> str:
    if _issuer_tool_key is not None:
        try:
            return _issuer_tool_key(name)
        except Exception:
            pass
    return tool_key(name)


# ── coordinates ───────────────────────────────────────────────────────────────


def parse_coordinate(server: str) -> tuple[str, str]:
    """``(kind, target)`` for a server coordinate.

    Accepted: an ``https://`` (or ``http://``) MCP endpoint, ``mcp:<url>``,
    ``owner/repo`` or ``github:owner/repo``, and ``<surface>:<name>`` for
    npm / pypi / crates / docker / huggingface packages.
    """
    s = (server or "").strip()
    if not s:
        raise ValueError("empty server coordinate")
    low = s.lower()
    if low.startswith(("https://", "http://")):
        return "mcp", s
    if low.startswith("mcp:"):
        return "mcp", s[4:].strip()
    if low.startswith("github:"):
        return "github", s[7:].strip().strip("/")
    for surface in PACKAGE_SURFACES:
        if low.startswith(surface + ":"):
            return surface, s[len(surface) + 1:].strip()
    if s.count("/") == 1 and ":" not in s:
        return "github", s.strip("/")
    raise ValueError(f"unrecognized server coordinate: {server!r}")


def grade_url(base_url: str, server: str) -> str:
    """The public scan URL that grades ``server`` (no auth needed)."""
    kind, target = parse_coordinate(server)
    base = base_url.rstrip("/")
    if kind == "mcp":
        return f"{base}/public/scan/mcp?endpoint={urllib.parse.quote(target, safe='')}"
    if kind == "github":
        return f"{base}/public/scan/{target}"
    return f"{base}/public/scan/package/{kind}/{urllib.parse.quote(target, safe='/@')}"


def report_url(server: str) -> str:
    try:
        kind, target = parse_coordinate(server)
    except ValueError:
        return f"{WEB}/check"
    if kind == "mcp":
        return f"{WEB}/check/mcp?endpoint={urllib.parse.quote(target, safe='')}"
    if kind == "github":
        return f"{WEB}/check/{target}"
    return f"{WEB}/check/pkg/{kind}/{target}"


def is_mcp(server: str) -> bool:
    try:
        return parse_coordinate(server)[0] == "mcp"
    except ValueError:
        return False


# ── grade and decision ────────────────────────────────────────────────────────


@dataclass
class Grade:
    """What the gate needs from one public scan response."""

    server: str
    score: int | None = None
    tier: str = ""
    critical: int = 0
    high: int = 0
    findings: list[dict] = field(default_factory=list)
    tool_digests: dict[str, str] = field(default_factory=dict)
    report_url: str = ""
    jws: str | None = None
    fetched_at: float = 0.0
    error: str | None = None  # set when AgentAvow could not answer
    # The three-phrase decision: safe | review | do_not_connect (+ reason, final).
    decision: str = ""
    decision_reason: str = ""
    decision_final: bool = True
    certified: bool = False

    @classmethod
    def from_response(cls, server: str, data: dict) -> Grade:
        findings = data.get("findings") or {}
        items = findings.get("items") if isinstance(findings, dict) else findings
        items = [f for f in (items or []) if isinstance(f, dict)]
        sev = [str(f.get("severity", "")).lower() for f in items]
        crit = int(findings.get("critical", 0) or 0) if isinstance(findings, dict) else 0
        high = int(findings.get("high", 0) or 0) if isinstance(findings, dict) else 0
        score = data.get("trust_score")
        dec, dec_reason, dec_final = _decision_of(data)
        return cls(
            decision=dec, decision_reason=dec_reason, decision_final=dec_final,
            certified=_certified_mark_of(data),
            server=server,
            score=int(score) if isinstance(score, (int, float)) else None,
            tier=str(data.get("trust_tier") or ""),
            critical=max(crit, sev.count("critical")),
            high=max(high, sev.count("high")),
            findings=items,
            tool_digests={
                str(k): str(v) for k, v in (data.get("tool_digests") or {}).items()},
            report_url=report_url(server),
            jws=data.get("jws"),
            fetched_at=time.time(),
        )

    def blocking_findings(self, block_on: Iterable[str]) -> list[str]:
        """The severities in ``block_on`` that the grade carries, in that order."""
        counts = {"critical": self.critical, "high": self.high}
        for f in self.findings:
            s = str(f.get("severity", "")).lower()
            if s not in counts:
                counts[s] = counts.get(s, 0) + 1
        return [s for s in block_on if counts.get(str(s).lower(), 0) > 0]


@dataclass
class GateDecision:
    """The gate's verdict for one tool call."""

    allow: bool
    # allow | low_score | finding | decision | drift | unknown_tool | api_error | unmapped
    outcome: str
    reason: str
    tool_name: str
    server: str | None
    grade: Grade | None = None
    served_digest: str | None = None
    signed_digest: str | None = None
    # ``warnings`` carries what the gate could not evaluate (e.g. no served
    # definition to compare) and, for a fail-open API error, why it still allowed.
    warnings: list[str] = field(default_factory=list)

    @property
    def decision(self) -> str:
        """The tool's three-phrase decision (safe | review | do_not_connect), or ""
        when there is no grade to read it from."""
        return self.grade.decision if self.grade is not None else ""

    def as_dict(self) -> dict:
        d = asdict(self)
        d["decision"] = self.decision
        if self.grade is not None:
            d["grade"] = {
                "server": self.grade.server, "score": self.grade.score,
                "tier": self.grade.tier, "critical": self.grade.critical,
                "high": self.grade.high, "report_url": self.grade.report_url,
                "error": self.grade.error, "decision": self.grade.decision,
                "decision_reason": self.grade.decision_reason,
                "decision_final": self.grade.decision_final,
                "certified": self.grade.certified,
            }
        return d


class ToolGateBlockedError(Exception):
    """Raised instead of returning a block message when ``on_fail="raise"``."""

    def __init__(self, decision: GateDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


# The three headline phrases (src/trust_tiers.py DECISIONS; pinned by
# tests/test_trust_tiers.py). Kept inline: this module depends only on httpx.
DECISION_PHRASES = {
    "safe": "Safe to connect",
    "review": "Review before you connect",
    "do_not_connect": "Do not connect",
}


def _certified_mark_of(data: dict) -> bool:
    """The Certified MARK from a public scan response: the API's ``certified_mark``,
    else the shared display rule when importable, else no mark (fail closed). Never
    the raw ``certified.eligible`` provenance gate, which can sit beside Review."""
    mark = data.get("certified_mark")
    if isinstance(mark, bool):
        return mark
    try:
        from src.scanner.verdict import certified_mark
    except Exception:  # noqa: BLE001 — standalone install: no local rule
        return False
    return certified_mark(data)


def _decision_of(data: dict) -> tuple[str, str, bool]:
    """(decision, reason, final) from a public scan response: the API's own fields,
    else the shared rule (``src.scanner.verdict.decide``) when importable, else ""."""
    dec = data.get("decision")
    if isinstance(dec, str) and dec in DECISION_PHRASES:
        return dec, str(data.get("decision_reason") or ""), data.get("decision_final") is not False
    try:
        from src.scanner.verdict import decide
    except Exception:  # noqa: BLE001 — standalone install: no local rule
        return "", "", True
    d = decide(data)
    return d.decision, d.reason, d.final


def _score_text(grade: Grade) -> str:
    """"Review before you connect (one high finding: …) · 85/100, tier trusted"."""
    if grade.score is None:
        return "no score"
    tier = f", tier {grade.tier}" if grade.tier else ""
    lead = ""
    if grade.decision in DECISION_PHRASES:
        lead = DECISION_PHRASES[grade.decision] + (" · Certified" if grade.certified else "")
        if grade.decision_reason:
            lead += f" ({grade.decision_reason})"
        lead += " · "
    return f"{lead}{grade.score}/100{tier}"


def evaluate(
    tool_name: str,
    server: str,
    grade: Grade,
    *,
    min_score: int = DEFAULT_MIN_SCORE,
    block_on: Iterable[str] = DEFAULT_BLOCK_ON,
    fail_closed: bool = True,
    served_definition: dict | None = None,
    fail_on: str = DEFAULT_FAIL_ON,
) -> GateDecision:
    """Pure policy: grade + optional served definition -> decision. No I/O."""
    report = grade.report_url or report_url(server)
    if grade.error:
        reason = (f"AgentAvow could not grade {server} ({grade.error}); "
                  f"'{tool_name}' was {'not run' if fail_closed else 'run unchecked'}. "
                  f"Report: {report}")
        d = GateDecision(not fail_closed, "api_error", reason, tool_name, server, grade)
        if not fail_closed:
            d.warnings.append(reason)
        return d
    if grade.score is None or grade.score < min_score:
        return GateDecision(
            False, "low_score",
            f"AgentAvow blocked '{tool_name}' on {server}: graded {_score_text(grade)}, "
            f"below the floor of {min_score}. Not run. Report: {report}",
            tool_name, server, grade)
    hits = grade.blocking_findings(block_on)
    if hits:
        return GateDecision(
            False, "finding",
            f"AgentAvow blocked '{tool_name}' on {server}: the grade "
            f"({_score_text(grade)}) carries {' and '.join(hits)} findings. Not run. "
            f"Report: {report}",
            tool_name, server, grade)
    failing = {"review": ("review", "do_not_connect"),
               "do_not_connect": ("do_not_connect",)}.get(fail_on, ())
    if grade.decision in failing:
        return GateDecision(
            False, "decision",
            f"AgentAvow blocked '{tool_name}' on {server}: {_score_text(grade)}. "
            f"Not run. Report: {report}",
            tool_name, server, grade)

    decision = GateDecision(True, "allow", f"AgentAvow: {server} graded {_score_text(grade)}; "
                            f"'{tool_name}' allowed.", tool_name, server, grade)
    signed_map = grade.tool_digests
    if served_definition is None:
        if signed_map:
            decision.warnings.append(
                f"no served definition for '{tool_name}' was available; drift not checked")
        return decision
    if not signed_map:
        decision.warnings.append(
            f"the grade for {server} carries no signed tool digests; drift not checked")
        return decision
    if len(signed_map) > _MAX_TOOL_DIGESTS:
        decision.warnings.append("the signed digest map is folded (too many tools); "
                                 "drift not checked")
        return decision
    served = served_tool_digest(served_definition)
    decision.served_digest = served
    if served is None:
        decision.warnings.append(
            f"the definition of '{tool_name}' uses a number form the gate cannot "
            "canonicalize; drift not checked")
        return decision
    key = served_tool_key(str(served_definition.get("name") or tool_name))
    signed = signed_map.get(key)
    decision.signed_digest = signed
    if signed is None:
        return GateDecision(
            False, "unknown_tool",
            f"AgentAvow blocked '{tool_name}' on {server}: it was not among the tools "
            f"AgentAvow graded ({_score_text(grade)}); the server added it since. Not run. "
            f"Report: {report}",
            tool_name, server, grade, served, None)
    if signed != served:
        return GateDecision(
            False, "drift",
            f"AgentAvow blocked '{tool_name}' on {server}: its definition changed since "
            f"AgentAvow graded this server ({_score_text(grade)}) — signed {signed[:19]}…, "
            f"served {served[:19]}…. Not run. Report: {report}",
            tool_name, server, grade, served, signed)
    decision.reason += " Definition matches the signed digest."
    return decision


# ── HTTP: the grade, and a server's own tools/list ────────────────────────────


def _user_agent() -> str:
    return f"agentavow-tool-gate/{__version__} (python)"


def _redirect_target(resp: httpx.Response) -> str | None:
    """Where a redirect points, if the gate may follow it: https only."""
    if resp.status_code not in (301, 302, 303, 307, 308):
        return None
    loc = resp.headers.get("location")
    if not loc:
        raise httpx.HTTPStatusError("redirect without Location", request=resp.request,
                                    response=resp)
    target = urllib.parse.urljoin(str(resp.request.url), loc)
    if not target.lower().startswith("https://"):
        raise httpx.HTTPStatusError(
            f"refusing redirect to non-https URL {target}", request=resp.request, response=resp)
    return target


def _parse_rpc_text(text: str, want_id: int) -> dict | None:
    """The JSON-RPC reply to ``want_id`` from a JSON body or an SSE body."""
    text = text.strip()
    if text.startswith("{"):
        try:
            doc = json.loads(text)
        except ValueError:
            return None
        return doc if isinstance(doc, dict) else None
    return _rpc_lines_reply(text.splitlines(), want_id)


def _rpc_lines_reply(lines: Iterable[str], want_id: int) -> dict | None:
    """The JSON-RPC reply to ``want_id`` from SSE lines, left as soon as it arrives
    so a server that keeps the stream open cannot hold the gate past its timeout."""
    for raw in lines:
        line = raw.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload.startswith("{"):
            continue
        try:
            doc = json.loads(payload)
        except ValueError:
            continue
        if isinstance(doc, dict) and ("result" in doc or "error" in doc) and (
                doc.get("id") in (want_id, None)):
            return doc
    return None


_MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}
_INIT_BODY = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "agentavow-tool-gate", "version": __version__}},
}
_LIST_BODY = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}


class TrustGateClient:
    """Fetches grades (and, for drift, a server's own ``tools/list``) with a TTL cache.

    Sync and async paths share the cache. ``transport`` is for tests
    (``httpx.MockTransport``); redirects are followed only to ``https://``.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        cache_ttl: float = DEFAULT_CACHE_TTL,
        transport: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._transport = transport
        self._headers = {"User-Agent": _user_agent(), "Accept": "application/json"}
        if headers:
            self._headers.update(headers)
        self._grades: dict[str, tuple[float, Grade]] = {}
        self._served: dict[str, tuple[float, list[dict] | None]] = {}

    # cache ---------------------------------------------------------------

    def _cached_grade(self, server: str) -> Grade | None:
        hit = self._grades.get(server)
        if hit and hit[0] > time.monotonic():
            return hit[1]
        return None

    def _store_grade(self, server: str, grade: Grade) -> Grade:
        ttl = self.cache_ttl if grade.error is None else min(self.cache_ttl, 30.0)
        self._grades[server] = (time.monotonic() + ttl, grade)
        return grade

    def clear_cache(self) -> None:
        self._grades.clear()
        self._served.clear()

    # clients -------------------------------------------------------------

    def _client_kwargs(self) -> dict:
        kw: dict[str, Any] = {"timeout": self.timeout, "follow_redirects": False,
                              "headers": self._headers}
        if self._transport is not None:
            kw["transport"] = self._transport
        return kw

    def _get(self, client: httpx.Client, url: str) -> httpx.Response:
        for _ in range(MAX_REDIRECTS + 1):
            resp = client.get(url)
            nxt = _redirect_target(resp)
            if nxt is None:
                return resp
            url = nxt
        raise httpx.HTTPStatusError("too many redirects", request=resp.request, response=resp)

    async def _aget(self, client: httpx.AsyncClient, url: str) -> httpx.Response:
        for _ in range(MAX_REDIRECTS + 1):
            resp = await client.get(url)
            nxt = _redirect_target(resp)
            if nxt is None:
                return resp
            url = nxt
        raise httpx.HTTPStatusError("too many redirects", request=resp.request, response=resp)

    @staticmethod
    def _grade_from(server: str, resp: httpx.Response) -> Grade:
        if resp.status_code != 200:
            detail = ""
            try:
                body = resp.json()
                detail = str(body.get("detail") or body.get("error") or "")[:160]
            except Exception:
                pass
            return Grade(server=server, report_url=report_url(server), fetched_at=time.time(),
                         error=f"HTTP {resp.status_code}" + (f": {detail}" if detail else ""))
        try:
            data = resp.json()
        except ValueError:
            return Grade(server=server, report_url=report_url(server), fetched_at=time.time(),
                         error="non-JSON response")
        if not isinstance(data, dict):
            return Grade(server=server, report_url=report_url(server), fetched_at=time.time(),
                         error="unexpected response shape")
        return Grade.from_response(server, data)

    # grades --------------------------------------------------------------

    def grade(self, server: str, *, force: bool = False) -> Grade:
        if not force:
            hit = self._cached_grade(server)
            if hit is not None:
                return hit
        try:
            url = grade_url(self.base_url, server)
        except ValueError as e:
            return self._store_grade(server, Grade(server=server, error=str(e)))
        try:
            with httpx.Client(**self._client_kwargs()) as client:
                resp = self._get(client, url)
            grade = self._grade_from(server, resp)
        except Exception as e:  # network, TLS, redirect policy, timeout
            grade = Grade(server=server, report_url=report_url(server), fetched_at=time.time(),
                          error=f"{type(e).__name__}: {str(e)[:160]}")
        return self._store_grade(server, grade)

    async def agrade(self, server: str, *, force: bool = False) -> Grade:
        if not force:
            hit = self._cached_grade(server)
            if hit is not None:
                return hit
        try:
            url = grade_url(self.base_url, server)
        except ValueError as e:
            return self._store_grade(server, Grade(server=server, error=str(e)))
        try:
            async with httpx.AsyncClient(**self._client_kwargs()) as client:
                resp = await self._aget(client, url)
            grade = self._grade_from(server, resp)
        except Exception as e:
            grade = Grade(server=server, report_url=report_url(server), fetched_at=time.time(),
                          error=f"{type(e).__name__}: {str(e)[:160]}")
        return self._store_grade(server, grade)

    # the server's own tools/list ------------------------------------------

    def _cached_served(self, endpoint: str) -> tuple[bool, list[dict] | None]:
        hit = self._served.get(endpoint)
        if hit and hit[0] > time.monotonic():
            return True, hit[1]
        return False, None

    def _store_served(self, endpoint: str, tools: list[dict] | None) -> list[dict] | None:
        ttl = self.cache_ttl if tools is not None else min(self.cache_ttl, 30.0)
        self._served[endpoint] = (time.monotonic() + ttl, tools)
        return tools

    @staticmethod
    def _mcp_headers(extra: dict[str, str] | None) -> dict[str, str]:
        h = dict(_MCP_HEADERS)
        h["User-Agent"] = _user_agent()
        if extra:
            h.update(extra)
        return h

    def served_tools(self, endpoint: str, *, headers: dict[str, str] | None = None,
                     force: bool = False) -> list[dict] | None:
        """``tools/list`` as the server serves it now (Streamable HTTP). None on failure."""
        if not force:
            hit, tools = self._cached_served(endpoint)
            if hit:
                return tools
        if not endpoint.lower().startswith("https://"):
            return self._store_served(endpoint, None)
        h = self._mcp_headers(headers)
        try:
            kw = self._client_kwargs()
            kw.pop("headers", None)
            with httpx.Client(**kw) as client:
                with client.stream("POST", endpoint, json=_INIT_BODY, headers=h) as resp:
                    init = _rpc_lines_reply(resp.iter_lines(), 1) if "text/event-stream" in (
                        resp.headers.get("content-type") or "") else _parse_rpc_text(
                            resp.read().decode("utf-8", "replace"), 1)
                    session = resp.headers.get("mcp-session-id")
                if not init or "result" not in init:
                    return self._store_served(endpoint, None)
                if session:
                    h["Mcp-Session-Id"] = session
                h["MCP-Protocol-Version"] = "2025-06-18"
                try:
                    client.post(endpoint, json={"jsonrpc": "2.0",
                                                "method": "notifications/initialized"},
                                headers=h)
                except Exception:
                    pass  # a notification; some servers answer 202, some 4xx. Either is fine.
                with client.stream("POST", endpoint, json=_LIST_BODY, headers=h) as resp:
                    listing = _rpc_lines_reply(resp.iter_lines(), 2) if "text/event-stream" in (
                        resp.headers.get("content-type") or "") else _parse_rpc_text(
                            resp.read().decode("utf-8", "replace"), 2)
            tools = ((listing or {}).get("result") or {}).get("tools")
            return self._store_served(endpoint, tools if isinstance(tools, list) else None)
        except Exception as e:
            logger.debug("tools/list from %s failed: %s", endpoint, e)
            return self._store_served(endpoint, None)

    async def aserved_tools(self, endpoint: str, *, headers: dict[str, str] | None = None,
                            force: bool = False) -> list[dict] | None:
        if not force:
            hit, tools = self._cached_served(endpoint)
            if hit:
                return tools
        if not endpoint.lower().startswith("https://"):
            return self._store_served(endpoint, None)
        h = self._mcp_headers(headers)
        try:
            kw = self._client_kwargs()
            kw.pop("headers", None)
            async with httpx.AsyncClient(**kw) as client:
                async with client.stream("POST", endpoint, json=_INIT_BODY, headers=h) as resp:
                    if "text/event-stream" in (resp.headers.get("content-type") or ""):
                        init = _rpc_lines_reply([ln async for ln in resp.aiter_lines()], 1)
                    else:
                        init = _parse_rpc_text((await resp.aread()).decode("utf-8", "replace"), 1)
                    session = resp.headers.get("mcp-session-id")
                if not init or "result" not in init:
                    return self._store_served(endpoint, None)
                if session:
                    h["Mcp-Session-Id"] = session
                h["MCP-Protocol-Version"] = "2025-06-18"
                try:
                    await client.post(endpoint, json={"jsonrpc": "2.0",
                                                      "method": "notifications/initialized"},
                                      headers=h)
                except Exception:
                    pass
                async with client.stream("POST", endpoint, json=_LIST_BODY, headers=h) as resp:
                    if "text/event-stream" in (resp.headers.get("content-type") or ""):
                        listing = _rpc_lines_reply([ln async for ln in resp.aiter_lines()], 2)
                    else:
                        listing = _parse_rpc_text(
                            (await resp.aread()).decode("utf-8", "replace"), 2)
            tools = ((listing or {}).get("result") or {}).get("tools")
            return self._store_served(endpoint, tools if isinstance(tools, list) else None)
        except Exception as e:
            logger.debug("tools/list from %s failed: %s", endpoint, e)
            return self._store_served(endpoint, None)


# ── the gate ──────────────────────────────────────────────────────────────────


class ToolGate:
    """Policy + lookups for one agent. Framework adapters wrap this.

    Args:
        base_url: AgentAvow API root (``/api/v1``).
        min_score: allow at or above this score (default 51, the floor of Safe
            to connect; 81, Trusted, is stricter).
        block_on: finding severities that fail the gate (default critical, high).
        fail_on: the answer that fails the gate — ``review`` (default: Review
            before you connect or Do not connect), ``do_not_connect``, or ``none``.
        on_fail: what a fail does — ``block`` (return a message in place of the
            tool result), ``confirm`` (ask before running), ``warn`` (run, log a
            warning), ``raise`` (raise :class:`ToolGateBlockedError`).
        cache_ttl: seconds a grade (and a served ``tools/list``) is reused.
        fail_closed: an AgentAvow API error is a fail (True) or an allow with a
            warning (False).
        tool_to_server: ``{tool name: server coordinate}`` — the explicit map.
        servers: ``{server name: server coordinate}`` — matched against the
            framework's notion of the serving server (a ``<name>_`` tool-name
            prefix, or ``metadata["mcp"]["server"]["name"]``).
        resolve_server: ``(tool_name, hint) -> coordinate | None`` for anything
            the two maps cannot express. ``hint`` carries what the adapter knows.
        served_tools: the ``tools/list`` each server served the agent, keyed by
            coordinate, or a callable returning it; used for the drift check.
        fetch_served: when no served definition is supplied, fetch ``tools/list``
            from the (https) server itself — the same definition the agent was
            served moments earlier (default True).
        unmapped: ``allow`` (default) or ``block`` a tool that maps to no server
            (a local function tool has no grade to check).
        confirm: ``(decision) -> bool`` used by ``on_fail="confirm"``; adapters
            fall back to their framework's own approval mechanism when None.
        on_warn: called with each warning string (default: ``logger.warning``).
    """

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        min_score: int = DEFAULT_MIN_SCORE,
        block_on: Iterable[str] = DEFAULT_BLOCK_ON,
        fail_on: str = DEFAULT_FAIL_ON,
        on_fail: str = "block",
        cache_ttl: float = DEFAULT_CACHE_TTL,
        fail_closed: bool = True,
        tool_to_server: dict[str, str] | None = None,
        servers: dict[str, str] | None = None,
        resolve_server: Callable[[str, dict], str | None] | None = None,
        served_tools: Any = None,
        fetch_served: bool = True,
        unmapped: str = "allow",
        confirm: Callable[[GateDecision], bool] | None = None,
        on_warn: Callable[[str], Any] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: Any = None,
        headers: dict[str, str] | None = None,
        server_headers: dict[str, dict[str, str]] | None = None,
    ) -> None:
        if on_fail not in ON_FAIL_MODES:
            raise ValueError(f"on_fail must be one of {ON_FAIL_MODES}, got {on_fail!r}")
        if unmapped not in ("allow", "block"):
            raise ValueError("unmapped must be 'allow' or 'block'")
        if fail_on not in FAIL_ON_MODES:
            raise ValueError(f"fail_on must be one of {FAIL_ON_MODES}, got {fail_on!r}")
        self.fail_on = fail_on
        self.min_score = int(min_score)
        self.block_on = tuple(str(s).lower() for s in block_on)
        self.on_fail = on_fail
        self.fail_closed = bool(fail_closed)
        self.tool_to_server = dict(tool_to_server or {})
        self.servers = dict(servers or {})
        self.resolve_server = resolve_server
        self.served_tools = served_tools
        self.fetch_served = bool(fetch_served)
        self.unmapped = unmapped
        self.confirm = confirm
        self.on_warn = on_warn or (lambda msg: logger.warning("%s", msg))
        self.server_headers = dict(server_headers or {})
        self.client = TrustGateClient(base_url, timeout=timeout, cache_ttl=cache_ttl,
                                      transport=transport, headers=headers)

    # mapping -------------------------------------------------------------

    def resolve(self, tool_name: str, hint: dict | None = None) -> tuple[str | None, str]:
        """``(server coordinate or None, the tool's name on that server)``.

        ``hint`` may carry ``server_name`` (the framework's name for the serving
        server), ``endpoint`` (its URL) and ``mcp_name`` (the tool's unprefixed
        name).
        """
        hint = hint or {}
        mcp_name = str(hint.get("mcp_name") or tool_name)
        if tool_name in self.tool_to_server:
            return self.tool_to_server[tool_name], mcp_name
        endpoint = hint.get("endpoint")
        if isinstance(endpoint, str) and endpoint:
            return endpoint, mcp_name
        name = hint.get("server_name")
        if isinstance(name, str) and name in self.servers:
            return self.servers[name], mcp_name
        for sname, coord in self.servers.items():  # langchain-mcp-adapters' tool_name_prefix
            prefix = f"{sname}_"
            if tool_name.startswith(prefix) and len(tool_name) > len(prefix):
                return coord, tool_name[len(prefix):]
        if self.resolve_server is not None:
            coord = self.resolve_server(tool_name, dict(hint))
            if coord:
                return coord, mcp_name
        return None, mcp_name

    def unmapped_decision(self, tool_name: str) -> GateDecision:
        if self.unmapped == "block":
            return GateDecision(False, "unmapped",
                                f"AgentAvow blocked '{tool_name}': it maps to no graded "
                                "server (unmapped='block'). Not run.", tool_name, None)
        return GateDecision(True, "unmapped",
                            f"'{tool_name}' maps to no server; not gated.", tool_name, None)

    # served definitions --------------------------------------------------

    def _explicit_served(self, server: str) -> tuple[bool, list[dict] | None]:
        src = self.served_tools
        if src is None:
            return False, None
        if callable(src):
            return True, src(server)
        return (True, src.get(server)) if isinstance(src, dict) else (False, None)

    @staticmethod
    def _pick(tools: list[dict] | None, mcp_name: str) -> dict | None:
        for t in tools or []:
            if isinstance(t, dict) and t.get("name") == mcp_name:
                return t
        return None

    def served_definition(self, server: str, mcp_name: str) -> dict | None:
        explicit, tools = self._explicit_served(server)
        if explicit:
            return self._pick(tools, mcp_name)
        if self.fetch_served and is_mcp(server):
            endpoint = parse_coordinate(server)[1]
            return self._pick(self.client.served_tools(
                endpoint, headers=self.server_headers.get(server)), mcp_name)
        return None

    async def aserved_definition(self, server: str, mcp_name: str) -> dict | None:
        explicit, tools = self._explicit_served(server)
        if explicit:
            return self._pick(tools, mcp_name)
        if self.fetch_served and is_mcp(server):
            endpoint = parse_coordinate(server)[1]
            return self._pick(await self.client.aserved_tools(
                endpoint, headers=self.server_headers.get(server)), mcp_name)
        return None

    # decisions -----------------------------------------------------------

    def _finish(self, decision: GateDecision) -> GateDecision:
        for w in decision.warnings:
            self.on_warn(w)
        return decision

    def check(self, tool_name: str, server: str, *, mcp_name: str | None = None,
              served_definition: dict | None = None) -> GateDecision:
        """Sync: grade the server and evaluate this call."""
        mcp_name = mcp_name or tool_name
        grade = self.client.grade(server)
        if served_definition is None and grade.error is None and grade.tool_digests:
            served_definition = self.served_definition(server, mcp_name)
        return self._finish(evaluate(
            tool_name, server, grade, min_score=self.min_score, block_on=self.block_on,
            fail_closed=self.fail_closed, served_definition=served_definition,
            fail_on=self.fail_on))

    async def acheck(self, tool_name: str, server: str, *, mcp_name: str | None = None,
                     served_definition: dict | None = None) -> GateDecision:
        """Async: grade the server and evaluate this call."""
        mcp_name = mcp_name or tool_name
        grade = await self.client.agrade(server)
        if served_definition is None and grade.error is None and grade.tool_digests:
            served_definition = await self.aserved_definition(server, mcp_name)
        return self._finish(evaluate(
            tool_name, server, grade, min_score=self.min_score, block_on=self.block_on,
            fail_closed=self.fail_closed, served_definition=served_definition,
            fail_on=self.fail_on))

    def action(self, decision: GateDecision) -> str:
        """``allow`` | ``block`` | ``confirm`` for a decision under ``on_fail``.

        ``warn`` resolves to ``allow`` after reporting; ``raise`` raises.
        """
        if decision.allow:
            return "allow"
        if self.on_fail == "raise":
            raise ToolGateBlockedError(decision)
        if self.on_fail == "warn":
            self.on_warn(decision.reason)
            return "allow"
        if self.on_fail == "confirm":
            if self.confirm is not None:
                return "allow" if self.confirm(decision) else "block"
            return "confirm"
        return "block"


__all__ = [
    "DEFAULT_BASE_URL", "DEFAULT_BLOCK_ON", "DEFAULT_MIN_SCORE", "GateDecision", "Grade",
    "ToolGate", "ToolGateBlockedError", "TrustGateClient", "UnhashableError", "evaluate",
    "grade_url", "jcs", "parse_coordinate", "report_url", "served_tool_digest",
    "served_tool_key", "tool_digest", "tool_key",
]
