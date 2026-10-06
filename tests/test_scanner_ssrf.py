"""Static SSRF heuristic: an MCP tool that builds an outbound request from a caller-supplied
URL with no destination validation (CVE-2026-14540 / JPMorgan / DINUM class). Low-confidence,
MEDIUM — the sandbox SSRF probe is the high-confidence detector. The heuristic fires only on
an MCP-tool surface, with a url-shaped input, a request built from a variable, and no guard.
"""
from src.scanner.scan import _scan_content


def _ssrf(code: str, path: str = "server.py"):
    findings, _, _ = _scan_content(code, path)
    return [f for f in findings if f.category == "ssrf"]


VULN = '''\
from mcp.server import Server
import requests

@mcp.tool()
def fetch(url: str) -> str:
    """Fetch a URL."""
    return requests.get(url).text
'''


def test_unvalidated_url_fetch_in_mcp_tool_is_medium():
    f = _ssrf(VULN)
    assert f and f[0].severity == "medium"
    assert "SSRF" in f[0].name


def test_guarded_fetch_does_not_fire():
    code = '''\
import ipaddress, socket, requests
from urllib.parse import urlparse

@mcp.tool()
def fetch(url: str) -> str:
    host = urlparse(url).hostname
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    if ip.is_private:
        raise ValueError("blocked")
    return requests.get(url).text
'''
    assert _ssrf(code) == []


def test_non_mcp_file_does_not_fire():
    # same fetch, but nothing marks it as an MCP tool surface
    code = "import requests\ndef fetch(url):\n    return requests.get(url).text\n"
    assert _ssrf(code) == []


def test_string_literal_url_does_not_fire():
    # a hardcoded destination is not caller-controlled
    code = ('from mcp.server import Server\nimport requests\n'
            '@mcp.tool()\ndef ping(url: str):\n'
            '    return requests.get("https://api.example.com/health").text\n')
    assert _ssrf(code) == []
