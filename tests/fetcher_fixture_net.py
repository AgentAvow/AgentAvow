"""A fake registry network for the fetcher before/after comparison (#406).

Patches ``httpx.AsyncHTTPTransport.handle_async_request``, the lowest layer both the old
plain ``httpx.AsyncClient`` fetchers and the new shared fetch client go through, so the
same canned responses can be replayed against either. Routing is on the ``Host`` header
and path, because the SSRF-safe transport rewrites the request URL to the pinned IP.

``python -m tests.fetcher_fixture_net`` (run with ``DEBUG=true``) rewrites
``tests/fixtures/source_import_fetch_results.json`` from the current fetchers. The
committed file was generated from the fetchers before the shared client existed.
"""
from __future__ import annotations

import json
import socket
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "source_import_fetch_results.json"

_PUBLIC_IP = "93.184.216.34"

_README = (
    "# demo\n\n![badge](x)\n\nA demo MCP server that reads files.\n\n"
    "## Features\n- Reads files\n- Lists directories\n\n## Install\npip install demo\n"
)

ROUTES: dict[tuple[str, str], tuple[int, object]] = {
    ("api.github.com", "/repos/acme/demo"): (200, {
        "full_name": "acme/demo", "description": "", "topics": ["mcp", "files"],
        "stargazers_count": 12, "forks_count": 3, "subscribers_count": 2,
        "open_issues_count": 1, "language": "Python", "default_branch": "main",
        "license": {"spdx_id": "MIT"}, "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2026-11-01T00:00:00Z", "owner": {"avatar_url": "https://a/x.png"},
    }),
    ("api.github.com", "/repos/acme/demo/readme"): (200, _README),
    ("api.github.com", "/repos/acme/demo/contents/requirements.txt"): (200, "mcp>=1.0\n"),
    ("api.github.com", "/repos/acme/demo/contents/pyproject.toml"): (404, {}),
    ("api.github.com", "/repos/acme/demo/contents/setup.py"): (404, {}),
    ("api.github.com", "/repos/acme/demo/contents/package.json"): (404, {}),
    ("registry.npmjs.org", "/demo-pkg"): (200, {
        "name": "demo-pkg", "description": "A demo package", "keywords": ["mcp", "agent"],
        "dist-tags": {"latest": "1.2.3"},
        "versions": {"1.2.3": {"license": "MIT",
                               "dependencies": {"@modelcontextprotocol/sdk": "^1"}}},
        "maintainers": [{"name": "alice"}], "homepage": "https://example.org",
        "repository": {"type": "git", "url": "git+https://github.com/acme/demo.git"},
    }),
    ("api.npmjs.org", "/downloads/point/last-month/demo-pkg"): (200, {"downloads": 4321}),
    ("pypi.org", "/pypi/demo-pkg/json"): (200, {"info": {
        "name": "demo-pkg", "summary": "A demo", "version": "0.4.0",
        "classifiers": ["Topic :: Scientific/Engineering :: Artificial Intelligence"],
        "requires_dist": ["langchain>=0.2"], "description": "long description",
        "project_urls": {"Logo": "https://example.org/logo.png"}, "author": "Alice",
        "license": "MIT", "requires_python": ">=3.10",
    }}),
    ("crates.io", "/api/v1/crates/demo"): (200, {
        "crate": {"name": "demo", "description": "A crate", "keywords": ["agent"],
                  "categories": ["ai"], "downloads": 99, "recent_downloads": 9},
        "versions": [{"num": "0.1.0"}],
    }),
    ("hub.docker.com", "/v2/repositories/acme/demo"): (200, {
        "pull_count": 500, "star_count": 4, "description": "Demo image",
        "full_description": "Long text", "last_updated": "2026-10-01T00:00:00Z",
    }),
    ("huggingface.co", "/api/models/acme/demo"): (200, {
        "modelId": "acme/demo", "pipeline_tag": "text-generation", "tags": ["pytorch"],
        "cardData": {"summary": "A model"}, "downloads": 10, "likes": 2, "sha": "abc123",
    }),
}


async def fake_handle(self, request: httpx.Request) -> httpx.Response:
    host = request.headers.get("host", request.url.host).split(":")[0]
    status, body = ROUTES.get((host, request.url.path), (404, {"error": "not found"}))
    if isinstance(body, str):
        return httpx.Response(status, text=body, request=request)
    return httpx.Response(status, json=body, request=request)


def fake_getaddrinfo(host, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_PUBLIC_IP, 0))]


def patched_network() -> ExitStack:
    stack = ExitStack()
    stack.enter_context(
        patch.object(httpx.AsyncHTTPTransport, "handle_async_request", fake_handle)
    )
    stack.enter_context(patch("socket.getaddrinfo", fake_getaddrinfo))
    stack.enter_context(
        patch("src.github_auth.get_github_token", AsyncMock(return_value=None))
    )
    return stack


async def run_all_fetchers() -> dict[str, dict]:
    from src.source_import.crates_fetcher import fetch_crates
    from src.source_import.docker_fetcher import fetch_docker
    from src.source_import.github_fetcher import fetch_github
    from src.source_import.huggingface_fetcher import fetch_huggingface
    from src.source_import.npm_fetcher import fetch_npm
    from src.source_import.pypi_fetcher import fetch_pypi

    with patched_network():
        results = {
            "github": await fetch_github("acme", "demo", "https://github.com/acme/demo"),
            "npm": await fetch_npm("demo-pkg", "https://www.npmjs.com/package/demo-pkg"),
            "pypi": await fetch_pypi("demo-pkg", "https://pypi.org/project/demo-pkg/"),
            "crates": await fetch_crates("demo", "https://crates.io/crates/demo"),
            "docker": await fetch_docker("acme", "demo", "https://hub.docker.com/r/acme/demo"),
            "huggingface": await fetch_huggingface(
                "acme/demo", "https://huggingface.co/acme/demo"
            ),
        }
    return {k: json.loads(json.dumps(asdict(v), default=str)) for k, v in results.items()}


def _override(status: int | None = None, exc: Exception | None = None, body=None):
    """A handler that answers every request with ``status`` (or raises ``exc``)."""

    async def handle(self, request: httpx.Request) -> httpx.Response:
        if exc is not None:
            raise exc
        return httpx.Response(status, json=body or {}, headers={"x-ratelimit-remaining": "0"},
                              request=request)

    return handle


async def run_error_cases() -> dict[str, str]:
    """The error message a user sees for each failure, per fetcher."""
    from src.source_import.crates_fetcher import fetch_crates
    from src.source_import.docker_fetcher import fetch_docker
    from src.source_import.errors import SourceFetchError
    from src.source_import.github_fetcher import SourceFetchError as GitHubFetchError
    from src.source_import.github_fetcher import fetch_github
    from src.source_import.huggingface_fetcher import fetch_huggingface
    from src.source_import.npm_fetcher import fetch_npm
    from src.source_import.pypi_fetcher import fetch_pypi

    calls = {
        "github": lambda: fetch_github("acme", "demo", "https://github.com/acme/demo"),
        "npm": lambda: fetch_npm("demo-pkg", "https://www.npmjs.com/package/demo-pkg"),
        "pypi": lambda: fetch_pypi("demo-pkg", "https://pypi.org/project/demo-pkg/"),
        "crates": lambda: fetch_crates("demo", "https://crates.io/crates/demo"),
        "docker": lambda: fetch_docker("acme", "demo", "https://hub.docker.com/r/acme/demo"),
        "huggingface": lambda: fetch_huggingface(
            "acme/demo", "https://huggingface.co/acme/demo"
        ),
    }
    cases = {
        "404": _override(404),
        "403": _override(403),
        "500": _override(500),
        "read_timeout": _override(exc=httpx.ReadTimeout("read timed out")),
    }
    out: dict[str, str] = {}
    for case, handler in cases.items():
        for name, call in calls.items():
            with patched_network(), patch.object(
                httpx.AsyncHTTPTransport, "handle_async_request", handler
            ):
                try:
                    await call()
                    out[f"{name}:{case}"] = "ok"
                except (SourceFetchError, GitHubFetchError) as exc:
                    out[f"{name}:{case}"] = f"{type(exc).__name__}: {exc}"
    return out


async def build_fixture() -> dict:
    return {"results": await run_all_fetchers(), "errors": await run_error_cases()}


if __name__ == "__main__":
    import asyncio

    out = asyncio.run(build_fixture())
    FIXTURE_PATH.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(f"wrote {FIXTURE_PATH}")
