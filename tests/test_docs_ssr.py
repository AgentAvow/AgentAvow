"""B7: server-rendered docs pages must be readable without JavaScript.

Renders every real .md doc through the router's renderer and asserts the output is
well-formed HTML with the actual content present — so crawlers and compliance
reviewers see the docs, not the SPA's empty shell.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.api import docs_content_router as mod
from src.database import get_db
from src.main import app


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


def test_content_dir_resolves():
    """The .md source directory must be found (dev repo path)."""
    assert mod._content_dir() is not None, "docs .md source directory not found"


@pytest.mark.parametrize("slug,title", mod.DOCS)
def test_every_doc_loads_and_renders(slug, title):
    md = mod._load(slug)
    assert md, f"{slug}.md missing or empty"
    body = mod._render_body(md)
    assert body.strip(), f"{slug} rendered empty"
    # balanced fenced code blocks
    assert body.count("<pre>") == body.count("</pre>")
    assert body.count("<ul>") == body.count("</ul>")
    assert body.count("<ol>") == body.count("</ol>")
    # no unrendered fence markers or raw markdown bold left behind in output
    assert "```" not in body
    # code-span placeholders must all be restored
    assert "\x00" not in body


def test_renderer_handles_core_markdown():
    md = (
        "# Title\n\n"
        "A paragraph with **bold** and `code` and a [link](./check-guide.md).\n\n"
        "## Section\n\n"
        "- one\n- two\n\n"
        "1. first\n2. second\n\n"
        "> a quote\n\n"
        "```\nraw <code> & stuff\n```\n\n"
        "---\n"
    )
    h = mod._render_body(md)
    assert "<h1>Title</h1>" in h
    assert "<strong>bold</strong>" in h
    assert "<code>code</code>" in h
    # intra-doc link rewritten .md -> /docs/<slug>
    assert 'href="/docs/check-guide"' in h
    assert "<h2>Section</h2>" in h
    assert "<ul>" in h and "<li>one</li>" in h
    assert "<ol>" in h and "<li>first</li>" in h
    assert "<blockquote>" in h
    assert "<hr>" in h
    # fenced code is HTML-escaped, not interpreted
    assert "raw &lt;code&gt; &amp; stuff" in h


def test_inline_code_not_treated_as_markdown():
    """Bold/link markers inside a code span must stay literal."""
    h = mod._render_body("Use `**not bold**` here.\n")
    assert "<code>**not bold**</code>" in h
    assert "<strong>" not in h


def test_external_and_mailto_links_preserved():
    h = mod._render_body("See [site](https://example.com) or [mail](mailto:a@b.com).\n")
    assert 'href="https://example.com"' in h
    assert 'href="mailto:a@b.com"' in h


@pytest.mark.asyncio
async def test_hub_endpoint_lists_all_docs(client: AsyncClient):
    resp = await client.get("/api/v1/docpages")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    import html as _html
    page = resp.text
    for slug, title in mod.DOCS:
        assert f'/docs/{slug}' in page
        assert _html.escape(title) in page  # titles are HTML-escaped (e.g. & -> &amp;)


@pytest.mark.asyncio
async def test_slug_endpoint_renders_doc(client: AsyncClient):
    resp = await client.get("/api/v1/docpages/how-grading-works")
    assert resp.status_code == 200
    assert "<h1>How scoring works</h1>" in resp.text
    assert "<!doctype html>" in resp.text.lower()


@pytest.mark.asyncio
async def test_unknown_slug_falls_back_to_hub(client: AsyncClient):
    resp = await client.get("/api/v1/docpages/does-not-exist")
    assert resp.status_code == 200
    assert "AgentAvow Documentation" in resp.text
