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
    assert '<h2 id="section">Section</h2>' in h
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


@pytest.mark.parametrize("text,expected", [
    ("How the sandbox moves the score", "how-the-sandbox-moves-the-score"),
    ("Tool definitions: per-tool digests and drift", "tool-definitions-per-tool-digests-and-drift"),
    ("Declare your tool's scope (optional)", "declare-your-tools-scope-optional"),
    ("Score → recommended posture", "score--recommended-posture"),  # GitHub keeps both hyphens
    ("The trust score: 0–100", "the-trust-score-0100"),
    ("`code` in a Heading", "code-in-a-heading"),
    ("  padded  ", "padded"),
])
def test_slugify_matches_github_style(text, expected):
    """Same inputs → same ids as web/src/rebrand/lib/slugify.ts (see that file)."""
    assert mod._slugify(text) == expected


def test_headings_get_ids_and_anchors_survive_rewrite():
    h = mod._render_body(
        "# Title\n\n## Score → recommended posture\n\n### Sub-heading!\n\n"
        "See [there](./check-guide.md#stay-safe-over-time) and [here](#sub-heading).\n"
    )
    assert "<h1>Title</h1>" in h  # only h2/h3 carry ids
    assert '<h2 id="score--recommended-posture">' in h
    assert '<h3 id="sub-heading">' in h
    assert 'href="/docs/check-guide#stay-safe-over-time"' in h
    assert 'href="#sub-heading"' in h


# Every cross-doc / in-page anchor the docs actually use must land on a real heading.
_KNOWN_ANCHORS = [
    ("behavioral-sandbox", "how-the-sandbox-moves-the-score"),   # how-grading-works.md, in-page
    ("verify-attestations", "behavioral-observations"),           # behavioral-sandbox.md
    ("verify-attestations", "tool-definitions-per-tool-digests-and-drift"),  # check-guide.md
    ("check-guide", "declare-your-tools-scope-optional"),         # behavioral-sandbox.md
    ("check-guide", "stay-safe-over-time"),                       # behavioral-sandbox.md
]


@pytest.mark.parametrize("slug,anchor", _KNOWN_ANCHORS)
def test_known_anchors_resolve_to_heading_ids(slug, anchor):
    assert slug in mod._TITLES, f"{slug} missing from DOCS (SSR would fall back to the hub)"
    body = mod._render_body(mod._load(slug) or "")
    assert f'id="{anchor}"' in body


def test_every_doc_anchor_link_targets_an_existing_id():
    """No doc may link to a #fragment that neither renderer can resolve."""
    import re

    ids = {slug: set(re.findall(r' id="([^"]+)"', mod._render_body(mod._load(slug) or "")))
           for slug, _ in mod.DOCS}
    for slug, _ in mod.DOCS:
        for href in mod._LINK_RE.findall(mod._load(slug) or ""):
            m = re.match(r"^(?:\./([\w-]+)\.md)?#([\w-]+)$", href[1].strip())
            if not m:
                continue
            target = m.group(1) or slug
            assert m.group(2) in ids[target], f"{slug}: {href[1]} → no such heading id"


def test_meta_description_cuts_at_word_boundary():
    words = "word " * 60  # 300 chars, no word is ever split
    d = mod._meta_description(words.strip())
    assert len(d) <= mod._META_DESCRIPTION_MAX
    assert d.endswith("…")
    assert d[:-1].endswith("word")
    assert mod._meta_description("short") == "short"
    exact = "x" * mod._META_DESCRIPTION_MAX
    assert mod._meta_description(exact) == exact


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
async def test_slug_endpoint_has_heading_ids_and_bounded_description(client: AsyncClient):
    resp = await client.get("/api/v1/docpages/behavioral-sandbox")
    assert resp.status_code == 200
    assert '<h2 id="how-the-sandbox-moves-the-score">' in resp.text
    assert 'href="/docs/verify-attestations#behavioral-observations"' in resp.text
    import re
    m = re.search(r'<meta name="description" content="([^"]*)">', resp.text)
    assert m and 0 < len(m.group(1)) <= mod._META_DESCRIPTION_MAX


@pytest.mark.asyncio
async def test_unknown_slug_falls_back_to_hub(client: AsyncClient):
    resp = await client.get("/api/v1/docpages/does-not-exist")
    assert resp.status_code == 200
    assert "AgentAvow Documentation" in resp.text
