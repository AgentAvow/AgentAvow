"""Server-rendered documentation pages.

The interactive docs live in the SPA (web/src/rebrand/pages/Docs.tsx, rendered with
react-markdown), but a JS-only render is an empty shell to non-browser fetchers —
crawlers, link unfurlers, and app-store/Directory compliance reviewers. This router
serves the SAME Markdown source as fully-rendered, self-contained HTML so every doc is
readable without executing JavaScript.

The Markdown source is the single source of truth: the very same .md files the SPA
imports (web/src/rebrand/docs/*.md) are bundled into the backend image and rendered
here by a small, dependency-free renderer covering exactly the Markdown subset those
docs use (headings, paragraphs, bold, inline + fenced code, ordered/unordered lists,
blockquotes, horizontal rules, links). No content is duplicated, so nothing can drift.

Nginx routes a direct hit on /docs and /docs/<slug> here; in-app soft navigation still
renders the React page. Keep DOCS below in sync with the DOCS array in Docs.tsx.
"""
from __future__ import annotations

import html
import re
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/docpages", tags=["docs"])

# slug -> human title, in the same order as Docs.tsx's DOCS array.
DOCS: list[tuple[str, str]] = [
    ("how-grading-works", "How scoring works"),
    ("gate-on-the-grade", "Gate on the score"),
    ("check-guide", "Reading your scan score"),
    ("run-locally", "Run locally & in CI"),
    ("trust-badges", "Add a trust badge"),
    ("verify-attestations", "Verify an attestation"),
    ("mcp-connector", "MCP connector"),
    ("auto-scan-claude-code", "Auto-scan in Claude Code"),
]
_TITLES = dict(DOCS)
_SLUGS = [s for s, _ in DOCS]

# The .md files: the repo path in dev, the image-bundled copy in prod (see Dockerfile).
_CONTENT_DIRS = [
    Path(__file__).resolve().parents[2] / "web" / "src" / "rebrand" / "docs",
    Path("/app/docpages_content"),
    Path("docpages_content"),
]


def _content_dir() -> Path | None:
    for d in _CONTENT_DIRS:
        if d.is_dir():
            return d
    return None


def _load(slug: str) -> str | None:
    d = _content_dir()
    if d is None:
        return None
    f = d / f"{slug}.md"
    if not f.is_file():
        return None
    return f.read_text(encoding="utf-8")


# --- Markdown → HTML (scoped, dependency-free) --------------------------------

_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
# ./some-slug.md or ./some-slug.md#anchor  → /docs/some-slug
_INTRA_RE = re.compile(r"^\./([\w-]+)\.md(?:#.*)?$")


def _rewrite_href(href: str) -> str:
    m = _INTRA_RE.match(href.strip())
    if m and m.group(1) in _TITLES:
        return f"/docs/{m.group(1)}"
    return href.strip()


def _inline(text: str) -> str:
    """Render inline markdown for a single already-line-joined string.

    Order matters: pull out inline code spans first (their contents must NOT be
    treated as markdown), then escape, then apply bold and links. Code-span and
    link/bold outputs are stitched back with placeholders so escaping never
    double-encodes generated tags.
    """
    tokens: list[str] = []

    def _stash(html_fragment: str) -> str:
        tokens.append(html_fragment)
        return f"\x00{len(tokens) - 1}\x00"

    # 1. inline code spans `...`
    def _code(m: re.Match[str]) -> str:
        return _stash(f"<code>{html.escape(m.group(1))}</code>")

    text = re.sub(r"`([^`]+)`", _code, text)

    # 2. links [text](href) — escape text, rewrite/escape href
    def _link(m: re.Match[str]) -> str:
        label = html.escape(m.group(1))
        href = html.escape(_rewrite_href(m.group(2)), quote=True)
        return _stash(f'<a href="{href}">{label}</a>')

    text = _LINK_RE.sub(_link, text)

    # 3. bold **...**
    def _bold(m: re.Match[str]) -> str:
        return _stash(f"<strong>{html.escape(m.group(1))}</strong>")

    text = _BOLD_RE.sub(_bold, text)

    # 4. escape whatever plain text remains, then restore stashed fragments
    text = html.escape(text)

    def _restore(m: re.Match[str]) -> str:
        return tokens[int(m.group(1))]

    # Restore iteratively: a stashed fragment (e.g. a link) may itself contain a
    # placeholder (e.g. an inline-code span inside the link text), and re.sub does
    # not re-scan inserted text in a single pass. Loop until stable.
    while "\x00" in text:
        new = re.sub(r"\x00(\d+)\x00", _restore, text)
        if new == text:
            break
        text = new
    return text


def _render_body(md: str) -> str:
    """Render the supported Markdown subset to an HTML body string."""
    lines = md.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    i = 0
    n = len(lines)
    list_stack: list[str] = []  # "ul" / "ol" currently open

    def _close_lists() -> None:
        while list_stack:
            out.append(f"</{list_stack.pop()}>")

    while i < n:
        line = lines[i]

        # fenced code block
        if line.lstrip().startswith("```"):
            _close_lists()
            i += 1
            code: list[str] = []
            while i < n and not lines[i].lstrip().startswith("```"):
                code.append(lines[i])
                i += 1
            i += 1  # skip closing fence
            out.append(f"<pre><code>{html.escape(chr(10).join(code))}</code></pre>")
            continue

        stripped = line.strip()

        # blank line ends any open list/paragraph grouping
        if not stripped:
            _close_lists()
            i += 1
            continue

        # horizontal rule
        if re.fullmatch(r"-{3,}|\*{3,}|_{3,}", stripped):
            _close_lists()
            out.append("<hr>")
            i += 1
            continue

        # heading
        h = re.match(r"(#{1,6})\s+(.*)$", stripped)
        if h:
            _close_lists()
            level = min(len(h.group(1)), 6)
            out.append(f"<h{level}>{_inline(h.group(2).strip())}</h{level}>")
            i += 1
            continue

        # blockquote (one level; consecutive > lines join)
        if stripped.startswith(">"):
            _close_lists()
            quote: list[str] = []
            while i < n and lines[i].strip().startswith(">"):
                quote.append(re.sub(r"^\s*>\s?", "", lines[i]))
                i += 1
            out.append(f"<blockquote>{_inline(' '.join(q.strip() for q in quote))}</blockquote>")
            continue

        # unordered list item
        um = re.match(r"[-*]\s+(.*)$", stripped)
        if um:
            if not list_stack or list_stack[-1] != "ul":
                _close_lists()
                list_stack.append("ul")
                out.append("<ul>")
            out.append(f"<li>{_inline(um.group(1).strip())}</li>")
            i += 1
            continue

        # ordered list item
        om = re.match(r"\d+\.\s+(.*)$", stripped)
        if om:
            if not list_stack or list_stack[-1] != "ol":
                _close_lists()
                list_stack.append("ol")
                out.append("<ol>")
            out.append(f"<li>{_inline(om.group(1).strip())}</li>")
            i += 1
            continue

        # paragraph: gather consecutive plain lines
        _close_lists()
        para: list[str] = []
        while i < n:
            s = lines[i].strip()
            if (not s or s.startswith(("#", ">", "```"))
                    or re.match(r"[-*]\s+", s) or re.match(r"\d+\.\s+", s)
                    or re.fullmatch(r"-{3,}|\*{3,}|_{3,}", s)):
                break
            para.append(s)
            i += 1
        out.append(f"<p>{_inline(' '.join(para))}</p>")

    _close_lists()
    return "\n".join(out)


# --- Page template ------------------------------------------------------------

_STYLE = """
  :root { color-scheme: light dark; --bg:#0b0f17; --fg:#e6edf3; --muted:#9aa7b6; --accent:#5eead4; --line:#1e2733; --surface:#111826; }
  @media (prefers-color-scheme: light) { :root { --bg:#ffffff; --fg:#0b0f17; --muted:#5b6673; --accent:#0d9488; --line:#e5e9ef; --surface:#f5f7fa; } }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  .wrap { max-width:760px; margin:0 auto; padding:56px 24px 80px; }
  a { color:var(--accent); }
  h1 { font-size:32px; font-weight:800; letter-spacing:-0.02em; margin:0 0 6px; }
  h2 { font-size:20px; font-weight:700; margin:34px 0 8px; padding-top:22px; border-top:1px solid var(--line); }
  h3 { font-size:17px; font-weight:600; margin:22px 0 4px; }
  .sub { color:var(--muted); font-size:14px; margin:0 0 32px; }
  p { color:var(--muted); margin:12px 0; }
  ul, ol { color:var(--muted); margin:12px 0; padding-left:22px; }
  li { margin:3px 0; }
  strong { color:var(--fg); font-weight:600; }
  code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px; color:var(--accent); background:var(--surface); padding:1px 6px; border-radius:5px; }
  pre { background:var(--surface); border:1px solid var(--line); border-radius:12px; padding:16px; margin:16px 0; overflow-x:auto; }
  pre code { color:var(--fg); background:none; padding:0; font-size:12.5px; }
  blockquote { border-left:3px solid var(--line); margin:16px 0; padding:2px 0 2px 16px; color:var(--muted); font-size:14px; }
  hr { border:none; border-top:1px solid var(--line); margin:32px 0; }
  .index { list-style:none; padding:0; margin:24px 0 0; }
  .index li { margin:0; border-top:1px solid var(--line); }
  .index a { display:block; padding:16px 0; color:var(--fg); text-decoration:none; font-weight:600; }
  .index a:hover { color:var(--accent); }
  .index .blurb { display:block; color:var(--muted); font-weight:400; font-size:14px; margin-top:2px; }
  .home { display:inline-block; margin-top:36px; color:var(--muted); font-size:14px; }
"""


def _page(title: str, description: str, canonical: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} · AgentAvow Docs</title>
<meta name="description" content="{html.escape(description, quote=True)}">
<link rel="canonical" href="{html.escape(canonical, quote=True)}">
<style>{_STYLE}</style>
</head>
<body>
  <main class="wrap">
{body}
    <a class="home" href="https://agentavow.com/">← Back to AgentAvow</a>
  </main>
</body>
</html>"""


def _first_paragraph(md: str) -> str:
    """First real paragraph of a doc, as plain text, for the hub blurb."""
    for block in md.replace("\r\n", "\n").split("\n\n"):
        b = block.strip()
        if not b or b.startswith(("#", ">", "```", "-", "*")):
            continue
        text = " ".join(line.strip() for line in b.split("\n"))
        text = _BOLD_RE.sub(r"\1", text)
        text = re.sub(r"`([^`]+)`", r"\1", text)
        text = _LINK_RE.sub(r"\1", text)
        return text
    return ""


@router.get("", include_in_schema=False)
async def docs_hub() -> HTMLResponse:
    """SSR docs index — every doc, readable without JavaScript."""
    items = []
    for slug, title in DOCS:
        md = _load(slug) or ""
        blurb = html.escape(_first_paragraph(md))
        items.append(
            f'<li><a href="/docs/{slug}">{html.escape(title)}'
            f'<span class="blurb">{blurb}</span></a></li>'
        )
    body = (
        "<h1>AgentAvow Documentation</h1>\n"
        '<p class="sub">Guides for checking, verifying, gating, and badging AI-agent tools.</p>\n'
        f'<ul class="index">{"".join(items)}</ul>'
    )
    return HTMLResponse(_page(
        "Documentation",
        "AgentAvow documentation — how scoring works, gating on the score, verifying "
        "attestations, trust badges, and running locally.",
        "https://agentavow.com/docs",
        body,
    ))


@router.get("/{slug}", include_in_schema=False)
async def docs_page(slug: str) -> HTMLResponse:
    """SSR a single doc by slug — readable without JavaScript."""
    if slug not in _TITLES:
        return await docs_hub()
    md = _load(slug)
    if md is None:
        return await docs_hub()
    title = _TITLES[slug]
    body = (
        f"<h1>{html.escape(title)}</h1>\n"
        '<p class="sub">AgentAvow Docs · agentavow.com</p>\n'
        f"{_render_body(md)}"
    )
    return HTMLResponse(_page(
        title,
        _first_paragraph(md)[:180] or f"AgentAvow documentation — {title}.",
        f"https://agentavow.com/docs/{slug}",
        body,
    ))
