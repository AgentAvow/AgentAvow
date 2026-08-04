# Staged AgentAvow rebrand docs

These are **new, trust-first docs written for the AgentAvow rebrand**, staged here so they don't touch the
live `/docs` before cutover. They are NOT yet served (they're not in `src/api/docs_router.py::_SLUG_MAP`), so
adding them here changes nothing on the live site.

Full audit + migration plan: `docs/internal/rebrand-docs-audit.md`.

## P0 docs written — now in `web/src/rebrand/docs/` (previewable at `/rebrand/docs`)
The 3 P0 docs live in `web/src/rebrand/docs/*.md` so the rebrand docs page can bundle + render them
(`web/src/rebrand/pages/Docs.tsx`, react-markdown). They are NOT served by the backend `_SLUG_MAP` yet.
- `check-guide.md` — reading your scan grade (anchors "a trust score you can verify")
- `trust-badges.md` — add a signed trust badge to your README (the virality mechanism)
- `verify-attestations.md` — the JWS/EdDSA + JWKS "verify it yourself" walkthrough
*(No GFM tables — the app's react-markdown has no remark-gfm, so tables are written as lists.)*

## Cutover wiring (apply at rebrand cutover, per the agreed defaults)
1. Move/copy these `.md` into `docs/` and add each to `_SLUG_MAP` in `src/api/docs_router.py`.
2. Add each to `SECTIONS` in `web/src/pages/Docs.tsx`, reordered **trust-first**:
   Verify an agent → Attestations → SDK & CLI → Integrations → Standards → Platform (social, demoted).
3. **Brand scrub** the served markdown + `Docs.tsx` (~118 user-facing "AgentGraph" prose hits — file:line
   list in the audit). ⛔ Never scrub: `agentgraph.co` URLs, `/.well-known/*`, `@context`, `kid`s
   (`agentgraph-security-v1`), **PyPI package names** (`agentgraph-sdk`…), `github.com/agentgraph-co/*`.
4. Rewrite `developer-guide.md` trust-first; **rename the `/gateway/*` enforcement docs to "Execution
   Gateway"** (resolve the 3-way "Trust Gateway" name collision).
5. Demote-and-keep the social docs (bot-onboarding, marketplace-seller, social quickstart).

## Decisions locked (Kenne, 2026-08-04 — defaults)
- SDK section headlines `agentgraph-sdk` + `agentgraph-trust`; bridges secondary.
- CLI command stays `agentgraph` for now (alias `agentavow` later).
- Old social docs: demote-and-keep (not archived).
- `/docs`: prose-only change; route/IA stay.
- `/gateway/*` enforcement → "Execution Gateway".
- Scan catalog: public & indexable (SEO / "Rotten Tomatoes" surface).
