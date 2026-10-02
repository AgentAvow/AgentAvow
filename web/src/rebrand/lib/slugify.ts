/**
 * GitHub-style heading id: lowercase, drop punctuation, each space → '-'.
 *
 * Must stay byte-identical to `_slugify` in src/api/docs_content_router.py — the
 * server-rendered docs give the same headings the same ids, so a `#anchor` in a doc
 * link resolves in both renderers. ASCII-only on purpose (JS `\w` is ASCII; Python's
 * is not).
 */
export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9 _-]/g, '')
    .replace(/^ +| +$/g, '')
    .replace(/ /g, '-')
}
