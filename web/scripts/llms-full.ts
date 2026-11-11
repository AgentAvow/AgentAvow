/**
 * Build-time /llms-full.txt: public/llms.txt (the index) followed by every doc in
 * src/rebrand/docs/*.md, in the order the Docs page lists them. Generated on every
 * `vite build` (see llmsFullPlugin in vite.config.ts), so it can never drift from the
 * docs it is made of. Relative links between docs become absolute agentavow.com URLs,
 * since the file is read away from the site.
 */
import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'

const SITE = 'https://agentavow.com'

/** Doc slugs in the order the Docs page shows them; any doc it doesn't list goes last. */
export function docOrder(webDir: string): string[] {
  const docsDir = path.join(webDir, 'src', 'rebrand', 'docs')
  const files = readdirSync(docsDir).filter((f) => f.endsWith('.md')).map((f) => f.slice(0, -3))
  const page = readFileSync(path.join(webDir, 'src', 'rebrand', 'pages', 'Docs.tsx'), 'utf8')
  const listed = [...page.matchAll(/\{ slug: '([a-z0-9-]+)'/g)].map((m) => m[1])
  const ordered = listed.filter((slug) => files.includes(slug))
  return [...ordered, ...files.filter((f) => !ordered.includes(f)).sort()]
}

/** `](./other-doc.md#anchor)` → `](https://agentavow.com/docs/other-doc#anchor)`. */
export function absolutizeDocLinks(markdown: string): string {
  return markdown.replace(/\]\(\.\/([a-z0-9-]+)\.md(#[^)\s]*)?\)/g,
    (_, slug: string, hash: string | undefined) => `](${SITE}/docs/${slug}${hash ?? ''})`)
}

export function buildLlmsFull(webDir: string): string {
  const index = readFileSync(path.join(webDir, 'public', 'llms.txt'), 'utf8').trimEnd()
  const parts = [index, '', '# Full documentation', '']
  for (const slug of docOrder(webDir)) {
    const body = readFileSync(path.join(webDir, 'src', 'rebrand', 'docs', `${slug}.md`), 'utf8')
    parts.push('---', '', `Source: ${SITE}/docs/${slug}`, '', absolutizeDocLinks(body).trim(), '')
  }
  return parts.join('\n')
}
