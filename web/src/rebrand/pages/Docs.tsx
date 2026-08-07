import { useState } from 'react'
import { Link } from 'react-router-dom'
import { rp } from '../basePath'
import Markdown from 'react-markdown'
import checkGuide from '../docs/check-guide.md?raw'
import trustBadges from '../docs/trust-badges.md?raw'
import verifyAttestations from '../docs/verify-attestations.md?raw'

/**
 * Rebrand docs PREVIEW — renders the staged trust-first docs (web/src/rebrand/docs/*.md)
 * with react-markdown, styled via a prose wrapper. Isolated from the live /docs; at
 * cutover these get wired into the backend docs system (see docs/rebrand/README.md).
 */

const DOCS = [
  { slug: 'check-guide', title: 'Reading your scan grade', body: checkGuide },
  { slug: 'trust-badges', title: 'Add a trust badge', body: trustBadges },
  { slug: 'verify-attestations', title: 'Verify an attestation', body: verifyAttestations },
]

// Real destinations that already exist (were "coming at launch" placeholders).
const MORE: [string, string][] = [
  ['API sandbox', '/rebrand/sandbox'],
  ['Scan catalog', '/rebrand/browse'],
  ['How it works', '/rebrand/how-it-works'],
  ['Standards & research', '/rebrand/research'],
  ['SDK & CLI', 'https://github.com/AgentAvow/AgentAvow/tree/main/sdk'],
  ['GitHub Action', 'https://github.com/AgentAvow/AgentAvow/tree/main/sdk/github-action'],
  ['API reference', '/api/v1/redoc'],
]

const PROSE = [
  '[&_h1]:text-3xl [&_h1]:font-extrabold [&_h1]:tracking-tight [&_h1]:mb-2',
  '[&_h2]:text-xl [&_h2]:font-bold [&_h2]:mt-9 [&_h2]:mb-2 [&_h2]:pt-6 [&_h2]:border-t [&_h2]:border-border/60',
  '[&_h3]:text-[17px] [&_h3]:font-semibold [&_h3]:mt-6 [&_h3]:mb-1',
  '[&_p]:text-text-muted [&_p]:leading-relaxed [&_p]:my-3',
  '[&_ul]:list-disc [&_ul]:pl-5 [&_ul]:my-3 [&_ul]:space-y-1 [&_ul]:text-text-muted',
  '[&_ol]:list-decimal [&_ol]:pl-5 [&_ol]:my-3 [&_ol]:space-y-1 [&_ol]:text-text-muted',
  '[&_a]:text-primary-light [&_a]:underline-offset-2 hover:[&_a]:underline',
  '[&_strong]:text-text [&_strong]:font-semibold',
  '[&_blockquote]:border-l-4 [&_blockquote]:border-border [&_blockquote]:pl-4 [&_blockquote]:my-4 [&_blockquote]:text-text-muted/80 [&_blockquote]:text-[14px]',
  '[&_:not(pre)>code]:font-mono [&_:not(pre)>code]:text-[12.5px] [&_:not(pre)>code]:text-primary-light [&_:not(pre)>code]:bg-surface [&_:not(pre)>code]:px-1.5 [&_:not(pre)>code]:py-0.5 [&_:not(pre)>code]:rounded',
  '[&_pre]:font-mono [&_pre]:text-[12.5px] [&_pre]:bg-surface [&_pre]:border [&_pre]:border-border [&_pre]:rounded-xl [&_pre]:p-4 [&_pre]:my-4 [&_pre]:overflow-x-auto',
  '[&_hr]:my-8 [&_hr]:border-border/60',
].join(' ')

export default function RebrandDocs() {
  const [active, setActive] = useState(DOCS[0].slug)
  const doc = DOCS.find((d) => d.slug === active) ?? DOCS[0]

  return (
    <div className="max-w-[1080px] mx-auto px-6 py-14 grid md:grid-cols-[220px_1fr] gap-10">
      <aside className="md:sticky md:top-[86px] self-start">
        <div className="font-mono text-[11px] uppercase tracking-wide text-primary-light mb-3">Verify an agent</div>
        <nav className="flex flex-col gap-1">
          {DOCS.map((d) => (
            <button
              key={d.slug}
              onClick={() => setActive(d.slug)}
              className={`text-left text-[14px] px-3 py-2 rounded-lg transition-colors ${
                active === d.slug ? 'bg-primary/10 text-primary-light font-medium' : 'text-text-muted hover:text-text hover:bg-surface'
              }`}
            >
              {d.title}
            </button>
          ))}
        </nav>
        <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted mt-6 mb-2">More</div>
        <nav className="flex flex-col gap-1">
          {MORE.map(([label, href]) => (
            href.startsWith('/api') || href.startsWith('http')
              ? <a key={label} href={href} target="_blank" rel="noopener noreferrer" className="text-[13.5px] px-3 py-1.5 text-text-muted hover:text-primary-light">{label} ↗</a>
              : <Link key={label} to={rp(href)} className="text-[13.5px] px-3 py-1.5 text-text-muted hover:text-primary-light">{label}</Link>
          ))}
        </nav>
      </aside>

      <article className={`min-w-0 ${PROSE}`}>
        <Markdown>{doc.body}</Markdown>
      </article>
    </div>
  )
}
