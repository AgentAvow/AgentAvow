import { useEffect } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { rp } from '../basePath'
import Markdown from 'react-markdown'
import howGradingWorks from '../docs/how-grading-works.md?raw'
import gateOnTheGrade from '../docs/gate-on-the-grade.md?raw'
import checkGuide from '../docs/check-guide.md?raw'
import runLocally from '../docs/run-locally.md?raw'
import trustBadges from '../docs/trust-badges.md?raw'
import verifyAttestations from '../docs/verify-attestations.md?raw'

/**
 * Rebrand docs PREVIEW — renders the staged trust-first docs (web/src/rebrand/docs/*.md)
 * with react-markdown, styled via a prose wrapper. Isolated from the live /docs; at
 * cutover these get wired into the backend docs system (see docs/rebrand/README.md).
 */

const DOCS = [
  { slug: 'how-grading-works', title: 'How scoring works', body: howGradingWorks },
  { slug: 'gate-on-the-grade', title: 'Gate on the score', body: gateOnTheGrade },
  { slug: 'check-guide', title: 'Reading your scan score', body: checkGuide },
  { slug: 'run-locally', title: 'Run locally & in CI', body: runLocally },
  { slug: 'trust-badges', title: 'Add a trust badge', body: trustBadges },
  { slug: 'verify-attestations', title: 'Verify an attestation', body: verifyAttestations },
]

// Real destinations that already exist (were "coming at launch" placeholders).
const MORE: [string, string][] = [
  ['API sandbox', '/rebrand/sandbox'],
  ['Scan catalog', '/rebrand/browse'],
  ['How it works', '/rebrand/how-it-works'],
  ['Standards & research', '/rebrand/research'],
  ['CLI (local scan)', 'https://github.com/AgentAvow/AgentAvow/tree/main/src/scanner/local_scan.py'],
  ['GitHub Action', 'https://github.com/AgentAvow/AgentAvow/tree/main/local-scan-action'],
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
  // Deep-linkable: /docs/<slug> selects a doc (shareable URLs); the bare /docs
  // lands on the first. Clicking a doc pushes the slug so the URL stays copyable.
  const { slug } = useParams()
  const navigate = useNavigate()
  const doc = DOCS.find((d) => d.slug === slug) ?? DOCS[0]
  const active = doc.slug
  const setActive = (s: string) => {
    navigate(rp(`/rebrand/docs/${s}`))
    window.scrollTo({ top: 0 })
  }
  // If someone hits an unknown slug, normalize the URL to the first doc.
  useEffect(() => {
    if (slug && !DOCS.some((d) => d.slug === slug)) navigate(rp('/rebrand/docs'), { replace: true })
  }, [slug, navigate])

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
        <Markdown components={{
          a: ({ href, children }) => {
            const h = href || ''
            // In-doc cross-link (./slug.md): switch the active doc client-side instead of
            // navigating to a .md URL that would hit the SPA catch-all and land on Home.
            const m = h.match(/\.\/([\w-]+)\.md(?:#.*)?$/)
            if (m && DOCS.some((d) => d.slug === m[1])) {
              return (
                <a href={`#${m[1]}`} className="text-primary-light hover:underline cursor-pointer"
                  onClick={(e) => { e.preventDefault(); setActive(m[1]); window.scrollTo({ top: 0 }) }}>{children}</a>
              )
            }
            const external = /^https?:/.test(h)
            return <a href={h} className="text-primary-light hover:underline" {...(external ? { target: '_blank', rel: 'noopener noreferrer' } : {})}>{children}</a>
          },
        }}>{doc.body}</Markdown>
      </article>
    </div>
  )
}
