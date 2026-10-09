import { isValidElement, useEffect, type ReactNode } from 'react'
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom'
import { rp } from '../basePath'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import SEOHead from '../../components/SEOHead'
import { slugify } from '../lib/slugify'
import howGradingWorks from '../docs/how-grading-works.md?raw'
import gateOnTheGrade from '../docs/gate-on-the-grade.md?raw'
import checkGuide from '../docs/check-guide.md?raw'
import runLocally from '../docs/run-locally.md?raw'
import trustBadges from '../docs/trust-badges.md?raw'
import verifyAttestations from '../docs/verify-attestations.md?raw'
import autoScanClaudeCode from '../docs/auto-scan-claude-code.md?raw'
import mcpConnector from '../docs/mcp-connector.md?raw'
import behavioralSandbox from '../docs/behavioral-sandbox.md?raw'

/**
 * Rebrand docs PREVIEW — renders the staged trust-first docs (web/src/rebrand/docs/*.md)
 * with react-markdown, styled via a prose wrapper. Isolated from the live /docs; at
 * cutover these get wired into the backend docs system (see docs/rebrand/README.md).
 */

// `blurb` is the page's meta description (≤155 chars). Keep slugs in sync with the
// DOCS list in src/api/docs_content_router.py (SSR of the same files).
const DOCS = [
  { slug: 'how-grading-works', title: 'How scoring works', body: howGradingWorks,
    blurb: 'How the 0–100 trust score and the adoption score are computed from scan findings, and why anyone can recompute them offline.' },
  { slug: 'gate-on-the-grade', title: 'Gate on the answer', body: gateOnTheGrade,
    blurb: 'Block a tool below a minimum trust score — per call, in CI with the GitHub Action, at runtime in your agent, or anywhere via the API.' },
  { slug: 'check-guide', title: 'Reading your scan score', body: checkGuide,
    blurb: 'What a check result means: the trust score, the adoption score, subscores, findings, the recommended posture, and the signature under it.' },
  { slug: 'behavioral-sandbox', title: 'Behavioral sandbox', body: behavioralSandbox,
    blurb: 'What the behavioral sandbox runs, what it observes, how a signed observation moves the trust score, and what a clean run does not prove.' },
  { slug: 'run-locally', title: 'Run locally & in CI', body: runLocally,
    blurb: 'Run the same scanner on your own machine or in CI and get the same trust score as agentavow.com — no drift, no account.' },
  { slug: 'trust-badges', title: 'Add a trust badge', body: trustBadges,
    blurb: 'Add a trust-score badge and an adoption badge to your README — a one-line SVG that links to the full verifiable report.' },
  { slug: 'verify-attestations', title: 'Verify an attestation', body: verifyAttestations,
    blurb: 'Verify an AgentAvow attestation offline: fetch the public JWKS, check the Ed25519 signature, and recompute the trust score byte for byte.' },
  { slug: 'mcp-connector', title: 'MCP connector', body: mcpConnector,
    blurb: 'Connect the AgentAvow MCP server to Claude, Cursor, or VS Code and check any tool’s trust score before your agent connects to it.' },
  { slug: 'auto-scan-claude-code', title: 'Auto-scan in Claude Code', body: autoScanClaudeCode,
    blurb: 'Have Claude Code check every new tool’s trust score automatically — via the plugin, a CLAUDE.md rule, or a SessionStart hook.' },
]

/** Plain text of a react-markdown heading's children, for its id. */
function textOf(node: ReactNode): string {
  if (node == null || typeof node === 'boolean') return ''
  if (typeof node === 'string' || typeof node === 'number') return String(node)
  if (Array.isArray(node)) return node.map(textOf).join('')
  if (isValidElement<{ children?: ReactNode }>(node)) return textOf(node.props.children)
  return ''
}

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
  '[&_table]:w-full [&_table]:border-collapse [&_table]:text-[14px]',
  '[&_th]:border [&_th]:border-border [&_th]:bg-surface [&_th]:px-3 [&_th]:py-2 [&_th]:text-left [&_th]:align-top [&_th]:font-semibold [&_th]:text-text',
  '[&_td]:border [&_td]:border-border [&_td]:px-3 [&_td]:py-2 [&_td]:align-top [&_td]:text-text-muted',
].join(' ')

export default function RebrandDocs() {
  // Deep-linkable: /docs/<slug> selects a doc (shareable URLs); the bare /docs
  // lands on the first. Clicking a doc pushes the slug so the URL stays copyable.
  const { slug } = useParams()
  const { hash } = useLocation()
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
  // After the doc renders, land on the #anchor heading (direct hit, cross-doc link,
  // or in-page link); with no anchor, a doc switch starts at the top.
  useEffect(() => {
    const el = hash.length > 1 ? document.getElementById(hash.slice(1)) : null
    if (el) el.scrollIntoView()
    else window.scrollTo({ top: 0 })
  }, [doc.slug, hash])

  return (
    <div className="max-w-[1080px] mx-auto px-6 py-14 grid md:grid-cols-[220px_1fr] gap-10">
      <SEOHead title={`${doc.title} · Docs`} description={doc.blurb} path={`/docs/${doc.slug}`} />
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
        {/* GFM for tables. singleTilde off: the docs use "~" for "about", never strikethrough. */}
        <Markdown remarkPlugins={[[remarkGfm, { singleTilde: false }]]} components={{
          // Wide tables scroll inside their own box instead of widening the page.
          table: ({ children }) => <div className="my-4 overflow-x-auto"><table>{children}</table></div>,
          // GitHub-style ids on h2/h3 so #anchor links resolve (same ids as the SSR render).
          h2: ({ children }) => <h2 id={slugify(textOf(children))} className="scroll-mt-24">{children}</h2>,
          h3: ({ children }) => <h3 id={slugify(textOf(children))} className="scroll-mt-24">{children}</h3>,
          a: ({ href, children }) => {
            const h = href || ''
            // In-doc cross-link (./slug.md or ./slug.md#anchor): switch the active doc
            // client-side, keeping the anchor, instead of navigating to a .md URL that
            // would hit the SPA catch-all and land on Home.
            const m = h.match(/\.\/([\w-]+)\.md(#[\w-]+)?$/)
            if (m && DOCS.some((d) => d.slug === m[1])) {
              return (
                <Link to={rp(`/rebrand/docs/${m[1]}`) + (m[2] ?? '')} className="text-primary-light hover:underline">{children}</Link>
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
