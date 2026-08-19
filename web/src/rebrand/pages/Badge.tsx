import { useQuery } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import api from '../../lib/api'
import { rp } from '../basePath'
import { useRotatingPlaceholder } from '../lib/hooks'

declare global {
  interface Window { AgentAvow?: { render: (root?: Element | Document) => void } }
}

/**
 * Live preview that dogfoods the real hosted widget.js — loads the script once,
 * then re-renders a [data-agentavow-tool] target whenever the slug changes.
 */
function WidgetPreview({ slug }: { slug: string }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const origin = typeof window !== 'undefined' ? window.location.origin : ''
    const existing = document.querySelector<HTMLScriptElement>('script[data-agentavow-widget]')
    if (!existing) {
      const s = document.createElement('script')
      s.src = `${origin}/widget.js`
      s.async = true
      s.setAttribute('data-agentavow-widget', '1')
      s.onload = () => window.AgentAvow?.render(ref.current || undefined)
      document.body.appendChild(s)
    } else if (window.AgentAvow) {
      window.AgentAvow.render(ref.current || undefined)
    }
  }, [slug])
  // key forces a fresh, unmounted target element whenever the slug changes
  return (
    <div ref={ref}>
      <div key={slug} data-agentavow-tool={slug} />
    </div>
  )
}

const REPO_HINTS = ['owner/repo', 'your-org/mcp-server', 'your-agent-toolkit', 'your-python-package']

const DEV_RESOURCES: [string, string, string][] = [
  ['Declare your scope', 'Ship an .agentavow.yml — declared egress + capabilities, surfaced on your score.', 'https://github.com/AgentAvow/AgentAvow/blob/main/.agentavow.yml'],
  ['API sandbox', 'Try the scan API live — no signup, ephemeral token, read-only.', '/rebrand/sandbox'],
  ['Docs', 'Guides: reading a score, badges, verifying attestations.', '/rebrand/docs'],
  ['API reference', 'The REST API — every endpoint, offline-verifiable verdicts.', '/api/v1/redoc'],
  ['Verify keys (JWKS)', 'Public signing keys to verify any attestation offline.', 'https://agentgraph.co/.well-known/jwks.json'],
  ['How it works', 'The score, the evidence format, and the open standards.', '/rebrand/how-it-works'],
  ['GitHub', 'Source, specs, conformance fixtures, and issues.', 'https://github.com/AgentAvow/AgentAvow'],
]

/**
 * Developer landing — the badge growth loop (prototype).
 * check → badge → copy-paste embed → README → referral. Replaces the old
 * 5-line /developers stub. Static preview; wire to badgeUrl/live scan later.
 */

export default function RebrandBadge() {
  const [repo, setRepo] = useState('')
  const [copied, setCopied] = useState(false)
  const [copiedW, setCopiedW] = useState(false)
  // Trust, or Trust + Adoption (combined) — adoption never travels alone.
  const [variant, setVariant] = useState<'trust' | 'combined'>('trust')
  const navigate = useNavigate()
  const slug = repo.trim() || 'you/your-repo'
  const [owner, name] = slug.includes('/') ? slug.split('/') : ['', '']
  // Dynamic origin so the copied badge resolves NOW (agentgraph.co) and after
  // cutover (agentavow.com) — never a dead hardcoded agentavow.com link pre-DNS.
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://agentavow.com'
  const _qs = variant === 'combined' ? '?metric=combined' : ''
  const badgeSrc = `${origin}/api/v1/public/scan/${slug}/badge${_qs}`
  const badgeAlt = variant === 'trust' ? 'AgentAvow Trust' : 'AgentAvow'
  const markdown = `[![${badgeAlt}](${badgeSrc})](${origin}/check/${slug})`

  const copy = () => {
    if (navigator.clipboard) navigator.clipboard.writeText(markdown)
    setCopied(true)
    setTimeout(() => setCopied(false), 1400)
  }

  const scan = () => navigate(owner && name ? rp(`/rebrand/check/${owner}/${name}`) : rp('/rebrand/check'))
  const hint = useRotatingPlaceholder(REPO_HINTS)

  // Certified detection — so a maintainer minting a Certified tool's badge sees the
  // level-up (the badge itself already renders the earned treatment server-side).
  const { data: certData } = useQuery({
    queryKey: ['badge-cert', owner, name],
    enabled: !!(owner && name.length >= 2),
    retry: false,
    staleTime: 60_000,
    queryFn: async () => {
      try {
        return (await api.get<{ certified?: { eligible?: boolean } }>(`/public/scan/${owner}/${name}`)).data
      } catch { return null }
    },
  })
  const isCertified = !!certData?.certified?.eligible

  const widgetSnippet = `<script src="${origin}/widget.js"\n        data-tool="${slug}"></script>`
  const copyWidget = () => {
    if (navigator.clipboard) navigator.clipboard.writeText(widgetSnippet)
    setCopiedW(true)
    setTimeout(() => setCopiedW(false), 1400)
  }

  return (
    <div className="max-w-[1080px] mx-auto px-6 py-14">
      <div className="max-w-[60ch]">
        <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">For developers</span>
        <h1 className="mt-3 text-3xl md:text-4xl font-extrabold tracking-tight">
          Ship a <span className="gradient-text-bio">signed</span> trust badge.
        </h1>
        <p className="mt-3 text-text-muted">
          Check your repo, choose a badge, copy one line of Markdown, and every README reader sees a live,
          verifiable safety score. Clicking it re-checks your tool — the whole loop is public and needs no account.
        </p>
      </div>

      {/* repo input → badge chooser → live preview */}
      <div className="glass rounded-2xl p-6 mt-8 max-w-[720px]">
        <div className="flex gap-2.5 rounded-xl border border-border bg-surface p-2 pl-4">
          <span className="self-center font-mono text-[14px] text-text-muted shrink-0">github.com/</span>
          <input
            value={repo}
            onChange={(e) => setRepo(e.target.value)}
            placeholder={repo ? '' : hint}
            className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[14px] text-text placeholder:text-text-muted"
          />
          <button
            onClick={scan}
            className="font-semibold text-[13.5px] px-4 py-2 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark whitespace-nowrap"
          >
            Scan &amp; mint
          </button>
        </div>

        {/* choose: badge variant */}
        <div className="mt-5 flex items-center gap-5 flex-wrap">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[11px] uppercase tracking-wide text-text-muted">Badge</span>
            <div className="inline-flex rounded-lg border border-border overflow-hidden">
              {([['trust', 'Trust'], ['combined', 'Trust + Adoption']] as const).map(([v, lbl]) => (
                <button key={v} onClick={() => setVariant(v)} className={`px-3 py-1 font-mono text-[12px] transition-colors ${variant === v ? 'bg-primary/15 text-primary-light' : 'text-text-muted hover:text-text'}`}>{lbl}</button>
              ))}
            </div>
          </div>
        </div>

        {isCertified && (
          <div className="mt-4 rounded-xl p-4 flex items-center gap-3.5" style={{ background: 'linear-gradient(120deg, rgba(45,212,191,0.12), rgba(232,121,249,0.10))', border: '1px solid rgba(45,212,191,0.3)' }}>
            <span className="font-mono text-[10.5px] font-extrabold tracking-[0.12em] px-2.5 py-1 rounded-full shrink-0" style={{ background: 'linear-gradient(120deg,#2dd4bf,#e879f9)', color: '#06231f' }}>✓ CERTIFIED</span>
            <div className="min-w-0">
              <div className="text-[14px] font-bold">Your badge just leveled up — {owner}/{name} is Certified.</div>
              <div className="text-[12.5px] text-text-muted mt-0.5">It clears the full conjunctive gate, so your README badge renders the earned Certified treatment automatically — and drops back if it ever slips. <Link to={rp('/rebrand/certified')} className="text-primary-light hover:text-primary font-semibold">What that means →</Link></div>
            </div>
          </div>
        )}

        <div className="mt-4 flex items-center gap-3 flex-wrap">
          <span className="font-mono text-[11.5px] text-text-muted">{owner && name ? 'Live badge:' : 'Preview:'}</span>
          <span className="inline-flex p-3 rounded-lg bg-surface-hover">
            {owner && name ? (
              <img src={badgeSrc} alt={`${slug} ${badgeAlt}`} className="h-[24px] rounded shadow-md" />
            ) : variant === 'trust' ? (
              <span className="inline-flex font-mono text-[12px] rounded overflow-hidden shadow-md">
                <span className="bg-[#38445f] text-white px-2.5 py-1.5">AgentAvow Trust</span>
                <span className="px-2.5 py-1.5 font-bold text-white bg-[#22C55E]">94/100</span>
              </span>
            ) : (
              <span className="inline-flex font-mono text-[12px] rounded overflow-hidden shadow-md">
                <span className="bg-[#38445f] text-white px-2.5 py-1.5">AgentAvow</span>
                <span className="px-2.5 py-1.5 font-bold text-white bg-[#22C55E]">94/100</span>
                <span className="px-2.5 py-1.5 font-bold text-[#7fe9d9] bg-[#233047]">★ 490M</span>
              </span>
            )}
          </span>
        </div>

        <div className="relative mt-4">
          <pre className="font-mono text-[12.5px] bg-surface border border-border rounded-xl px-4 py-3.5 pr-16 text-text overflow-x-auto whitespace-pre-wrap break-all">{markdown}</pre>
          <button onClick={copy} className="absolute top-2 right-2 font-mono text-[11px] px-2 py-1 rounded-md bg-surface-hover border border-border text-text-muted hover:text-primary-light">
            {copied ? 'copied ✓' : 'copy'}
          </button>
        </div>
        <p className="mt-3 font-mono text-[11.5px] text-text-muted/70">
          regenerates on every view — never goes stale in your README
        </p>
      </div>

      {/* live interactive widget — the card + in-browser verify, one <script> tag */}
      <div className="glass rounded-2xl p-6 mt-6 max-w-[720px]">
        <div className="flex items-baseline justify-between gap-3 flex-wrap">
          <h2 className="text-lg font-bold">Or embed the live widget</h2>
          <span className="font-mono text-[11px] text-text-muted">card + offline verify · one script tag</span>
        </div>
        <p className="mt-1.5 text-text-muted text-[13.5px] max-w-[58ch]">
          The full dual-mark card, linked to the report — plus a <strong className="text-text">Verify offline</strong> button
          that recomputes the Ed25519 signature in your reader's own browser. For docs sites, landing pages, and dashboards.
        </p>
        <div className="mt-4 grid sm:grid-cols-2 gap-5 items-start">
          <div>
            <div className="font-mono text-[10.5px] uppercase tracking-wide text-text-muted mb-1.5">Live preview</div>
            {owner && name
              ? <WidgetPreview slug={slug} />
              : <p className="text-text-muted text-[13px] italic">Enter a repo above to preview the live widget.</p>}
          </div>
          <div>
            <div className="font-mono text-[10.5px] uppercase tracking-wide text-text-muted mb-1.5">Embed</div>
            <div className="relative">
              <pre className="font-mono text-[12px] bg-surface border border-border rounded-xl px-4 py-3.5 pr-16 text-text overflow-x-auto whitespace-pre-wrap break-all">{widgetSnippet}</pre>
              <button onClick={copyWidget} className="absolute top-2 right-2 font-mono text-[11px] px-2 py-1 rounded-md bg-surface-hover border border-border text-text-muted hover:text-primary-light">
                {copiedW ? 'copied ✓' : 'copy'}
              </button>
            </div>
            <p className="mt-3 font-mono text-[11px] text-text-muted/70">
              no framework · no tracking · CORS-open endpoints only
            </p>
          </div>
        </div>
      </div>

      {/* CI + SDK — each links to its home */}
      <h2 className="mt-12 text-xl font-bold">Wire it into your workflow</h2>
      <div className="grid md:grid-cols-3 gap-3.5 mt-4">
        {([
          ['Local scan (CLI)', 'Scan your working tree offline — no code leaves your machine. SARIF + JSON out, gate on a min score.', 'agentavow scan .', 'https://github.com/AgentAvow/AgentAvow/tree/main/src/scanner/local_scan.py'],
          ['GitHub Action', 'Runs the scan in your runner — works on private repos, gates the build, uploads SARIF.', 'uses: AgentAvow/AgentAvow/local-scan-action@main', 'https://github.com/AgentAvow/AgentAvow/tree/main/local-scan-action'],
          ['REST API', 'The hosted scan + signed attestation, offline-verifiable against our JWKS.', 'GET /public/scan/{owner}/{repo}', '/api/v1/redoc'],
        ] as [string, string, string, string][]).map(([h, p, code, href]) => (
          <a key={h} href={rp(href)} target={href.startsWith('http') ? '_blank' : undefined} rel="noopener noreferrer" className="glass card-hover rounded-xl p-5 block">
            <div className="flex items-center justify-between gap-2"><div className="text-[15px] font-semibold">{h}</div><span className="text-primary-light text-[13px]">→</span></div>
            <p className="mt-2 text-text-muted text-[13.5px]">{p}</p>
            <code className="inline-block mt-3 font-mono text-[11.5px] text-primary-light bg-surface px-2 py-1 rounded break-all">{code}</code>
          </a>
        ))}
      </div>

      {/* everything a developer needs, in one place */}
      <h2 className="mt-12 text-xl font-bold">Developer resources</h2>
      <div className="grid sm:grid-cols-2 gap-2.5 mt-4">
        {DEV_RESOURCES.map(([h, p, href]) => {
          const external = href.startsWith('http') || href.startsWith('/api')
          const inner = (
            <>
              <div className="flex items-center justify-between gap-2"><div className="text-[14.5px] font-semibold">{h}</div><span className="text-primary-light text-[13px] shrink-0">{external ? '↗' : '→'}</span></div>
              <div className="text-[13px] text-text-muted mt-0.5">{p}</div>
            </>
          )
          return external
            ? <a key={h} href={href} target="_blank" rel="noopener noreferrer" className="glass card-hover rounded-xl px-4 py-3 block">{inner}</a>
            : <Link key={h} to={rp(href)} className="glass card-hover rounded-xl px-4 py-3 block">{inner}</Link>
        })}
      </div>
    </div>
  )
}
