import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { rp } from '../basePath'
import { useRotatingPlaceholder } from '../lib/hooks'

const REPO_HINTS = ['owner/repo', 'your-org/mcp-server', 'your-agent-toolkit', 'your-python-package']

const DEV_RESOURCES: [string, string, string][] = [
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
  // Trust, or Trust + Adoption (combined) — adoption never travels alone.
  const [variant, setVariant] = useState<'trust' | 'combined'>('trust')
  const [theme, setTheme] = useState<'dark' | 'light'>('dark')
  const navigate = useNavigate()
  const slug = repo.trim() || 'you/your-repo'
  const [owner, name] = slug.includes('/') ? slug.split('/') : ['', '']
  // Dynamic origin so the copied badge resolves NOW (agentgraph.co) and after
  // cutover (agentavow.com) — never a dead hardcoded agentavow.com link pre-DNS.
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://agentavow.com'
  const _p = new URLSearchParams()
  if (variant === 'combined') _p.set('metric', 'combined')
  if (theme === 'light') _p.set('theme', 'light')
  const _qs = _p.toString() ? `?${_p.toString()}` : ''
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

        {/* choose: badge + theme */}
        <div className="mt-5 flex items-center gap-5 flex-wrap">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[11px] uppercase tracking-wide text-text-muted">Badge</span>
            <div className="inline-flex rounded-lg border border-border overflow-hidden">
              {([['trust', 'Trust'], ['combined', 'Trust + Adoption']] as const).map(([v, lbl]) => (
                <button key={v} onClick={() => setVariant(v)} className={`px-3 py-1 font-mono text-[12px] transition-colors ${variant === v ? 'bg-primary/15 text-primary-light' : 'text-text-muted hover:text-text'}`}>{lbl}</button>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[11px] uppercase tracking-wide text-text-muted">Theme</span>
            <div className="inline-flex rounded-lg border border-border overflow-hidden">
              {(['dark', 'light'] as const).map((th) => (
                <button key={th} onClick={() => setTheme(th)} className={`px-3 py-1 font-mono text-[12px] capitalize transition-colors ${theme === th ? 'bg-primary/15 text-primary-light' : 'text-text-muted hover:text-text'}`}>{th}</button>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-4 flex items-center gap-3 flex-wrap">
          <span className="font-mono text-[11.5px] text-text-muted">{owner && name ? 'Live badge:' : 'Preview:'}</span>
          <span className={`inline-flex p-3 rounded-lg ${theme === 'light' ? 'bg-white' : 'bg-surface-hover'}`}>
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

      {/* CI + SDK — each links to its home */}
      <h2 className="mt-12 text-xl font-bold">Wire it into your workflow</h2>
      <div className="grid md:grid-cols-3 gap-3.5 mt-4">
        {([
          ['GitHub Action', 'Gate PRs on a minimum score. Posts the report as a check comment.', 'min_score: 60', 'https://github.com/AgentAvow/AgentAvow'],
          ['Python SDK / CLI', 'Programmatic scans + attestation verification in your pipeline.', 'agentavow scan owner/repo', '/rebrand/docs'],
          ['REST API', 'The same signed verdicts, offline-verifiable against our JWKS.', 'GET /public/scan/{owner}/{repo}', '/api/v1/redoc'],
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
