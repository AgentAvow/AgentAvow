import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { badgeUrl } from '../../lib/scanApi'

/**
 * Developer landing — the badge growth loop (prototype).
 * check → badge → copy-paste embed → README → referral. Replaces the old
 * 5-line /developers stub. Static preview; wire to badgeUrl/live scan later.
 */

export default function RebrandBadge() {
  const [repo, setRepo] = useState('')
  const [copied, setCopied] = useState(false)
  const navigate = useNavigate()
  const slug = repo.trim() || 'you/your-repo'
  const [owner, name] = slug.includes('/') ? slug.split('/') : ['', '']
  // Dynamic origin so the copied badge resolves NOW (agentgraph.co) and after
  // cutover (agentavow.com) — never a dead hardcoded agentavow.com link pre-DNS.
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://agentavow.com'
  const markdown = `[![AgentAvow Trust](${origin}/api/v1/public/scan/${slug}/badge)](${origin}/check/${slug})`

  const copy = () => {
    if (navigator.clipboard) navigator.clipboard.writeText(markdown)
    setCopied(true)
    setTimeout(() => setCopied(false), 1400)
  }

  const scan = () => navigate(owner && name ? `/rebrand/check/${owner}/${name}` : '/rebrand/check')

  return (
    <div className="max-w-[1080px] mx-auto px-6 py-14">
      <div className="max-w-[60ch]">
        <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">For developers</span>
        <h1 className="mt-3 text-3xl md:text-4xl font-extrabold tracking-tight">
          Ship a <span className="gradient-text-bio">signed</span> trust badge.
        </h1>
        <p className="mt-3 text-text-muted">
          Check your repo, copy one line of Markdown, and every README reader sees a live, verifiable safety
          grade. Clicking it re-checks your tool — the whole loop is public and needs no account.
        </p>
      </div>

      {/* repo input → badge preview */}
      <div className="glass rounded-2xl p-6 mt-8 max-w-[720px]">
        <div className="flex gap-2.5 rounded-xl border border-border bg-surface p-2 pl-4">
          <span className="self-center font-mono text-[14px] text-text-muted shrink-0">github.com/</span>
          <input
            value={repo}
            onChange={(e) => setRepo(e.target.value)}
            placeholder="owner/repo"
            className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[14px] text-text placeholder:text-text-muted"
          />
          <button
            onClick={scan}
            className="font-semibold text-[13.5px] px-4 py-2 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark whitespace-nowrap"
          >
            Scan &amp; mint
          </button>
        </div>

        <div className="mt-5 flex items-center gap-3 flex-wrap">
          <span className="font-mono text-[11.5px] text-text-muted">{owner && name ? 'Live badge:' : 'Preview:'}</span>
          {owner && name ? (
            <img src={badgeUrl(owner, name)} alt={`${slug} trust badge`} className="h-[26px] rounded shadow-md" />
          ) : (
            <span className="inline-flex font-mono text-[12px] rounded overflow-hidden shadow-md">
              <span className="bg-surface-hover text-text px-2.5 py-1.5">🛡 AgentAvow</span>
              <span className="px-2.5 py-1.5 font-bold text-white bg-gradient-to-r from-primary to-primary-dark">Trust: A 94</span>
            </span>
          )}
        </div>

        <div className="relative mt-4">
          <pre className="font-mono text-[12.5px] bg-surface border border-border rounded-xl px-4 py-3.5 text-text overflow-x-auto whitespace-pre-wrap break-all">{markdown}</pre>
          <button onClick={copy} className="absolute top-2 right-2 font-mono text-[11px] px-2 py-1 rounded-md bg-surface-hover border border-border text-text-muted hover:text-primary-light">
            {copied ? 'copied ✓' : 'copy'}
          </button>
        </div>
        <p className="mt-3 font-mono text-[11.5px] text-text-muted/70">
          regenerates on every view — never goes stale in your README
        </p>
      </div>

      {/* CI + SDK */}
      <div className="grid md:grid-cols-3 gap-3.5 mt-6">
        {[
          ['GitHub Action', 'Gate PRs on a minimum grade. Posts the report as a check comment.', 'fail-below: B'],
          ['Python SDK', 'Programmatic scans + attestation verification in your pipeline.', 'agentavow scan owner/repo'],
          ['REST API', 'The same signed verdicts, offline-verifiable against our JWKS.', 'GET /public/scan/{owner}/{repo}'],
        ].map(([h, p, code]) => (
          <div key={h} className="glass rounded-xl p-5">
            <div className="text-[15px] font-semibold">{h}</div>
            <p className="mt-2 text-text-muted text-[13.5px]">{p}</p>
            <code className="inline-block mt-3 font-mono text-[11.5px] text-primary-light bg-surface px-2 py-1 rounded break-all">{code}</code>
          </div>
        ))}
      </div>
      <div className="mt-8 text-center font-mono text-[12px] text-text-muted/70">
        prototype — badge preview + SDK/CLI to be wired to the live badge endpoint
      </div>
    </div>
  )
}
