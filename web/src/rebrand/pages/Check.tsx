import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { fetchPublicScan, badgeUrl } from '../../lib/scanApi'
import { getGradeInfo } from '../../components/trust/gradeSystem'

/**
 * Rebrand-native check result — reuses the real scan API + getGradeInfo, rendered in
 * the rebrand style (rather than forking the shared Check.tsx). Repo scans; wallet /
 * search / history parity is a follow-up.
 */

const CAT_LABELS: Record<string, string> = {
  secret_hygiene: 'Secret hygiene',
  code_safety: 'Code safety',
  data_handling: 'Data handling',
  filesystem_access: 'Filesystem access',
  dependency_health: 'Dependency health',
}

const SEV_CLASS: Record<string, string> = {
  critical: 'text-danger bg-danger/15',
  high: 'text-danger bg-danger/10',
  medium: 'text-warning bg-warning/15',
  low: 'text-text-muted bg-surface-hover',
  info: 'text-text-muted bg-surface-hover',
}

function Hero() {
  const [value, setValue] = useState('')
  const navigate = useNavigate()
  const go = () => {
    const m = value.trim().match(/(?:github\.com\/)?([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/)
    if (m) navigate(`/rebrand/check/${m[1]}/${m[2]}`)
  }
  return (
    <div className="max-w-[1080px] mx-auto px-6 py-20 text-center">
      <h1 className="text-3xl md:text-5xl font-extrabold tracking-tight">
        Check a <span className="gradient-text-bio">tool</span>.
      </h1>
      <p className="mt-4 text-text-muted">Paste a GitHub repo to get a signed safety grade.</p>
      <form onSubmit={(e) => { e.preventDefault(); go() }} className="glass mt-7 mx-auto max-w-[560px] flex gap-2.5 rounded-2xl p-2 pl-4">
        <input value={value} onChange={(e) => setValue(e.target.value)} placeholder="github.com/owner/repo"
          className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[15px] text-text placeholder:text-text-muted" />
        <button type="submit" className="font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark">Check</button>
      </form>
    </div>
  )
}

export default function RebrandCheck() {
  const { owner, repo } = useParams()
  if (!owner || !repo) return <Hero />
  return <Result owner={owner} repo={repo} />
}

function Result({ owner, repo }: { owner: string; repo: string }) {
  const { data: scan, isLoading, isError } = useQuery({
    queryKey: ['rebrand-scan', owner, repo],
    queryFn: () => fetchPublicScan(owner, repo),
    retry: 0,
  })

  if (isLoading) {
    return (
      <div className="max-w-[860px] mx-auto px-6 py-24 text-center">
        <div className="inline-block w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
        <p className="mt-4 font-mono text-[13px] text-text-muted">scanning {owner}/{repo}…</p>
      </div>
    )
  }
  if (isError || !scan) {
    return (
      <div className="max-w-[620px] mx-auto px-6 py-24 text-center">
        <div className="glass rounded-2xl p-8">
          <h2 className="text-xl font-semibold">Couldn't scan {owner}/{repo}</h2>
          <p className="mt-2 text-text-muted text-[14px]">The scanner didn't return a result. On-demand scans need the backend scan service (they don't run in local preview). Try a repo already in the catalog, or check back on the live site.</p>
        </div>
      </div>
    )
  }

  const g = getGradeInfo(scan.trust_score)
  const f = scan.findings
  const cats = scan.category_scores || {}

  return (
    <div className="max-w-[860px] mx-auto px-6 py-14">
      {/* hero result */}
      <div className="glass rounded-2xl p-6 flex items-center gap-5 flex-wrap">
        <div className={`w-20 h-20 rounded-2xl grid place-items-center text-4xl font-extrabold shrink-0 ${g.textClass} ${g.bgClass}`}>{g.grade}</div>
        <div className="min-w-0">
          <div className="font-mono text-[14px] text-text break-all">{scan.repo}</div>
          <div className="mt-1 text-[14px] font-semibold gradient-text">{scan.trust_tier} · {scan.trust_score}/100</div>
          {scan.metadata && <div className="mt-1 font-mono text-[11.5px] text-text-muted">{scan.metadata.primary_language || 'code'} · {scan.metadata.files_scanned} files · scanned {new Date(scan.scanned_at).toLocaleDateString()}</div>}
        </div>
        <div className="ml-auto flex flex-col items-end gap-1">
          <span className="flex items-center gap-2 font-mono text-[12px] text-success">
            <svg viewBox="0 0 24 24" fill="none" className="w-[16px] h-[16px]"><circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.6"/><path d="M7.5 12.4l3 3 6-6.4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
            Signed · Ed25519
          </span>
          <a href="https://agentgraph.co/.well-known/jwks.json" className="text-[12px] text-primary-light hover:text-primary">Verify this attestation →</a>
        </div>
      </div>

      {/* findings summary */}
      <div className="grid grid-cols-3 gap-3 mt-4">
        {[['critical', f?.critical ?? 0, 'text-danger'], ['high', f?.high ?? 0, 'text-warning'], ['total', f?.total ?? 0, 'text-text']].map(([lab, n, cls]) => (
          <div key={lab as string} className="glass rounded-xl p-4 text-center">
            <div className={`text-2xl font-bold tabular-nums ${cls}`}>{n as number}</div>
            <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted">{lab as string}</div>
          </div>
        ))}
      </div>

      {/* category subscores */}
      <h3 className="mt-8 text-[13px] font-mono uppercase tracking-wide text-text-muted">Category scores</h3>
      <div className="grid sm:grid-cols-2 gap-2.5 mt-3">
        {Object.entries(CAT_LABELS).map(([key, label]) => {
          const sc = (cats as Record<string, number>)[key]
          if (sc == null) return null
          const cg = getGradeInfo(sc)
          return (
            <div key={key} className="glass rounded-xl px-4 py-3 flex items-center justify-between">
              <span className="text-[14px]">{label}</span>
              <span className={`font-bold text-[13px] px-2 py-0.5 rounded ${cg.textClass} ${cg.bgClass}`}>{cg.grade} · {sc}</span>
            </div>
          )
        })}
      </div>

      {/* positive signals */}
      {scan.positive_signals && scan.positive_signals.length > 0 && (
        <div className="mt-6 glass rounded-xl p-5">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-success mb-2">Clean signals</h3>
          <ul className="list-disc pl-5 text-[13.5px] text-text-muted space-y-1">
            {scan.positive_signals.slice(0, 6).map((p) => <li key={p}>{p}</li>)}
          </ul>
        </div>
      )}

      {/* findings list */}
      {f?.items && f.items.length > 0 && (
        <>
          <h3 className="mt-8 text-[13px] font-mono uppercase tracking-wide text-text-muted">Findings</h3>
          <div className="flex flex-col gap-2 mt-3">
            {f.items.slice(0, 12).map((it, i) => (
              <div key={i} className="glass rounded-xl px-4 py-3 flex gap-3 items-start">
                <span className={`font-mono text-[10.5px] uppercase tracking-wide px-1.5 py-0.5 rounded shrink-0 mt-0.5 ${SEV_CLASS[it.severity] || SEV_CLASS.info}`}>{it.severity}</span>
                <div className="min-w-0">
                  <div className="text-[14px]">{it.name}</div>
                  <div className="font-mono text-[11.5px] text-text-muted break-all">{it.file_path}{it.line_number ? `:${it.line_number}` : ''}</div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* badge embed */}
      <div className="mt-8 glass rounded-xl p-5">
        <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-3">Show it off</h3>
        <div className="flex items-center gap-3 flex-wrap">
          <img src={badgeUrl(owner, repo)} alt="trust badge" className="h-[26px] rounded" />
          <code className="font-mono text-[11.5px] text-text-muted bg-surface px-2 py-1 rounded break-all">![Trust]({badgeUrl(owner, repo)})</code>
        </div>
      </div>
    </div>
  )
}
