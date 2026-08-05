import { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useQuery, useMutation } from '@tanstack/react-query'
import { motion, useReducedMotion } from 'framer-motion'
import { fetchPublicScan, badgeUrl } from '../../lib/scanApi'
import { getGradeInfo } from '../../components/trust/gradeSystem'
import { useAuth } from '../../hooks/useAuth'
import api from '../../lib/api'
import { Reveal, RevealStagger, CountUp } from '../components/motion'

/**
 * Rebrand-native check / trust-score page. Reuses the real scan API + getGradeInfo,
 * rendered in the AgentAvow style: animated grade ring, count-up score, prominent
 * badge promotion, and sharing. Repo scans; wallet/search/history parity is a follow-up.
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

/** "Watch this tool" — POSTs to /watches (the alerting backend) when signed in. */
function WatchButton({ owner, repo }: { owner: string; repo: string }) {
  const { user } = useAuth()
  const [watching, setWatching] = useState(false)
  const mutation = useMutation({
    mutationFn: () => api.post('/watches', { owner, repo }),
    onSuccess: () => setWatching(true),
  })
  if (!user) {
    return (
      <Link
        to="/rebrand/login"
        className="text-[13px] font-semibold px-3.5 py-1.5 rounded-lg border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors"
      >
        + Watch this tool
      </Link>
    )
  }
  return (
    <button
      onClick={() => !watching && mutation.mutate()}
      disabled={watching || mutation.isPending}
      className={`text-[13px] font-semibold px-3.5 py-1.5 rounded-lg transition-colors disabled:opacity-70 ${
        watching
          ? 'bg-success/15 text-success border border-success/40'
          : 'border border-border text-text hover:border-primary-light hover:text-primary-light'
      }`}
    >
      {watching ? '✓ Watching — we\'ll alert you' : mutation.isPending ? 'Adding…' : '+ Watch this tool'}
    </button>
  )
}

/** Animated circular grade ring — draws to the score and counts the number up. */
function GradeRing({ score, grade, colorClass }: { score: number; grade: string; colorClass: string }) {
  const reduce = useReducedMotion()
  const r = 52
  return (
    <div className={`relative w-[132px] h-[132px] shrink-0 ${colorClass}`}>
      <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" stroke="currentColor" strokeWidth="8" opacity="0.12" />
        <motion.circle
          cx="60" cy="60" r={r} fill="none" stroke="currentColor" strokeWidth="8" strokeLinecap="round"
          pathLength={1}
          initial={reduce ? false : { pathLength: 0 }}
          animate={{ pathLength: Math.max(score, 0) / 100 }}
          transition={{ duration: 1.1, ease: 'easeOut', delay: 0.15 }}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center">
        <div className="text-center leading-none">
          <div className="text-4xl font-extrabold">{grade}</div>
          <CountUp value={score} className="text-[13px] font-mono text-text-muted" suffix="/100" duration={1100} />
        </div>
      </div>
    </div>
  )
}

/** Share row — copy the link, or post to X. */
function ShareRow({ owner, repo, score, grade }: { owner: string; repo: string; score: number; grade: string }) {
  const [copied, setCopied] = useState(false)
  const url = typeof window !== 'undefined' ? window.location.href : ''
  const text = `${owner}/${repo} scored ${grade} (${score}/100) on AgentAvow — a signed, verifiable trust grade.`
  const copy = () => {
    if (navigator.clipboard) navigator.clipboard.writeText(url)
    setCopied(true)
    setTimeout(() => setCopied(false), 1400)
  }
  return (
    <div className="flex items-center gap-2">
      <button onClick={copy} className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg border border-border text-text-muted hover:border-primary-light hover:text-primary-light transition-colors">
        {copied ? 'Link copied ✓' : '🔗 Copy link'}
      </button>
      <a
        href={`https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(url)}`}
        target="_blank" rel="noopener noreferrer"
        className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg border border-border text-text-muted hover:border-primary-light hover:text-primary-light transition-colors"
      >
        Share on X
      </a>
    </div>
  )
}

/** Prominent badge promotion — the growth loop, not buried at the bottom. */
function BadgePromo({ owner, repo }: { owner: string; repo: string }) {
  const [copied, setCopied] = useState(false)
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://agentavow.com'
  // Dynamic origin so the copied badge actually resolves now (agentgraph.co) and
  // after cutover (agentavow.com) — never a dead agentavow.com link pre-DNS.
  const md = `[![AgentAvow Trust](${origin}/api/v1/public/scan/${owner}/${repo}/badge)](${origin}/check/${owner}/${repo})`
  const copy = () => {
    if (navigator.clipboard) navigator.clipboard.writeText(md)
    setCopied(true)
    setTimeout(() => setCopied(false), 1400)
  }
  return (
    <div className="glass rounded-2xl p-6 mt-6 border-l-4 border-accent/60 relative overflow-hidden">
      <div className="absolute -right-10 -top-10 w-32 h-32 rounded-full bg-accent/10 blur-3xl" />
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="font-mono text-[11px] uppercase tracking-wide text-accent">Show it off</div>
          <h3 className="mt-1 text-lg font-bold">Put a signed trust badge in your README.</h3>
          <p className="mt-1 text-text-muted text-[13.5px] max-w-[46ch]">Regenerates on every view, links back to this verifiable report. One line, no account.</p>
        </div>
        <img src={badgeUrl(owner, repo)} alt="trust badge" className="h-[28px] rounded shadow-md shrink-0" />
      </div>
      <div className="relative mt-4">
        <pre className="font-mono text-[12px] bg-surface border border-border rounded-xl px-4 py-3.5 text-text overflow-x-auto whitespace-pre-wrap break-all">{md}</pre>
        <button onClick={copy} className="absolute top-2 right-2 font-mono text-[11px] px-2.5 py-1 rounded-md bg-surface-hover border border-border text-text-muted hover:text-primary-light">
          {copied ? 'copied ✓' : 'copy'}
        </button>
      </div>
    </div>
  )
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

/** Ghosted skeleton while the scan runs. */
function ResultSkeleton({ owner, repo }: { owner: string; repo: string }) {
  return (
    <div className="max-w-[860px] mx-auto px-6 py-14">
      <div className="glass rounded-2xl p-6 flex items-center gap-6 flex-wrap">
        <div className="w-[132px] h-[132px] rounded-full bg-surface-hover animate-pulse shrink-0" />
        <div className="flex-1 min-w-[200px] space-y-3">
          <div className="h-4 w-2/3 bg-surface-hover rounded animate-pulse" />
          <div className="h-3 w-1/3 bg-surface-hover rounded animate-pulse" />
          <div className="h-3 w-1/2 bg-surface-hover rounded animate-pulse" />
        </div>
      </div>
      <div className="grid grid-cols-3 gap-3 mt-4">
        {[0, 1, 2].map((i) => <div key={i} className="glass rounded-xl h-[76px] animate-pulse" />)}
      </div>
      <div className="mt-6 text-center font-mono text-[12.5px] text-text-muted">scanning {owner}/{repo}…</div>
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

  if (isLoading) return <ResultSkeleton owner={owner} repo={repo} />

  if (isError || !scan) {
    return (
      <div className="max-w-[620px] mx-auto px-6 py-24 text-center">
        <div className="glass rounded-2xl p-8">
          <h2 className="text-xl font-semibold">Couldn't scan {owner}/{repo}</h2>
          <p className="mt-2 text-text-muted text-[14px]">The scanner didn't return a result. On-demand scans need the backend scan service (they don't run in local preview). Try a repo already in the catalog, or check back on the live site.</p>
          <Link to="/rebrand/browse" className="inline-block mt-5 text-[13.5px] font-semibold text-primary-light hover:text-primary">Browse scored tools →</Link>
        </div>
      </div>
    )
  }

  const g = getGradeInfo(scan.trust_score)
  const f = scan.findings
  const cats = scan.category_scores || {}

  return (
    <div className="max-w-[860px] mx-auto px-6 py-14">
      {/* grade hero */}
      <motion.div
        className="glass rounded-2xl p-6 flex items-center gap-6 flex-wrap"
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: 'easeOut' }}
      >
        <GradeRing score={scan.trust_score} grade={g.grade} colorClass={g.textClass} />
        <div className="min-w-0 flex-1">
          <div className="font-mono text-[14px] text-text break-all">{scan.repo}</div>
          <div className="mt-1 text-[15px] font-semibold gradient-text">{scan.trust_tier}</div>
          {scan.metadata && <div className="mt-1 font-mono text-[11.5px] text-text-muted">{scan.metadata.primary_language || 'code'} · {scan.metadata.files_scanned} files · scanned {new Date(scan.scanned_at).toLocaleDateString()}</div>}
          <div className="mt-3 flex items-center gap-2 flex-wrap">
            <span className="flex items-center gap-1.5 font-mono text-[12px] text-success">
              <svg viewBox="0 0 24 24" fill="none" className="w-[15px] h-[15px]"><circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.6" /><path d="M7.5 12.4l3 3 6-6.4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
              Signed · Ed25519
            </span>
            <a href="https://agentgraph.co/.well-known/jwks.json" target="_blank" rel="noopener noreferrer" className="text-[12px] text-primary-light hover:text-primary">Verify →</a>
          </div>
          <div className="mt-3 flex items-center gap-2 flex-wrap">
            <WatchButton owner={owner} repo={repo} />
            <ShareRow owner={owner} repo={repo} score={scan.trust_score} grade={g.grade} />
          </div>
        </div>
      </motion.div>

      {/* findings summary — staggered */}
      <RevealStagger className="grid grid-cols-3 gap-3 mt-4" stagger={0.06}>
        {[['critical', f?.critical ?? 0, 'text-danger'], ['high', f?.high ?? 0, 'text-warning'], ['total', f?.total ?? 0, 'text-text']].map(([lab, n, cls]) => (
          <div key={lab as string} className="glass rounded-xl p-4 text-center">
            <CountUp value={n as number} className={`block text-2xl font-bold tabular-nums ${cls}`} />
            <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted">{lab as string}</div>
          </div>
        ))}
      </RevealStagger>

      {/* badge promotion — moved up, prominent */}
      <Reveal><BadgePromo owner={owner} repo={repo} /></Reveal>

      {/* category subscores */}
      <Reveal>
        <h3 className="mt-8 text-[13px] font-mono uppercase tracking-wide text-text-muted">Category scores</h3>
      </Reveal>
      <RevealStagger className="grid sm:grid-cols-2 gap-2.5 mt-3" stagger={0.04}>
        {Object.entries(CAT_LABELS)
          .filter(([key]) => (cats as Record<string, number>)[key] != null)
          .map(([key, label]) => {
            const sc = (cats as Record<string, number>)[key]
            const cg = getGradeInfo(sc)
            return (
              <div key={key} className="glass rounded-xl px-4 py-3 flex items-center justify-between">
                <span className="text-[14px]">{label}</span>
                <span className={`font-bold text-[13px] px-2 py-0.5 rounded ${cg.textClass} ${cg.bgClass}`}>{cg.grade} · {sc}</span>
              </div>
            )
          })}
      </RevealStagger>

      {/* positive signals */}
      {scan.positive_signals && scan.positive_signals.length > 0 && (
        <Reveal>
          <div className="mt-6 glass rounded-xl p-5">
            <h3 className="text-[13px] font-mono uppercase tracking-wide text-success mb-2">Clean signals</h3>
            <ul className="list-disc pl-5 text-[13.5px] text-text-muted space-y-1">
              {scan.positive_signals.slice(0, 6).map((p) => <li key={p}>{p}</li>)}
            </ul>
          </div>
        </Reveal>
      )}

      {/* findings list */}
      {f?.items && f.items.length > 0 && (
        <>
          <Reveal><h3 className="mt-8 text-[13px] font-mono uppercase tracking-wide text-text-muted">Findings</h3></Reveal>
          <RevealStagger className="flex flex-col gap-2 mt-3" stagger={0.03}>
            {f.items.slice(0, 12).map((it, i) => (
              <div key={i} className="glass rounded-xl px-4 py-3 flex gap-3 items-start">
                <span className={`font-mono text-[10.5px] uppercase tracking-wide px-1.5 py-0.5 rounded shrink-0 mt-0.5 ${SEV_CLASS[it.severity] || SEV_CLASS.info}`}>{it.severity}</span>
                <div className="min-w-0">
                  <div className="text-[14px]">{it.name}</div>
                  <div className="font-mono text-[11.5px] text-text-muted break-all">{it.file_path}{it.line_number ? `:${it.line_number}` : ''}</div>
                </div>
              </div>
            ))}
          </RevealStagger>
        </>
      )}
    </div>
  )
}
