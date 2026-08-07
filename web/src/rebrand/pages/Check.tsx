import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { rp } from '../basePath'
import { useQuery, useMutation } from '@tanstack/react-query'
import { motion, useReducedMotion } from 'framer-motion'
import { fetchPublicScan, badgeUrl, publicApi } from '../../lib/scanApi'
import { getGradeInfo } from '../../components/trust/gradeSystem'
import { useAuth } from '../../hooks/useAuth'
import api from '../../lib/api'
import { Reveal, RevealStagger, CountUp } from '../components/motion'
import { useRotatingPlaceholder } from '../lib/hooks'
import { summarize } from '../lib/summarize'
import { downloadScoreCard } from '../lib/scoreCard'

/**
 * Rebrand-native check / trust-score page — built for ANY user, not just devs.
 * Plain-English verdict up top, then the signed evidence. Animated scanning
 * loader (scans are slow, so we make the wait fun). Developer bits (badge, SVG,
 * API) live lower down where the people who need them will look.
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

const VERDICT_STYLE = {
  safe: { ring: 'text-success', chip: 'bg-success/15 text-success', label: 'SAFE' },
  caution: { ring: 'text-warning', chip: 'bg-warning/15 text-warning', label: 'CAUTION' },
  risky: { ring: 'text-danger', chip: 'bg-danger/15 text-danger', label: 'RISKY' },
}

const CHECK_HINTS = ['github.com/owner/repo', 'an MCP server', 'an npm package', 'a Python package', 'an agent skill']

/** "Watch this tool" — the PRIMARY action. Full-width gradient CTA. */
function WatchCTA({ owner, repo }: { owner: string; repo: string }) {
  const { user } = useAuth()
  const [watching, setWatching] = useState(false)
  const mutation = useMutation({ mutationFn: () => api.post('/watches', { owner, repo }), onSuccess: () => setWatching(true) })
  const base = 'w-full flex items-center justify-center gap-2.5 text-[15px] font-bold px-5 py-3.5 rounded-xl transition-all'
  const grad = 'text-white bg-gradient-to-r from-primary to-accent shadow-lg shadow-primary/25 hover:shadow-primary/40 hover:-translate-y-0.5'
  const star = <svg viewBox="0 0 24 24" fill="currentColor" className="w-[17px] h-[17px] shrink-0"><path d="M12 2.5l2.9 6.1 6.6.9-4.8 4.6 1.2 6.6L12 18.6 6.1 21.3l1.2-6.6L2.5 9.5l6.6-.9z"/></svg>
  if (!user) return <Link to={rp('/rebrand/login')} className={`${base} ${grad}`}>{star} Watch this tool</Link>
  if (watching) return <div className={`${base} bg-success/15 text-success border border-success/40`}>✓ Watching — we'll alert you if the grade drops</div>
  return (
    <button onClick={() => mutation.mutate()} disabled={mutation.isPending} className={`${base} ${grad} disabled:opacity-70`}>
      {star} {mutation.isPending ? 'Adding…' : 'Watch this tool'}
    </button>
  )
}

/** Co-equal score ring — used for BOTH Attestation Trust and Adoption so the two
 * scores read as peers. Draws to `fill` (0–1) when given, a full ring otherwise;
 * dashed + muted when there's no data (e.g. a just-launched tool with no adoption). */
function ScoreRing({ center, sub, hex, fill, dashed }: { center: string; sub?: string; hex: string; fill?: number; dashed?: boolean }) {
  const reduce = useReducedMotion()
  return (
    <div className="relative w-[128px] h-[128px] shrink-0 mx-auto" style={{ color: hex }}>
      <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
        <circle cx="60" cy="60" r="52" fill="none" stroke="currentColor" strokeWidth="9" opacity="0.14" />
        {dashed ? (
          <circle cx="60" cy="60" r="52" fill="none" stroke="currentColor" strokeWidth="9" strokeLinecap="round" strokeDasharray="2 12" opacity="0.55" />
        ) : (
          <motion.circle cx="60" cy="60" r="52" fill="none" stroke="currentColor" strokeWidth="9" strokeLinecap="round"
            pathLength={1} initial={reduce ? false : { pathLength: 0 }} animate={{ pathLength: fill == null ? 1 : Math.max(fill, 0.02) }}
            transition={{ duration: 1.2, ease: 'easeOut', delay: 0.15 }} />
        )}
      </svg>
      <div className="absolute inset-0 grid place-items-center">
        <div className="text-center leading-none">
          <div className="text-[38px] font-extrabold" style={{ color: hex }}>{center}</div>
          {sub && <div className="mt-1 text-[12px] font-mono text-text-muted">{sub}</div>}
        </div>
      </div>
    </div>
  )
}

/** Score-over-time line chart. Only shown once there's real multi-scan history —
 * a single point is meaningless, so we hide it until the tool has been re-scanned. */
function ScoreHistory({ history, current }: { history: { score: number; at?: number }[]; current: number }) {
  const merged = [...history]
  // Append the current scan as "now" if it isn't already the last recorded point.
  if (!merged.length || merged[merged.length - 1].score !== current) merged.push({ score: current })
  const pts = merged.slice(-30)
  if (pts.length < 2) return null // nothing meaningful to plot yet

  const W = 320, H = 90, PAD = 8
  const x = (i: number) => PAD + (i / (pts.length - 1)) * (W - 2 * PAD)
  const y = (s: number) => H - PAD - (s / 100) * (H - 2 * PAD) // fixed 0–100 axis
  const line = pts.map((p, i) => `${x(i)},${y(p.score)}`).join(' ')
  const lastG = getGradeInfo(pts[pts.length - 1].score)
  const fmt = (at?: number) => at ? new Date(at * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : 'now'
  const firstDate = fmt(pts[0].at)
  const lastDate = fmt(pts[pts.length - 1].at)

  return (
    <Reveal>
      <div className="mt-6 glass rounded-2xl p-6">
        <div className="flex items-baseline justify-between gap-3 flex-wrap">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Trust score over time</h3>
          <span className="font-mono text-[11.5px] text-text-muted">{pts.length} scans · now <b style={{ color: lastG.color }}>{current}/100</b></span>
        </div>
        <p className="text-text-muted text-[13px] mt-1 mb-3">A living record — every re-scan, not a one-shot snapshot. Watch this tool to be alerted the moment the line drops.</p>
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-[90px]" preserveAspectRatio="none" aria-hidden="true">
          {[0, 50, 100].map((g) => <line key={g} x1={PAD} y1={y(g)} x2={W - PAD} y2={y(g)} stroke="currentColor" className="text-border" strokeWidth="0.5" opacity="0.5" />)}
          <polyline points={line} fill="none" stroke={lastG.color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
          {pts.map((p, i) => <circle key={i} cx={x(i)} cy={y(p.score)} r={i === pts.length - 1 ? 4 : 2.5} fill={getGradeInfo(p.score).color} />)}
        </svg>
        {/* time axis labels */}
        <div className="flex justify-between font-mono text-[10.5px] text-text-muted/70 mt-1">
          <span>{firstDate}</span>
          <span className="text-text-muted/50">score 0–100 (higher = safer)</span>
          <span>{lastDate}</span>
        </div>
      </div>
    </Reveal>
  )
}

/** Share row — copy link + branded X / Bluesky icons. */
function ShareRow({ owner, repo, score, grade }: { owner: string; repo: string; score: number; grade: string }) {
  const [copied, setCopied] = useState(false)
  const url = typeof window !== 'undefined' ? window.location.href : ''
  const text = `${owner}/${repo} scored ${grade} (${score}/100) on AgentAvow — a signed, verifiable trust grade.`
  const copy = () => { if (navigator.clipboard) navigator.clipboard.writeText(url); setCopied(true); setTimeout(() => setCopied(false), 1400) }
  const icon = 'grid place-items-center w-8 h-8 rounded-lg border border-border text-text-muted hover:border-primary-light hover:text-primary-light transition-colors'
  return (
    <div className="flex items-center gap-2 flex-wrap">
      <button onClick={copy} className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg border border-border text-text-muted hover:border-primary-light hover:text-primary-light transition-colors">{copied ? 'Link copied ✓' : '🔗 Copy link'}</button>
      <a href={`https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(url)}`} target="_blank" rel="noopener noreferrer" className={icon} aria-label="Share on X">
        <svg viewBox="0 0 24 24" fill="currentColor" className="w-[15px] h-[15px]"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
      </a>
      <a href={`https://bsky.app/intent/compose?text=${encodeURIComponent(text + ' ' + url)}`} target="_blank" rel="noopener noreferrer" className={icon} aria-label="Share on Bluesky">
        <svg viewBox="0 0 24 24" fill="currentColor" className="w-[15px] h-[15px]"><path d="M12 10.8c-1.087-2.114-4.046-6.053-6.798-7.995C2.566.944 1.561 1.266.902 1.565.139 1.908 0 3.08 0 3.768c0 .69.378 5.65.624 6.479.785 2.627 3.6 3.476 6.18 3.232-4.165.712-8.232 2.625-4.412 8.51C5.777 26.373 11.268 21.248 12 17.04c.732 4.208 6.13 9.282 9.608 4.95 3.82-5.886-.247-7.799-4.412-8.511 2.58.244 5.395-.605 6.18-3.232.246-.828.624-5.79.624-6.479 0-.688-.139-1.86-.902-2.203-.659-.299-1.664-.621-4.3 1.24C16.046 4.748 13.087 8.687 12 10.8z"/></svg>
      </a>
    </div>
  )
}

/** Prominent badge promotion — dynamic origin so copied embeds always resolve. */
function BadgePromo({ owner, repo }: { owner: string; repo: string }) {
  const [copied, setCopied] = useState(false)
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://agentavow.com'
  const md = `[![AgentAvow Trust](${origin}/api/v1/public/scan/${owner}/${repo}/badge)](${origin}/check/${owner}/${repo})`
  const copy = () => { if (navigator.clipboard) navigator.clipboard.writeText(md); setCopied(true); setTimeout(() => setCopied(false), 1400) }
  return (
    <div className="glass rounded-2xl p-6 border-l-4 border-accent/60 relative overflow-hidden">
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
        <button onClick={copy} className="absolute top-2 right-2 font-mono text-[11px] px-2.5 py-1 rounded-md bg-surface-hover border border-border text-text-muted hover:text-primary-light">{copied ? 'copied ✓' : 'copy'}</button>
      </div>
    </div>
  )
}

function Hero() {
  const [value, setValue] = useState('')
  const navigate = useNavigate()
  const hint = useRotatingPlaceholder(CHECK_HINTS)
  const go = () => {
    const m = value.trim().match(/(?:github\.com\/)?([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/)
    if (m) navigate(rp(`/rebrand/check/${m[1]}/${m[2]}`))
  }
  return (
    <div className="max-w-[1080px] mx-auto px-6 py-20 text-center">
      <h1 className="text-3xl md:text-5xl font-extrabold tracking-tight">Is this tool <span className="gradient-text-bio">safe</span>?</h1>
      <p className="mt-4 text-text-muted max-w-[46ch] mx-auto">Paste anything your agent connects to. We'll tell you — in plain English — whether it's safe, and prove it with a signed grade.</p>
      <form onSubmit={(e) => { e.preventDefault(); go() }} className="glass mt-7 mx-auto max-w-[560px] flex gap-2.5 rounded-2xl p-2 pl-4 shadow-lg shadow-primary/10">
        <input value={value} onChange={(e) => setValue(e.target.value)} placeholder={value ? '' : hint}
          className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[15px] text-text placeholder:text-text-muted" />
        <button type="submit" className="font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark">Check</button>
      </form>
      <div className="mt-3 font-mono text-[11.5px] text-text-muted/70">no account · signed result you can verify offline</div>
    </div>
  )
}

// Floating binary bits — fixed positions so it's stable across renders.
const BITS = [
  { c: '1', l: '6%', d: 0.0 }, { c: '0', l: '18%', d: 0.6 }, { c: '1', l: '30%', d: 1.2 },
  { c: '0', l: '42%', d: 0.3 }, { c: '1', l: '54%', d: 0.9 }, { c: '0', l: '66%', d: 1.5 },
  { c: '1', l: '78%', d: 0.4 }, { c: '0', l: '90%', d: 1.1 }, { c: '1', l: '12%', d: 1.8 },
  { c: '0', l: '36%', d: 2.1 }, { c: '1', l: '60%', d: 2.4 }, { c: '0', l: '84%', d: 0.75 },
  { c: '1', l: '24%', d: 2.7 }, { c: '0', l: '48%', d: 1.65 }, { c: '1', l: '72%', d: 2.25 },
]

/** Fun scanning loader — a barcode reader sweeping up & down over binary rain. */
function ScanningLoader({ owner, repo }: { owner: string; repo: string }) {
  const reduce = useReducedMotion()
  const phases = [
    'Cloning the repository…',
    'Sweeping for exposed secrets & API keys…',
    'Checking for unsafe code execution…',
    'Inspecting how it handles your data…',
    'Mapping file & network access…',
    'Auditing dependencies…',
    'Signing the attestation…',
  ]
  const [phase, setPhase] = useState(0)
  useEffect(() => {
    if (reduce) return
    const id = setInterval(() => setPhase((p) => (p + 1) % phases.length), 1400)
    return () => clearInterval(id)
  }, [reduce, phases.length])
  return (
    <div className="max-w-[560px] mx-auto px-6 py-24 text-center">
      {/* scan window — borderless, blends into the background */}
      <div className="relative w-[220px] h-[132px] mx-auto overflow-hidden">
        {/* floating binary rain */}
        {!reduce && BITS.map((b, i) => (
          <motion.span key={i} className="absolute font-mono text-[13px] text-primary-light/50 select-none" style={{ left: b.l, top: '-14px' }}
            animate={{ y: [0, 150], opacity: [0, 0.8, 0] }} transition={{ duration: 3, ease: 'linear', repeat: Infinity, delay: b.d }}>
            {b.c}
          </motion.span>
        ))}
        {/* scan line sweeping up & down */}
        {!reduce && (
          <motion.div className="absolute left-0 right-0 h-[3px] bg-gradient-to-r from-transparent via-primary-light to-transparent shadow-[0_0_16px_3px_rgba(45,212,191,0.55)]"
            animate={{ top: ['6%', '92%', '6%'] }} transition={{ duration: 2.2, ease: 'easeInOut', repeat: Infinity }} />
        )}
      </div>
      <div className="mt-6 font-mono text-[13px] text-text break-all">scanning {owner}/{repo}</div>
      <motion.div key={phase} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="mt-2 text-[14px] text-primary-light">
        {phases[phase]}
      </motion.div>
      <div className="mt-6 flex gap-1.5 justify-center">
        {phases.map((_, i) => <div key={i} className={`h-1 w-6 rounded-full transition-colors ${i <= phase ? 'bg-primary-light' : 'bg-surface-hover'}`} />)}
      </div>
      <p className="mt-6 text-[12.5px] text-text-muted/70">First scan of a tool takes a moment — we're reading the actual code, not guessing.</p>
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
  // Real adoption signals — checks (Redis), watchers, GitHub stars, score history.
  const { data: adoptionData } = useQuery({
    queryKey: ['rebrand-checks', owner, repo],
    queryFn: async () => (await publicApi.get<{ checks: number; watchers: number; stars: number | null; history: { score: number; at?: number }[] }>(`/public/scan/${owner}/${repo}/checks`)).data,
    retry: 0,
    enabled: !!scan,
  })

  if (isLoading) return <ScanningLoader owner={owner} repo={repo} />

  if (isError || !scan) {
    return (
      <div className="max-w-[620px] mx-auto px-6 py-24 text-center">
        <div className="glass rounded-2xl p-8">
          <h2 className="text-xl font-semibold">Couldn't scan {owner}/{repo}</h2>
          <p className="mt-2 text-text-muted text-[14px]">The scanner didn't return a result. It may be a private repo, or the scan service is busy. Try a repo already in the catalog, or check back shortly.</p>
          <Link to={rp("/rebrand/browse")} className="inline-block mt-5 text-[13.5px] font-semibold text-primary-light hover:text-primary">Browse scored tools →</Link>
        </div>
      </div>
    )
  }

  const g = getGradeInfo(scan.trust_score)
  const f = scan.findings
  const cats = scan.category_scores || {}
  const sum = summarize(scan, scan.repo)
  const v = VERDICT_STYLE[sum.verdict]
  const adoption = adoptionData
    ? {
        label: adoptionData.stars != null && adoptionData.stars > 0
          ? `★ ${adoptionData.stars.toLocaleString()}`
          : `${adoptionData.checks.toLocaleString()} check${adoptionData.checks === 1 ? '' : 's'}`,
        sub: `${adoptionData.stars != null && adoptionData.stars > 0 ? `${adoptionData.checks.toLocaleString()} checks · ` : ''}${adoptionData.watchers} watching · on AgentAvow`,
      }
    : null

  // Adoption ring content — compact number + unit, or "New" when there's no adoption yet.
  const adStars = adoptionData?.stars && adoptionData.stars > 0 ? adoptionData.stars : 0
  const adChecks = adoptionData?.checks ?? 0
  const adCount = adStars || adChecks
  const adUnit = adStars ? 'stars' : 'checks'
  const compact = (n: number) => (n >= 10000 ? Math.round(n / 1000) + 'k' : n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(n))
  const ADOPTION_HEX = '#F59E0B'

  return (
    <div className="max-w-[860px] mx-auto px-6 py-14">
      {/* BRANDED HERO — two co-equal scores + primary Watch CTA */}
      <motion.div className="rounded-2xl overflow-hidden relative border border-border/60"
        style={{ background: `linear-gradient(135deg, ${g.color}12, transparent 55%), var(--color-surface)` }}
        initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, ease: 'easeOut' }}>
        <div className="absolute inset-0 rounded-2xl pointer-events-none" style={{ boxShadow: `inset 0 0 60px -22px ${g.color}55` }} />

        {/* header: verdict + plain-English headline */}
        <div className="relative px-7 pt-7">
          <span className={`inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded ${v.chip}`}>{v.label}</span>
          <h1 className="mt-2 text-2xl font-extrabold tracking-tight">{sum.headline}</h1>
          <div className="mt-1 font-mono text-[13px] text-text-muted break-all">{scan.repo}</div>
          <div className="mt-0.5 text-[13px] font-semibold gradient-text">{scan.trust_tier}</div>
        </div>

        {/* two co-equal scores — Attestation Trust + Adoption */}
        <div className="relative px-7 py-6 grid grid-cols-2 gap-3">
          <div className="rounded-xl border border-border/60 bg-surface/40 p-4 text-center">
            <ScoreRing center={g.grade} sub={`${scan.trust_score}/100`} hex={g.color} fill={scan.trust_score / 100} />
            <div className="mt-3 font-mono text-[11px] font-bold uppercase tracking-wide" style={{ color: g.color }}>Attestation Trust</div>
            <div className="mt-0.5 text-[12px] text-text-muted">Signed scanner grade · verifiable now</div>
          </div>
          <div className="rounded-xl border border-border/60 bg-surface/40 p-4 text-center">
            <ScoreRing center={adCount ? compact(adCount) : 'New'} sub={adCount ? adUnit : 'be the first'} hex={adCount ? ADOPTION_HEX : 'var(--color-text-muted)'} dashed={!adCount} />
            <div className="mt-3 font-mono text-[11px] font-bold uppercase tracking-wide" style={{ color: adCount ? ADOPTION_HEX : 'var(--color-text-muted)' }}>Adoption</div>
            <div className="mt-0.5 text-[12px] text-text-muted">{adoption ? adoption.sub : 'Just launched — no adoption signal yet'}</div>
          </div>
        </div>

        {/* PRIMARY action — watch */}
        <div className="relative px-7">
          <WatchCTA owner={owner} repo={repo} />
          <p className="mt-2 text-center text-[12px] text-text-muted">We re-scan daily and alert you the moment this grade drops.</p>
        </div>

        {/* secondary actions */}
        <div className="relative px-7 pb-6 mt-4 flex items-center justify-center gap-2 flex-wrap border-t border-border/50 pt-4">
          <ShareRow owner={owner} repo={repo} score={scan.trust_score} grade={g.grade} />
          <button
            onClick={() => downloadScoreCard({ repo: scan.repo, grade: g.grade, score: scan.trust_score, tier: scan.trust_tier, gradeHex: g.color, attestation: scan.trust_score, adoption: adCount ? compact(adCount) : 'New', adoptionSub: adCount ? adUnit : '' })}
            className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg border border-border text-text-muted hover:border-primary-light hover:text-primary-light transition-colors"
          >
            ↓ Download score card
          </button>
        </div>
      </motion.div>

      {/* PLAIN-ENGLISH VERDICT — for any user */}
      <Reveal>
        <div className="mt-4 glass rounded-2xl p-6">
          <p className="text-[15.5px] leading-relaxed">{sum.paragraph}</p>
          <div className="grid sm:grid-cols-2 gap-4 mt-5">
            {sum.goodPractices.length > 0 && (
              <div>
                <div className="font-mono text-[11px] uppercase tracking-wide text-success mb-2">What's good</div>
                <ul className="space-y-1.5">{sum.goodPractices.map((p) => <li key={p} className="text-[13.5px] text-text-muted flex gap-2"><span className="text-success">✓</span>{p}</li>)}</ul>
              </div>
            )}
            {sum.risks.length > 0 && (
              <div>
                <div className="font-mono text-[11px] uppercase tracking-wide text-warning mb-2">Worth knowing</div>
                <ul className="space-y-1.5">{sum.risks.map((p) => <li key={p} className="text-[13.5px] text-text-muted flex gap-2"><span className="text-warning">!</span>{p}</li>)}</ul>
              </div>
            )}
          </div>
        </div>
      </Reveal>

      {/* score history timeline (living record) */}
      <ScoreHistory history={adoptionData?.history ?? []} current={scan.trust_score} />

      {/* findings summary */}
      <RevealStagger className="grid grid-cols-3 gap-3 mt-4" stagger={0.06}>
        {[['critical', f?.critical ?? 0, 'text-danger'], ['high', f?.high ?? 0, 'text-warning'], ['total', f?.total ?? 0, 'text-text']].map(([lab, n, cls]) => (
          <div key={lab as string} className="glass rounded-xl p-4 text-center">
            <CountUp value={n as number} className={`block text-2xl font-bold tabular-nums ${cls}`} />
            <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted">{lab as string}</div>
          </div>
        ))}
      </RevealStagger>

      {/* category subscores */}
      <Reveal><h3 className="mt-8 text-[13px] font-mono uppercase tracking-wide text-text-muted">Category scores</h3></Reveal>
      <RevealStagger className="grid sm:grid-cols-2 gap-2.5 mt-3" stagger={0.04}>
        {Object.entries(CAT_LABELS).filter(([key]) => (cats as Record<string, number>)[key] != null).map(([key, label]) => {
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

      {/* scan facts */}
      <Reveal>
        <div className="mt-6 glass rounded-xl p-5">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-2">Scan facts</h3>
          <div className="flex flex-wrap gap-2">
            {sum.facts.map((fct) => <span key={fct} className="text-[12.5px] text-text-muted bg-surface border border-border rounded-full px-3 py-1">{fct}</span>)}
          </div>
        </div>
      </Reveal>

      {/* SIGNED & VERIFIABLE — the powerful part, explained */}
      <Reveal>
        <div className="mt-6 glass rounded-2xl p-6 border-l-4 border-primary/60">
          <div className="flex items-center gap-2 text-success font-mono text-[12.5px]">
            <svg viewBox="0 0 24 24" fill="none" className="w-[18px] h-[18px]"><circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.6" /><path d="M7.5 12.4l3 3 6-6.4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
            Signed · Ed25519 / JWS
          </div>
          <h3 className="mt-2 text-lg font-bold">This grade is signed — you don't have to trust us.</h3>
          <p className="mt-1 text-text-muted text-[14px] max-w-[62ch]">Every result carries a cryptographic signature you can verify offline against our public keys. If anyone tampers with the grade, verification fails. That's the difference between a badge and a signature.</p>
          <div className="mt-3 flex gap-4 flex-wrap">
            <a href="https://agentgraph.co/.well-known/jwks.json" target="_blank" rel="noopener noreferrer" className="text-[13px] font-semibold text-primary-light hover:text-primary">Public keys (JWKS) →</a>
            <Link to={rp("/rebrand/how-it-works")} className="text-[13px] font-semibold text-primary-light hover:text-primary">How verification works →</Link>
          </div>
        </div>
      </Reveal>

      {/* badge promotion */}
      <Reveal><div className="mt-6"><BadgePromo owner={owner} repo={repo} /></div></Reveal>

      {/* claim CTA */}
      <Reveal>
        <div className="mt-6 glass rounded-2xl p-6 flex items-center justify-between gap-4 flex-wrap">
          <div>
            <h3 className="text-[15px] font-bold">Own this tool?</h3>
            <p className="text-text-muted text-[13.5px] mt-0.5">Claim it to get a fix-it report, respond to findings, scan it privately, and take ownership of how it appears on AgentAvow.</p>
          </div>
          <Link to={rp(`/rebrand/claim?owner=${owner}&repo=${repo}`)} className="text-[13.5px] font-semibold px-4 py-2 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors shrink-0">Claim this tool</Link>
        </div>
      </Reveal>

      {/* findings detail */}
      {f?.items && f.items.length > 0 && (
        <>
          <Reveal><h3 className="mt-8 text-[13px] font-mono uppercase tracking-wide text-text-muted">The details ({f.items.length})</h3></Reveal>
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
