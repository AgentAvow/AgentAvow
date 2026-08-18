import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link, useLocation, useSearchParams } from 'react-router-dom'
import { rp } from '../basePath'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion, useReducedMotion } from 'framer-motion'
import { fetchPublicScan, fetchBehavioralScan, fetchPackageScan, fetchPackageBehavioral, fetchMcpScan, fetchSkillScan, publicApi } from '../../lib/scanApi'
import type { PublicScanResponse } from '../../types/scan'
import { getGradeInfo, getTrustTier } from '../../components/trust/gradeSystem'
import { TrustBar, AdoptionNeedle, TrustPill, CertifiedMark } from '../components/TrustMark'
import {
  mcpNameFromUrl, cursorInstall, vscodeInstall, gooseInstall, claudeCodeCmd,
  geminiCmd, codexCmd, claudeDesktopConfig, packageInstallCommands, skillInstallCommands,
  packageStdioTarget, cursorStdio, vscodeStdio, gooseStdio, claudeCodeStdio,
  geminiStdio, codexStdio, stdioServersConfig,
} from '../lib/installLinks'
import { useAuth } from '../../hooks/useAuth'
import SEOHead from '../../components/SEOHead'
import api from '../../lib/api'
import { Reveal, RevealStagger, CountUp } from '../components/motion'
import { useRotatingPlaceholder , useIsDesktop } from '../lib/hooks'
import { summarize } from '../lib/summarize'

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
  ok: { ring: 'text-success', chip: 'bg-success/15 text-success', label: 'GENERALLY SAFE' },
  caution: { ring: 'text-warning', chip: 'bg-warning/15 text-warning', label: 'CAUTION' },
  risky: { ring: 'text-danger', chip: 'bg-danger/15 text-danger', label: 'RISKY' },
}

const CHECK_HINTS = ['github.com/owner/repo', 'npm:chalk', 'pypi:requests', 'crates:serde', 'hf:openai-community/gpt2', 'mcp:https://…', 'a repo, package, model, or MCP server']

/** "Watch this tool" — the PRIMARY action. Full-width gradient CTA.
 * Works across every surface: pass the coordinate as stored server-side
 * (github → owner/repo · npm/pypi → surface/pkg · mcp → mcp/url · openclaw → owner/repo). */
function WatchCTA({ surface = 'github', owner, repo }: { surface?: string; owner: string; repo: string }) {
  const { user } = useAuth()
  const [clicked, setClicked] = useState(false)
  // Reflect whether this tool is already watched — the CTA must not offer "Watch"
  // when the user already watches it. Only queried when signed in.
  const { data: watches } = useQuery({
    queryKey: ['rebrand-watches'],
    queryFn: async () => (await api.get<{ surface?: string; owner: string; repo: string }[]>('/watches')).data,
    enabled: !!user,
  })
  const alreadyWatching = !!user && (watches ?? []).some(
    (w) => (w.surface ?? 'github') === surface
      && w.owner.toLowerCase() === owner.toLowerCase() && w.repo.toLowerCase() === repo.toLowerCase(),
  )
  const watching = alreadyWatching || clicked
  const mutation = useMutation({ mutationFn: () => api.post('/watches', { surface, owner, repo }), onSuccess: () => setClicked(true) })
  // Quiet outline treatment — the marks are the hero; the CTA supports, not competes.
  const base = 'w-full flex items-center justify-center gap-2.5 text-[15px] font-semibold px-5 py-3 rounded-xl transition-all'
  const cta = 'text-primary-light border border-primary/45 bg-primary/[0.06] hover:bg-primary/[0.12] hover:border-primary/70'
  const star = <svg viewBox="0 0 24 24" fill="currentColor" className="w-[16px] h-[16px] shrink-0"><path d="M12 2.5l2.9 6.1 6.6.9-4.8 4.6 1.2 6.6L12 18.6 6.1 21.3l1.2-6.6L2.5 9.5l6.6-.9z"/></svg>
  if (!user) return <Link to={rp('/rebrand/login')} className={`${base} ${cta}`}>{star} Watch this tool</Link>
  if (watching) return <div className={`${base} bg-success/10 text-success border border-success/40`}>✓ Watching — we'll alert you if the score drops</div>
  return (
    <button onClick={() => mutation.mutate()} disabled={mutation.isPending} className={`${base} ${cta} disabled:opacity-70`}>
      {star} {mutation.isPending ? 'Adding…' : 'Watch this tool'}
    </button>
  )
}

/** schema.org Review JSON-LD so a scan result is a rich, indexable object. */
function scanReviewJsonLd(name: string, grade: string, score: number): Record<string, unknown> {
  return {
    '@context': 'https://schema.org', '@type': 'Review',
    itemReviewed: { '@type': 'SoftwareApplication', name, applicationCategory: 'DeveloperApplication' },
    reviewRating: { '@type': 'Rating', ratingValue: score, bestRating: 100, worstRating: 0 },
    author: { '@type': 'Organization', name: 'AgentAvow' },
    reviewBody: `Signed, offline-verifiable safety score ${grade} (${score}/100).`,
  }
}

/** "✓ Maintainer-claimed" — a public trust signal shown when a verified owner has
 * claimed this exact tool. Coordinates follow the claim/watch convention per
 * surface (github/openclaw → owner/repo · npm/pypi → repo=pkg · mcp → repo=url). */
function ClaimedBadge({ surface, owner = '', repo }: { surface: string; owner?: string; repo: string }) {
  const { data } = useQuery({
    queryKey: ['claim-status', surface, owner, repo],
    queryFn: async () => (await api.get<{ claimed: boolean }>(
      `/account/claim-status?surface=${encodeURIComponent(surface)}&owner=${encodeURIComponent(owner)}&repo=${encodeURIComponent(repo)}`,
    )).data,
    staleTime: 60_000,
    retry: 0,
  })
  if (!data?.claimed) return null
  return (
    <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-success/15 text-success" title="A verified owner has claimed this tool">✓ Maintainer-claimed</span>
  )
}

/** Adoption as a co-equal RING for the non-GitHub views (was only a small pill). Big
 * number + unit; a dashed muted ring when there's no adoption signal (e.g. a live MCP
 * endpoint, or a brand-new package) so it never fabricates reliance. */
/** "Safer than X% of tools scanned" — the Insygna-style percentile, from the live
 * catalog distribution. Renders nothing until it resolves (or if the corpus is empty). */
function Percentile({ score }: { score: number }) {
  const { data } = useQuery({
    queryKey: ['score-percentile', score],
    queryFn: async () => (await publicApi.get<{ percentile: number | null; population: number }>(
      `/public/scan-catalog/percentile?score=${score}`)).data,
    staleTime: 600_000, retry: 0,
  })
  if (data?.percentile == null) return null
  return (
    <div className="mt-1.5 text-[11.5px] text-text-muted">
      Safer than <b className="text-text tabular-nums">{data.percentile}%</b> of tools scanned
    </div>
  )
}

/** Declared scope — a tool's own `.agentavow.yml`: the hosts it says it contacts + the
 * capabilities it uses. Transparency now; the behavioral tier verifies observed-vs-declared. */
function DeclaredScopePanel({ scope }: { scope?: { present?: boolean; egress?: string[]; capabilities?: string[]; note?: string } }) {
  if (!scope?.present) return null
  const egress = scope.egress || []
  const caps = scope.capabilities || []
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6 border-l-4 border-primary/50">
        <div className="flex items-center gap-2">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Declared scope</h3>
          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-primary/15 text-primary-light">.agentavow.yml</span>
        </div>
        <p className="mt-1.5 text-text-muted text-[13px] max-w-[64ch]">What this tool says it does. The sandbox holds it to its own declaration — any egress it didn't declare is a finding.</p>
        {scope.note && <p className="mt-2 text-[13.5px] text-text">{scope.note}</p>}
        <div className="mt-3 grid sm:grid-cols-2 gap-4">
          <div>
            <div className="font-mono text-[10.5px] uppercase tracking-wide text-text-muted mb-1.5">Declared egress ({egress.length})</div>
            <div className="flex flex-wrap gap-1.5">
              {egress.length ? egress.map((h) => (
                <span key={h} className="font-mono text-[11.5px] px-2 py-1 rounded-md bg-surface border border-border text-text">{h}</span>
              )) : <span className="text-text-muted text-[12.5px]">none declared</span>}
            </div>
          </div>
          <div>
            <div className="font-mono text-[10.5px] uppercase tracking-wide text-text-muted mb-1.5">Capabilities ({caps.length})</div>
            <div className="flex flex-wrap gap-1.5">
              {caps.length ? caps.map((c) => (
                <span key={c} className="font-mono text-[11.5px] px-2 py-1 rounded-md bg-surface border border-border text-text-muted">{c}</span>
              )) : <span className="text-text-muted text-[12.5px]">none declared</span>}
            </div>
          </div>
        </div>
      </div>
    </Reveal>
  )
}

function ScoreDuo({ trustScore, trustLabel, surface, owner = '', repo, certified = false }: {
  trustScore: number; trustLabel: string; surface: string; owner?: string; repo: string; certified?: boolean
}) {
  const t = getTrustTier(trustScore)
  const { data } = useQuery({
    queryKey: ['surface-adoption', surface, owner, repo],
    queryFn: async () => (await api.get<{ headline?: { count: number; unit: string } | null; adoption_score_100?: number }>(
      `/public/scan/adoption?surface=${encodeURIComponent(surface)}&owner=${encodeURIComponent(owner)}&repo=${encodeURIComponent(repo)}`,
    )).data,
    staleTime: 300_000,
    retry: 0,
  })
  const h = data?.headline
  const has = !!(h && h.count && h.count > 0)
  const big = useIsDesktop() ? 1.5 : 1  // scale the marks up on desktop; spec size on mobile
  return (
    <div className="relative px-4 sm:px-7 py-6">
      <div className="relative rounded-2xl border border-border/70 overflow-hidden bg-gradient-to-b from-surface/50 to-surface/10">
        <div className="absolute inset-0 pointer-events-none" style={{ background: `radial-gradient(460px 200px at 24% -25%, ${t.color}20, transparent 70%), radial-gradient(460px 200px at 78% -25%, rgba(45,212,191,0.13), transparent 70%)` }} />
        <div className="relative grid grid-cols-2">
          <div className="p-4 sm:p-6 pb-5 text-center flex flex-col items-center">
            <div className="min-h-[132px] md:min-h-[196px] flex items-center justify-center">{certified ? <CertifiedMark score={trustScore} scale={big} /> : <TrustBar score={trustScore} scale={big} />}</div>
            <div className="mt-3 font-mono text-[10.5px] font-bold uppercase tracking-[0.16em]" style={{ color: certified ? undefined : t.color }}>{trustLabel}</div>
            <div className="mt-0.5 text-[11.5px] text-text-muted">Signed · verifiable now</div>
            <Percentile score={trustScore} />
          </div>
          <div className="p-4 sm:p-6 pb-5 text-center flex flex-col items-center border-l border-border/50">
            <div className="min-h-[132px] md:min-h-[196px] flex items-center justify-center">
              <AdoptionNeedle count={has ? h!.count : 0} unit={has ? h!.unit : undefined} scorePct={data?.adoption_score_100} scale={big} />
            </div>
            <div className="mt-3 font-mono text-[10.5px] font-bold uppercase tracking-[0.16em] gradient-text">Adoption</div>
            <div className="mt-0.5 text-[11.5px] text-text-muted">{has ? 'independent reliance' : 'no adoption signal yet'}</div>
          </div>
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
  // Version-diff: the change since the FIRST recorded scan (all-time). Always shown —
  // "unchanged" is itself a signal for a trust score.
  const delta = current - pts[0].score

  return (
    <Reveal>
      <div className="mt-6 glass rounded-2xl p-6">
        <div className="flex items-baseline justify-between gap-3 flex-wrap">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Trust score over time</h3>
          <span className="font-mono text-[11.5px] text-text-muted">
            <b className="mr-2" style={{ color: delta > 0 ? '#22c55e' : delta < 0 ? '#ef4444' : undefined }}>
              {delta > 0 ? `↑${delta}` : delta < 0 ? `↓${Math.abs(delta)}` : 'unchanged'} since {firstDate}
            </b>
            {pts.length} scans · now <b style={{ color: lastG.color }}>{current}/100</b>
          </span>
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
  const text = `${owner}/${repo} scored ${grade} (${score}/100) on AgentAvow — a signed, verifiable trust score.`
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
/** "Show it off" — the two signed, LIVE, hosted assets: the README badge (Trust or
 * Trust+Adoption) and the dual-mark card. Both are served from a URL and regenerate
 * from the current signed verdict — always current, embeddable anywhere, never a
 * stale download. */
function BadgePromo({ owner, repo }: { owner: string; repo: string }) {
  const [tab, setTab] = useState<'trust' | 'combined'>('trust')
  const [copied, setCopied] = useState<'badge' | 'card' | null>(null)
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://agentavow.com'
  const link = `${origin}/check/${owner}/${repo}`
  const badgeBase = `${origin}/api/v1/public/scan/${owner}/${repo}/badge`
  const badge = tab === 'trust'
    ? { url: badgeBase, alt: 'AgentAvow Trust' }
    : { url: `${badgeBase}?metric=combined`, alt: 'AgentAvow' }
  const badgeMd = `[![${badge.alt}](${badge.url})](${link})`
  const cardUrl = `${origin}/api/v1/public/scan/${owner}/${repo}/card.svg`
  const cardMd = `[![AgentAvow scores](${cardUrl})](${link})`
  const copyIt = (which: 'badge' | 'card', text: string) => {
    if (navigator.clipboard) navigator.clipboard.writeText(text)
    setCopied(which); setTimeout(() => setCopied(null), 1400)
  }
  const codeBox = (which: 'badge' | 'card', text: string) => (
    <div className="relative mt-3">
      <pre className="font-mono text-[11.5px] bg-surface border border-border rounded-lg px-3 py-2.5 pr-14 text-text-muted overflow-x-auto whitespace-pre-wrap break-all">{text}</pre>
      <button onClick={() => copyIt(which, text)} className="absolute top-1.5 right-1.5 font-mono text-[10.5px] px-2 py-0.5 rounded bg-surface-hover border border-border text-text-muted hover:text-primary-light">{copied === which ? 'copied ✓' : 'copy'}</button>
    </div>
  )
  return (
    <div className="glass rounded-2xl p-6 relative overflow-hidden">
      <div className="absolute -right-20 -top-20 w-48 h-48 rounded-full bg-accent/10 blur-3xl pointer-events-none" />
      <div className="relative">
        <div className="font-mono text-[11px] uppercase tracking-wide text-accent">Show it off</div>
        <h3 className="mt-1 text-lg font-bold">Put your signed mark anywhere.</h3>
        <p className="mt-1 text-text-muted text-[13.5px] max-w-[56ch]">Both are hosted, always-current images that regenerate from the live signed verdict — they can&apos;t go stale or be faked. Free, no account.</p>

        <div className="mt-5 grid md:grid-cols-2 gap-4 items-stretch">
          {/* README badge — Trust or Trust+Adoption */}
          <div className="rounded-xl border border-border bg-surface/40 p-5 flex flex-col">
            <div className="flex items-center justify-between gap-2">
              <div className="font-semibold text-[14px]">README badge</div>
              <div className="inline-flex rounded-lg border border-border overflow-hidden font-mono text-[11px]">
                {([['trust', 'Trust'], ['combined', '+ Adoption']] as const).map(([k, lbl]) => (
                  <button key={k} onClick={() => setTab(k)} className={`px-2.5 py-1 transition-colors ${tab === k ? 'bg-primary/15 text-primary-light' : 'text-text-muted hover:text-text'}`}>{lbl}</button>
                ))}
              </div>
            </div>
            <a href={link} target="_blank" rel="noopener noreferrer" className="mt-4 flex items-center justify-center rounded-lg border border-border/60 bg-surface py-7">
              <img src={badge.url} alt={badge.alt} className="h-[26px] rounded shadow-md" />
            </a>
            {codeBox('badge', badgeMd)}
            <p className="mt-2 font-mono text-[10.5px] text-text-muted/70">the badge row · regenerates on every view</p>
          </div>
          {/* Live card — the hosted dual-mark image */}
          <div className="rounded-xl border border-border bg-surface/40 p-5 flex flex-col">
            <div className="flex items-center justify-between gap-2">
              <div className="font-semibold text-[14px]">Live card</div>
              <a href={cardUrl} target="_blank" rel="noopener noreferrer" className="font-mono text-[11px] text-primary-light hover:text-primary">open ↗</a>
            </div>
            <a href={link} target="_blank" rel="noopener noreferrer" className="mt-4 block rounded-lg overflow-hidden border border-border/60">
              <img src={cardUrl} alt="AgentAvow trust + adoption card" className="w-full block" />
            </a>
            {codeBox('card', cardMd)}
            <p className="mt-2 font-mono text-[10.5px] text-text-muted/70">a richer, always-current image · a Security section or product page</p>
          </div>
        </div>
        <Link to={rp('/rebrand/badge')} className="mt-4 inline-flex items-center gap-1.5 text-[13px] font-semibold text-primary-light hover:text-primary">Badge builder — pick a badge, theme, and format →</Link>
      </div>
    </div>
  )
}

/** Claim CTA that becomes an owned state for signed-in users who've claimed this repo.
 * Only queries claims when signed in — the anonymous check flow never fires it. */
function OwnershipCTA({ owner, repo, token }: { owner: string; repo: string; token?: string }) {
  const { user } = useAuth()
  const qc = useQueryClient()
  const { data: claimsData } = useQuery({
    queryKey: ['rebrand-claims'],
    queryFn: async () => (await api.get<{ claims: { owner: string; repo: string; status: string }[] }>('/account/claims')).data,
    enabled: !!user,
  })
  // From a private scan we hold the token, so claiming can verify ownership in
  // one step (no topic needed for a private repo).
  const claimWithToken = useMutation({
    mutationFn: async () => (await api.post('/account/claims', { owner, repo, token })).data,
    onSuccess: () => qc.refetchQueries({ queryKey: ['rebrand-claims'] }),
  })
  const owned = !!user && (claimsData?.claims ?? []).some(
    (c) => c.owner.toLowerCase() === owner.toLowerCase() && c.repo.toLowerCase() === repo.toLowerCase()
      && c.status === 'verified',
  )
  if (owned) {
    return (
      <Reveal>
        <div className="mt-6 glass rounded-2xl p-6 border-l-4 border-success/60 flex items-center justify-between gap-4 flex-wrap">
          <div>
            <h3 className="text-[15px] font-bold text-success">✓ You own this</h3>
            <p className="text-text-muted text-[13.5px] mt-0.5">This tool is claimed under your account. Manage it, run re-scans, and control alerts.</p>
          </div>
          <Link to={rp("/rebrand/tools") + "#your-repos"} className="text-[13.5px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shrink-0">Manage in My Tools →</Link>
        </div>
      </Reveal>
    )
  }
  // Private scan (token in hand): claim + verify in one click.
  if (user && token) {
    return (
      <Reveal>
        <div className="mt-6 glass rounded-2xl p-6 flex items-center justify-between gap-4 flex-wrap">
          <div>
            <h3 className="text-[15px] font-bold">Own this private repo?</h3>
            <p className="text-text-muted text-[13.5px] mt-0.5">Claim it now — your read token verifies ownership, no topic needed.</p>
            {claimWithToken.isError && <p className="text-danger text-[12.5px] mt-1">Couldn't claim — the token may no longer have access.</p>}
          </div>
          <button onClick={() => claimWithToken.mutate()} disabled={claimWithToken.isPending}
            className="text-[13.5px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shrink-0 disabled:opacity-60">
            {claimWithToken.isPending ? 'Claiming…' : 'Claim & verify'}</button>
        </div>
      </Reveal>
    )
  }
  return (
    <Reveal>
      <div className="mt-6 glass rounded-2xl p-6 flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h3 className="text-[15px] font-bold">Own this tool?</h3>
          <p className="text-text-muted text-[13.5px] mt-0.5">Claim it to scan it privately, get change alerts, and own how it appears on AgentAvow.</p>
        </div>
        <Link to={rp(`/rebrand/claim?owner=${owner}&repo=${repo}`)} className="text-[13.5px] font-semibold px-4 py-2 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors shrink-0">Claim this tool</Link>
      </div>
    </Reveal>
  )
}

/** The secondary-action slot for a stored PRIVATE repo, sitting right below the
 * watch CTA. Not listed → a clear "Publish to search" CTA; on publish it animates
 * into the share row (which is also what shows if it's already listed). */
function PrivateSearchSlot({ owner, repo, score, grade, published }: { owner: string; repo: string; score: number; grade: string; published: boolean }) {
  const qc = useQueryClient()
  const reduce = useReducedMotion()
  const publish = useMutation({
    mutationFn: async () => (await api.post(`/account/private-report/${owner}/${repo}/publish`)).data,
    onSuccess: () => {
      qc.refetchQueries({ queryKey: ['rebrand-private-report', owner, repo] })
      qc.refetchQueries({ queryKey: ['rebrand-claims'] })
    },
  })
  if (published || publish.isSuccess) {
    return (
      <motion.div
        initial={reduce ? false : { opacity: 0, y: 10, scale: 0.96 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.45, ease: 'easeOut' }}
        className="flex flex-col items-center gap-2"
      >
        <div className="text-[12px] text-success font-medium">🌐 Listed in search — share it</div>
        <ShareRow owner={owner} repo={repo} score={score} grade={grade} />
      </motion.div>
    )
  }
  return (
    <div className="flex flex-col items-center gap-1.5">
      <button onClick={() => publish.mutate()} disabled={publish.isPending}
        className="text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">
        {publish.isPending ? 'Publishing…' : '🌐 Publish to search'}</button>
      <p className="text-[11.5px] text-text-muted text-center max-w-[42ch]">List the score in search — your code stays private.</p>
      {publish.isError && <div className="text-[11.5px] text-danger">Couldn&apos;t publish — try again.</div>}
    </div>
  )
}

/** The A+ "Certified" panel (roadmap §7.5) — the transparent 6-point checklist.
 * Renders only when the backend supplied a `certified.checks` map (a full public
 * scan). Certified means every check currently passes; otherwise it doubles as a
 * "how to earn A+" guide by showing exactly which requirements aren't met yet. */
const _CERT_LABELS: Array<[string, string]> = [
  ['artifact_scanned', 'Published artifact scanned — not just the repo'],
  ['provenance_verified', 'Build provenance verified & cryptographically bound to source'],
  ['no_drift', 'No artifact-vs-source drift and no install-time hooks'],
  ['no_critical_or_high', 'Zero critical/high findings · no known-malicious dependencies'],
  ['recompute_ready', 'Signed verdict recomputes offline against pinned snapshots'],
  ['full_coverage', 'Full coverage — not a sampled/truncated scan'],
]
function CertifiedPanel({ certified }: { certified?: { eligible?: boolean; checks?: Record<string, boolean> } }) {
  const checks = certified?.checks
  if (!checks || Object.keys(checks).length === 0) return null
  const eligible = !!certified?.eligible
  const accent = eligible ? '#14B8A6' : 'var(--color-border)'
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6 border-l-4" style={{ borderLeftColor: accent }}>
        <div className="flex items-center gap-2 flex-wrap">
          {eligible ? (
            <span className="inline-flex items-center gap-1.5 font-bold text-[15px]" style={{ color: '#14B8A6' }}>
              <span aria-hidden>✦</span> AgentAvow Certified
            </span>
          ) : (
            <h3 className="text-[15px] font-bold">Not yet Certified</h3>
          )}
        </div>
        <p className="text-text-muted text-[13.5px] mt-1 max-w-[62ch]">
          {eligible
            ? 'This tool meets every requirement for AgentAvow Certified — the top tier. Certification is re-checked on every scan, so it stays true only while it stays true.'
            : 'Certified is earned, not just a high score — it requires all of the following. Anything unchecked shows exactly what to fix to earn it:'}
        </p>
        <ul className="mt-3 flex flex-col gap-1.5">
          {_CERT_LABELS.filter(([k]) => checks[k] !== undefined).map(([k, label]) => (
            <li key={k} className="flex items-start gap-2 text-[13px]">
              <span className={checks[k] ? 'text-success' : 'text-text-muted'} aria-hidden>{checks[k] ? '✓' : '○'}</span>
              <span className={checks[k] ? 'text-text' : 'text-text-muted'}>{label}</span>
            </li>
          ))}
        </ul>
        <Link to={rp('/rebrand/certified')} className="inline-block mt-3 text-[12.5px] font-semibold text-primary-light hover:text-primary">Learn about Certified →</Link>
      </div>
    </Reveal>
  )
}

/** Owner opt-in: publish a connected private repo's stored grade to public search. */
function PublishStoredCTA({ owner, repo, published }: { owner: string; repo: string; published: boolean }) {
  const qc = useQueryClient()
  const publish = useMutation({
    mutationFn: async () => (await api.post(`/account/private-report/${owner}/${repo}/publish`)).data,
    // Refetch the stored report so `published` flips → the share row appears here,
    // and the claims list (My Tools) picks up the new published state too.
    onSuccess: () => {
      qc.refetchQueries({ queryKey: ['rebrand-private-report', owner, repo] })
      qc.refetchQueries({ queryKey: ['rebrand-claims'] })
    },
  })
  const done = published || publish.isSuccess
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6 border-l-4 border-primary/50">
        <h3 className="text-[15px] font-bold">Publish to search</h3>
        <p className="text-text-muted text-[13.5px] mt-1 max-w-[62ch]">Private repos aren&apos;t listed in AgentAvow search. Publishing makes this score public and findable — your choice as the owner.</p>
        {done ? (
          <div className="mt-3 text-[13px] text-success">✓ Published — anyone can now find {owner}/{repo} in search.</div>
        ) : (
          <button onClick={() => publish.mutate()} disabled={publish.isPending}
            className="mt-3 text-[13.5px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">
            {publish.isPending ? 'Publishing…' : 'Publish to search'}</button>
        )}
        {publish.isError && <div className="mt-2 text-[12.5px] text-danger">Couldn&apos;t publish — try again.</div>}
      </div>
    </Reveal>
  )
}

function Hero() {
  const [value, setValue] = useState('')
  const navigate = useNavigate()
  const hint = useRotatingPlaceholder(CHECK_HINTS)
  const go = (raw?: string) => {
    const v = (raw ?? value).trim()
    // Live MCP server: `mcp:https://…`.
    const mcp = v.match(/^mcp\s*:\s*(https?:\/\/.+)$/i)
    if (mcp) { navigate(rp('/rebrand/check/mcp') + '?endpoint=' + encodeURIComponent(mcp[1].trim())); return }
    // Agent Skill: `skill:owner/repo`.
    const sk = v.match(/^skill\s*:\s*(?:github\.com\/)?([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/i)
    if (sk) { navigate(rp(`/rebrand/check/skill/${sk[1]}/${sk[2]}`)); return }
    // Package coordinate: `npm:chalk`, `pypi:requests`, `npm:@scope/pkg`.
    const pkg = v.match(/^(npm|pypi|python|crates|cargo|rust|hf|huggingface|docker|container|oci)\s*:\s*(.+)$/i)
    if (pkg) {
      const k = pkg[1].toLowerCase()
      const surface = k === 'python' ? 'pypi'
        : (k === 'cargo' || k === 'rust') ? 'crates'
        : k === 'hf' ? 'huggingface'
        : (k === 'container' || k === 'oci') ? 'docker' : k
      navigate(rp(`/rebrand/check/pkg/${surface}/${pkg[2].trim()}`))
      return
    }
    // A pasted registry URL → the right package scan (before the bare-URL→MCP rule).
    let ru
    if ((ru = v.match(/^https?:\/\/(?:www\.)?crates\.io\/crates\/([\w-]+)/i))) { navigate(rp(`/rebrand/check/pkg/crates/${ru[1]}`)); return }
    // huggingface.co/org/model (skip /datasets, /spaces, and reserved single-segment paths).
    if ((ru = v.match(/^https?:\/\/huggingface\.co\/([\w.-]+\/[\w.-]+)(?:$|[/?#])/i)) &&
        !/^(datasets|spaces|models|organizations|settings)\//i.test(ru[1])) {
      navigate(rp(`/rebrand/check/pkg/huggingface/${ru[1]}`)); return
    }
    // Docker Hub: hub.docker.com/_/nginx (official) or /r/ns/name; and ghcr.io/owner/img.
    if ((ru = v.match(/^https?:\/\/hub\.docker\.com\/_\/([\w.-]+)/i))) { navigate(rp(`/rebrand/check/pkg/docker/${ru[1]}`)); return }
    if ((ru = v.match(/^https?:\/\/hub\.docker\.com\/r\/([\w.-]+\/[\w.-]+)/i))) { navigate(rp(`/rebrand/check/pkg/docker/${ru[1]}`)); return }
    if ((ru = v.match(/^https?:\/\/ghcr\.io\/([\w.-]+\/[\w.-]+)/i))) { navigate(rp(`/rebrand/check/pkg/docker/ghcr.io/${ru[1]}`)); return }
    if ((ru = v.match(/^https?:\/\/(?:www\.)?npmjs\.com\/package\/((?:@[\w.-]+\/)?[\w.-]+)/i))) { navigate(rp(`/rebrand/check/pkg/npm/${ru[1]}`)); return }
    if ((ru = v.match(/^https?:\/\/pypi\.org\/project\/([\w.-]+)/i))) { navigate(rp(`/rebrand/check/pkg/pypi/${ru[1]}`)); return }
    // A bare URL (no prefix) that isn't a GitHub/GitLab repo link → a live MCP
    // endpoint. Users paste the endpoint URL directly, without the `mcp:` prefix.
    if (/^https?:\/\/\S+$/i.test(v) && !/^https?:\/\/(www\.)?(github|gitlab)\.com\//i.test(v)) {
      navigate(rp('/rebrand/check/mcp') + '?endpoint=' + encodeURIComponent(v)); return
    }
    const m = v.match(/(?:github\.com\/)?([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/)
    if (m) navigate(rp(`/rebrand/check/${m[1]}/${m[2]}`))
  }
  const EXAMPLES: Array<[string, string]> = [
    ['GitHub repo', 'github.com/vercel/next.js'],
    ['npm package', 'npm:sigstore'],
    ['PyPI package', 'pypi:requests'],
    ['HF model', 'hf:openai-community/gpt2'],
    ['Container', 'docker:nginx'],
    ['MCP server', 'mcp:https://mcp.deepwiki.com/mcp'],
  ]
  return (
    <div className="max-w-[1080px] mx-auto px-6 py-20 text-center">
      <h1 className="text-3xl md:text-5xl font-extrabold tracking-tight">Is this tool <span className="gradient-text-bio">safe</span>?</h1>
      <p className="mt-4 text-text-muted max-w-[46ch] mx-auto">Paste anything your agent connects to. We'll tell you — in plain English — whether it's safe, and prove it with a signed score.</p>
      <form onSubmit={(e) => { e.preventDefault(); go() }} className="glass mt-7 mx-auto max-w-[560px] flex gap-2.5 rounded-2xl p-2 pl-4 shadow-lg shadow-primary/10">
        <input value={value} onChange={(e) => setValue(e.target.value)} placeholder={value ? '' : hint}
          className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[15px] text-text placeholder:text-text-muted" />
        <button type="submit" className="font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark">Check</button>
      </form>
      <div className="mt-4 flex items-center justify-center gap-2 flex-wrap">
        <span className="text-[11.5px] text-text-muted/70">Try:</span>
        {EXAMPLES.map(([label, coord]) => (
          <button key={coord} type="button" onClick={() => go(coord)}
            className="font-mono text-[11.5px] px-2.5 py-1 rounded-full border border-border text-text-muted hover:border-primary-light hover:text-primary-light transition-colors">
            {coord}
            <span className="ml-1.5 text-text-muted/50">{label}</span>
          </button>
        ))}
      </div>
      <div className="mt-3 font-mono text-[11.5px] text-text-muted/70">no account · signed result you can verify offline · GitHub repos, npm &amp; PyPI packages</div>
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

/** Adoption panel — the real 5-axis "do independent parties rely on this?" score,
 * DISTINCT from safety. Surfaces the tier + rising/established badge + per-axis
 * breakdown from the /adoption endpoint. Hidden when there's no signal (cold-start
 * tools would just show an empty panel). */
const _ADOPTION_AXES: Record<string, string> = {
  A: 'Downloads + trend', B: 'Reverse-dependents', C: 'Stars + velocity',
  D: 'First-party (AgentAvow)', E: 'MCP / registry usage',
}
interface AdoptionResp {
  adoption_score_100?: number; tier?: string; badge?: string; insufficient_data?: boolean
  axes?: Array<{ axis: string; label: string; absolute: number; momentum: number }>
}
function AdoptionPanel({ owner, repo }: { owner: string; repo: string }) {
  const { data } = useQuery({
    queryKey: ['rebrand-adoption', owner, repo],
    queryFn: async () => (await publicApi.get<AdoptionResp>(`/public/scan/${owner}/${repo}/adoption`)).data,
    retry: 0,
  })
  const axes = data?.axes ?? []
  if (!data || axes.length === 0) return null  // no independent signal → don't clutter
  const score = data.adoption_score_100 ?? 0
  const badge = data.badge
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6 border-l-4 border-accent/50">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <h3 className="text-[15px] font-bold">Adoption</h3>
          {badge && (
            <span className="font-mono text-[10.5px] uppercase tracking-wide px-2 py-0.5 rounded"
              style={{ background: badge === 'rising' ? 'rgba(56,189,248,.14)' : 'rgba(129,140,248,.14)', color: badge === 'rising' ? '#7dd3fc' : '#a5b4fc' }}>
              {badge === 'rising' ? '↑ Rising' : `◆ ${badge}`}
            </span>
          )}
        </div>
        <p className="text-text-muted text-[13px] mt-1 max-w-[62ch]">Do real, independent parties rely on this? A <span className="text-text">separate</span> score from safety — popular is not the same as safe.</p>
        {!data.insufficient_data && (
          <div className="mt-3 flex items-center gap-3">
            <div className="flex-1 h-2 rounded-full bg-surface-hover overflow-hidden"><div className="h-full rounded-full bg-gradient-to-r from-primary to-accent" style={{ width: `${score}%` }} /></div>
            <span className="font-mono text-[12px] text-text-muted tabular-nums">{score}/100</span>
          </div>
        )}
        <div className="mt-4 flex flex-col gap-2">
          {axes.map((a) => {
            const w = Math.round((a.absolute || 0) * 100)
            return (
              <div key={a.axis} className="grid grid-cols-[140px_1fr_auto] items-center gap-3 text-[12px]">
                <span className="text-text-muted truncate">{_ADOPTION_AXES[a.axis] || a.label}</span>
                <span className="h-1.5 rounded-full bg-surface-hover overflow-hidden"><span className="block h-full rounded-full bg-accent" style={{ width: `${w}%` }} /></span>
                <span className="font-mono text-[11px] text-text-muted/70 tabular-nums">{a.momentum > 0.05 ? '↑' : a.momentum < -0.05 ? '↓' : '·'} {w}</span>
              </div>
            )
          })}
        </div>
      </div>
    </Reveal>
  )
}

/** One copyable command/config row. */
function CopyRow({ cmd, label, multiline }: { cmd: string; label?: string; multiline?: boolean }) {
  const [copied, setCopied] = useState(false)
  const copy = () => { navigator.clipboard?.writeText(cmd); setCopied(true); setTimeout(() => setCopied(false), 1400) }
  return (
    <div className={`flex ${multiline ? 'items-start' : 'items-center'} gap-2 bg-surface border border-border rounded-lg px-3 py-2`}>
      {label && <span className="font-mono text-[10px] text-text-muted uppercase tracking-wide shrink-0 w-[92px] pt-0.5">{label}</span>}
      <code className={`font-mono text-[12px] text-text flex-1 min-w-0 ${multiline ? 'whitespace-pre-wrap break-all' : 'break-all'}`}>{cmd}</code>
      <button onClick={copy} className="shrink-0 text-[11px] font-semibold px-2 py-1 rounded-md border border-border text-text-muted hover:text-primary-light hover:border-primary-light transition-colors">{copied ? '✓' : 'Copy'}</button>
    </div>
  )
}

// Prominent, filled 1-click install buttons — the primary "install" action, given
// the same visual weight as the Watch CTA (they were easy to miss as subtle outlines).
const DEEPLINK_BTN = 'inline-flex items-center gap-2 text-[14px] font-bold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-md shadow-primary/25 hover:shadow-primary/45 hover:-translate-y-0.5 transition-all'

/** Fire-and-forget install/badge-click beacon for the admin metrics dashboard. */
function beacon(event: string) {
  try { navigator.sendBeacon?.(`/api/v1/public/scan/beacon/${event}`) } catch { /* ignore */ }
}

/** Package install block — an MCP-server package gets 1-click stdio deeplinks
 * (Cursor/VS Code + Claude Code/config), library install collapsed under it;
 * a plain library gets the install one-liners. */
function PkgInstall({ surface, name, isMcp }: { surface: string; name: string; isMcp?: boolean }) {
  const [more, setMore] = useState(false)
  const t = isMcp ? packageStdioTarget(surface, name) : null
  if (t) {
    return (
      <>
        <p className="text-text-muted text-[13px] mt-1">This package is an <span className="text-text">MCP server</span> — one click for Cursor, VS Code, or Goose (runs <span className="font-mono text-text">{t.command} {t.args.join(' ')}</span>):</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <a href={cursorStdio(t)} onClick={() => beacon('install_click')} target="_blank" rel="noopener noreferrer" className={DEEPLINK_BTN}>▸ Add to Cursor</a>
          <a href={vscodeStdio(t)} onClick={() => beacon('install_click')} className={DEEPLINK_BTN}>▸ Add to VS Code</a>
          <a href={gooseStdio(t)} onClick={() => beacon('install_click')} className={DEEPLINK_BTN}>▸ Add to Goose</a>
        </div>
        <button onClick={() => setMore((m) => !m)} className="mt-3 text-[12px] text-text-muted hover:text-text">Claude Code, Gemini, Codex &amp; config {more ? '▾' : '▸'}</button>
        {more && (
          <div className="mt-3 flex flex-col gap-2">
            <CopyRow label="Claude Code" cmd={claudeCodeStdio(t)} />
            <CopyRow label="Gemini CLI" cmd={geminiStdio(t)} />
            <CopyRow label="Codex CLI" cmd={codexStdio(t)} />
            <CopyRow label="Config" cmd={stdioServersConfig(t)} multiline />
          </div>
        )}
        <details className="mt-3">
          <summary className="cursor-pointer text-[12px] text-text-muted hover:text-text">Or install as a library</summary>
          <div className="mt-2 flex flex-col gap-2">
            {packageInstallCommands(surface, name).map((c) => <CopyRow key={c.label} label={c.label} cmd={c.cmd} />)}
          </div>
        </details>
      </>
    )
  }
  return (
    <>
      <p className="text-text-muted text-[13px] mt-1">Copy the install command for your package manager:</p>
      <div className="mt-3 flex flex-col gap-2">
        {packageInstallCommands(surface, name).map((c) => <CopyRow key={c.label} label={c.label} cmd={c.cmd} />)}
      </div>
    </>
  )
}

/** Opt-in behavioral deep scan — install & run the package in the gVisor sandbox
 * and report what it actually did (network egress, filesystem writes). Only shown
 * for npm/PyPI coordinates (the surfaces the sandbox can exercise). The result is
 * a runtime observation, kept SEPARATE from the signed score. */
type BehavioralData = { ran: boolean; pending?: boolean; timed_out?: boolean; reason?: string; egress_hosts?: string[]; unexpected_egress?: string[]; fs_writes_sample?: string[]; error?: string | null; findings?: { category: string; name: string; severity: string; remediation?: string }[] }

function BehavioralPanel({ owner, repo, surface, auto, pkg }: { owner: string; repo: string; surface?: string; auto?: BehavioralData | null; pkg?: { surface: string; name: string } }) {
  const mut = useMutation({ mutationFn: () => pkg ? fetchPackageBehavioral(pkg.surface, pkg.name) : fetchBehavioralScan(owner, repo) })
  const b: BehavioralData | null | undefined = mut.data?.behavioral ?? auto
  if (surface !== 'npm' && surface !== 'pypi') return null
  const pending = !!b?.pending
  const undeclared = b?.unexpected_egress ?? []
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6 border-l-4 border-primary/50">
        <div className="flex items-center gap-2 flex-wrap">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Behavioral analysis</h3>
          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-primary/15 text-primary-light">sandbox · gVisor</span>
        </div>
        <p className="mt-1.5 text-text-muted text-[13px] max-w-[64ch]">
          Install and run the package in an isolated sandbox and watch what it actually does —
          the hosts it contacts, the files it writes. Any egress beyond the package registry and
          its declared hosts is flagged. Takes ~45s and never changes the signed score.
        </p>

        <button
          onClick={() => mut.mutate()}
          disabled={mut.isPending}
          className="mt-3 font-semibold text-[13.5px] px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-70"
        >
          {mut.isPending ? 'Running in the sandbox… (~45s)' : (b && b.ran ? 'Re-run behavioral analysis' : 'Run behavioral analysis')}
        </button>
        {mut.isError && <p className="mt-3 text-[13px] text-danger">Couldn&apos;t run the behavioral scan — please try again in a moment.</p>}

        {pending && !mut.isPending && (
          <p className="mt-3 text-[13px] text-text-muted">Behavioral analysis is running in the background — reload in about a minute, or hit the button to run it now.</p>
        )}
        {b && !b.ran && !pending && (
          <p className="mt-3 text-[13px] text-text-muted">Behavioral scan didn&apos;t run: {b.reason || b.error || 'no package to exercise in the sandbox'}.</p>
        )}
        {b && b.ran && (
          <div className="mt-4 space-y-3">
            {undeclared.length > 0 ? (
              <div className="flex items-center gap-2 text-[13.5px] font-semibold text-danger"><span>⚠</span> Contacted {undeclared.length} undeclared host{undeclared.length > 1 ? 's' : ''} at install/run time.</div>
            ) : (
              <div className="flex items-center gap-2 text-[13.5px] font-semibold text-success"><span>✓</span> No unexpected network egress observed.</div>
            )}
            <div className="grid sm:grid-cols-2 gap-4">
              <div>
                <div className="font-mono text-[10.5px] uppercase tracking-wide text-text-muted mb-1.5">Network egress ({b.egress_hosts?.length ?? 0})</div>
                <div className="flex flex-wrap gap-1.5">
                  {b.egress_hosts?.length ? b.egress_hosts.map((h) => {
                    const bad = undeclared.includes(h)
                    return <span key={h} className={`font-mono text-[11.5px] px-2 py-1 rounded-md border ${bad ? 'bg-danger/10 border-danger/40 text-danger' : 'bg-surface border-border text-text'}`}>{h}{bad ? ' ⚠' : ''}</span>
                  }) : <span className="text-text-muted text-[12.5px]">none</span>}
                </div>
              </div>
              <div>
                <div className="font-mono text-[10.5px] uppercase tracking-wide text-text-muted mb-1.5">Filesystem writes ({b.fs_writes_sample?.length ?? 0})</div>
                <div className="flex flex-wrap gap-1.5">
                  {b.fs_writes_sample?.length ? b.fs_writes_sample.map((p) => (
                    <span key={p} className="font-mono text-[11.5px] px-2 py-1 rounded-md bg-surface border border-border text-text-muted">{p}</span>
                  )) : <span className="text-text-muted text-[12.5px]">none</span>}
                </div>
              </div>
            </div>
            {(b.findings?.length ?? 0) > 0 && (
              <div className="space-y-1.5">
                {b.findings!.map((fnd, i) => (
                  <div key={i} className="text-[12.5px] text-text-muted"><span className="font-mono text-[10.5px] uppercase px-1.5 py-0.5 rounded bg-danger/15 text-danger mr-2">{fnd.severity}</span>{fnd.name}</div>
                ))}
              </div>
            )}
            {b.timed_out && <p className="text-[12px] text-warning">Note: the run hit its time limit — results may be partial.</p>}
          </div>
        )}
      </div>
    </Reveal>
  )
}

/** "Add to your agent" — the install-with-the-grade affordance. MCP servers get
 * true 1-click deeplinks (Cursor/VS Code/Goose) + copy commands; packages get the
 * install one-liners; skills get the clone command. The grade travels because
 * this lives on the signed score page. */
function AddToAgent(props:
  | { kind: 'mcp'; url: string }
  | { kind: 'package'; surface: string; name: string; isMcp?: boolean }
  | { kind: 'skill'; owner: string; repo: string }
  | { kind: 'repo'; owner: string; repo: string; isMcpServer?: boolean; pkg?: { surface: string; name: string; isMcp?: boolean } }) {
  const [more, setMore] = useState(false)
  const deeplinkBtn = DEEPLINK_BTN
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6 border-l-4 border-primary/50">
        <h3 className="text-[15px] font-bold">Add to your agent</h3>
        {props.kind === 'mcp' && (() => {
          const t = { name: mcpNameFromUrl(props.url), url: props.url }
          return (
            <>
              <p className="text-text-muted text-[13px] mt-1 max-w-[62ch]">One click for Cursor, VS Code, or Goose — the graded server, ready to connect.</p>
              <div className="mt-3 flex flex-wrap gap-2">
                <a href={cursorInstall(t)} onClick={() => beacon('install_click')} target="_blank" rel="noopener noreferrer" className={deeplinkBtn}>▸ Add to Cursor</a>
                <a href={vscodeInstall(t)} onClick={() => beacon('install_click')} className={deeplinkBtn}>▸ Add to VS Code</a>
                <a href={gooseInstall(t)} onClick={() => beacon('install_click')} className={deeplinkBtn}>▸ Add to Goose</a>
              </div>
              <button onClick={() => setMore((m) => !m)} className="mt-3 text-[12px] text-text-muted hover:text-text">Claude, Gemini, Codex &amp; more {more ? '▾' : '▸'}</button>
              {more && (
                <div className="mt-3 flex flex-col gap-2">
                  <CopyRow label="Claude Code" cmd={claudeCodeCmd(t)} />
                  <CopyRow label="Gemini CLI" cmd={geminiCmd(t)} />
                  <CopyRow label="Codex CLI" cmd={codexCmd(t)} />
                  <CopyRow label="claude.ai" cmd={props.url} />
                  <div className="text-[11px] text-text-muted mt-1">↑ paste the URL in Claude&apos;s <span className="text-text">Settings → Connectors → Add custom connector</span>.</div>
                  <CopyRow label="Desktop" cmd={claudeDesktopConfig(t)} multiline />
                </div>
              )}
            </>
          )
        })()}
        {props.kind === 'package' && <PkgInstall surface={props.surface} name={props.name} isMcp={props.isMcp} />}
        {props.kind === 'skill' && (
          <>
            <p className="text-text-muted text-[13px] mt-1">Install the skill by cloning it into your skills directory:</p>
            <div className="mt-3 flex flex-col gap-2">
              {skillInstallCommands(props.owner, props.repo).map((c) => <CopyRow key={c.label} label={c.label} cmd={c.cmd} />)}
            </div>
          </>
        )}
        {props.kind === 'repo' && (props.pkg ? (
          <>
            <p className="text-text-muted text-[13px] mt-1">This repo publishes the <span className="font-mono text-text">{props.pkg.surface}</span> package <span className="font-mono text-text">{props.pkg.name}</span>{props.isMcpServer ? ' — an MCP server' : ''}.</p>
            <div className="mt-2"><PkgInstall surface={props.pkg.surface} name={props.pkg.name} isMcp={props.pkg.isMcp || props.isMcpServer} /></div>
          </>
        ) : props.isMcpServer ? (
          <>
            <p className="text-text-muted text-[13px] mt-1">This repo <span className="text-text">is an MCP server</span>, but it doesn&apos;t publish to a package registry we can resolve — so there&apos;s no 1-click. Clone it and follow its README to run it, then point your client at the command or URL it prints.</p>
            <div className="mt-3 flex flex-col gap-2">
              <CopyRow label="git" cmd={`git clone https://github.com/${props.owner}/${props.repo}`} />
            </div>
            <p className="mt-2 text-[12px] text-text-muted">If you already run it as a Streamable-HTTP endpoint, paste that URL on the <Link to={rp('/rebrand/check')} className="text-primary-light hover:text-primary font-semibold">Check</Link> page for a live grade + 1-click.</p>
          </>
        ) : (
          <>
            <p className="text-text-muted text-[13px] mt-1">A source repo — clone it to work with the code:</p>
            <div className="mt-3 flex flex-col gap-2">
              <CopyRow label="git" cmd={`git clone https://github.com/${props.owner}/${props.repo}`} />
            </div>
          </>
        ))}
      </div>
    </Reveal>
  )
}

/** OpenClaw / Agent Skill score view — grades the capability surface a repo scan
 * misses (auto-exec allowed-tools grant, always-loaded-description injection,
 * lifecycle hooks, script exfil). */
function SkillResult({ owner, repo }: { owner: string; repo: string }) {
  const { data: scan, isLoading, isError } = useQuery({
    queryKey: ['rebrand-skill-scan', owner, repo],
    queryFn: () => fetchSkillScan(owner, repo),
    retry: 0,
  })
  if (isLoading) return <ScanningLoader owner="skill" repo={`${owner}/${repo}`} />
  if (isError || !scan) {
    return (
      <div className="max-w-[560px] mx-auto px-6 py-24 text-center">
        <h1 className="text-2xl font-extrabold tracking-tight">Not a recognizable Agent Skill</h1>
        <p className="mt-3 text-text-muted text-[14px]">We couldn&apos;t find a <span className="font-mono">SKILL.md</span> in <span className="font-mono">{owner}/{repo}</span>. Point us at a repo (or the primary skill in a collection) that ships one.</p>
        <Link to={rp('/rebrand/check')} className="mt-6 inline-block text-primary-light hover:text-primary font-semibold">← Scan something else</Link>
      </div>
    )
  }
  const t = getTrustTier(scan.trust_score)
  const f = scan.findings
  const verdict = scan.trust_score >= 81 ? 'Safe to install' : scan.trust_score >= 61 ? 'Generally safe'
    : scan.trust_score >= 41 ? 'Install with caution' : 'Significant risks'
  return (
    <div className="max-w-[760px] mx-auto px-6 py-14">
      <SEOHead
        title={`${owner}/${repo} skill — safety score ${scan.trust_score}/100`}
        description={`${verdict}. AgentAvow's signed capability grade for the ${owner}/${repo} Agent Skill: ${scan.trust_score}/100 (${t.name}), verifiable offline.`}
        path={`/check/skill/${owner}/${repo}`}
        image={`https://agentavow.com/api/v1/public/scan/${owner}/${repo}/og-image`}
        jsonLd={scanReviewJsonLd(`${owner}/${repo}`, t.name, scan.trust_score)}
      />
      <Reveal>
        <div className="glass rounded-2xl relative overflow-hidden" style={{ background: `linear-gradient(135deg, ${t.color}12, transparent 55%), var(--color-surface)` }}>
          <div className="relative px-7 pt-7">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-primary/15 text-primary-light uppercase">Agent Skill</span>
              <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-success/15 text-success">🔒 Capability-graded</span>
              <ClaimedBadge surface="openclaw" owner={owner} repo={repo} />
            </div>
            <h1 className="mt-2 text-xl font-extrabold tracking-tight break-all font-mono">{owner}/{repo}</h1>
            {(scan as { tool_description?: string }).tool_description && <div className="mt-1.5 text-[13.5px] text-text-muted max-w-[62ch]">{(scan as { tool_description?: string }).tool_description}</div>}
            {(scan as { long_description?: string }).long_description && <div className="mt-1 text-[12.5px] leading-snug text-text-muted/75 max-w-[62ch]">{(scan as { long_description?: string }).long_description}</div>}
            <div className="mt-1 font-mono text-[13px] text-text-muted">{verdict} · {scan.trust_tier}</div>
          </div>
          <ScoreDuo trustScore={scan.trust_score} trustLabel="Capability Trust" surface="openclaw" owner={owner} repo={repo} certified={!!(scan as { certified?: { eligible?: boolean } }).certified?.eligible} />
        </div>
      </Reveal>

      {/* PRIMARY ACTIONS — watch + install, consistent across every score page */}
      <div className="mt-4"><WatchCTA surface="openclaw" owner={owner} repo={repo} /></div>
      <AddToAgent kind="skill" owner={owner} repo={repo} />

      <BlastRadius scan={scan} />

      <Reveal>
        <div className="mt-4 glass rounded-2xl p-6">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">What we graded</h3>
          <p className="mt-2 text-[13.5px] text-text-muted max-w-[62ch]">A skill&apos;s <span className="text-text">SKILL.md is injected into your model every session</span>, and its <span className="text-text font-mono">allowed-tools</span> pre-approves tools to run <span className="text-text">without asking</span>. We graded that auto-exec grant, hidden instructions in the always-loaded description, lifecycle-hook escalation, and credential-exfil in the bundled scripts.</p>
          {(() => {
            const sd = (scan as { surface_detail?: { skill_name?: string; allowed_tools?: string[]; has_lifecycle_hooks?: boolean } }).surface_detail
            const tools = sd?.allowed_tools ?? []
            if (!sd?.skill_name && tools.length === 0) return null
            return (
              <div className="mt-3 flex flex-col gap-2 text-[12.5px]">
                {sd?.skill_name && <div className="flex justify-between gap-3"><span className="text-text-muted">Skill</span><span className="font-mono">{sd.skill_name}</span></div>}
                <div className="flex justify-between gap-3 items-start"><span className="text-text-muted shrink-0">Auto-approved tools</span><span className="font-mono text-right">{tools.length ? tools.join(', ') : 'none'}</span></div>
                {sd?.has_lifecycle_hooks && <div className="flex justify-between gap-3"><span className="text-text-muted">Lifecycle hooks</span><span className="font-mono text-warning">present</span></div>}
              </div>
            )
          })()}
        </div>
      </Reveal>

      {f?.items && f.items.length > 0 ? (
        <>
          <Reveal><h3 className="mt-8 text-[13px] font-mono uppercase tracking-wide text-text-muted">The details ({f.items.length})</h3></Reveal>
          <div className="flex flex-col gap-2 mt-3">
            {f.items.slice(0, 15).map((it, i) => (
              <div key={i} className="glass rounded-xl px-4 py-3 flex gap-3 items-start">
                <span className={`font-mono text-[10.5px] uppercase tracking-wide px-1.5 py-0.5 rounded shrink-0 mt-0.5 ${SEV_CLASS[it.severity] || SEV_CLASS.info}`}>{it.severity}</span>
                <div className="min-w-0">
                  <div className="text-[14px]">{it.name}</div>
                  <div className="font-mono text-[11.5px] text-text-muted break-all">{it.file_path}{(it as {shipped?: boolean}).shipped === false && <span className="ml-2 font-sans text-[9.5px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-surface border border-border text-text-muted/60" title="In a test/doc/example file — scored at a fraction of shipped code">in tests</span>}</div>
                  {it.remediation && <div className="text-[12px] text-text-muted/85 mt-1">→ {it.remediation}</div>}
                </div>
              </div>
            ))}
          </div>
        </>
      ) : (
        <Reveal><div className="mt-6 glass rounded-2xl p-6 text-[13.5px] text-success">✓ No capability-surface risks found — clean skill.</div></Reveal>
      )}

      <div className="mt-8 flex justify-center">
        <ShareRow owner={owner} repo={repo} score={scan.trust_score} grade={t.name} />
      </div>
    </div>
  )
}

/** Live MCP server score view — grades the SERVED tool surface (what the server
 * actually advertises at runtime), not a repo. The agent-specific moat. */
/** Capability blast radius — what a tool could DO if misused / its input is poisoned,
 * distinct from its code grade. Reads surface_detail.blast_radius (MCP + skills). */
function BlastRadius({ scan }: { scan: unknown }) {
  const br = (scan as { surface_detail?: { blast_radius?: {
    level?: string; why?: string; lethal_trifecta?: boolean;
    capabilities?: { key: string; label: string; count: number }[] } } }).surface_detail?.blast_radius
  if (!br?.level) return null
  const STY: Record<string, { ring: string; text: string; bg: string; dot: string; label: string }> = {
    low: { ring: 'border-success/40', text: 'text-success', bg: 'bg-success/10', dot: 'bg-success', label: 'Low' },
    moderate: { ring: 'border-primary-light/40', text: 'text-primary-light', bg: 'bg-primary/10', dot: 'bg-primary-light', label: 'Moderate' },
    high: { ring: 'border-warning/50', text: 'text-warning', bg: 'bg-warning/10', dot: 'bg-warning', label: 'High' },
    critical: { ring: 'border-danger/50', text: 'text-danger', bg: 'bg-danger/12', dot: 'bg-danger', label: 'Critical' },
  }
  const s = STY[br.level] || STY.moderate
  return (
    <Reveal>
      <div className={`mt-4 glass rounded-2xl p-6 border-l-4 ${s.ring}`}>
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Capability blast radius</h3>
          <span className={`inline-flex items-center gap-1.5 font-bold text-[13px] px-3 py-1 rounded-full ${s.text} ${s.bg}`}>
            <span className={`w-2 h-2 rounded-full ${s.dot}`} />{s.label}
          </span>
        </div>
        <p className="mt-2 text-[13.5px] text-text-muted max-w-[64ch]">{br.why}</p>
        {br.capabilities && br.capabilities.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-2">
            {br.capabilities.map((c) => (
              <span key={c.key} className="font-mono text-[12px] text-text-muted bg-surface border border-border rounded-full px-3 py-1">{c.label}{c.count > 1 ? ` ·${c.count}` : ''}</span>
            ))}
            {br.lethal_trifecta && <span className="font-mono text-[12px] text-danger bg-danger/10 border border-danger/25 rounded-full px-3 py-1">⚠ lethal trifecta</span>}
          </div>
        )}
        <p className="mt-3 text-[11.5px] text-text-muted/70">Blast radius is what the tool <span className="text-text-muted">could do</span> if it's misused or its input is poisoned — separate from its score. A clean tool can still have a wide blast radius.</p>
      </div>
    </Reveal>
  )
}

function McpResult({ endpoint }: { endpoint: string }) {
  const { data: scan, isLoading, isError } = useQuery({
    queryKey: ['rebrand-mcp-scan', endpoint],
    queryFn: () => fetchMcpScan(endpoint),
    retry: 0,
  })
  if (isLoading) return <ScanningLoader owner="MCP server" repo={endpoint} />
  if (isError || !scan) {
    return (
      <div className="max-w-[560px] mx-auto px-6 py-24 text-center">
        <h1 className="text-2xl font-extrabold tracking-tight">Couldn&apos;t reach that MCP server</h1>
        <p className="mt-3 text-text-muted text-[14px]">We couldn&apos;t handshake it — it needs to be a reachable <span className="text-text">Streamable-HTTP</span> MCP endpoint (stdio / SSE-only servers aren&apos;t supported yet).</p>
        <Link to={rp('/rebrand/check')} className="mt-6 inline-block text-primary-light hover:text-primary font-semibold">← Scan something else</Link>
      </div>
    )
  }
  const t = getTrustTier(scan.trust_score)
  const f = scan.findings
  const verdict = scan.trust_score >= 81 ? 'Safe to connect' : scan.trust_score >= 61 ? 'Generally safe'
    : scan.trust_score >= 41 ? 'Connect with caution' : 'Significant risks'
  return (
    <div className="max-w-[760px] mx-auto px-6 py-14">
      <SEOHead
        title={`MCP server — safety score ${scan.trust_score}/100`}
        description={`${verdict}. AgentAvow live-graded this MCP server's served tool surface: ${scan.trust_score}/100 (${t.name}).`}
        path={`/check/mcp?endpoint=${encodeURIComponent(endpoint)}`}
        jsonLd={scanReviewJsonLd(endpoint, t.name, scan.trust_score)}
      />
      <Reveal>
        <div className="glass rounded-2xl relative overflow-hidden" style={{ background: `linear-gradient(135deg, ${t.color}12, transparent 55%), var(--color-surface)` }}>
          <div className="relative px-7 pt-7">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-primary/15 text-primary-light uppercase">MCP server</span>
              <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-success/15 text-success">⚡ Live-graded</span>
              <ClaimedBadge surface="mcp" repo={endpoint} />
            </div>
            <h1 className="mt-2 text-lg font-extrabold tracking-tight break-all font-mono">{endpoint}</h1>
            {(scan as { tool_description?: string }).tool_description && <div className="mt-1.5 text-[13.5px] text-text-muted max-w-[62ch]">{(scan as { tool_description?: string }).tool_description}</div>}
            {(scan as { long_description?: string }).long_description && <div className="mt-1 text-[12.5px] leading-snug text-text-muted/75 max-w-[62ch]">{(scan as { long_description?: string }).long_description}</div>}
            <div className="mt-1 font-mono text-[13px] text-text-muted">{verdict} · {scan.trust_tier}</div>
          </div>
          <ScoreDuo trustScore={scan.trust_score} trustLabel="Capability Trust" surface="mcp" owner="mcp" repo={endpoint} certified={!!(scan as { certified?: { eligible?: boolean } }).certified?.eligible} />
        </div>
      </Reveal>

      {/* PRIMARY ACTIONS — watch + install, consistent across every score page */}
      <div className="mt-4"><WatchCTA surface="mcp" owner="mcp" repo={endpoint} /></div>
      <AddToAgent kind="mcp" url={endpoint} />

      <BlastRadius scan={scan} />

      <Reveal>
        <div className="mt-4 glass rounded-2xl p-6">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">What we graded</h3>
          <p className="mt-2 text-[13.5px] text-text-muted max-w-[62ch]">We connected to the server and graded the <span className="text-text">tool surface it actually serves</span> — input-schema risk, hidden instructions in tool descriptions, dangerous capabilities, and the lethal trifecta across its tools. This is what a repo scan can&apos;t see.</p>
        </div>
      </Reveal>

      {/* WHAT WE CONNECTED TO — the live server facts (tools/resources/prompts/caps) */}
      {(() => {
        const sd = (scan as { surface_detail?: {
          server_name?: string; tool_count?: number; resource_count?: number;
          prompt_count?: number; capabilities?: Record<string, number>;
          lethal_trifecta?: boolean } }).surface_detail || {}
        const caps = sd.capabilities && Object.keys(sd.capabilities).length
          ? Object.keys(sd.capabilities) : []
        const facts: string[] = []
        if (sd.tool_count != null) facts.push(`${sd.tool_count} tool${sd.tool_count === 1 ? '' : 's'} graded`)
        if (sd.resource_count) facts.push(`${sd.resource_count} resource${sd.resource_count === 1 ? '' : 's'}`)
        if (sd.prompt_count) facts.push(`${sd.prompt_count} prompt${sd.prompt_count === 1 ? '' : 's'}`)
        return (
          <Reveal>
            <div className="mt-4 glass rounded-2xl p-6">
              <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">What we connected to</h3>
              <div className="mt-3 flex flex-col gap-2 text-[13px]">
                <div className="flex justify-between gap-3"><span className="text-text-muted">Server</span><span className="font-mono break-all">{sd.server_name || 'unnamed'}</span></div>
                <div className="flex justify-between gap-3"><span className="text-text-muted">Endpoint</span><span className="font-mono text-success">live · streamable-HTTP</span></div>
                <div className="flex justify-between gap-3"><span className="text-text-muted">Point-in-time</span><span className="font-mono">served surface, graded now</span></div>
                {sd.lethal_trifecta != null && (
                  <div className="flex justify-between gap-3"><span className="text-text-muted">Lethal trifecta</span><span className={`font-mono ${sd.lethal_trifecta ? 'text-danger' : 'text-success'}`}>{sd.lethal_trifecta ? 'present ⚠' : 'not present ✓'}</span></div>
                )}
              </div>
              {facts.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-2">
                  {facts.map((fct) => <span key={fct} className="text-[12.5px] text-text-muted bg-surface border border-border rounded-full px-3 py-1">{fct}</span>)}
                </div>
              )}
              {caps.length > 0 && (
                <div className="mt-3">
                  <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted mb-1.5">Capabilities detected</div>
                  <div className="flex flex-wrap gap-2">
                    {caps.map((c) => <span key={c} className="font-mono text-[12px] text-warning bg-warning/10 border border-warning/25 rounded-full px-3 py-1">{c}</span>)}
                  </div>
                </div>
              )}
            </div>
          </Reveal>
        )
      })()}

      {/* CATEGORY SCORES — the per-axis breakdown, same as every other score page */}
      {scan.category_scores && Object.keys(scan.category_scores).length > 0 && (
        <>
          <Reveal><h3 className="mt-8 text-[13px] font-mono uppercase tracking-wide text-text-muted">Category scores</h3></Reveal>
          <RevealStagger className="grid sm:grid-cols-2 gap-2.5 mt-3" stagger={0.04}>
            {Object.entries(CAT_LABELS).filter(([key]) => (scan.category_scores as Record<string, number>)[key] != null).map(([key, label]) => {
              const sc = (scan.category_scores as Record<string, number>)[key]
              return (
                <div key={key} className="glass rounded-xl px-4 py-3 flex items-center justify-between">
                  <span className="text-[14px]">{label}</span>
                  <TrustPill score={sc} />
                </div>
              )
            })}
          </RevealStagger>
        </>
      )}

      {/* findings summary — critical/high/total, consistent with repo/package pages */}
      <RevealStagger className="grid grid-cols-3 gap-3 mt-6" stagger={0.06}>
        {[['critical', f?.critical ?? 0, 'text-danger'], ['high', f?.high ?? 0, 'text-warning'], ['total', f?.total ?? 0, 'text-text']].map(([lab, n, cls]) => (
          <div key={lab as string} className="glass rounded-xl p-4 text-center">
            <CountUp value={n as number} className={`block text-2xl font-bold tabular-nums ${cls}`} />
            <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted">{lab as string}</div>
          </div>
        ))}
      </RevealStagger>

      {f?.items && f.items.length > 0 ? (
        <>
          <Reveal><h3 className="mt-8 text-[13px] font-mono uppercase tracking-wide text-text-muted">The details ({f.items.length})</h3></Reveal>
          <div className="flex flex-col gap-2 mt-3">
            {f.items.slice(0, 15).map((it, i) => (
              <div key={i} className="glass rounded-xl px-4 py-3 flex gap-3 items-start">
                <span className={`font-mono text-[10.5px] uppercase tracking-wide px-1.5 py-0.5 rounded shrink-0 mt-0.5 ${SEV_CLASS[it.severity] || SEV_CLASS.info}`}>{it.severity}</span>
                <div className="min-w-0">
                  <div className="text-[14px]">{it.name}</div>
                  <div className="font-mono text-[11.5px] text-text-muted break-all">{it.file_path}{(it as {shipped?: boolean}).shipped === false && <span className="ml-2 font-sans text-[9.5px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-surface border border-border text-text-muted/60" title="In a test/doc/example file — scored at a fraction of shipped code">in tests</span>}</div>
                  {it.remediation && <div className="text-[12px] text-text-muted/85 mt-1">→ {it.remediation}</div>}
                </div>
              </div>
            ))}
          </div>
        </>
      ) : (
        <Reveal><div className="mt-6 glass rounded-2xl p-6 text-[13.5px] text-success">✓ No capability-surface risks found — clean tool set.</div></Reveal>
      )}

      <div className="mt-8 flex justify-center">
        <ShareRow owner="mcp" repo={endpoint} score={scan.trust_score} grade={t.name} />
      </div>
    </div>
  )
}

/** Native npm/PyPI package score view — the published artifact, graded by
 * coordinate (no repo). Leads with the artifact/provenance trust-chain + the
 * Certified panel (this is where A+ is actually earned), then the findings.
 * Skips the GitHub-only surfaces (stars, adoption, README badge). */
function PackageResult({ surface, name }: { surface: string; name: string }) {
  const { data: scan, isLoading, isError } = useQuery({
    queryKey: ['rebrand-pkg-scan', surface, name],
    queryFn: () => fetchPackageScan(surface, name),
    retry: 0,
  })
  if (isLoading) return <ScanningLoader owner={surface} repo={name} />
  if (isError || !scan) {
    return (
      <div className="max-w-[560px] mx-auto px-6 py-24 text-center">
        <h1 className="text-2xl font-extrabold tracking-tight">Couldn&apos;t scan {surface}:{name}</h1>
        <p className="mt-3 text-text-muted text-[14px]">We couldn&apos;t fetch that from the {surface} registry — check the name{surface === 'npm' ? ' (scoped packages look like @scope/name)' : ''} and try again.</p>
        <Link to={rp('/rebrand/check')} className="mt-6 inline-block text-primary-light hover:text-primary font-semibold">← Scan something else</Link>
      </div>
    )
  }
  const t = getTrustTier(scan.trust_score)
  const f = scan.findings
  const cov = (scan as { coverage?: { artifact_digest?: string } }).coverage || {}
  const prov = (scan as { provenance?: { verified?: boolean; present?: boolean } }).provenance || {}
  const certified = (scan as { certified?: { eligible?: boolean; checks?: Record<string, boolean> } }).certified
  const digest = (cov.artifact_digest || '').replace(/^sha256:/, '').slice(0, 16)
  const verdict = scan.trust_score >= 81 ? 'Safe to use' : scan.trust_score >= 61 ? 'Generally safe'
    : scan.trust_score >= 41 ? 'Use with caution' : 'Significant risks'
  return (
    <div className="max-w-[760px] mx-auto px-6 py-14">
      <SEOHead
        title={`${name} (${surface}) — safety score ${scan.trust_score}/100`}
        description={`${verdict}. AgentAvow's signed score for ${surface}:${name}: ${scan.trust_score}/100 (${t.name}) — scanned on the published artifact, verifiable offline.`}
        path={`/check/pkg/${surface}/${name}`}
        jsonLd={scanReviewJsonLd(`${surface}:${name}`, t.name, scan.trust_score)}
      />
      <Reveal>
        <div className="glass rounded-2xl relative overflow-hidden" style={{ background: `linear-gradient(135deg, ${t.color}12, transparent 55%), var(--color-surface)` }}>
          <div className="relative px-7 pt-7">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-primary/15 text-primary-light uppercase">{surface}</span>
              <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-success/15 text-success">🔒 Artifact-scanned</span>
              {prov.verified && <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-primary/15 text-primary-light">✓ Provenance verified</span>}
              <ClaimedBadge surface={surface} repo={name} />
            </div>
            <h1 className="mt-2 text-2xl font-extrabold tracking-tight break-all">{name}</h1>
            {(scan as { tool_description?: string }).tool_description && <div className="mt-1.5 text-[13.5px] text-text-muted max-w-[62ch]">{(scan as { tool_description?: string }).tool_description}</div>}
            {(scan as { long_description?: string }).long_description && <div className="mt-1 text-[12.5px] leading-snug text-text-muted/75 max-w-[62ch]">{(scan as { long_description?: string }).long_description}</div>}
            <div className="mt-1 font-mono text-[13px] text-text-muted">{verdict} · {scan.trust_tier}</div>
          </div>
          <ScoreDuo trustScore={scan.trust_score} trustLabel="Attestation Trust" surface={surface} repo={name} certified={!!(scan as { certified?: { eligible?: boolean } }).certified?.eligible} />
        </div>
      </Reveal>

      {/* PRIMARY ACTIONS — watch + install, consistent across every score page */}
      <div className="mt-4"><WatchCTA surface={surface} owner={surface} repo={name} /></div>
      <AddToAgent kind="package" surface={surface} name={name} isMcp={!!(scan as { surface_detail?: { is_mcp_server?: boolean } }).surface_detail?.is_mcp_server} />

      {/* Certified panel — the A+ story for packages */}
      {(scan.trust_score >= 81 || certified?.eligible) && <CertifiedPanel certified={certified} />}

      {/* The verified chain */}
      <Reveal>
        <div className="mt-4 glass rounded-2xl p-6">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">The chain we verified</h3>
          <div className="mt-3 flex flex-col gap-2 text-[13px]">
            <div className="flex justify-between gap-3"><span className="text-text-muted">Coordinate</span><span className="font-mono break-all">{scan.repo}</span></div>
            <div className="flex justify-between gap-3"><span className="text-text-muted">Scan depth</span><span className="font-mono text-success">artifact (real published bytes)</span></div>
            <div className="flex justify-between gap-3"><span className="text-text-muted">Artifact digest</span><span className="font-mono break-all">{digest ? `sha256:${digest}…` : '—'}</span></div>
            <div className="flex justify-between gap-3"><span className="text-text-muted">Provenance</span><span className="font-mono">{prov.verified ? 'verified ✓' : prov.present ? 'present · unverified' : 'none published (N/A)'}</span></div>
          </div>
        </div>
      </Reveal>

      {/* Behavioral deep scan — auto-runs for npm/PyPI packages */}
      <BehavioralPanel owner={surface} repo={name} surface={surface} pkg={{ surface, name }} auto={(scan as { behavioral?: BehavioralData | null }).behavioral} />

      {/* findings detail */}
      {f?.items && f.items.length > 0 && (
        <>
          <Reveal><h3 className="mt-8 text-[13px] font-mono uppercase tracking-wide text-text-muted">The details ({f.items.length})</h3></Reveal>
          <div className="flex flex-col gap-2 mt-3">
            {f.items.slice(0, 12).map((it, i) => (
              <div key={i} className="glass rounded-xl px-4 py-3 flex gap-3 items-start">
                <span className={`font-mono text-[10.5px] uppercase tracking-wide px-1.5 py-0.5 rounded shrink-0 mt-0.5 ${SEV_CLASS[it.severity] || SEV_CLASS.info}`}>{it.severity}</span>
                <div className="min-w-0">
                  <div className="text-[14px]">{it.name}</div>
                  <div className="font-mono text-[11.5px] text-text-muted break-all">{it.file_path}{it.line_number ? `:${it.line_number}` : ''}{(it as {shipped?: boolean}).shipped === false && <span className="ml-2 font-sans text-[9.5px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-surface border border-border text-text-muted/60" title="In a test/doc/example file — scored at a fraction of shipped code">in tests</span>}</div>
                  {it.remediation && <div className="text-[12px] text-text-muted/85 mt-1">→ {it.remediation}</div>}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      <div className="mt-8 flex justify-center">
        <ShareRow owner={surface} repo={name} score={scan.trust_score} grade={t.name} />
      </div>
    </div>
  )
}

export default function RebrandCheck() {
  const params = useParams()
  const location = useLocation()
  const [sp] = useSearchParams()
  // Live MCP server route (/check/mcp?endpoint=…).
  if (location.pathname.replace(/\/$/, '').endsWith('/check/mcp')) {
    const ep = sp.get('endpoint')
    if (!ep) return <Hero />
    return <McpResult endpoint={ep} />
  }
  // OpenClaw / Agent Skill route (/check/skill/:owner/:repo).
  if (location.pathname.includes('/check/skill/') && params.owner && params.repo) {
    return <SkillResult owner={params.owner} repo={params.repo} />
  }
  // Package coordinate route (/check/pkg/:surface/*) → native npm/PyPI package scan.
  if (params.surface) {
    const name = params['*'] || ''
    if (!name) return <Hero />
    return <PackageResult surface={params.surface.toLowerCase()} name={name} />
  }
  // A /check/{surface}/{name} URL where the "owner" is actually a package registry
  // (npm/pypi/…) is a package coordinate, not a GitHub repo — render the native package
  // scan so it artifact-scans and shows registry downloads (not github checks/watchers).
  // Scoped names (@scope/pkg) keep using /check/pkg/:surface/*.
  const PKG_SURFACES = ['npm', 'pypi', 'crates', 'huggingface', 'docker']
  if (params.owner && params.repo && PKG_SURFACES.includes(params.owner.toLowerCase())) {
    return <PackageResult surface={params.owner.toLowerCase()} name={params.repo} />
  }
  const { owner, repo } = params
  // A private scan hands its result here via router state so the owner gets the
  // full detailed report on the real score page (a private repo can't be
  // re-fetched publicly). The token rides along so the Publish CTA can work.
  const state = location.state as { privateResult?: PublicScanResponse; token?: string } | null
  if (!owner || !repo) return <Hero />
  return <Result owner={owner} repo={repo} privateResult={state?.privateResult} />
}

function Result({ owner, repo, privateResult }: {
  owner: string; repo: string; privateResult?: PublicScanResponse
}) {
  const { user } = useAuth()
  // A one-time private scan arrives via router state — ephemeral, nothing is stored.
  const oneTimePrivate = !!privateResult
  const { data: fetched, isLoading } = useQuery({
    queryKey: ['rebrand-scan', owner, repo],
    queryFn: () => fetchPublicScan(owner, repo),
    retry: 0,
    enabled: !oneTimePrivate,
  })
  // When the public scan finds nothing and the viewer is signed in, fall back to the
  // owner's stored private report (via the GitHub App). 404 → they have none stored.
  const publicMissing = !oneTimePrivate && !isLoading && !fetched
  const { data: privateReport, isLoading: prLoading } = useQuery({
    queryKey: ['rebrand-private-report', owner, repo],
    queryFn: async () => (await api.get<PublicScanResponse>(`/account/private-report/${owner}/${repo}`)).data,
    retry: 0,
    enabled: !!user && publicMissing,
  })
  // A stored private report is a MANAGED repo — distinct from a one-time scan.
  const storedPrivate = !oneTimePrivate && !fetched && !!privateReport
  const isPrivate = oneTimePrivate || storedPrivate
  const scan = oneTimePrivate ? privateResult : (fetched ?? privateReport)
  // A private repo the owner has published to search HAS a public page/badge, so
  // sharing works — open the share row for it too (one-time scans never publish).
  const published = !!(scan as { published?: boolean } | null)?.published
  // Real adoption signals — checks (Redis), watchers, GitHub stars, score history.
  // Skipped for private repos (the public checks endpoint can't see them).
  const { data: adoptionData } = useQuery({
    queryKey: ['rebrand-checks', owner, repo],
    queryFn: async () => (await publicApi.get<{ checks: number; watchers: number; stars: number | null; history: { score: number; at?: number }[] }>(`/public/scan/${owner}/${repo}/checks`)).data,
    retry: 0,
    enabled: !!scan && !isPrivate,
  })
  // The canonical 0–100 adoption score + tier (same query the detail panel uses, so
  // the hero needle and the panel always agree). Deduped by react-query.
  const { data: adoptionScore } = useQuery({
    queryKey: ['rebrand-adoption', owner, repo],
    queryFn: async () => (await publicApi.get<{ adoption_score_100?: number; tier?: string }>(`/public/scan/${owner}/${repo}/adoption`)).data,
    retry: 0,
    enabled: !!scan && !isPrivate,
  })
  const heroBig = useIsDesktop() ? 1.5 : 1  // scale marks up on desktop; MUST be before any early return (hooks order)

  if (!oneTimePrivate && isLoading) return <ScanningLoader owner={owner} repo={repo} />
  // Public scan came back empty — we may still be checking the owner's private report.
  if (publicMissing && !!user && prLoading) return <ScanningLoader owner={owner} repo={repo} />

  if (!scan) {
    return (
      <div className="max-w-[620px] mx-auto px-6 py-24 text-center">
        <div className="glass rounded-2xl p-8">
          <h2 className="text-xl font-semibold">Couldn't scan {owner}/{repo}</h2>
          <p className="mt-2 text-text-muted text-[14px]">The scanner didn't return a result. <strong className="text-text">If this is a private repo</strong>, its report isn't public — re-scan it privately with a read-only token to see it. Otherwise the scan service may be busy; try again in a moment.</p>
          <div className="mt-5 flex items-center justify-center gap-4 flex-wrap">
            <Link to={rp(`/rebrand/tools?owner=${owner}&repo=${repo}`)} className="text-[13.5px] font-semibold text-primary-light hover:text-primary">Scan it privately →</Link>
            <Link to={rp("/rebrand/browse")} className="text-[13.5px] font-semibold text-text-muted hover:text-text">Browse scored tools →</Link>
          </div>
        </div>
      </div>
    )
  }

  // Prefer the backend's letter grade (it applies the A+ "Certified" gate); fall
  // back to deriving from the score for older responses that omit it. Identical to
  // score-derived while the gate is off, so the display is unchanged until it flips.
  const t = getTrustTier(scan.trust_score)
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

  return (
    <div className="max-w-[860px] mx-auto px-6 py-14">
      <SEOHead
        title={`Is ${owner}/${repo} safe? Trust score ${scan.trust_score}/100 (${t.name})`}
        description={`${sum.headline} AgentAvow's signed, offline-verifiable safety score for ${owner}/${repo}: ${scan.trust_score}/100 (${t.name}).`}
        path={`/check/${owner}/${repo}`}
        image={`https://agentavow.com/api/v1/public/scan/${owner}/${repo}/og-image`}
        noindex={isPrivate}
        jsonLd={isPrivate ? undefined : scanReviewJsonLd(`${owner}/${repo}`, t.name, scan.trust_score)}
      />
      {/* BRANDED HERO — two co-equal scores + primary Watch CTA */}
      <motion.div className="rounded-2xl overflow-hidden relative border border-border/60"
        style={{ background: `linear-gradient(135deg, ${t.color}12, transparent 55%), var(--color-surface)` }}
        initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, ease: 'easeOut' }}>
        <div className="absolute inset-0 rounded-2xl pointer-events-none" style={{ boxShadow: `inset 0 0 70px -30px ${t.color}2e` }} />

        {/* header: verdict + plain-English headline */}
        <div className="relative px-7 pt-6">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded ${v.chip}`}>{v.label}</span>
            {isPrivate && <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-warning/15 text-warning">{storedPrivate ? '🔒 Private · via GitHub App' : '🔒 Private scan · not public'}</span>}
            {!isPrivate && <ClaimedBadge surface="github" owner={owner} repo={repo} />}
          </div>
          <h1 className="mt-3 text-[26px] font-extrabold tracking-tight leading-tight">{sum.headline}</h1>
          <div className="mt-1.5 font-mono text-[13px] text-text-muted break-all">{scan.repo}</div>
          {(scan as { tool_description?: string }).tool_description && <div className="mt-2.5 text-[13.5px] text-text-muted max-w-[64ch]">{(scan as { tool_description?: string }).tool_description}</div>}
          {(scan as { long_description?: string }).long_description && <div className="mt-1 text-[12.5px] leading-snug text-text-muted/70 max-w-[64ch]">{(scan as { long_description?: string }).long_description}</div>}
        </div>

        {/* the dual mark — one cohesive instrument: trust (green→red) | adoption (teal→magenta) */}
        <div className="relative px-4 sm:px-7 py-6">
          <div className="relative rounded-2xl border border-border/70 overflow-hidden bg-gradient-to-b from-surface/50 to-surface/10">
            <div className="absolute inset-0 pointer-events-none" style={{ background: `radial-gradient(460px 200px at 24% -25%, ${t.color}20, transparent 70%), radial-gradient(460px 200px at 78% -25%, rgba(45,212,191,0.13), transparent 70%)` }} />
            <div className="relative grid grid-cols-2">
              <div className="p-4 sm:p-6 pb-5 text-center flex flex-col items-center">
                <div className="min-h-[132px] md:min-h-[196px] flex items-center justify-center">{(scan as { certified?: { eligible?: boolean } }).certified?.eligible ? <CertifiedMark score={scan.trust_score} scale={heroBig} /> : <TrustBar score={scan.trust_score} scale={heroBig} />}</div>
                <div className="mt-3 font-mono text-[10.5px] font-bold uppercase tracking-[0.16em]" style={{ color: t.color }}>Attestation Trust</div>
                <div className="mt-0.5 text-[11.5px] text-text-muted">Signed · verifiable now</div>
                <Percentile score={scan.trust_score} />
              </div>
              <div className="p-4 sm:p-6 pb-5 text-center flex flex-col items-center border-l border-border/50">
                <div className="min-h-[132px] md:min-h-[196px] flex items-center justify-center"><AdoptionNeedle count={adCount} unit={adUnit} scorePct={adoptionScore?.adoption_score_100} scale={heroBig} /></div>
                <div className="mt-3 font-mono text-[10.5px] font-bold uppercase tracking-[0.16em] gradient-text">Adoption</div>
                <div className="mt-0.5 text-[11.5px] text-text-muted">{adoption ? adoption.sub : 'no adoption signal yet'}</div>
              </div>
            </div>
          </div>
        </div>

        {/* PRIMARY action — watch */}
        <div className={`relative px-7 ${storedPrivate ? '' : 'pb-7'}`}>
          <WatchCTA owner={owner} repo={repo} />
          <p className="mt-2.5 text-center text-[12px] text-text-muted">We re-scan daily and alert you the moment this score drops.</p>
        </div>

        {/* a stored private repo publishes to search here (then animates into share) */}
        {storedPrivate && (
          <div className="relative px-7 pb-6 mt-4 flex items-center justify-center gap-2 flex-wrap border-t border-border/50 pt-4">
            <PrivateSearchSlot owner={owner} repo={repo} score={scan.trust_score} grade={t.name} published={published} />
          </div>
        )}
      </motion.div>

      {/* PRIMARY ACTIONS — install right below watch (watch is in the hero), so the two
          primary actions lead, consistent with every other score page. */}
      {!isPrivate && (() => {
        const cov = (scan as { coverage?: { surface?: string } }).coverage || {}
        const sd = (scan as { surface_detail?: { name?: string; is_mcp_server?: boolean } }).surface_detail || {}
        const isMcpServer = !!(scan as { metadata?: { is_mcp_server?: boolean } }).metadata?.is_mcp_server
        // Prefer the resolved package coordinate (accurate registry name from the
        // manifest, always set for a package-backed repo) over surface_detail, which
        // is only populated when the flag-gated artifact fetch actually ran.
        const pc = (scan as { package_coordinate?: { surface?: string; name?: string } }).package_coordinate || {}
        const pkg = (pc.surface === 'npm' || pc.surface === 'pypi') && pc.name
          ? { surface: pc.surface, name: pc.name, isMcp: isMcpServer }
          : (cov.surface === 'npm' || cov.surface === 'pypi') && sd.name
            ? { surface: cov.surface, name: sd.name, isMcp: !!sd.is_mcp_server || isMcpServer }
            : undefined
        return <AddToAgent kind="repo" owner={owner} repo={repo} pkg={pkg} isMcpServer={isMcpServer} />
      })()}

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

      {/* A+ "Certified" transparency panel (roadmap §7.5) — only meaningful for
          A-band-or-above (or already-certified) repos; the "how to earn A+" guide
          is noise on a low grade. */}
      {(scan.trust_score >= 81 || (scan as { certified?: { eligible?: boolean } }).certified?.eligible) && (
        <CertifiedPanel certified={(scan as { certified?: { eligible?: boolean; checks?: Record<string, boolean> } }).certified} />
      )}

      {/* Declared scope — the tool's own .agentavow.yml, if present */}
      <DeclaredScopePanel scope={(scan as { declared_scope?: { present?: boolean; egress?: string[]; capabilities?: string[]; note?: string } }).declared_scope} />

      {/* Behavioral deep scan — auto-runs for npm/PyPI; re-run on demand */}
      {!isPrivate && <BehavioralPanel owner={owner} repo={repo} surface={(scan as { package_coordinate?: { surface?: string } }).package_coordinate?.surface} auto={(scan as { behavioral?: BehavioralData | null }).behavioral} />}

      {/* Adoption — the real 5-axis metric, distinct from safety (public repos only) */}
      {!isPrivate && <AdoptionPanel owner={owner} repo={repo} />}

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
          return (
            <div key={key} className="glass rounded-xl px-4 py-3 flex items-center justify-between">
              <span className="text-[14px]">{label}</span>
              <TrustPill score={sc} />
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
          <h3 className="mt-2 text-lg font-bold">This score is signed — you don't have to trust us.</h3>
          <p className="mt-1 text-text-muted text-[14px] max-w-[62ch]">Every result carries a cryptographic signature you can verify offline against our public keys. If anyone tampers with the score, verification fails. That's the difference between a badge and a signature.</p>
          <div className="mt-3 flex gap-4 flex-wrap">
            <a href="https://agentgraph.co/.well-known/jwks.json" target="_blank" rel="noopener noreferrer" className="text-[13px] font-semibold text-primary-light hover:text-primary">Public keys (JWKS) →</a>
            <Link to={rp("/rebrand/how-it-works")} className="text-[13px] font-semibold text-primary-light hover:text-primary">How verification works →</Link>
          </div>
        </div>
      </Reveal>

      {/* the distribution showcase — README badge (trust / trust+adoption) + share card */}
      <Reveal>
        <div className="mt-6"><BadgePromo owner={owner} repo={repo} /></div>
      </Reveal>

      {/* claim / ownership CTA — a one-time scan is ephemeral (report only, nothing stored) */}
      {oneTimePrivate ? (
        <Reveal>
          <div className="mt-6 glass rounded-2xl p-6 border-l-4 border-warning/50">
            <h3 className="text-[15px] font-bold">This is a one-time scan</h3>
            <p className="text-text-muted text-[13.5px] mt-1 max-w-[62ch]">Nothing is stored or listed. For continuous scanning + change alerts, connect the GitHub App on your <Link to={rp('/rebrand/tools')} className="text-primary-light hover:text-primary font-semibold">tools page</Link>.</p>
          </div>
        </Reveal>
      ) : (
        <OwnershipCTA owner={owner} repo={repo} />
      )}
      {storedPrivate && <PublishStoredCTA owner={owner} repo={repo} published={published} />}

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
                  <div className="font-mono text-[11.5px] text-text-muted break-all">{it.file_path}{it.line_number ? `:${it.line_number}` : ''}{(it as {shipped?: boolean}).shipped === false && <span className="ml-2 font-sans text-[9.5px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-surface border border-border text-text-muted/60" title="In a test/doc/example file — scored at a fraction of shipped code">in tests</span>}</div>
                  {it.remediation && <div className="text-[12px] text-text-muted/85 mt-1">→ {it.remediation}</div>}
                </div>
              </div>
            ))}
          </RevealStagger>
        </>
      )}

      {/* share — floats at the bottom, consistent with every other score page */}
      {!isPrivate && (
        <div className="mt-8 flex justify-center">
          <ShareRow owner={owner} repo={repo} score={scan.trust_score} grade={t.name} />
        </div>
      )}
    </div>
  )
}
