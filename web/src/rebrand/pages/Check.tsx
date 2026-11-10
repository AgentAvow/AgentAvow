import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link, useLocation, useSearchParams, Navigate } from 'react-router-dom'
import { rp } from '../basePath'
import { unsupportedRepoHost, unsupportedRepoHostMessage } from '../lib/unsupportedHost'
import { endpointFromCheckPath } from '../lib/endpointPath'
import { NoticeText } from '../components/NoticeText'
import ImageScanDepth from '../components/ImageScanDepth'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion, useReducedMotion } from 'framer-motion'
import { fetchPublicScan, fetchSkillCollectionLead, fetchBehavioralScan, fetchPackageScan, fetchPackageBehavioral, fetchMcpScan, fetchA2aScan, fetchMcpProbe, fetchSkillScan, fetchSkillBehavioral, publicApi } from '../../lib/scanApi'
import type { PublicScanResponse } from '../../types/scan'
import { getTrustTier, decisionOf, decisionPhrase, headline as decisionHeadline, coverageGapNotes } from '../../components/trust/gradeSystem'
import { TrustPill } from '../components/TrustMark'
import { ResultPage, ResultTitle, CertifiedChecklist, NextStepCards, Section, EmptyPanel, type ResultAdoption, type ResultRecheck, type ResultKind } from '../components/ResultPage'
import {
  mcpNameFromUrl, cursorInstall, vscodeInstall, gooseInstall, claudeCodeCmd,
  geminiCmd, codexCmd, claudeDesktopConfig, packageInstallCommands, skillInstallCommands,
  packageStdioTarget, cursorStdio, vscodeStdio, gooseStdio, claudeCodeStdio,
  geminiStdio, codexStdio, stdioServersConfig, collectionSkillInstallCommands,
} from '../lib/installLinks'
import { useAuth } from '../../hooks/useAuth'
import SEOHead from '../../components/SEOHead'
import api from '../../lib/api'
import { trackBadgeCopied, trackCheckSubmit, trackResultView } from '../../lib/analytics'
import { Reveal, RevealStagger, CountUp } from '../components/motion'
import { useRotatingPlaceholder } from '../lib/hooks'
import { summarize } from '../lib/summarize'
import { CapabilitiesPanel, AdvisoriesPanel, McpToolList, PackageFacts, PackageClaim, VerifyPanel, McpWhatItCanDo, McpNotes, hasToolList, packageBadgeUrl } from '../components/ScanEvidence'
import type { AxiosError } from 'axios'

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

/** The one-line verdict for SEO/share copy: the three-phrase headline + its reason
 * (gradeSystem.decisionOf — the same decision VerdictBadge and summarize() read, so the
 * description never disagrees with the banner). "Safe to connect · Certified — …". */
/** "mcp.deepwiki.com/mcp" from an endpoint URL, for titles. */
/** Reports result_view once per result shown. The page path is all it sends: no verdict or score. */
function useResultView(shown: boolean) {
  const { pathname, search } = useLocation()
  useEffect(() => { if (shown) trackResultView() }, [shown, pathname, search])
}

function mcpHostLabel(endpoint: string): string {
  try {
    const u = new URL(endpoint)
    return u.hostname + (u.pathname && u.pathname !== '/' ? u.pathname : '')
  } catch {
    return 'this MCP server'
  }
}

function scanVerdict(scan: PublicScanResponse): string {
  const d = decisionOf(scan)
  return `${decisionHeadline(scan)} — ${d.reason}`
}

const SEV_CLASS: Record<string, string> = {
  critical: 'text-danger bg-danger/15',
  high: 'text-danger bg-danger/10',
  medium: 'text-warning bg-warning/15',
  low: 'text-text-muted bg-surface-hover',
  info: 'text-text-muted bg-surface-hover',
}

function prettyCat(key: string): string {
  return CAT_LABELS[key] || key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

// Detection-category → subscore axis, mirroring src/scanner/scan.py, so a toggle on an
// axis (e.g. Code safety) filters the findings that roll up into it (unsafe_exec, obfuscation…).
const FINDING_AXIS: Record<string, string> = {
  secret: 'secret_hygiene',
  unsafe_exec: 'code_safety', obfuscation: 'code_safety', dynamic_remote_load: 'code_safety',
  hidden_unicode: 'code_safety', prompt_injection: 'code_safety', insecure_deserialization: 'code_safety',
  artifact_drift: 'code_safety', schema_risk: 'code_safety', annotation_lie: 'code_safety',
  exfiltration: 'data_handling', toxic_flow: 'data_handling', lethal_trifecta: 'data_handling',
  fs_access: 'filesystem_access',
  dependency: 'dependency_health', install_hook: 'dependency_health',
}
const axisOf = (c?: string): string => (c ? (FINDING_AXIS[c] || c) : '')

type FindingItem = { category?: string; name?: string; severity?: string; file_path?: string; line_number?: number; remediation?: string; shipped?: boolean }

/**
 * Category scores + findings with "what do you care about" priority toggles (Shawn #5).
 * A VIEW only: toggles reorder/emphasize the subscore cards and re-rank the findings;
 * they NEVER change the score, grade, or verdict. Nothing is hidden — findings outside
 * the selected categories collapse behind a counted "show" fold.
 */
function CategoryFindings({ categoryScores, findings, maxFindings = 15, emptyMessage }: {
  categoryScores?: Record<string, number> | null
  findings?: { items?: FindingItem[]; critical?: number; high?: number; total?: number } | null
  maxFindings?: number
  emptyMessage: string
}) {
  const scores = categoryScores || {}
  const items = findings?.items || []
  const scoreKeys = Object.keys(scores).filter((k) => scores[k] != null)
  const universe = Array.from(new Set([...scoreKeys, ...items.map((i) => axisOf(i.category)).filter(Boolean)]))
  // Default: every category selected, so the chips read as an obvious set you narrow
  // by deselecting — clearer affordance than starting empty.
  const [selected, setSelected] = useState<Set<string>>(() => new Set(universe))
  const [showOther, setShowOther] = useState(false)
  const narrowed = selected.size !== universe.length
  const toggle = (k: string) => setSelected((prev) => {
    const n = new Set(prev)
    if (n.has(k)) n.delete(k); else n.add(k)
    return n
  })
  const orderedKeys = narrowed
    ? [...scoreKeys.filter((k) => selected.has(k)), ...scoreKeys.filter((k) => !selected.has(k))]
    : scoreKeys
  const inCare = items.filter((i) => selected.has(axisOf(i.category)))
  const other = items.filter((i) => !selected.has(axisOf(i.category)))
  const otherCats = Array.from(new Set(other.map((i) => axisOf(i.category)).filter(Boolean)))

  const renderItem = (it: FindingItem, i: number) => (
    <div key={i} className="glass rounded-xl px-4 py-3 flex gap-3 items-start">
      <span className={`font-mono text-[10.5px] uppercase tracking-wide px-1.5 py-0.5 rounded shrink-0 mt-0.5 ${SEV_CLASS[it.severity || 'info'] || SEV_CLASS.info}`}>{it.severity}</span>
      <div className="min-w-0">
        <div className="text-[14px]">{it.name}</div>
        <div className="font-mono text-[11.5px] text-text-muted break-all">{it.file_path}{it.line_number ? `:${it.line_number}` : ''}{it.shipped === false && <span className="ml-2 font-sans text-[9.5px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-surface border border-border text-text-muted/60" title="In a test/doc/example file — scored at a fraction of shipped code">in tests</span>}</div>
        {it.remediation && <div className="text-[12px] text-text-muted/85 mt-1">→ {it.remediation}</div>}
      </div>
    </div>
  )

  return (
    <>
      {universe.length > 1 && (
        <Reveal>
          <div className="mt-8 flex items-center gap-2 flex-wrap">
            <span className="font-mono text-[11px] uppercase tracking-wide text-text-muted mr-1">What do you care about?</span>
            {universe.map((k) => {
              const on = selected.has(k)
              return (
                <button key={k} onClick={() => toggle(k)}
                  className={`font-mono text-[12px] rounded-full px-3 py-1 border transition-colors ${on ? 'border-primary-light text-primary-light bg-primary/10' : 'border-border text-text-muted hover:text-text'}`}>
                  {on ? '✓ ' : ''}{prettyCat(k)}
                </button>
              )
            })}
            {narrowed && <button onClick={() => setSelected(new Set(universe))} className="text-[11.5px] text-text-muted hover:text-text underline underline-offset-2">reset</button>}
          </div>
          <div className="mt-1.5 text-[11px] text-text-muted/70">Filters what you see, not the score.</div>
        </Reveal>
      )}

      {scoreKeys.length > 0 && (
        <>
          <Reveal><h3 className="mt-6 text-[13px] font-mono uppercase tracking-wide text-text-muted">Category scores{narrowed ? ' · your priorities first' : ''}</h3></Reveal>
          <RevealStagger className="grid sm:grid-cols-2 gap-2.5 mt-3" stagger={0.04}>
            {orderedKeys.map((key) => (
              <div key={key} className={`glass rounded-xl px-4 py-3 flex items-center justify-between transition-opacity ${narrowed && !selected.has(key) ? 'opacity-45' : ''}`}>
                <span className="text-[14px]">{prettyCat(key)}</span>
                <TrustPill score={scores[key]} />
              </div>
            ))}
          </RevealStagger>
        </>
      )}

      <RevealStagger className="grid grid-cols-3 gap-3 mt-6" stagger={0.06}>
        {[['critical', findings?.critical ?? 0, 'text-danger'], ['high', findings?.high ?? 0, 'text-warning'], ['total', findings?.total ?? 0, 'text-text']].map(([lab, n, cls]) => (
          <div key={lab as string} className="glass rounded-xl p-4 text-center">
            <CountUp value={n as number} className={`block text-2xl font-bold tabular-nums ${cls}`} />
            <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted">{lab as string}</div>
          </div>
        ))}
      </RevealStagger>

      {items.length > 0 ? (
        <>
          <Reveal><h3 className="mt-8 text-[13px] font-mono uppercase tracking-wide text-text-muted">{narrowed ? `Findings in the categories you care about (${inCare.length})` : `The details (${items.length})`}</h3></Reveal>
          <div className="flex flex-col gap-2 mt-3">
            {inCare.slice(0, maxFindings).map(renderItem)}
          </div>
          {narrowed && other.length > 0 && (showOther ? (
            <div className="flex flex-col gap-2 mt-2">{other.slice(0, maxFindings).map((it, i) => renderItem(it, i + 100000))}</div>
          ) : (
            <button onClick={() => setShowOther(true)} className="mt-3 text-[12.5px] text-text-muted hover:text-text">▸ {other.length} more in other categories ({otherCats.map(prettyCat).join(', ')}) — show</button>
          ))}
        </>
      ) : (
        <Reveal><div className="mt-6 glass rounded-2xl p-6 text-[13.5px] text-success">{emptyMessage}</div></Reveal>
      )}
    </>
  )
}

const CHECK_HINTS = ['github.com/owner/repo', 'npm:chalk', 'pypi:requests', 'crates:serde', 'hf:openai-community/gpt2', 'mcp:https://…', 'a2a:https://…', 'a repo, package, model, MCP server, or A2A agent card']

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
function scanReviewJsonLd(name: string, score: number): Record<string, unknown> {
  return {
    '@context': 'https://schema.org', '@type': 'Review',
    itemReviewed: { '@type': 'SoftwareApplication', name, applicationCategory: 'DeveloperApplication' },
    reviewRating: { '@type': 'Rating', ratingValue: score, bestRating: 100, worstRating: 0 },
    author: { '@type': 'Organization', name: 'AgentAvow' },
    reviewBody: `Signed, offline-verifiable trust score ${score}/100.`,
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

/** Declared scope — a tool's own `.agentavow.yml`: the hosts it says it contacts + the
 * capabilities it uses. Transparency now; the behavioral tier verifies observed-vs-declared. */
function DeclaredScopePanel({ scope, what = 'tool' }: { scope?: { present?: boolean; egress?: string[]; capabilities?: string[]; note?: string }; what?: string }) {
  if (!scope?.present) {
    return <EmptyPanel title="Declared scope">No <span className="font-mono">.agentavow.yml</span> in this {what}. When there is one, the network hosts, files and capabilities it declares show here next to what we found.</EmptyPanel>
  }
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

// ── Shared score-page data hooks and panels (every result type) ─────────────────

/** Re-check: a fresh scan (force) that replaces the cached result on the page. The API
 * rate-limits forced scans; an error just says to try later. */
function useRecheck(key: unknown[], fn: () => Promise<PublicScanResponse>): ResultRecheck {
  const qc = useQueryClient()
  const m = useMutation({ mutationFn: fn, onSuccess: (data) => qc.setQueryData(key, data) })
  return { run: () => m.mutate(), pending: m.isPending, error: m.isError }
}

interface AdoptionResp {
  adoption_score_100?: number; tier?: string; badge?: string; insufficient_data?: boolean
  axes?: Array<{ axis: string; label: string; absolute: number; momentum: number }>
  headline?: { count: number; unit: string } | null
}

/** Surface-aware adoption (packages, MCP servers, skills): the needle's headline count
 * plus the 5-axis breakdown. */
function useSurfaceAdoption(surface: string, owner: string, repo: string, enabled = true) {
  return useQuery({
    queryKey: ['surface-adoption', surface, owner, repo],
    queryFn: async () => (await api.get<AdoptionResp>(
      `/public/scan/adoption?surface=${encodeURIComponent(surface)}&owner=${encodeURIComponent(owner)}&repo=${encodeURIComponent(repo)}`,
    )).data,
    staleTime: 300_000,
    retry: 0,
    enabled,
  }).data
}

/** "downloads/wk" → "downloads a week" for the plain line under the needle. */
function unitWords(unit: string): string {
  return unit.replace(/\/wk$/, ' a week').replace(/\/mo$/, ' a month').replace(/\/yr$/, ' a year').replace(/\/90d$/, ' in 90 days')
}

function adoptionFrom(data: AdoptionResp | undefined, none: string): ResultAdoption {
  const h = data?.headline
  const has = !!(h && h.count && h.count > 0)
  const rising = data?.badge === 'rising' ? ' · rising' : ''
  return {
    count: has ? h!.count : 0,
    unit: has ? h!.unit : undefined,
    scorePct: data?.adoption_score_100,
    sub: has ? `${h!.count.toLocaleString('en-US')} ${unitWords(h!.unit)}${rising}` : none,
  }
}

const _ADOPTION_AXES: Record<string, string> = {
  A: 'Downloads + trend', B: 'Reverse-dependents', C: 'Stars + velocity',
  D: 'First-party (AgentAvow)', E: 'MCP / registry usage',
}

/** Adoption detail — the real 5-axis metric, distinct from safety. */
function AdoptionDetail({ data }: { data?: AdoptionResp | null }) {
  const axes = data?.axes ?? []
  if (!data || axes.length === 0) {
    return <EmptyPanel title="Adoption detail">No usage data yet: no downloads, dependents, stars or registry listings we can count for this tool. Adoption is a separate score from safety; popular is not the same as safe.</EmptyPanel>
  }
  const score = data.adoption_score_100 ?? 0
  const badge = data.badge
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6 border-l-4 border-accent/50">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Adoption detail{!data.insufficient_data ? ` · score ${score}` : ''}</h3>
          {badge && (
            <span className="font-mono text-[10.5px] uppercase tracking-wide px-2 py-0.5 rounded"
              style={{ background: badge === 'rising' ? 'rgba(56,189,248,.14)' : 'rgba(129,140,248,.14)', color: badge === 'rising' ? '#7dd3fc' : '#a5b4fc' }}>
              {badge === 'rising' ? '↑ Rising' : `◆ ${badge}`}
            </span>
          )}
        </div>
        <p className="text-text-muted text-[13px] mt-1 max-w-[62ch]">Do real, independent parties rely on this? A <span className="text-text">separate</span> score from safety: popular is not the same as safe.</p>
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
              <div key={a.axis} className="grid grid-cols-[150px_1fr_auto] items-center gap-3 text-[12px]">
                <span className="text-text-muted truncate">{_ADOPTION_AXES[a.axis] || a.label}</span>
                <span className="h-1.5 rounded-full bg-surface-hover overflow-hidden"><span className="block h-full rounded-full bg-gradient-to-r from-primary to-accent" style={{ width: `${w}%` }} /></span>
                <span className="font-mono text-[11px] text-text-muted/70 tabular-nums">{a.momentum > 0.05 ? '↑' : a.momentum < -0.05 ? '↓' : '·'} {w}</span>
              </div>
            )
          })}
        </div>
      </div>
    </Reveal>
  )
}

type DriftPoint = { scanned_at: string | null; trust_score: number | null; score_delta: number | null; manifest_drift: boolean }
type DriftFeed = { summary: { points: number; drift_events?: number }; history: DriftPoint[] }

/** The signed drift feed for a result (repo, package, MCP endpoint or skill). */
function useDriftFeed(path: string | null) {
  return useQuery({
    queryKey: ['drift-feed', path],
    retry: false,
    enabled: !!path,
    queryFn: async () => {
      try {
        return (await publicApi.get<DriftFeed>(path!, { params: { quiet: 1 } })).data
      } catch { return null }
    },
  }).data
}

/** Score-over-time line chart, from the /checks history (repos) or the signed drift
 * feed (everything else). With fewer than two points it says so instead of hiding. */
function ScoreHistory({ history, current, feedHref, rows }: { history: { score: number; at?: number }[]; current: number; feedHref?: string; rows?: DriftPoint[] }) {
  const merged = [...history]
  // Append the current scan as "now" if it isn't already the last recorded point.
  if (!merged.length || merged[merged.length - 1].score !== current) merged.push({ score: current })
  const pts = merged.slice(-30)
  const feed = feedHref ? <a href={feedHref} target="_blank" rel="noopener noreferrer" className="font-mono text-[11px] text-primary-light hover:text-primary">signed feed ↗</a> : null
  if (pts.length < 2) {
    return (
      <Reveal>
        <div className="mt-4 glass rounded-2xl p-6">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Score history</h3>
            {feed}
          </div>
          <p className="mt-1.5 text-[13px] text-text-muted max-w-[64ch]">Now {current}/100. No change recorded yet: a point is added each time a fresh check moves the score or changes the signed definition. Watch this tool to be alerted when that happens.</p>
        </div>
      </Reveal>
    )
  }

  const W = 320, H = 90, PAD = 8
  const x = (i: number) => PAD + (i / (pts.length - 1)) * (W - 2 * PAD)
  const y = (s: number) => H - PAD - (s / 100) * (H - 2 * PAD) // fixed 0–100 axis
  const line = pts.map((p, i) => `${x(i)},${y(p.score)}`).join(' ')
  const lastG = getTrustTier(pts[pts.length - 1].score)
  const fmt = (at?: number) => at ? new Date(at * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : 'now'
  const firstDate = fmt(pts[0].at)
  const lastDate = fmt(pts[pts.length - 1].at)
  // Version-diff: the change since the FIRST recorded scan (all-time). Always shown —
  // "unchanged" is itself a signal for a trust score.
  const delta = current - pts[0].score

  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6">
        <div className="flex items-baseline justify-between gap-3 flex-wrap">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Score history</h3>
          <span className="font-mono text-[11.5px] text-text-muted">
            <b className="mr-2" style={{ color: delta > 0 ? '#22c55e' : delta < 0 ? '#ef4444' : undefined }}>
              {delta > 0 ? `↑${delta}` : delta < 0 ? `↓${Math.abs(delta)}` : 'unchanged'} since {firstDate}
            </b>
            {pts.length} scans · now <b style={{ color: lastG.color }}>{current}/100</b>
          </span>
        </div>
        <p className="text-text-muted text-[13px] mt-1 mb-3">A living record of every re-check, not a one-shot snapshot. Watch this tool to be alerted the moment the line drops. {feed}</p>
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-[90px]" preserveAspectRatio="none" aria-hidden="true">
          {[0, 50, 100].map((g) => <line key={g} x1={PAD} y1={y(g)} x2={W - PAD} y2={y(g)} stroke="currentColor" className="text-border" strokeWidth="0.5" opacity="0.5" />)}
          <line x1={PAD} y1={y(81)} x2={W - PAD} y2={y(81)} stroke="#2DD4BF" strokeWidth="0.6" strokeDasharray="3 3" opacity="0.6" />
          <polyline points={line} fill="none" stroke={lastG.color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
          {pts.map((p, i) => <circle key={i} cx={x(i)} cy={y(p.score)} r={i === pts.length - 1 ? 4 : 2.5} fill={getTrustTier(p.score).color} />)}
        </svg>
        {/* time axis labels */}
        <div className="flex justify-between font-mono text-[10.5px] text-text-muted/70 mt-1">
          <span>{firstDate}</span>
          <span className="text-text-muted/50">score 0–100 · dashed line = 81, the Certified line</span>
          <span>{lastDate}</span>
        </div>
        {rows && rows.length > 0 && (
          <div className="mt-3 flex flex-col gap-1.5 text-[12.5px]">
            {rows.slice(0, 8).map((p, i) => (
              <div key={i} className="flex justify-between gap-3">
                <span className="font-mono text-text-muted">{(p.scanned_at || '').slice(0, 10)}</span>
                <span className="font-mono">{p.trust_score ?? '–'}/100{p.score_delta ? <span className={p.score_delta > 0 ? 'text-success' : 'text-danger'}> ({p.score_delta > 0 ? '+' : ''}{p.score_delta})</span> : null}{p.manifest_drift ? <span className="text-warning"> · definition changed</span> : null}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </Reveal>
  )
}

/** Score history from the signed drift feed (packages, MCP endpoints, skills). */
function FeedHistory({ path, current }: { path: string; current: number }) {
  const data = useDriftFeed(path)
  const rows = data?.history ?? []
  const pts = [...rows].reverse().filter((p) => typeof p.trust_score === 'number')
    .map((p) => ({ score: p.trust_score as number, at: p.scanned_at ? Date.parse(p.scanned_at) / 1000 : undefined }))
  return <ScoreHistory history={pts} current={current} feedHref={`/api/v1${path}`} rows={rows} />
}

/** Definition changes — whether the tool's SIGNED DEFINITION drifted (a rug-pull can
 * change the tools without moving the score), from the signed, offline-recomputable
 * drift feed. Says plainly when there is no history yet. */
function DefinitionChanges({ path, toolCount }: { path: string; toolCount?: number }) {
  const data = useDriftFeed(path)
  const feedUrl = `/api/v1${path}`
  const history = data?.history ?? []
  const changes = history.filter((h) => h.manifest_drift)
  const watched = toolCount ? `${toolCount} tool${toolCount === 1 ? '' : 's'} watched` : ''
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-5">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Definition changes{watched ? <span className="normal-case tracking-normal font-sans text-[12px]"> · {watched}</span> : null}</h3>
          {history.length > 0 && <a href={feedUrl} target="_blank" rel="noopener noreferrer" className="font-mono text-[11px] text-primary-light hover:text-primary">signed feed ↗</a>}
        </div>
        {!history.length ? (
          <p className="text-[13px] mt-1.5 text-text-muted">No recorded history yet. Each fresh check signs the tool&apos;s definition; when a later one differs, the date and the change show here.</p>
        ) : changes.length > 0 ? (
          <>
            <p className="text-[13px] mt-1.5"><span className="text-warning font-semibold">Signed definition changed {changes.length}×</span>: the tool&apos;s manifest drifted across a release, even where the score held. That&apos;s the rug-pull signal.</p>
            <ul className="mt-2 flex flex-col gap-1 text-[12.5px]">
              {changes.slice(0, 6).map((c, i) => <li key={i} className="flex justify-between gap-3"><span className="font-mono text-text-muted">{(c.scanned_at || '').slice(0, 10)}</span><span className="text-warning">definition changed · {c.trust_score ?? '–'}/100</span></li>)}
            </ul>
          </>
        ) : (
          <p className="text-[13px] mt-1.5"><span className="text-success font-semibold">No change</span>: the definition matches across {data!.summary.points} recorded check{data!.summary.points === 1 ? '' : 's'}.</p>
        )}
        <p className="text-text-muted text-[12px] mt-1">A signed, offline-recomputable timeline: verify it against our public keys instead of taking our word.</p>
      </div>
    </Reveal>
  )
}

/** Share row — copy link + branded X / Bluesky icons. */
function ShareRow({ label, score }: { label: string; score: number }) {
  const [copied, setCopied] = useState(false)
  const url = typeof window !== 'undefined' ? window.location.href : ''
  const text = `${label} scored ${score}/100 on AgentAvow — a signed, verifiable trust score.`
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

/** The share panel ("Share this result"), anchored for the next-steps line. */
function SharePanel({ label, score }: { label: string; score: number }) {
  return (
    <Reveal>
      <div id="share" className="mt-4 glass rounded-2xl p-6 flex items-center justify-between gap-4 flex-wrap scroll-mt-24">
        <div>
          <h3 className="text-[15px] font-bold">Share this result</h3>
          <p className="text-text-muted text-[13.5px] mt-0.5">The link opens this signed, always-current result.</p>
        </div>
        <ShareRow label={label} score={score} />
      </div>
    </Reveal>
  )
}

/** The hosted, always-current assets for a result. */
interface BadgeAssets {
  /** the result page link the badge points to */
  link: string
  badgeUrl: string
  cardUrl: string
  /** the widget.js data-tool coordinate, where the widget can render this tool */
  widgetTool?: string
  /** extra copy-paste HTML for the card (MCP endpoints embed it on websites) */
  cardHtml?: string
}

function badgeMarkdownOf(a: BadgeAssets): string {
  return `[![AgentAvow](${a.badgeUrl})](${a.link})`
}

/** "Show this result in your README" — Badge / Card / Widget tabs. Every asset is a
 * hosted image or script that regenerates from the live signed result: it can't go
 * stale or be faked. */
function BadgeTabs({ assets, unavailable }: { assets?: BadgeAssets; unavailable?: string }) {
  const [tab, setTab] = useState<'badge' | 'card' | 'widget'>('badge')
  const [copied, setCopied] = useState<string | null>(null)
  if (!assets) {
    return <EmptyPanel title="Badge">{unavailable || 'No public badge for this result yet.'}</EmptyPanel>
  }
  const badgeMd = badgeMarkdownOf(assets)
  const cardMd = `[![AgentAvow scores](${assets.cardUrl})](${assets.link})`
  const widget = assets.widgetTool ? `<script src="${typeof window !== 'undefined' ? window.location.origin : 'https://agentavow.com'}/widget.js"\n        data-tool="${assets.widgetTool}"></script>` : ''
  const copyIt = (format: 'badge' | 'card' | 'widget', key: string, text: string) => {
    if (navigator.clipboard) navigator.clipboard.writeText(text)
    trackBadgeCopied(format)
    setCopied(key); setTimeout(() => setCopied(null), 1400)
  }
  const codeBox = (format: 'badge' | 'card' | 'widget', key: string, text: string) => (
    <div className="relative mt-3">
      <pre className="font-mono text-[11.5px] bg-surface border border-border rounded-lg px-3 py-2.5 pr-14 text-text-muted overflow-x-auto whitespace-pre-wrap break-all">{text}</pre>
      <button onClick={() => copyIt(format, key, text)} className="absolute top-1.5 right-1.5 font-mono text-[10.5px] px-2 py-0.5 rounded bg-surface-hover border border-border text-text-muted hover:text-primary-light">{copied === key ? 'copied ✓' : 'copy'}</button>
    </div>
  )
  const tabs: Array<['badge' | 'card' | 'widget', string]> = [['badge', 'Badge'], ['card', 'Card'], ['widget', 'Widget']]
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <h3 className="text-[15px] font-bold">Show this result in your README</h3>
          <Link to={rp('/rebrand/badge')} className="font-mono text-[11px] text-primary-light hover:text-primary">badge builder →</Link>
        </div>
        <p className="mt-1 text-text-muted text-[13px] max-w-[60ch]">Hosted, always-current images that regenerate from the live signed result: they can&apos;t go stale or be faked. Free, no account.</p>
        <div className="mt-4 flex gap-1.5" role="tablist">
          {tabs.map(([k, l]) => (
            <button key={k} role="tab" aria-selected={tab === k} onClick={() => setTab(k)}
              className={`text-[12.5px] px-3 py-1 rounded-lg border transition-colors ${tab === k ? 'border-primary-light text-primary-light bg-primary/10' : 'border-border text-text-muted hover:text-text'}`}>{l}</button>
          ))}
        </div>
        {tab === 'badge' && (
          <>
            <a href={assets.link} target="_blank" rel="noopener noreferrer" className="mt-4 flex items-center justify-center rounded-lg border border-border/60 bg-surface py-6 px-2 overflow-x-auto">
              <img src={assets.badgeUrl} alt="AgentAvow" className="h-[20px] w-auto max-w-none" />
            </a>
            {codeBox('badge', 'badge', badgeMd)}
            <p className="mt-2 font-mono text-[10.5px] text-text-muted/70">the README badge · the answer, the trust score and the adoption score · regenerates on every view</p>
          </>
        )}
        {tab === 'card' && (
          <>
            <a href={assets.link} target="_blank" rel="noopener noreferrer" className="mt-4 block rounded-lg overflow-hidden border border-border/60 max-w-[420px]">
              <img src={assets.cardUrl} alt="AgentAvow trust + adoption card" className="w-full block" loading="lazy" />
            </a>
            {codeBox('card', 'card', cardMd)}
            {assets.cardHtml && codeBox('card', 'cardHtml', assets.cardHtml)}
            <p className="mt-2 font-mono text-[10.5px] text-text-muted/70">a richer, always-current image · a Security section or product page · <a href={assets.cardUrl} target="_blank" rel="noopener noreferrer" className="text-primary-light">open ↗</a></p>
          </>
        )}
        {tab === 'widget' && (widget ? (
          <>
            <p className="mt-4 text-[13px] text-text-muted">One script tag: the live card plus an in-browser signature check.</p>
            {codeBox('widget', 'widget', widget)}
          </>
        ) : (
          <p className="mt-4 text-[13px] text-text-muted">The live widget doesn&apos;t render this kind of result yet. Use the badge or the card; both regenerate from the live result.</p>
        ))}
      </div>
    </Reveal>
  )
}

/** A claim panel for surfaces claimed on My Tools (MCP endpoints, skills, …). */
function ClaimPanel({ href, title = 'Is this your tool?', text }: { href: string | null; title?: string; text?: string }) {
  return (
    <Reveal>
      <div id="claim" className="mt-4 glass rounded-2xl p-6 flex items-center justify-between gap-4 flex-wrap scroll-mt-24">
        <div>
          <h3 className="text-[15px] font-bold">{title}</h3>
          <p className="text-text-muted text-[13.5px] mt-0.5 max-w-[56ch]">{text || 'Claim it to get alerts first, add a declared scope, and show a claimed badge.'}</p>
        </div>
        {href && <Link to={rp(href)} className="text-[13.5px] font-semibold px-4 py-2 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors shrink-0">Claim this tool</Link>}
      </div>
    </Reveal>
  )
}

/** The panels every "What's inside" shares: capabilities, tools and blast radius,
 * advisories and declared scope — each says plainly when it's empty. */
function InsideCommon({ scan, kind, what }: { scan: PublicScanResponse; kind: ResultKind; what: string }) {
  const o = scan as unknown as { capabilities?: unknown[] | null; advisories?: unknown[] | null; incident_history?: { advisories?: unknown[] } | null; package_version?: string | null; declared_scope?: { present?: boolean; egress?: string[]; capabilities?: string[]; note?: string }; surface_detail?: { blast_radius?: Record<string, unknown> } | null; behavioral?: { tool_surface?: { blast_radius?: Record<string, unknown> } } | null }
  const caps = (o.capabilities ?? []).length
  const advisories = (o.advisories?.length ? o.advisories : o.incident_history?.advisories) ?? []
  const br = o.surface_detail?.blast_radius ?? o.behavioral?.tool_surface?.blast_radius
  const tools = hasToolList(scan)
  return (
    <>
      {kind === 'mcp'
        ? <McpWhatItCanDo scan={scan} />
        : caps > 0
          ? <><CapabilitiesPanel scan={scan} /><p className="mt-1.5 px-1 text-[12px] text-text-muted/80">Normal for many tools. Listed so you know, not counted as defects.</p></>
          : <EmptyPanel title="What it can do">No capabilities found in the code it ships: it doesn&apos;t write files, run commands or open sockets in ways we detect.</EmptyPanel>}
      {tools ? <McpToolList scan={scan} /> : (kind === 'mcp' || kind === 'skill' || (scan as { surface_detail?: { is_mcp_server?: boolean } }).surface_detail?.is_mcp_server)
        ? <EmptyPanel title="Tools it serves">No tool list for this result yet. A sandbox run of the published package lists the tools its server serves.</EmptyPanel>
        : null}
      {br?.level ? <BlastRadius scan={{ surface_detail: { blast_radius: br } }} /> : null}
      {kind === 'mcp'
        ? <EmptyPanel title="Advisories">Doesn&apos;t apply: security advisories are published against packages, not hosted endpoints. Scan its package or repo for them.</EmptyPanel>
        : advisories.length > 0 ? <AdvisoriesPanel scan={scan} />
          : <EmptyPanel title="Advisories">None known{o.package_version ? ` for ${o.package_version}` : ''}.</EmptyPanel>}
      <DeclaredScopePanel scope={o.declared_scope} what={what} />
    </>
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
        <div id="claim" className="scroll-mt-24 mt-4 glass rounded-2xl p-6 border-l-4 border-success/60 flex items-center justify-between gap-4 flex-wrap">
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
        <div id="claim" className="scroll-mt-24 mt-4 glass rounded-2xl p-6 flex items-center justify-between gap-4 flex-wrap">
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
      <div id="claim" className="scroll-mt-24 mt-4 glass rounded-2xl p-6 flex items-center justify-between gap-4 flex-wrap">
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
function PrivateSearchSlot({ owner, repo, score, published }: { owner: string; repo: string; score: number; published: boolean }) {
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
        <ShareRow label={`${owner}/${repo}`} score={score} />
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

/** A neutral provenance line: the published artifact matches its source. Shown on every
 * result whose provenance verified, whatever the answer — it says "this is the real
 * artifact", not "this is safe", so it carries no Certified seal. */
function ProvenanceChip() {
  return (
    <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-primary/15 text-primary-light" title="The published artifact's build provenance verified and is bound to its source">
      ✓ Provenance verified · artifact matches source
    </span>
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
  const [notice, setNotice] = useState<string | null>(null)
  const navigate = useNavigate()
  const hint = useRotatingPlaceholder(CHECK_HINTS)
  const go = (raw?: string) => {
    // A pasted install command → its registry coordinate: `npm install chalk` → `npm:chalk`.
    const v = (raw ?? value).trim()
      .replace(/^(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+(?:add|install|i)|bun\s+add)\s+(?:-{1,2}[\w-]+\s+)*/i, 'npm:')
      .replace(/^(?:pip3?\s+install|uv\s+(?:add|pip\s+install)|poetry\s+add)\s+(?:-{1,2}[\w-]+\s+)*/i, 'pypi:')
      .replace(/^cargo\s+(?:add|install)\s+/i, 'crates:')
      // `npm core-js` / `pypi litellm`: a space works like the colon.
      .replace(/^(npm|pypi|python|crates|cargo|hf|huggingface|docker)\s+(?=\S+$)/i, '$1:')
    if (v) trackCheckSubmit()
    setNotice(null)
    // A repo host we know but can't read yet: say so instead of scanning the same-named GitHub repo.
    const host = unsupportedRepoHost(v)
    if (host) { setNotice(unsupportedRepoHostMessage(host)); return }
    // Live MCP server: `mcp:https://…`.
    const mcp = v.match(/^mcp\s*:\s*(https?:\/\/.+)$/i)
    if (mcp) { navigate(rp('/rebrand/check/mcp') + '?endpoint=' + encodeURIComponent(mcp[1].trim())); return }
    // A2A Agent Card: `a2a:https://…`, or a pasted URL to a well-known card path.
    const a2a = v.match(/^a2a\s*:\s*(https?:\/\/.+)$/i)
    if (a2a || /^https?:\/\/\S+\/\.well-known\/agent(?:-card)?\.json(?:[?#]\S*)?$/i.test(v)) {
      navigate(rp('/rebrand/check/a2a') + '?card=' + encodeURIComponent(a2a ? a2a[1].trim() : v)); return
    }
    // Wallet address: EVM `0x…` (40 hex) or Solana base58, optionally `wallet:`-prefixed.
    const wal = v.match(/^(?:wallet\s*:\s*)?(0x[a-fA-F0-9]{40}|[1-9A-HJ-NP-Za-km-z]{32,44})$/)
    if (wal) { navigate(rp(`/rebrand/check/wallet/${wal[1]}`)); return }
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
      // Drop a pinned version: `left-pad@1.3.0`, `@scope/pkg@2`, `litellm==1.0`.
      const name = pkg[2].trim().replace(/(.)@[^@/]*$/, '$1').replace(/\s*(?:===?|>=|<=|~=|!=|[<>]).*$/, '')
      navigate(rp(`/rebrand/check/pkg/${surface}/${name}`))
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
    if (m) { navigate(rp(`/rebrand/check/${m[1]}/${m[2]}`)); return }
    // A bare name is ambiguous across registries: say how to pick one instead of doing nothing.
    if (/^@?[\w.-]+$/.test(v)) setNotice(`Which registry? Try npm:${v} or pypi:${v}`)
  }
  const EXAMPLES: Array<[string, string]> = [
    ['GitHub repo', 'github.com/vercel/next.js'],
    ['npm package', 'npm:sigstore'],
    ['PyPI package', 'pypi:requests'],
    ['HF model', 'hf:openai-community/gpt2'],
    ['Container', 'docker:nginx'],
    ['MCP server', 'mcp:https://mcp.deepwiki.com/mcp'],
    ['A2A agent card', 'a2a:https://agentavow.com/.well-known/agent-card.json'],
  ]
  return (
    <div className="max-w-[1080px] mx-auto px-6 py-20 text-center">
      <SEOHead title="Check a tool" description="Is this tool safe for your agent to connect? Paste a GitHub repo, MCP server, npm/PyPI/crates package, Docker image, Hugging Face model or agent skill for Safe to connect, Review before you connect, or Do not connect, with a signed trust score." path="/check" />
      <h1 className="text-3xl md:text-5xl font-extrabold tracking-tight">Is this tool <span className="gradient-text-bio">safe</span>?</h1>
      <p className="mt-4 text-text-muted max-w-[46ch] mx-auto">Paste anything your agent connects to. We'll tell you — in plain English — whether it's safe, and prove it with a signed score.</p>
      <p className="mt-2 text-[13px] text-text-muted max-w-[56ch] mx-auto">Paste any A2A Agent Card URL for an answer, findings and a signed attestation, including whether the card&apos;s own signature verifies.</p>
      <form onSubmit={(e) => { e.preventDefault(); go() }} className="glass mt-7 mx-auto max-w-[560px] flex gap-2.5 rounded-2xl p-2 pl-4 shadow-lg shadow-primary/10">
        <input value={value} onChange={(e) => setValue(e.target.value)} placeholder={value ? '' : hint}
          className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[15px] text-text placeholder:text-text-muted" />
        <button type="submit" className="font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark">Check</button>
      </form>
      {notice && <p role="alert" className="mt-3 mx-auto max-w-[560px] text-[13px] text-amber-300"><NoticeText text={notice} /></p>}
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
      <div className="mt-3 font-mono text-[11.5px] text-text-muted/70">no account · signed result you can verify offline · GitHub repos, MCP servers, npm, PyPI &amp; crates packages, Docker images, Hugging Face models, agent skills</div>
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
type ExerciseCall = { tool: string; ok: boolean; is_error?: boolean; duration_ms?: number; fs_writes?: string[]; error?: string | null; result_sample?: string }
type ExerciseData = {
  launch_ok: boolean
  server?: { name?: string; version?: string }
  tools?: { name: string; annotations?: Record<string, unknown> }[]
  /** live probe only: the read-only-annotated tools that were eligible to be called */
  eligible?: string[]
  calls?: ExerciseCall[]
  canary?: { env_names?: string[]; seen_in_result?: string[] }
  timed_out?: boolean
  error?: string | null
}
type BehavioralData = {
  ran: boolean; pending?: boolean; timed_out?: boolean; reason?: string
  /** Why it is pending: a run is going, or every sandbox slot is busy and it is queued.
   * `unavailable` = no longer pending; the static result is final. */
  state?: 'running' | 'queued' | 'unavailable'; queue_position?: number
  /** `plan: "live-probe"` blocks are advisory: reported, never scored, no attestation */
  advisory?: boolean; notes?: string[]; observed_at?: string
  egress_hosts?: string[]; unexpected_egress?: string[]; declared_egress?: string[]; vendor_egress?: string[]; fs_writes_sample?: string[]
  error?: string | null
  plan?: string
  exit_code?: number | null
  grade_summary?: { start_reason?: string; start_reason_detail?: string; tools_called?: number }
  attestation?: { jws: string; kid: string; context: string; observed_at: string; verify_url?: string } | null
  canary_exfil?: { via: string; host?: string }[]
  exercise?: ExerciseData | null
  findings?: { category: string; name: string; severity: string; remediation?: string; evidence?: string; rule?: string; advisory?: boolean; tool?: string | null }[]
}
const SANDBOX_SURFACES = new Set(['npm', 'pypi', 'docker', 'skill'])
/** Why a server did not start in the sandbox — none of these is a finding. */
const START_REASONS: Record<string, string> = {
  needs_credentials: 'The server needs credentials to start (an API key or token). The sandbox never supplies real ones, so its tools were not exercised.',
  needs_arguments: 'The server needs a startup argument (a URL, a path, a flag) that the sandbox cannot guess, so its tools were not exercised.',
  missing_binary: 'The server depends on a program the sandbox image does not have, so it could not start.',
  install_failed: 'The package could not be installed in the sandbox, so its server was not started.',
  resource_limit: 'The run exceeded the sandbox memory or time limit (common for packages that download a browser), so its server was not exercised.',
  no_entrypoint: 'The package exposes no runnable entry point, so there was nothing to start.',
  timeout: 'The server never completed the MCP handshake in the sandbox, so its tools were not exercised.',
  crashed: 'The server exited during startup in the sandbox, so its tools were not exercised.',
  unknown: 'The server did not start in the sandbox, so its tools were not exercised.',
}

type ScoreEffect = { applied?: boolean; static_score?: number; score?: number; delta?: number; reason?: string }
/** Why a live probe did not get to call anything — none of these is a finding. */
const PROBE_START_REASONS: Record<string, string> = {
  needs_credentials: 'The server answered the handshake with 401/403 — it needs credentials. No tool was called.',
  timeout: 'The server did not answer the MCP handshake in time, so no tool was called.',
  unknown: 'The MCP handshake failed, so no tool was called.',
}
/** Four targets share the panel: a package coordinate, a GitHub repo, (skill) an OpenClaw /
 * Agent Skill repo whose hooks and scripts the sandbox runs, or (probe) the OPT-IN live
 * probe of a remote MCP server: a button the user must press, read-only-annotated tools
 * only, advisory, never scored. */
function BehavioralPanel({ owner, repo, surface, auto, pkg, skill, effect, probe }: { owner: string; repo: string; surface?: string; auto?: BehavioralData | null; pkg?: { surface: string; name: string; version?: string }; skill?: boolean; effect?: ScoreEffect | null; probe?: { endpoint: string } }) {
  const mut = useMutation({ mutationFn: () => probe ? fetchMcpProbe(probe.endpoint) : skill ? fetchSkillBehavioral(owner, repo) : pkg ? fetchPackageBehavioral(pkg.surface, pkg.name, pkg.version) : fetchBehavioralScan(owner, repo) })
  // While the background run is pending, poll the (cached, non-forcing) scan so the panel
  // fills in by itself. ~8 s interval, gives up after 5 minutes.
  const [startedAt] = useState(() => Date.now())
  const [now, setNow] = useState(() => Date.now())
  const autoPending = !!auto?.pending && !mut.data && !probe
  const poll = useQuery({
    queryKey: ['behavioral-poll', skill ? 'skill' : pkg?.surface ?? 'github', pkg?.name ?? `${owner}/${repo}`, pkg?.version ?? ''],
    queryFn: () => skill ? fetchSkillScan(owner, repo) : pkg ? fetchPackageScan(pkg.surface, pkg.name, false, pkg.version) : fetchPublicScan(owner, repo),
    enabled: autoPending,
    refetchInterval: (q) => {
      const blk = (q.state.data as { behavioral?: BehavioralData | null } | undefined)?.behavioral
      if (blk && !blk.pending) return false
      return Date.now() - startedAt > 5 * 60_000 ? false : 8_000
    },
    refetchIntervalInBackground: false,
  })
  const polled = (poll.data as { behavioral?: BehavioralData | null } | undefined)?.behavioral
  // When the run lands, reload the page's main result too, so the answer, score and
  // "sandbox still running" line above update instead of keeping the provisional copy.
  const qc = useQueryClient()
  const landed = !!polled && !polled.pending
  const pkgSurface = pkg?.surface
  const pkgName = pkg?.name
  useEffect(() => {
    if (!landed || !autoPending) return
    const key = skill ? ['rebrand-skill-scan', owner, repo]
      : pkgSurface ? ['rebrand-pkg-scan', pkgSurface, pkgName]
      : ['rebrand-scan', owner, repo]
    void qc.invalidateQueries({ queryKey: key })
  }, [landed, autoPending, skill, pkgSurface, pkgName, owner, repo, qc])
  const b: BehavioralData | null | undefined = mut.data?.behavioral ?? (polled && !polled.pending ? polled : undefined) ?? auto
  const stillPending = !!b?.pending && !mut.isPending
  useEffect(() => {
    if (!stillPending) return
    const id = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(id)
  }, [stillPending])
  const waited = Math.max(0, Math.round((now - startedAt) / 1000))
  const observedAt = b?.attestation?.observed_at ? new Date(b.attestation.observed_at) : b?.observed_at ? new Date(b.observed_at) : null
  // The live probe panel is always shown on an MCP page (it is the opt-in affordance).
  if (probe) return <LiveProbePanel b={b} pending={mut.isPending} error={mut.isError} observedAt={observedAt} onRun={() => mut.mutate()} />
  // Packages always get the panel; a repo gets it once the sandbox has a result for it
  // (installed straight from git when it publishes no package).
  if ((!surface || !SANDBOX_SURFACES.has(surface)) && !b) return null
  const pending = !!b?.pending
  const undeclared = b?.unexpected_egress ?? []
  const ex = b?.exercise ?? null
  const exercised = ex ? (ex.calls ?? []).length : 0
  const listed = ex ? (ex.tools ?? []).length : 0
  const canaryLeaked = (b?.canary_exfil?.length ?? 0) > 0
  const isMcpRun = !!b?.plan && b.plan.endsWith('-mcp')
  const isSkillRun = b?.plan === 'skill'
  const skillKinds = isSkillRun && ex ? (ex.calls ?? []).reduce((acc, c) => {
    const k = ((ex.tools ?? []).find((t) => t.name === c.tool)?.annotations as { kind?: string } | undefined)?.kind ?? 'script'
    acc[k] = (acc[k] ?? 0) + 1
    return acc
  }, {} as Record<string, number>) : null
  const skillRanLine = skillKinds
    ? [skillKinds.hook ? `${skillKinds.hook} hook${skillKinds.hook === 1 ? '' : 's'}` : '', skillKinds.mcp ? `${skillKinds.mcp} MCP server${skillKinds.mcp === 1 ? '' : 's'}` : '', skillKinds.script ? `${skillKinds.script} script${skillKinds.script === 1 ? '' : 's'}` : ''].filter(Boolean).join(', ')
    : ''
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6 border-l-4 border-primary/50">
        <div className="flex items-center gap-2 flex-wrap">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Behavioral analysis</h3>
          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-primary/15 text-primary-light">sandbox · gVisor</span>
        </div>
        <p className="mt-1.5 text-text-muted text-[13px] max-w-[64ch]">
          Install and run the tool in an isolated sandbox and watch what it actually does —
          the hosts it contacts, the files it writes. An MCP server is started and each of its
          tools (up to 25) is called with synthetic arguments, so a tool that claims to be read-only but
          writes, or that leaks a credential, is caught in the act. Nothing real is given to it:
          credentials are canaries, and the sandbox is destroyed after the run. Any egress beyond
          the registry and the tool&apos;s declared hosts is flagged. The signed observation also
          feeds the trust score by fixed, recomputable rules — a caught credential leak caps it at 45.
          {skill && <> A skill is cloned and every lifecycle hook, bundled MCP server and bundled script it ships is run with no arguments, each with its own timeout, so what runs on your machine without asking is what runs here.</>}
        </p>

        <button
          onClick={() => mut.mutate()}
          disabled={mut.isPending}
          className="mt-3 font-semibold text-[13.5px] px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-70"
        >
          {mut.isPending ? 'Running in the sandbox… (~45s)' : (b && b.ran ? 'Re-run behavioral analysis' : 'Run now')}
        </button>
        <span className="ml-3 text-[12px] text-text-muted">Runs automatically on the first scan; results are kept for a day.</span>
        {mut.isError && <p className="mt-3 text-[13px] text-danger">Couldn&apos;t run the behavioral scan — please try again in a moment.</p>}

        <div className="mt-3 flex items-center gap-2 text-[12.5px]" aria-live="polite">
          {mut.isPending ? (
            <><span className="inline-block w-2 h-2 rounded-full bg-primary animate-pulse" /><span className="text-text-muted">Running now in the sandbox…</span></>
          ) : stillPending && b?.state === 'queued' ? (
            <><span className="inline-block w-2 h-2 rounded-full bg-warning" /><span className="text-text-muted">Waiting for a sandbox slot{b.queue_position ? ` (position ${b.queue_position} in the queue)` : ''} — every slot is busy. The static result above stands; this panel updates by itself.</span></>
          ) : stillPending ? (
            waited < 300 ? (
              <><span className="inline-block w-2 h-2 rounded-full bg-primary animate-pulse" /><span className="text-text-muted">Running in the sandbox · {waited}s — this panel updates by itself (usually under a minute)</span></>
            ) : (
              <><span className="inline-block w-2 h-2 rounded-full bg-warning" /><span className="text-text-muted">Still running or queued behind other runs — reload later, or press Run now.</span></>
            )
          ) : b?.state === 'unavailable' && !b.ran ? (
            <><span className="inline-block w-2 h-2 rounded-full bg-warning" /><span className="text-text-muted">Sandbox unavailable — no slot freed up for two hours, so the answer stands on static analysis alone. Press Run now to try again.</span></>
          ) : b?.ran && (b.grade_summary?.start_reason === 'install_failed' || (isMcpRun && !ex && typeof b.exit_code === 'number' && b.exit_code !== 0)) ? (
            <><span className="inline-block w-2 h-2 rounded-full bg-warning" /><span className="text-text-muted">Ran, but the install failed, so nothing was exercised{observedAt ? ` · ${observedAt.toLocaleString()}` : ''}{b.plan ? ` · plan ${b.plan}` : ''}. Not a finding.</span></>
          ) : b?.ran ? (
            <><span className={`inline-block w-2 h-2 rounded-full ${b.timed_out || ex?.timed_out ? 'bg-warning' : 'bg-success'}`} /><span className="text-text-muted">{b.timed_out || ex?.timed_out ? 'Ran partly (hit its time limit)' : 'Completed'}{observedAt ? ` · observed ${observedAt.toLocaleString()}` : ''}{b.plan ? ` · plan ${b.plan}` : ''}</span></>
          ) : b ? (
            <><span className="inline-block w-2 h-2 rounded-full bg-text-muted" /><span className="text-text-muted">Not run</span></>
          ) : (
            <><span className="inline-block w-2 h-2 rounded-full bg-text-muted" /><span className="text-text-muted">No sandbox result yet</span></>
          )}
        </div>
        {effect?.applied && typeof effect.delta === 'number' && (
          <p className="mt-2 text-[12.5px] text-text-muted">
            <span className="font-mono text-[10.5px] uppercase tracking-wide mr-2">Score</span>
            This observation {effect.delta > 0 ? 'added' : 'took'} {Math.abs(effect.delta)} point{Math.abs(effect.delta) === 1 ? '' : 's'} {effect.delta > 0 ? 'to' : 'from'} the trust score ({effect.static_score} → {effect.score}){effect.reason ? ` — ${effect.reason}` : ''}. <a className="underline" href="/docs/behavioral-sandbox#how-the-sandbox-moves-the-score">How</a>
          </p>
        )}
        {b && !b.ran && !pending && (
          <p className="mt-3 text-[13px] text-text-muted">Behavioral scan didn&apos;t run: {b.reason || b.error || 'no package to exercise in the sandbox'}.</p>
        )}
        {b && b.ran && (
          <div className="mt-4 space-y-3">
            {canaryLeaked && (
              <div className="flex items-center gap-2 text-[13.5px] font-semibold text-danger"><span>⚠</span> Sent a canary credential off the machine ({b.canary_exfil!.map((c) => `${c.via}${c.host ? ` → ${c.host}` : ''}`).join(', ')}).</div>
            )}
            {undeclared.length > 0 ? (
              <div className="flex items-center gap-2 text-[13.5px] font-semibold text-danger"><span>⚠</span> Contacted {undeclared.length} undeclared host{undeclared.length > 1 ? 's' : ''} at install/run time.</div>
            ) : (
              <div className="flex items-center gap-2 text-[13.5px] font-semibold text-success"><span>✓</span> No unexpected network egress observed.</div>
            )}
            {isMcpRun && !ex && typeof b.exit_code === 'number' && b.exit_code !== 0 && (
              <p className="text-[12.5px] text-text-muted">The package could not be installed in the sandbox (install step exited {b.exit_code}), so its MCP server was not started.</p>
            )}
            {(isMcpRun || isSkillRun) && ex && (
              <div>
                <div className="font-mono text-[10.5px] uppercase tracking-wide text-text-muted mb-1.5">
                  {isSkillRun
                    ? (ex.launch_ok ? `Skill cloned${ex.server?.name ? ` (${ex.server.name}${ex.server.version ? ` @ ${ex.server.version}` : ''})` : ''} · ran ${skillRanLine || `${exercised} of ${listed} entrypoints`}` : 'Skill cloned · nothing ran')
                    : `MCP server ${ex.launch_ok ? `started${ex.server?.name ? ` (${ex.server.name}${ex.server.version ? ` ${ex.server.version}` : ''})` : ''} · ${exercised} of ${listed} tool${listed === 1 ? '' : 's'} exercised` : 'did not start'}`}
                </div>
                {!ex.launch_ok && isSkillRun && (
                  <p className="text-[12.5px] text-text-muted">
                    {b.grade_summary?.start_reason === 'no_entrypoint' ? 'The skill ships no lifecycle hook or runnable script, so there was nothing to run.' : (START_REASONS[b.grade_summary?.start_reason ?? ''] ?? ex.error ?? 'Nothing in the skill could be started in the sandbox.')}
                    {b.grade_summary?.start_reason_detail ? <span className="block mt-0.5 font-mono text-[11px] text-text-muted/80">{b.grade_summary.start_reason_detail}</span> : null}
                    <span className="block mt-0.5">Not a finding: a skill with nothing runnable is reported as not exercised, never penalized.</span>
                  </p>
                )}
                {!ex.launch_ok && !isSkillRun && (
                  <p className="text-[12.5px] text-text-muted">
                    {START_REASONS[b.grade_summary?.start_reason ?? ''] ?? ex.error ?? START_REASONS.unknown}
                    {b.grade_summary?.start_reason_detail ? <span className="block mt-0.5 font-mono text-[11px] text-text-muted/80">{b.grade_summary.start_reason_detail}</span> : null}
                    <span className="block mt-0.5">Not a finding: a server that cannot start here is reported as not exercised, never penalized.</span>
                  </p>
                )}
                {ex.launch_ok && (ex.calls ?? []).length > 0 && (
                  <ul className="space-y-1">
                    {(ex.calls ?? []).map((c, i) => {
                      const spec = (ex.tools ?? []).find((t) => t.name === c.tool)
                      const readOnly = spec?.annotations?.readOnlyHint === true
                      const kind = isSkillRun ? ((spec?.annotations as { kind?: string } | undefined)?.kind ?? 'script') : null
                      const wrote = (c.fs_writes?.length ?? 0) > 0
                      const lied = readOnly && wrote
                      return (
                        <li key={i} className="text-[12.5px] flex flex-wrap items-center gap-x-2 gap-y-0.5">
                          <span className={`font-mono break-all ${lied ? 'text-danger' : 'text-text'}`}>{c.tool}</span>
                          {kind && <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-surface border border-border text-text-muted">{kind === 'mcp' ? 'MCP server' : kind}</span>}
                          {readOnly && <span className={`font-mono text-[10px] px-1.5 py-0.5 rounded ${lied ? 'bg-danger/15 text-danger' : 'bg-surface border border-border text-text-muted'}`}>declares read-only</span>}
                          <span className="text-text-muted">{c.ok && !c.is_error ? 'ok' : c.is_error ? 'returned an error' : (c.error || 'failed')}{typeof c.duration_ms === 'number' ? ` · ${c.duration_ms} ms` : ''}</span>
                          {wrote && <span className={`font-mono text-[11px] ${lied ? 'text-danger' : 'text-text-muted'}`}>wrote {c.fs_writes!.length} file{c.fs_writes!.length > 1 ? 's' : ''}{lied ? ' ⚠' : ''}</span>}
                        </li>
                      )
                    })}
                  </ul>
                )}
                {(ex.canary?.seen_in_result?.length ?? 0) > 0 && (
                  <p className="mt-1 text-[12.5px] text-warning">{isSkillRun ? 'A hook or script printed' : 'A tool returned'} the value of {ex.canary!.seen_in_result!.join(', ')} from its environment{isSkillRun ? '' : ' in a result'}.</p>
                )}
                {(ex.canary?.env_names?.length ?? 0) > 0 && (
                  <p className="mt-1 text-[11.5px] text-text-muted">Canary credentials supplied for: {ex.canary!.env_names!.join(', ')}. No real secret was used.</p>
                )}
              </div>
            )}
            <div className="grid sm:grid-cols-2 gap-4">
              <div>
                <div className="font-mono text-[10.5px] uppercase tracking-wide text-text-muted mb-1.5">Network egress ({b.egress_hosts?.length ?? 0})</div>
                <div className="flex flex-wrap gap-1.5">
                  {b.egress_hosts?.length ? b.egress_hosts.map((h) => {
                    const bad = undeclared.includes(h)
                    const vendor = (b.vendor_egress ?? []).includes(h)
                    return <span key={h} title={vendor ? "the tool's own vendor, by name" : undefined} className={`font-mono text-[11.5px] px-2 py-1 rounded-md border ${bad ? 'bg-danger/10 border-danger/40 text-danger' : 'bg-surface border-border text-text'}`}>{h}{bad ? ' ⚠' : vendor ? ' · vendor' : ''}</span>
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
            {(b.timed_out || ex?.timed_out) && <p className="text-[12px] text-warning">Ran partly (hit its time limit) — behavior after that was not observed.</p>}
            {b.attestation?.jws && (
              <p className="text-[12px] text-text-muted">
                <span className="font-mono text-[10.5px] uppercase tracking-wide mr-2">Signed observation</span>
                What you see above is signed (EdDSA, key <span className="font-mono">{b.attestation.kid}</span>) as a dated observation; it feeds the score by the rules above.
                {' '}<a className="underline" href="/docs/verify-attestations#behavioral-observations">Verify it</a>
                {' '}· <button type="button" className="underline" onClick={() => { void navigator.clipboard?.writeText(b.attestation!.jws) }}>copy JWS</button>
              </p>
            )}
          </div>
        )}
      </div>
    </Reveal>
  )
}

/** The opt-in live probe of a remote MCP server, rendered in the behavioral panel's
 * place on the MCP score page. Nothing runs until the user presses the button; only
 * tools whose annotations declare them read-only (and not destructive) are called, at
 * most 10, once each, with synthetic inputs. Advisory — never part of the signed score. */
function LiveProbePanel({ b, pending, error, observedAt, onRun }: { b: BehavioralData | null | undefined; pending: boolean; error: boolean; observedAt: Date | null; onRun: () => void }) {
  const ex = b?.exercise ?? null
  const calls = ex?.calls ?? []
  const eligible = ex?.eligible ?? []
  const listed = ex?.tools ?? []
  const called = new Set(calls.map((c) => c.tool)).size
  const skipped = Math.max(0, listed.length - Math.max(eligible.length, called))
  const findings = b?.findings ?? []
  const ran = !!b?.ran
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6 border-l-4 border-primary/50">
        <div className="flex items-center gap-2 flex-wrap">
          <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Live probe</h3>
          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-warning/15 text-warning">Live probe · advisory</span>
          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-surface border border-border text-text-muted">not scored</span>
        </div>
        <p className="mt-1.5 text-text-muted text-[13px] max-w-[64ch]">
          Calls only tools that declare themselves read-only, with synthetic inputs, once each.
          Use on servers you own or are allowed to test. At most 10 tools, 8 seconds each, no
          credentials sent. What comes back is checked for injection text and credential-looking
          values. A live answer cannot be recomputed by a verifier, so this never changes the
          signed score or the verdict.
        </p>
        <button
          onClick={onRun}
          disabled={pending}
          className="mt-3 font-semibold text-[13.5px] px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-70"
        >
          {pending ? 'Probing… (up to 60s)' : ran ? 'Probe again (read-only tools)' : 'Probe live (read-only tools)'}
        </button>
        <span className="ml-3 text-[12px] text-text-muted">Runs only when you press it; the result is kept for a day.</span>
        {error && <p className="mt-3 text-[13px] text-danger">Couldn&apos;t run the live probe — please try again in a moment.</p>}

        <div className="mt-3 flex items-center gap-2 text-[12.5px]" aria-live="polite">
          {pending ? (
            <><span className="inline-block w-2 h-2 rounded-full bg-primary animate-pulse" /><span className="text-text-muted">Handshaking and calling read-only tools…</span></>
          ) : ran ? (
            <><span className="inline-block w-2 h-2 rounded-full bg-success" /><span className="text-text-muted">Completed{observedAt ? ` · probed ${observedAt.toLocaleString()}` : ''}</span></>
          ) : b ? (
            <><span className="inline-block w-2 h-2 rounded-full bg-text-muted" /><span className="text-text-muted">Not run{b.reason ? `: ${b.reason}` : ''}</span></>
          ) : (
            <><span className="inline-block w-2 h-2 rounded-full bg-text-muted" /><span className="text-text-muted">Not probed — nothing is called until you ask.</span></>
          )}
        </div>

        {ran && ex && (
          <div className="mt-4 space-y-3">
            <div className="font-mono text-[10.5px] uppercase tracking-wide text-text-muted">
              {ex.launch_ok
                ? `Handshake ok${ex.server?.name ? ` (${ex.server.name}${ex.server.version ? ` ${ex.server.version}` : ''})` : ''} · called ${called} of ${Math.max(eligible.length, called)} read-only tool${Math.max(eligible.length, called) === 1 ? '' : 's'}${skipped > 0 ? ` · ${skipped} without a read-only annotation not called` : ''}`
                : 'Handshake failed · nothing called'}
            </div>
            {!ex.launch_ok && (
              <p className="text-[12.5px] text-text-muted">
                {PROBE_START_REASONS[b?.grade_summary?.start_reason ?? ''] ?? PROBE_START_REASONS.unknown}
                {b?.grade_summary?.start_reason_detail ? <span className="block mt-0.5 font-mono text-[11px] text-text-muted/80">{b.grade_summary.start_reason_detail}</span> : null}
                <span className="block mt-0.5">Not a finding.</span>
              </p>
            )}
            {ex.launch_ok && listed.length > 0 && eligible.length === 0 && (
              <p className="text-[12.5px] text-text-muted">None of the {listed.length} listed tool{listed.length === 1 ? '' : 's'} declares <span className="font-mono">readOnlyHint: true</span>, so nothing was called.</p>
            )}
            {ex.launch_ok && calls.length > 0 && (
              <ul className="space-y-1.5">
                {calls.map((c, i) => (
                  <li key={i} className="text-[12.5px]">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                      <span className="font-mono text-text">{c.tool}</span>
                      <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-surface border border-border text-text-muted">declares read-only</span>
                      <span className="text-text-muted">{c.ok && !c.is_error ? 'ok' : c.is_error ? 'returned an error' : (c.error || 'failed')}{typeof c.duration_ms === 'number' ? ` · ${c.duration_ms} ms` : ''}</span>
                    </div>
                    {c.result_sample && <div className="mt-0.5 font-mono text-[11px] text-text-muted/80 break-all line-clamp-2">{c.result_sample}</div>}
                  </li>
                ))}
              </ul>
            )}
            {ex.timed_out && <p className="text-[12px] text-warning">Stopped at the time budget — not every eligible tool was called.</p>}
            {findings.length > 0 ? (
              <div className="space-y-1.5">
                {findings.map((fnd, i) => (
                  <div key={i} className="text-[12.5px] text-text-muted">
                    <span className={`font-mono text-[10.5px] uppercase px-1.5 py-0.5 rounded mr-2 ${fnd.severity === 'high' || fnd.severity === 'critical' ? 'bg-danger/15 text-danger' : fnd.severity === 'medium' ? 'bg-warning/15 text-warning' : 'bg-surface border border-border text-text-muted'}`}>{fnd.severity}</span>
                    <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-warning/10 text-warning mr-2">advisory</span>
                    {fnd.name}
                    {fnd.evidence && <div className="mt-0.5 font-mono text-[11px] text-text-muted/80 break-all">{fnd.evidence}</div>}
                  </div>
                ))}
              </div>
            ) : ex.launch_ok && calls.length > 0 ? (
              <div className="flex items-center gap-2 text-[13.5px] font-semibold text-success"><span>✓</span> No injection text or credential-looking value in any result.</div>
            ) : null}
            <p className="text-[11.5px] text-text-muted/70">Advisory only: a live probe is not reproducible, carries no attestation, and never changes the trust score or the answer (Safe to connect, Review before you connect, or Do not connect).</p>
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
  | { kind: 'skill'; owner: string; repo: string; skillName?: string }
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
              <p className="text-text-muted text-[13px] mt-1 max-w-[62ch]">One click for Cursor, VS Code, or Goose — the checked server, ready to connect.</p>
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
        {props.kind === 'skill' && (props.skillName && props.skillName.toLowerCase() !== props.repo.toLowerCase() ? (
          <>
            <p className="text-text-muted text-[13px] mt-1 max-w-[62ch]">This repo holds a skills collection; we checked the <span className="font-mono text-text">{props.skillName}</span> skill. Cloning the whole repo into your skills directory won&apos;t load it. Copy that skill&apos;s folder instead:</p>
            <div className="mt-3 flex flex-col gap-2">
              {collectionSkillInstallCommands(props.owner, props.repo, props.skillName).map((c) => <CopyRow key={c.label} label={c.label} cmd={c.cmd} multiline />)}
            </div>
          </>
        ) : (
          <>
            <p className="text-text-muted text-[13px] mt-1">Install the skill by cloning it into your skills directory:</p>
            <div className="mt-3 flex flex-col gap-2">
              {skillInstallCommands(props.owner, props.repo).map((c) => <CopyRow key={c.label} label={c.label} cmd={c.cmd} />)}
            </div>
          </>
        ))}
        {props.kind === 'repo' && (props.pkg ? (
          <>
            <p className="text-text-muted text-[13px] mt-1">This repo publishes the <span className="font-mono text-text">{props.pkg.surface}</span> package <span className="font-mono text-text">{props.pkg.name}</span>{props.pkg.isMcp ? ' — an MCP server' : ''}.</p>
            <div className="mt-2"><PkgInstall surface={props.pkg.surface} name={props.pkg.name} isMcp={props.pkg.isMcp} /></div>
          </>
        ) : props.isMcpServer ? (
          <>
            <p className="text-text-muted text-[13px] mt-1">This repo <span className="text-text">contains MCP server code</span>, but no published package is confirmed for it, so there&apos;s no 1-click install. Clone it and follow its README to run it, then point your client at the command or URL it prints.</p>
            <div className="mt-3 flex flex-col gap-2">
              <CopyRow label="git" cmd={`git clone https://github.com/${props.owner}/${props.repo}`} />
            </div>
            <p className="mt-2 text-[12px] text-text-muted">If you already run it as a Streamable-HTTP endpoint, paste that URL on the <Link to={rp('/rebrand/check')} className="text-primary-light hover:text-primary font-semibold">Check</Link> page for a live score + 1-click.</p>
          </>
        ) : (
          <>
            <p className="text-text-muted text-[13px] mt-1">A source repo — clone it to work with the code:</p>
            <div className="mt-3 flex flex-col gap-2">
              <CopyRow label="git" cmd={`git clone https://github.com/${props.owner}/${props.repo}`} />
            </div>
          </>
        ))}
        <div className="mt-4 pt-4 border-t border-border/50 text-[12.5px] text-text-muted">
          Want your agent to run this check itself, before it connects any tool?{' '}
          <Link to={rp('/rebrand/how-it-works') + '#mcp-check'} className="text-primary-light hover:text-primary font-semibold">Add AgentAvow&apos;s MCP &rarr;</Link>
        </div>
      </div>
    </Reveal>
  )
}

/** OpenClaw / Agent Skill score view — grades the capability surface a repo scan
 * misses (auto-exec allowed-tools grant, always-loaded-description injection,
 * lifecycle hooks, script exfil). */
/** The scanner labels every SKILL.md repo "An OpenClaw agent skill"; most are Claude
 * Code / Agent Skills, so the page says what the format is rather than one runtime. */
function skillDescription(d?: string): string | undefined {
  return d === 'An OpenClaw agent skill' ? 'An Agent Skill (SKILL.md) for Claude Code, OpenClaw and other skill-aware agents' : d
}

/** A wallet address resolves to the agent it is bound to, and that agent's linked
 * repo; we send the visitor to that repo's result. */
function WalletResult({ addr }: { addr: string }) {
  const navigate = useNavigate()
  const chain = /^0x/i.test(addr) ? 'ethereum' : 'solana'
  const { data, isLoading, isError } = useQuery({
    queryKey: ['wallet', addr, chain],
    retry: 0,
    queryFn: async () => (await publicApi.get<{ found: boolean; repo?: string; reason?: string }>(
      `/public/scan/wallet/${encodeURIComponent(addr)}?chain=${chain}`)).data,
  })
  useEffect(() => {
    if (data?.repo) navigate(rp(`/rebrand/check/${data.repo}`), { replace: true })
  }, [data, navigate])
  if (isLoading || data?.repo) return <ScanningLoader owner="wallet" repo={addr} />
  const why = isError ? 'We couldn\u2019t look that address up right now. Try again shortly.'
    : !data?.found ? 'No agent on AgentAvow is bound to this address yet.'
    : 'An agent is bound to this address, but it has no linked GitHub repo to check yet.'
  return (
    <div className="max-w-[560px] mx-auto px-6 py-24 text-center">
      <SEOHead title="Wallet not linked to a tool yet" description="Resolve a wallet address to the tool it is linked to." path={`/check/wallet/${addr}`} />
      <h1 className="text-2xl font-extrabold tracking-tight">Not linked to a tool yet</h1>
      <p className="mt-2 font-mono text-[12.5px] text-text-muted break-all">{addr} · {chain}</p>
      <p className="mt-3 text-text-muted text-[14px]">{why} A wallet resolves to a tool once its owner binds the wallet to their AgentAvow account and links the tool&apos;s repo.</p>
      <Link to={rp('/rebrand/check')} className="mt-6 inline-block text-primary-light hover:text-primary font-semibold">← Check something else</Link>
    </div>
  )
}

type SkillRow = { path: string; name: string; trust_score: number; decision: string; critical: number; high: number; files_scanned: number }

/** A repo holding many skills: every skill's answer, each linking to its own page.
 * The repo-level answer above is the WORST of them. */
function SkillCollection({ owner, repo, scan }: { owner: string; repo: string; scan: unknown }) {
  const sd = (scan as { surface_detail?: { collection?: boolean; skills?: SkillRow[]; skills_total?: number; skills_graded?: number; worst_skill?: string } }).surface_detail
  if (!sd?.collection || !sd.skills?.length) return null
  const left = (sd.skills_total ?? sd.skills.length) - (sd.skills_graded ?? sd.skills.length)
  const label: Record<string, [string, string]> = {
    safe: ['Safe to connect', 'text-success'],
    review: ['Review before you connect', 'text-warning'],
    do_not_connect: ['Do not connect', 'text-danger'],
  }
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6">
        <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Skills in this repo ({sd.skills_total ?? sd.skills.length})</h3>
        <p className="mt-2 text-[13.5px] text-text-muted max-w-[62ch]">Each skill installs on its own, so each is checked on its own. The answer above is the <span className="text-text">worst of them</span>{sd.worst_skill ? <> (<span className="font-mono">{sd.worst_skill}</span>)</> : null}. Open a skill for its own result.</p>
        <div className="mt-3 flex flex-col divide-y divide-border">
          {sd.skills.map((k) => {
            const [txt, cls] = label[k.decision] ?? [k.decision, 'text-text-muted']
            return (
              <Link key={k.path} to={rp(`/rebrand/check/skill/${owner}/${repo}/${k.path}`)} className="flex items-center justify-between gap-3 py-2.5 hover:bg-surface/60 rounded-lg px-2 -mx-2">
                <span className="min-w-0"><span className="font-mono text-[13px] break-all">{k.name}</span>{k.name !== k.path && <span className="block font-mono text-[11px] text-text-muted break-all">{k.path}</span>}</span>
                <span className="shrink-0 text-right"><span className={`text-[12.5px] font-semibold ${cls}`}>{txt}</span><span className="block font-mono text-[11px] text-text-muted">{k.trust_score}/100</span></span>
              </Link>
            )
          })}
        </div>
        {left > 0 && <p className="mt-2 text-[12px] text-text-muted">{left} more skill{left === 1 ? '' : 's'} not checked in this pass (size or time cap); open them by path to check each one.</p>}
      </div>
    </Reveal>
  )
}

const ORIGIN = () => (typeof window !== 'undefined' ? window.location.origin : 'https://agentavow.com')
const encPath = (name: string) => name.split('/').map(encodeURIComponent).join('/')

/** The repo-level badge, card and widget (a GitHub repo, or a skill collection whose
 * repo badge leads with the collection's answer). */
function repoBadgeAssets(owner: string, repo: string): BadgeAssets {
  const origin = ORIGIN()
  return {
    link: `${origin}/check/${owner}/${repo}`,
    badgeUrl: `${origin}/api/v1/public/scan/${owner}/${repo}/badge`,
    cardUrl: `${origin}/api/v1/public/scan/${owner}/${repo}/card.svg`,
    widgetTool: `${owner}/${repo}`,
  }
}

function SkillResult({ owner, repo, skill }: { owner: string; repo: string; skill?: string }) {
  const key = ['rebrand-skill-scan', owner, repo, skill ?? '']
  const { data: scan, isLoading, isError } = useQuery({
    queryKey: key,
    queryFn: () => fetchSkillScan(owner, repo, false, skill),
    retry: 0,
  })
  const recheck = useRecheck(key, () => fetchSkillScan(owner, repo, true, skill))
  const adoptionData = useSurfaceAdoption('openclaw', owner, repo, !!scan)
  const driftPath = `/public/drift/pkg/skill/${owner}/${repo}${skill ? `/${encPath(skill)}` : ''}`
  useResultView(!!scan)
  if (isLoading) return <ScanningLoader owner="skill" repo={`${owner}/${repo}${skill ? `/${skill}` : ''}`} />
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
  const verdict = scanVerdict(scan)
  const sd = (scan as { surface_detail?: { collection?: boolean; skill_name?: string; allowed_tools?: string[]; has_lifecycle_hooks?: boolean; script_count?: number } }).surface_detail
  const collection = !!sd?.collection
  const skillName = sd?.skill_name || (skill ? skill.split('/').pop() : '')
  const label = `${owner}/${repo}${skill ? `/${skill}` : ''}`
  const tools = sd?.allowed_tools ?? []
  const badge = collection && !skill ? repoBadgeAssets(owner, repo) : undefined
  return (
    <>
      <SEOHead
        title={`Is ${skill ? `the ${skill.split('/').pop()} skill (${owner}/${repo})` : `the ${owner}/${repo} skill`} safe? ${decisionHeadline(scan)} · trust score ${scan.trust_score}/100`}
        description={`${verdict}. AgentAvow's signed capability score for the ${owner}/${repo} Agent Skill: ${scan.trust_score}/100 (${t.name}), verifiable offline.`}
        path={`/check/skill/${owner}/${repo}${skill ? `/${skill}` : ''}`}
        image={`https://agentavow.com/api/v1/public/scan/${owner}/${repo}/og-image`}
        jsonLd={scanReviewJsonLd(`${owner}/${repo}`, scan.trust_score)}
      />
      <ResultPage
        scan={scan as unknown as Record<string, unknown> & { trust_score: number }}
        kind="skill"
        eyebrow={['Agent Skill', label]}
        name={skillName && !collection ? `the ${skillName} skill` : `${owner}/${repo}`}
        recheck={recheck}
        banner={<IncidentBanner scan={scan} />}
        chips={<>
          <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-primary/15 text-primary-light uppercase">Agent Skill</span>
          <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-success/15 text-success">🔒 Capability-checked</span>
          <ClaimedBadge surface="openclaw" owner={owner} repo={repo} />
        </>}
        intro={<>
          {skill && <Link to={rp(`/rebrand/check/skill/${owner}/${repo}`)} className="mt-2 inline-block text-[12.5px] text-primary-light hover:text-primary">← All skills in {owner}/{repo}</Link>}
          {!skill && collection && <p className="mt-2 text-[12.5px] text-text-muted max-w-[62ch]">This repo is a collection of agent skills, so its answer is its worst skill&apos;s. <Link to={`${rp(`/rebrand/check/${owner}/${repo}`)}?code=1`} className="text-primary-light hover:text-primary">See the repository code scan →</Link></p>}
          {(scan as { tool_description?: string }).tool_description && <div className="mt-2 text-[13.5px] text-text-muted max-w-[62ch]">{skillDescription((scan as { tool_description?: string }).tool_description)}</div>}
          {(scan as { long_description?: string }).long_description && <div className="mt-1 text-[12.5px] leading-snug text-text-muted/75 max-w-[62ch]">{(scan as { long_description?: string }).long_description}</div>}
        </>}
        adoption={adoptionFrom(adoptionData, 'No usage data: no installs or stars we can count yet')}
        allFindings={<CategoryFindings categoryScores={null} findings={scan.findings} maxFindings={15} emptyMessage={coverageGapNotes(scan).length ? '✓ No capability-surface risks found in what was read; see what we couldn’t check above.' : '✓ No capability-surface risks found: clean skill.'} />}
        install={!collection ? <AddToAgent kind="skill" owner={owner} repo={repo} skillName={sd?.skill_name} /> : undefined}
        watch={<WatchCTA surface="openclaw" owner={owner} repo={repo} />}
        badgeMarkdown={badge ? badgeMarkdownOf(badge) : undefined}
        keepWatching={{
          history: <FeedHistory path={driftPath} current={scan.trust_score} />,
          adoption: <AdoptionDetail data={adoptionData} />,
          drift: <DefinitionChanges path={driftPath} />,
        }}
        inside={<>
          <SkillCollection owner={owner} repo={repo} scan={scan} />
          {skill && (
            <p className="mt-4 px-1 text-[12.5px] text-text-muted">
              The sandbox runs the whole <span className="font-mono">{owner}/{repo}</span> repo, so the run below covers every skill in it, not only <span className="font-mono">{skill.split('/').pop()}</span>.
            </p>
          )}
          <BehavioralPanel owner={owner} repo={repo} surface="skill" skill auto={(scan as { behavioral?: BehavioralData | null }).behavioral} effect={(scan as { behavioral_score_effect?: ScoreEffect | null }).behavioral_score_effect} />
          <Reveal>
            <div className="mt-4 glass rounded-2xl p-6">
              <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">What runs without asking</h3>
              <div className="mt-3 flex flex-col gap-2 text-[12.5px]">
                {sd?.skill_name && <div className="flex justify-between gap-3"><span className="text-text-muted">Skill</span><span className="font-mono">{sd.skill_name}</span></div>}
                <div className="flex justify-between gap-3 items-start"><span className="text-text-muted shrink-0">Auto-approved tools</span><span className="font-mono text-right">{tools.length ? tools.join(', ') : 'none'}</span></div>
                <div className="flex justify-between gap-3"><span className="text-text-muted">Lifecycle hooks</span><span className={`font-mono ${sd?.has_lifecycle_hooks ? 'text-warning' : ''}`}>{sd?.has_lifecycle_hooks ? 'present' : 'none'}</span></div>
                {typeof sd?.script_count === 'number' && <div className="flex justify-between gap-3"><span className="text-text-muted">Bundled scripts</span><span className="font-mono">{sd.script_count}</span></div>}
              </div>
            </div>
          </Reveal>
          <InsideCommon scan={scan} kind="skill" what="skill" />
        </>}
        badgeClaimShare={<>
          <BadgeTabs assets={badge} unavailable="A badge for a single skill isn't available yet. The repo's own badge shows its code scan, which can read differently from this skill's answer." />
          <ClaimPanel href={`/rebrand/tools?coord=${encodeURIComponent(`skill:${owner}/${repo}`)}`} text="Claim this skill's repo to get alerts first, add a declared scope, and show a claimed badge. Proof is a GitHub topic on the repo." />
          <SharePanel label={label} score={scan.trust_score} />
        </>}
        proof={<VerifyPanel scan={scan} />}
        whatWeChecked={
          <div className="mt-4 rounded-xl border border-border/60 p-5">
            <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">What we checked</h3>
            <p className="mt-2 text-[13.5px] text-text-muted max-w-[62ch]">A skill&apos;s <span className="text-text">description is loaded into your model every session</span>, and its <span className="text-text font-mono">allowed-tools</span> pre-approves tools to run <span className="text-text">without asking</span>. We checked that auto-exec grant, hidden instructions in the always-loaded description, lifecycle-hook escalation, and credential-exfil in the bundled scripts.</p>
          </div>
        }
      />
    </>
  )
}

/** Live MCP server score view — grades the SERVED tool surface (what the server
 * actually advertises at runtime), not a repo. The agent-specific moat. */
/** Capability blast radius — what a tool could DO if misused / its input is poisoned,
 * distinct from its code grade. Reads surface_detail.blast_radius (MCP + skills). */
/** Context-only incident-history banner (OSV MAL- advisories for the target's own
 * coordinate). Never affects the score — red if the current version is flagged, amber
 * for a past-and-cleaned compromise. Renders nothing when there's no known incident. */
function IncidentBanner({ scan }: { scan: PublicScanResponse }) {
  return <><DeprecationBanner scan={scan} /><IncidentHistoryBanner scan={scan} /></>
}

/** The maintainer retired this package (npm deprecated / PyPI yanked or Inactive). Clean
 * code can still be abandoned: no security fixes are coming. Also a medium finding. */
function DeprecationBanner({ scan }: { scan: PublicScanResponse }) {
  if (!scan.deprecation) return null
  return (
    <div className="mt-4 rounded-2xl border border-warning/40 bg-warning/10 p-4 text-[13px]">
      <div className="font-semibold text-warning">Deprecated by its maintainer</div>
      <p className="mt-1 text-text-muted">This package is retired and won&apos;t receive security fixes. Don&apos;t adopt it for new work; use a maintained alternative and scan that.</p>
      <p className="mt-1 font-mono text-[11.5px] text-text-muted break-words">“{scan.deprecation}”</p>
    </div>
  )
}

function IncidentHistoryBanner({ scan }: { scan: PublicScanResponse }) {
  const ih = scan.incident_history
  if (!ih?.has_incident) return null
  const latest = (ih.incidents || [])[0] || {}
  const affected = !!ih.current_version_affected
  const when = (latest.published || '').slice(0, 10)
  const id = latest.id || 'advisory'
  return (
    <div className={`mt-3 rounded-xl border-l-4 px-4 py-3 text-[13px] leading-relaxed ${affected ? 'border-red-500 bg-red-500/10' : 'border-amber-500 bg-amber-500/10'}`}>
      {affected ? (
        <><span className="font-bold text-red-500">🚨 Known compromise — this version is flagged malicious.</span> Do not install this version.</>
      ) : (
        <><span className="font-bold text-amber-500">⚠ Incident history</span> — this package had a known compromise; the current version is not flagged. <span className="text-text-muted">Context only — it doesn’t change the score.</span></>
      )}
      <div className="mt-1 font-mono text-[11px] text-text-muted">
        {id}{when ? ` · ${when}` : ''}{ih.count && ih.count > 1 ? ` · ${ih.count} advisories` : ''}{latest.summary ? ` — ${latest.summary}` : ''}
      </div>
    </div>
  )
}

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

/** The API's own words for a failed check (FastAPI `detail`), if it sent any. */
function errorDetail(err: unknown): string {
  const d = (err as AxiosError<{ detail?: unknown }> | null)?.response?.data?.detail
  return typeof d === 'string' ? d : ''
}

/** The couldn't-check state for a live MCP server we could not read (a sign-in wall, no
 * handshake). There is no signed result, so there is no answer or score to show: the
 * page says what we couldn't read and what to check instead. */
function McpCouldntCheck({ endpoint, detail }: { endpoint: string; detail: string }) {
  const signIn = /sign-in|oauth|401|403|credential/i.test(detail)
  const host = mcpHostLabel(endpoint)
  const rows = [
    { label: 'Reads Safe to connect at 81+', state: 'fail' as const, evidence: "No answer: the live tools couldn't be read" },
    { label: 'Published package matches its source', state: 'fail' as const, evidence: 'A server checked by URL has no published package to match' },
    { label: 'Every file read, nothing changed', state: 'fail' as const, evidence: "The live tool list couldn't be read" },
    { label: 'Sandbox ran it, anyone can recompute', state: 'fail' as const, evidence: 'no signed result for this server' },
  ]
  return (
    <div className="max-w-[860px] mx-auto px-6 py-14" data-result-kind="mcp" data-state="couldnt-check">
      <SEOHead title={`Is ${host} safe to connect? We couldn't check it`} description={`AgentAvow couldn't read the tools served at ${host}.`} path={`/check/mcp?endpoint=${encodeURIComponent(endpoint)}`} noindex />
      <ResultTitle eyebrow={['MCP server', host, signIn ? 'sign-in required' : 'not reachable']} checked="just now" name={host} />
      <Reveal>
        <div className="mt-6 glass rounded-2xl border border-warning/40 px-6 py-6" data-testid="answer-card">
          <div className="flex items-center gap-2.5 text-[22px] sm:text-[26px] font-extrabold tracking-tight text-warning"><span aria-hidden="true">!</span><span>We couldn&apos;t check this server</span></div>
          <p className="mt-2 text-[14.5px] text-text-muted max-w-[68ch]">
            {signIn
              ? 'The live server needs a sign-in, so its tool list isn’t public and we can’t read it. There is no signed answer or score for it.'
              : <>We couldn&apos;t handshake it. It needs to be a reachable <span className="text-text">Streamable-HTTP</span> MCP endpoint (stdio and SSE-only servers aren&apos;t supported yet). There is no signed answer or score for it.</>}
          </p>
          {detail && <p className="mt-2 font-mono text-[11.5px] text-text-muted/80 break-words">{detail}</p>}
        </div>
      </Reveal>
      <CertifiedChecklist scan={{}} kind="mcp" rowsOverride={rows} statusOverride={{ lead: 'Not Certified', rest: "the live server couldn't be read" }} />
      <Section id="not-checked" title="What we couldn't check">
        <Reveal>
          <div className="mt-4 glass rounded-2xl px-5 py-4 flex flex-col gap-2 text-[13.5px] text-text-muted border border-warning/35" data-testid="not-checked">
            <p><b>The live server&apos;s tools:</b> not read{signIn ? `, because ${host} requires a sign-in` : ''}. Connect it and ask Claude or ChatGPT to check the tools it shows you.</p>
            <p><b>What to check instead:</b> its published source repo or package. Paste either into the <Link to={rp('/rebrand/check')} className="text-primary-light hover:text-primary font-semibold">check box</Link> for a signed answer.</p>
          </div>
        </Reveal>
      </Section>
      <Section id="next-steps" title="Next steps">
        <NextStepCards oneTime />
      </Section>
    </div>
  )
}

function McpResult({ endpoint }: { endpoint: string }) {
  const key = ['rebrand-mcp-scan', endpoint]
  const { data: scan, isLoading, isError, error } = useQuery({
    queryKey: key,
    queryFn: () => fetchMcpScan(endpoint),
    retry: 0,
  })
  const recheck = useRecheck(key, () => fetchMcpScan(endpoint, true))
  const adoptionData = useSurfaceAdoption('mcp', 'mcp', endpoint, !!scan)
  const driftPath = `/public/drift/mcp?endpoint=${encodeURIComponent(endpoint)}`
  useResultView(!!scan)
  if (isLoading) return <ScanningLoader owner="MCP server" repo={endpoint} />
  if (isError || !scan) return <McpCouldntCheck endpoint={endpoint} detail={errorDetail(error)} />
  const t = getTrustTier(scan.trust_score)
  const f = scan.findings
  const verdict = scanVerdict(scan)
  const origin = ORIGIN()
  const q = `endpoint=${encodeURIComponent(endpoint)}`
  const assets: BadgeAssets = {
    link: `${origin}/check/mcp?${q}`,
    badgeUrl: `${origin}/api/v1/public/scan/mcp/badge?${q}`,
    cardUrl: `${origin}/api/v1/public/scan/mcp/card.svg?${q}`,
  }
  assets.cardHtml = `<a href="${assets.link}"><img src="${assets.cardUrl}" alt="AgentAvow Trust" width="360"></a>`
  const sd = (scan as { surface_detail?: {
    server_name?: string; tool_count?: number; resource_count?: number;
    prompt_count?: number; capabilities?: Record<string, number>;
    lethal_trifecta?: boolean } }).surface_detail || {}
  const caps = sd.capabilities && Object.keys(sd.capabilities).length ? Object.keys(sd.capabilities) : []
  const facts: string[] = []
  if (sd.tool_count != null) facts.push(`${sd.tool_count} tool${sd.tool_count === 1 ? '' : 's'} checked`)
  if (sd.resource_count) facts.push(`${sd.resource_count} resource${sd.resource_count === 1 ? '' : 's'}`)
  if (sd.prompt_count) facts.push(`${sd.prompt_count} prompt${sd.prompt_count === 1 ? '' : 's'}`)
  return (
    <>
      <SEOHead
        title={`Is ${mcpHostLabel(endpoint)} safe? ${decisionHeadline(scan)} · trust score ${scan.trust_score}/100`}
        description={`${verdict}. AgentAvow live-checked this MCP server's served tool surface: ${scan.trust_score}/100 (${t.name}).`}
        path={`/check/mcp?endpoint=${encodeURIComponent(endpoint)}`}
        jsonLd={scanReviewJsonLd(endpoint, scan.trust_score)}
      />
      <ResultPage
        scan={scan as unknown as Record<string, unknown> & { trust_score: number }}
        kind="mcp"
        eyebrow={['MCP server', mcpHostLabel(endpoint)]}
        name={mcpHostLabel(endpoint)}
        recheck={recheck}
        banner={<IncidentBanner scan={scan} />}
        chips={<>
          <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-primary/15 text-primary-light uppercase">MCP server</span>
          <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-success/15 text-success">⚡ Live-checked</span>
          <ClaimedBadge surface="mcp" repo={endpoint} />
        </>}
        intro={<>
          <div className="mt-2 font-mono text-[12px] text-text-muted break-all">{endpoint}</div>
          {(scan as { tool_description?: string }).tool_description && <div className="mt-1.5 text-[13.5px] text-text-muted max-w-[62ch]">{(scan as { tool_description?: string }).tool_description}</div>}
          {(scan as { long_description?: string }).long_description && <div className="mt-1 text-[12.5px] leading-snug text-text-muted/75 max-w-[62ch]">{(scan as { long_description?: string }).long_description}</div>}
        </>}
        adoption={adoptionFrom(adoptionData, 'No usage data: a hosted URL has no public download count')}
        allFindings={<CategoryFindings categoryScores={null} findings={f} maxFindings={15} emptyMessage={coverageGapNotes(scan).length ? '✓ No capability-surface risks found in what was read; see what we couldn’t check above.' : '✓ No capability-surface risks found: clean tool set.'} />}
        gapNotes={[
          <p key="code"><b>Server code:</b> not read. A live endpoint is graded on the tools it serves; its hosted code isn&apos;t visible to us, so the code categories (secret hygiene, code safety, data handling, filesystem, dependencies) aren&apos;t scored. Scan its repo or package for those.</p>,
        ]}
        gapPanel={<McpNotes endpoint={endpoint} />}
        install={<AddToAgent kind="mcp" url={endpoint} />}
        watch={<WatchCTA surface="mcp" owner="mcp" repo={endpoint} />}
        badgeMarkdown={badgeMarkdownOf(assets)}
        keepWatching={{
          history: <FeedHistory path={driftPath} current={scan.trust_score} />,
          adoption: <AdoptionDetail data={adoptionData} />,
          drift: <DefinitionChanges path={driftPath} toolCount={sd.tool_count} />,
        }}
        inside={<>
          {/* Opt-in live probe — nothing is called until the user presses the button */}
          <BehavioralPanel owner="mcp" repo={endpoint} probe={{ endpoint }} auto={(scan as { behavioral?: BehavioralData | null }).behavioral} />
          <InsideCommon scan={scan} kind="mcp" what="server" />
        </>}
        badgeClaimShare={<>
          <BadgeTabs assets={assets} />
          <ClaimPanel href={`/rebrand/tools?coord=${encodeURIComponent(`mcp:${endpoint}`)}`} title="Run this server?" text="Claim it to get alerts first, add a declared scope, and show a claimed badge." />
          <SharePanel label={mcpHostLabel(endpoint)} score={scan.trust_score} />
        </>}
        proof={<VerifyPanel scan={scan} />}
        whatWeChecked={
          <div className="mt-4 rounded-xl border border-border/60 p-5">
            <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">What we checked</h3>
            <p className="mt-2 text-[13.5px] text-text-muted max-w-[62ch]">We connected to the server and checked the <span className="text-text">tool surface it actually serves</span>: input-schema risk, hidden instructions in tool descriptions, dangerous capabilities, and the lethal trifecta across its tools. This is what a repo scan can&apos;t see.</p>
            <div className="mt-3 flex flex-col gap-2 text-[13px]">
              <div className="flex justify-between gap-3"><span className="text-text-muted">Server</span><span className="font-mono break-all">{sd.server_name || 'unnamed'}</span></div>
              <div className="flex justify-between gap-3"><span className="text-text-muted">Endpoint</span><span className="font-mono text-success">live · streamable-HTTP</span></div>
              <div className="flex justify-between gap-3"><span className="text-text-muted">Point-in-time</span><span className="font-mono">served surface, checked now</span></div>
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
        }
      />
    </>
  )
}

type A2aSurface = {
  agent_name?: string; card_url?: string; card_shape?: string; protocol_version?: string
  skill_count?: number; interface_count?: number; legacy_path?: boolean
  interfaces?: { url: string; binding: string }[]
  auth?: { schemes?: Record<string, string>; card_requires_auth?: boolean }
  skills?: { id: string; name: string; description: string; capabilities: string[]; authenticated: boolean }[]
  signature?: { state?: string; alg?: string; kid?: string; jku?: string; reason?: string }
  card_digest?: string
}

const SIGNATURE_LABEL: Record<string, [string, string]> = {
  verified: ['verifies ✓', 'text-success'],
  unverified: ['present, could not be verified', 'text-warning'],
  absent: ['not signed', 'text-text-muted'],
}

/** The couldn't-check state for an A2A Agent Card we could not read. */
function A2aCouldntCheck({ card, detail }: { card: string; detail: string }) {
  const host = mcpHostLabel(card)
  return (
    <div className="max-w-[860px] mx-auto px-6 py-14" data-result-kind="a2a" data-state="couldnt-check">
      <SEOHead title={`Is ${host} safe to connect? We couldn't check it`} description={`AgentAvow couldn't read an A2A Agent Card at ${host}.`} path={`/check/a2a?card=${encodeURIComponent(card)}`} noindex />
      <ResultTitle eyebrow={['A2A agent card', host, 'not readable']} checked="just now" name={host} />
      <Reveal>
        <div className="mt-6 glass rounded-2xl border border-warning/40 px-6 py-6" data-testid="answer-card">
          <div className="flex items-center gap-2.5 text-[22px] sm:text-[26px] font-extrabold tracking-tight text-warning"><span aria-hidden="true">!</span><span>We couldn&apos;t read that agent card</span></div>
          <p className="mt-2 text-[14.5px] text-text-muted max-w-[68ch]">Give the card&apos;s https URL (for example <span className="font-mono text-text">https://agent.example.com/.well-known/agent-card.json</span>) or the agent&apos;s base URL. There is no signed answer or score for it.</p>
          {detail && <p className="mt-2 font-mono text-[11.5px] text-text-muted/80 break-words">{detail}</p>}
        </div>
      </Reveal>
      <Section id="next-steps" title="Next steps">
        <NextStepCards oneTime />
      </Section>
    </div>
  )
}

/** An A2A Agent Card, graded on the card alone (interfaces, auth, skill text, its own
 * signature), rendered through the shared ResultPage. The agent's code is never seen,
 * so the code categories are not scored. */
function A2aResult({ card }: { card: string }) {
  const key = ['rebrand-a2a-scan', card]
  const { data: scan, isLoading, isError, error } = useQuery({
    queryKey: key,
    queryFn: () => fetchA2aScan(card),
    retry: 0,
  })
  const recheck = useRecheck(key, () => fetchA2aScan(card, true))
  useResultView(!!scan)
  if (isLoading) return <ScanningLoader owner="A2A agent" repo={card} />
  if (isError || !scan) return <A2aCouldntCheck card={card} detail={errorDetail(error)} />
  const t = getTrustTier(scan.trust_score)
  const sd = ((scan as { surface_detail?: A2aSurface }).surface_detail || {}) as A2aSurface
  const sig = sd.signature?.state || 'absent'
  const [sigText, sigClass] = SIGNATURE_LABEL[sig] || SIGNATURE_LABEL.absent
  const schemes = Object.entries(sd.auth?.schemes || {})
  const host = mcpHostLabel(sd.card_url || card)
  const name = sd.agent_name || host
  const skills = sd.skills || []
  return (
    <>
      <SEOHead
        title={`Is ${name} safe? ${decisionHeadline(scan)} · trust score ${scan.trust_score}/100`}
        description={`${scanVerdict(scan)}. AgentAvow checked this A2A Agent Card: ${scan.trust_score}/100 (${t.name}).`}
        path={`/check/a2a?card=${encodeURIComponent(card)}`}
      />
      <ResultPage
        scan={scan as unknown as Record<string, unknown> & { trust_score: number }}
        kind="a2a"
        eyebrow={['A2A agent card', host]}
        name={name}
        recheck={recheck}
        chips={<span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-primary/15 text-primary-light uppercase">A2A agent card</span>}
        intro={<div className="mt-2 font-mono text-[12px] text-text-muted break-all">{sd.card_url || card}</div>}
        adoption={adoptionFrom(undefined, 'No usage data: an agent card has no public download count')}
        allFindings={<CategoryFindings categoryScores={null} findings={scan.findings} maxFindings={15} emptyMessage={coverageGapNotes(scan).length ? '✓ No risks found in what was read; see what we couldn’t check above.' : '✓ No risks found in the agent card.'} />}
        gapNotes={[
          <p key="code"><b>Agent code:</b> not read. An agent card is graded on what it declares; the agent behind it isn&apos;t visible to us, so the code categories aren&apos;t scored. We sent the agent no task.</p>,
        ]}
        inside={<>
          {skills.length > 0
            ? <Reveal>
                <div className="mt-4 glass rounded-2xl p-6">
                  <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Skills it declares</h3>
                  <div className="mt-3 flex flex-col gap-3">
                    {skills.slice(0, 40).map((s) => (
                      <div key={s.id} className="text-[13px]">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-semibold">{s.name || s.id}</span>
                          {!s.authenticated && <span className="font-mono text-[11px] text-text-muted">no auth</span>}
                          {s.capabilities.map((c) => <span key={c} className="font-mono text-[11px] text-warning bg-warning/10 border border-warning/25 rounded-full px-2 py-0.5">{c}</span>)}
                        </div>
                        {s.description && <div className="text-[12.5px] text-text-muted">{s.description}</div>}
                      </div>
                    ))}
                  </div>
                </div>
              </Reveal>
            : <EmptyPanel title="Skills it declares">The card declares no skills.</EmptyPanel>}
          <EmptyPanel title="Advisories">Doesn&apos;t apply: security advisories are published against packages, not agent cards.</EmptyPanel>
        </>}
        badgeClaimShare={<SharePanel label={name} score={scan.trust_score} />}
        proof={<VerifyPanel scan={scan} />}
        whatWeChecked={
          <div className="mt-4 rounded-xl border border-border/60 p-5">
            <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">What we checked</h3>
            <p className="mt-2 text-[13.5px] text-text-muted max-w-[62ch]">We read the <span className="text-text">agent card</span> and nothing else: where it tells a client to send tasks, which auth it asks for, the skill text an orchestrating model reads, and the card&apos;s own signature.</p>
            <div className="mt-3 flex flex-col gap-2 text-[13px]">
              <div className="flex justify-between gap-3"><span className="text-text-muted">Card format</span><span className="font-mono">{sd.card_shape || '?'}{sd.protocol_version ? ` · protocol ${sd.protocol_version}` : ''}{sd.legacy_path ? ' · legacy agent.json path' : ''}</span></div>
              <div className="flex justify-between gap-3"><span className="text-text-muted">Skills</span><span className="font-mono">{sd.skill_count ?? 0}</span></div>
              <div className="flex justify-between gap-3"><span className="text-text-muted">Auth schemes</span><span className="font-mono break-all text-right">{schemes.length ? schemes.map(([n, k]) => `${n} (${k})`).join(', ') : 'none declared'}</span></div>
              <div className="flex justify-between gap-3"><span className="text-text-muted">Signature</span><span className={`font-mono text-right ${sigClass}`}>{sigText}{sig === 'verified' && sd.signature?.alg ? ` · ${sd.signature.alg}` : ''}</span></div>
              {sig === 'unverified' && sd.signature?.reason && <div className="text-[12px] text-text-muted">{sd.signature.reason}</div>}
              {sd.card_digest && <div className="flex justify-between gap-3"><span className="text-text-muted">Card digest</span><span className="font-mono text-[11.5px] break-all text-right">{sd.card_digest}</span></div>}
            </div>
            {(sd.interfaces || []).length > 0 && (
              <div className="mt-3">
                <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted mb-1.5">Interfaces</div>
                {(sd.interfaces || []).map((i, n) => <div key={n} className="font-mono text-[12px] break-all">{i.binding ? `${i.binding} · ` : ''}{i.url}</div>)}
              </div>
            )}
          </div>
        }
      />
    </>
  )
}

/** The package version control in the eyebrow: latest, the pinned version, or another
 * one typed in (it rides in `?version=`, the same pin the MCP connector links to). The
 * API returns no version list, so the picker can't offer one. */
function VersionPicker({ scanned, pinned }: { scanned?: string | null; pinned?: string }) {
  const [sp, setSp] = useSearchParams()
  const [other, setOther] = useState(false)
  const [val, setVal] = useState('')
  const go = (v?: string) => {
    const n = new URLSearchParams(sp)
    if (v) n.set('version', v); else n.delete('version')
    setSp(n)
    setOther(false)
  }
  if (other) {
    return (
      <form onSubmit={(e) => { e.preventDefault(); if (val.trim()) go(val.trim()) }} className="inline-flex items-center gap-1.5">
        <input autoFocus value={val} onChange={(e) => setVal(e.target.value)} placeholder="1.2.3" aria-label="Version to check"
          className="w-[96px] bg-surface border border-border rounded-md px-1.5 py-0.5 font-mono text-[11.5px] text-text outline-none focus:border-primary-light" />
        <button type="submit" className="text-primary-light hover:text-primary">check</button>
        <button type="button" onClick={() => setOther(false)} className="text-text-muted hover:text-text">cancel</button>
      </form>
    )
  }
  return (
    <select aria-label="Version" value={pinned ? 'pinned' : 'latest'}
      onChange={(e) => { const v = e.target.value; if (v === 'latest') go(undefined); else if (v === 'other') setOther(true) }}
      className="font-mono text-[11.5px] bg-surface border border-border rounded-md px-1.5 py-0.5 text-text cursor-pointer">
      <option value="latest">{pinned ? 'latest' : `${scanned || 'latest'} (latest)`}</option>
      {pinned && <option value="pinned">{scanned && scanned !== pinned ? `${pinned} → ${scanned}` : pinned} (pinned)</option>}
      <option value="other">another version…</option>
    </select>
  )
}

/** Native package score view (npm, PyPI, crates, Docker, Hugging Face) — the published
 * artifact, graded by coordinate. */
function PackageResult({ surface, name, version }: { surface: string; name: string; version?: string }) {
  // `version` is the `?version=` the MCP connector / plugin link to for a pinned scan:
  // it rides into the fetch, the canonical path and the share link unchanged.
  const key = ['rebrand-pkg-scan', surface, name, version ?? '']
  const { data: scan, isLoading, isError } = useQuery({
    queryKey: key,
    queryFn: () => fetchPackageScan(surface, name, false, version),
    retry: 0,
  })
  const recheck = useRecheck(key, () => fetchPackageScan(surface, name, true, version))
  const adoptionData = useSurfaceAdoption(surface, '', name, !!scan)
  const driftPath = `/public/drift/pkg/${surface}/${encPath(name)}`
  useResultView(!!scan)
  const versionQs = version ? `?version=${encodeURIComponent(version)}` : ''
  if (isLoading) return <ScanningLoader owner={surface} repo={name} />
  if (isError || !scan) {
    return (
      <div className="max-w-[560px] mx-auto px-6 py-24 text-center">
        <h1 className="text-2xl font-extrabold tracking-tight">Couldn&apos;t scan {surface}:{name}</h1>
        <p className="mt-3 text-text-muted text-[14px]">We couldn&apos;t fetch that from the {surface} registry — check the name{surface === 'npm' ? ' (scoped packages look like @scope/name)' : ''}{version ? ` and the version (${version})` : ''} and try again.</p>
        <Link to={rp('/rebrand/check')} className="mt-6 inline-block text-primary-light hover:text-primary font-semibold">← Scan something else</Link>
      </div>
    )
  }
  const t = getTrustTier(scan.trust_score)
  const cov = (scan as { coverage?: { artifact_digest?: string } }).coverage || {}
  const prov = (scan as { provenance?: { verified?: boolean; present?: boolean } }).provenance || {}
  const digest = (cov.artifact_digest || '').replace(/^sha256:/, '').slice(0, 16)
  const verdict = scanVerdict(scan)
  const origin = ORIGIN()
  const assets: BadgeAssets = {
    link: `${origin}/check/pkg/${surface}/${encPath(name)}`,
    badgeUrl: packageBadgeUrl(origin, surface, name),
    cardUrl: `${origin}/api/v1/public/scan/package/${surface}/${encPath(name)}/card.svg`,
    widgetTool: `${surface}/${name}`,
  }
  const claimable = ['npm', 'pypi', 'crates'].includes(surface)
  return (
    <>
      <SEOHead
        title={`Is ${name} (${surface}) safe? ${decisionHeadline(scan)} · trust score ${scan.trust_score}/100`}
        description={`${verdict}. AgentAvow's signed score for ${surface}:${name}${version ? `@${version}` : ''}: ${scan.trust_score}/100 (${t.name}) — scanned on the published artifact, verifiable offline.`}
        path={`/check/pkg/${surface}/${name}${versionQs}`}
        jsonLd={scanReviewJsonLd(`${surface}:${name}`, scan.trust_score)}
      />
      <ResultPage
        scan={scan as unknown as Record<string, unknown> & { trust_score: number }}
        kind="package"
        eyebrow={[surface, name]}
        version={<VersionPicker scanned={scan.package_version} pinned={version} />}
        name={name}
        recheck={recheck}
        banner={<IncidentBanner scan={scan} />}
        chips={<>
          <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-primary/15 text-primary-light uppercase">{surface}</span>
          <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-success/15 text-success">🔒 Artifact-scanned</span>
          {version && <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-surface border border-border text-text-muted" title={`Scanned exactly this published version${scan.package_version && scan.package_version !== version ? ` (resolved to ${scan.package_version})` : ''}`}>pinned to {version}</span>}
          {prov.verified && <ProvenanceChip />}
          <ClaimedBadge surface={surface} repo={name} />
        </>}
        intro={<>
          {(scan as { tool_description?: string }).tool_description && <div className="mt-2 text-[13.5px] text-text-muted max-w-[62ch]">{(scan as { tool_description?: string }).tool_description}</div>}
          {(scan as { long_description?: string }).long_description && <div className="mt-1 text-[12.5px] leading-snug text-text-muted/75 max-w-[62ch]">{(scan as { long_description?: string }).long_description}</div>}
        </>}
        adoption={adoptionFrom(adoptionData, 'No usage data: no downloads or outside adoption signals yet')}
        allFindings={<CategoryFindings categoryScores={(scan.category_scores || null) as Record<string, number> | null} findings={scan.findings} maxFindings={20} emptyMessage={coverageGapNotes(scan).length ? '✓ No risks found in what was read; see what we couldn’t check above.' : '✓ No risks found in the published package.'} />}
        install={<AddToAgent kind="package" surface={surface} name={name} isMcp={!!(scan as { surface_detail?: { is_mcp_server?: boolean } }).surface_detail?.is_mcp_server} />}
        watch={<WatchCTA surface={surface} owner={surface} repo={name} />}
        badgeMarkdown={badgeMarkdownOf(assets)}
        keepWatching={{
          history: <FeedHistory path={driftPath} current={scan.trust_score} />,
          adoption: <AdoptionDetail data={adoptionData} />,
          drift: <DefinitionChanges path={driftPath} />,
        }}
        inside={<>
          {/* Behavioral deep scan — auto-runs for npm/PyPI packages */}
          <BehavioralPanel owner={surface} repo={name} surface={surface} pkg={{ surface, name, version }} auto={(scan as { behavioral?: BehavioralData | null }).behavioral} effect={(scan as { behavioral_score_effect?: ScoreEffect | null }).behavioral_score_effect} />
          <PackageFacts scan={scan} surface={surface} />
          <InsideCommon scan={scan} kind="package" what="package" />
        </>}
        badgeClaimShare={<>
          <BadgeTabs assets={assets} />
          {version && <p className="mt-2 px-1 text-[12px] text-text-muted">The badge, card and widget show the latest release&apos;s result, not this pinned version.</p>}
          {claimable
            ? <div id="claim" className="scroll-mt-24"><PackageClaim surface={surface} name={name} /></div>
            : <ClaimPanel href={null} title="Maintain this package?" text={`Claiming a ${surface} package isn't available yet. Watch it to get an alert when its result changes.`} />}
          <SharePanel label={`${surface}:${name}${version ? `@${version}` : ''}`} score={scan.trust_score} />
        </>}
        proof={<VerifyPanel scan={scan} />}
        whatWeChecked={
          <div className="mt-4 rounded-xl border border-border/60 p-5">
            <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">What we checked</h3>
            <div className="mt-3 flex flex-col gap-2 text-[13px]">
              <div className="flex justify-between gap-3"><span className="text-text-muted">Coordinate</span><span className="font-mono break-all">{scan.repo}{scan.package_version ? `@${scan.package_version}` : ''}</span></div>
              {surface === 'docker'
                ? <ImageScanDepth scan={scan} />
                : <div className="flex justify-between gap-3"><span className="text-text-muted">Scan depth</span><span className="font-mono text-success text-right">artifact (real published bytes)</span></div>}
              <div className="flex justify-between gap-3"><span className="text-text-muted">Artifact digest</span><span className="font-mono break-all">{digest ? `sha256:${digest}…` : '—'}</span></div>
              <div className="flex justify-between gap-3"><span className="text-text-muted">Provenance</span><span className="font-mono">{prov.verified ? 'verified ✓' : prov.present ? 'present · unverified' : 'none published (N/A)'}</span></div>
              {typeof scan.metadata?.files_scanned === 'number' && <div className="flex justify-between gap-3"><span className="text-text-muted">Files read</span><span className="font-mono">{scan.metadata.files_scanned}</span></div>}
            </div>
          </div>
        }
      />
    </>
  )
}

interface SkillCollectionLead {
  trust_score: number
  decision: string
  decision_reason?: string
  worst_skill?: string
  skills_total?: number
  report_url?: string
}

export default function RebrandCheck() {
  const params = useParams()
  const location = useLocation()
  const [sp] = useSearchParams()
  // A2A Agent Card route (/check/a2a?card=…).
  if (location.pathname.replace(/\/$/, '').endsWith('/check/a2a')) {
    const card = sp.get('card')
    if (!card) return <Hero />
    return <A2aResult card={card} />
  }
  // Live MCP server route (/check/mcp?endpoint=…).
  if (location.pathname.replace(/\/$/, '').endsWith('/check/mcp')) {
    const ep = sp.get('endpoint')
    if (!ep) return <Hero />
    return <McpResult endpoint={ep} />
  }
  // Wallet route (/check/wallet/:addr): resolve to the linked tool, then its result.
  if (location.pathname.includes('/check/wallet/') && params.addr) {
    return <WalletResult addr={params.addr} />
  }
  // An MCP endpoint in the path (/check/mcp.deepwiki.com/mcp) → the live MCP check.
  const pathEndpoint = endpointFromCheckPath(location.pathname)
  if (pathEndpoint) {
    return <Navigate replace to={`${rp('/rebrand/check/mcp')}?endpoint=${encodeURIComponent(pathEndpoint)}`} />
  }
  // OpenClaw / Agent Skill route (/check/skill/:owner/:repo).
  if (location.pathname.includes('/check/skill/') && params.owner && params.repo) {
    return <SkillResult owner={params.owner} repo={params.repo} skill={(params['*'] || '').replace(/\/+$/, '') || undefined} />
  }
  // A pinned package scan (/check/pkg/npm/chalk?version=5.3.0 — what the MCP connector
  // and the plugin link to). Empty/blank = latest.
  const pinnedVersion = (sp.get('version') || '').trim() || undefined
  // Package coordinate route (/check/pkg/:surface/*) → native npm/PyPI package scan.
  if (params.surface) {
    const name = params['*'] || ''
    if (!name) return <Hero />
    return <PackageResult surface={params.surface.toLowerCase()} name={name} version={pinnedVersion} />
  }
  // A /check/{surface}/{name} URL where the "owner" is actually a package registry
  // (npm/pypi/…) is a package coordinate, not a GitHub repo — render the native package
  // scan so it artifact-scans and shows registry downloads (not github checks/watchers).
  // Scoped names (@scope/pkg) keep using /check/pkg/:surface/*.
  const PKG_SURFACES = ['npm', 'pypi', 'crates', 'huggingface', 'docker']
  if (params.owner && params.repo && PKG_SURFACES.includes(params.owner.toLowerCase())) {
    return <PackageResult surface={params.owner.toLowerCase()} name={params.repo} version={pinnedVersion} />
  }
  const { owner, repo } = params
  // ?code=1 keeps the repository code scan in view for a repo that is a skill
  // collection (otherwise it leads with the collection result, see Result).
  const showCode = sp.get('code') === '1'
  // A private scan hands its result here via router state so the owner gets the
  // full detailed report on the real score page (a private repo can't be
  // re-fetched publicly). The token rides along so the Publish CTA can work.
  const state = location.state as { privateResult?: PublicScanResponse; token?: string } | null
  if (!owner || !repo) return <Hero />
  return <Result owner={owner} repo={repo} privateResult={state?.privateResult} showCode={showCode} />
}

function Result({ owner, repo, privateResult, showCode = false }: {
  owner: string; repo: string; privateResult?: PublicScanResponse; showCode?: boolean
}) {
  const { user } = useAuth()
  // A one-time private scan arrives via router state — ephemeral, nothing is stored.
  const oneTimePrivate = !!privateResult
  // Ask the cache first whether this repo is a known skill collection: if it is,
  // redirect straight to its collection page instead of waiting on a full repo
  // code scan (~25 s). Unknown repos fall through to the normal scan.
  const checkCollection = !oneTimePrivate && !showCode
  const { data: collectionLead, isFetched: collectionChecked } = useQuery({
    queryKey: ['rebrand-skill-collection', owner, repo],
    queryFn: () => fetchSkillCollectionLead(owner, repo),
    retry: 0,
    enabled: checkCollection,
  })
  const scanKey = ['rebrand-scan', owner, repo]
  const { data: fetched, isLoading } = useQuery({
    queryKey: scanKey,
    queryFn: () => fetchPublicScan(owner, repo),
    retry: 0,
    enabled: !oneTimePrivate && (!checkCollection || (collectionChecked && !collectionLead)),
  })
  const recheck = useRecheck(scanKey, () => fetchPublicScan(owner, repo, true))
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
  // The canonical 0–100 adoption score, tier and 5-axis breakdown (the needle and the
  // adoption detail panel read the same query, so they always agree).
  const { data: adoptionScore } = useQuery({
    queryKey: ['rebrand-adoption', owner, repo],
    queryFn: async () => (await publicApi.get<AdoptionResp>(`/public/scan/${owner}/${repo}/adoption`)).data,
    retry: 0,
    enabled: !!scan && !isPrivate,
  })
  const collection = (scan as { skill_collection?: SkillCollectionLead | null } | null)?.skill_collection
  // Private results are not reported, and a skill collection reports from the page it redirects to.
  useResultView(!!scan && !isPrivate && !(checkCollection && collectionLead) && (!collection || showCode))

  if (checkCollection && collectionLead) {
    return <Navigate replace to={rp(`/rebrand/check/skill/${owner}/${repo}`)} />
  }
  if (checkCollection && !collectionChecked) return <ScanningLoader owner={owner} repo={repo} />
  if (!oneTimePrivate && isLoading) return <ScanningLoader owner={owner} repo={repo} />
  // A repo that is a collection of agent skills leads with the collection's answer
  // (its worst skill), the same number its badge, card, preview and Browse row show.
  if (collection && !isPrivate && !showCode) {
    return <Navigate replace to={rp(`/rebrand/check/skill/${owner}/${repo}`)} />
  }
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

  const t = getTrustTier(scan.trust_score)
  const f = scan.findings
  const cats = scan.category_scores || {}
  const sum = summarize(scan, scan.repo)
  // Adoption needle — compact number + unit, or no usage data when there's none yet.
  const adStars = adoptionData?.stars && adoptionData.stars > 0 ? adoptionData.stars : 0
  const adChecks = adoptionData?.checks ?? 0
  const adoption: ResultAdoption | null = isPrivate
    ? { count: 0, sub: 'Not shown for a private repo' }
    : adoptionData
      ? {
          count: adStars || adChecks,
          unit: adStars ? 'stars' : 'checks',
          scorePct: adoptionScore?.adoption_score_100,
          sub: `${adStars ? `${adStars.toLocaleString('en-US')} stars · ` : ''}${adChecks.toLocaleString('en-US')} check${adChecks === 1 ? '' : 's'} · ${adoptionData.watchers} watching on AgentAvow${adoptionScore?.badge === 'rising' ? ' · rising' : ''}`,
        }
      : null
  const publicPage = !isPrivate || published
  const assets = publicPage ? repoBadgeAssets(owner, repo) : undefined
  const driftPath = `/public/drift/${owner}/${repo}`

  // The package coordinate is set only when the package's own registry entry points
  // back at this repo (a manifest name alone can match a stranger's package). MCP
  // install only when the PACKAGE is an MCP server — the repo containing MCP code
  // doesn't make its published package one.
  const install = (() => {
    if (isPrivate) return undefined
    const cov = (scan as { coverage?: { surface?: string } }).coverage || {}
    const sd = (scan as { surface_detail?: { name?: string; is_mcp_server?: boolean } }).surface_detail || {}
    const isMcpServer = !!(scan as { metadata?: { is_mcp_server?: boolean } }).metadata?.is_mcp_server
    const pc = (scan as { package_coordinate?: { surface?: string; name?: string; is_mcp_server?: boolean } }).package_coordinate || {}
    const pkg = (pc.surface === 'npm' || pc.surface === 'pypi') && pc.name
      ? { surface: pc.surface, name: pc.name, isMcp: !!pc.is_mcp_server }
      : (cov.surface === 'npm' || cov.surface === 'pypi') && sd.name
        ? { surface: cov.surface, name: sd.name, isMcp: !!sd.is_mcp_server }
        : undefined
    return <AddToAgent kind="repo" owner={owner} repo={repo} pkg={pkg} isMcpServer={isMcpServer} />
  })()

  // The repo's manifest names a published package, but that package's registry entry
  // doesn't point back at this repo — so it was neither scanned nor run as this repo,
  // and the grade covers the source alone.
  const unconfirmed = (() => {
    const sd = (scan as { surface_detail?: { skipped?: string; ecosystem?: string; name?: string } }).surface_detail || {}
    if (sd.skipped !== 'unconfirmed' || !sd.name) return null
    return <p key="unconfirmed"><b>No published package confirmed for this repo:</b> the {sd.ecosystem} package <code className="font-mono">{sd.name}</code> doesn&apos;t point back here, so this result covers the source code only.</p>
  })()

  return (
    <>
      <SEOHead
        title={`Is ${owner}/${repo} safe? ${sum.headline} · trust score ${scan.trust_score}/100`}
        description={`${sum.headline} — ${sum.reason}. AgentAvow's signed, offline-verifiable safety score for ${owner}/${repo}: ${scan.trust_score}/100 (tier: ${t.name}).`}
        path={`/check/${owner}/${repo}`}
        image={`https://agentavow.com/api/v1/public/scan/${owner}/${repo}/og-image`}
        noindex={isPrivate}
        jsonLd={isPrivate ? undefined : scanReviewJsonLd(`${owner}/${repo}`, scan.trust_score)}
      />
      <ResultPage
        scan={scan as unknown as Record<string, unknown> & { trust_score: number }}
        kind="repo"
        eyebrow={[isPrivate ? 'Private GitHub repo' : 'GitHub repo', scan.repo || `${owner}/${repo}`]}
        name={`${owner}/${repo}`}
        privateScan={oneTimePrivate ? 'one-time' : storedPrivate ? 'stored' : undefined}
        recheck={isPrivate ? undefined : recheck}
        banner={<IncidentBanner scan={scan} />}
        chips={<>
          {isPrivate && <span className="inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-warning/15 text-warning">{storedPrivate ? '🔒 Private · via GitHub App' : '🔒 Private scan · not public'}</span>}
          {!isPrivate && <ClaimedBadge surface="github" owner={owner} repo={repo} />}
          {(scan as { provenance?: { verified?: boolean } }).provenance?.verified && <ProvenanceChip />}
        </>}
        intro={<>
          {(scan as { tool_description?: string }).tool_description && <div className="mt-2.5 text-[13.5px] text-text-muted max-w-[64ch]">{(scan as { tool_description?: string }).tool_description}</div>}
          {(scan as { long_description?: string }).long_description && <div className="mt-1 text-[12.5px] leading-snug text-text-muted/70 max-w-[64ch]">{(scan as { long_description?: string }).long_description}</div>}
          {collection && <div className="mt-2 text-[13px] text-text-muted">Repository code scan. This repo is a collection of agent skills; its answer is <Link to={rp(`/rebrand/check/skill/${owner}/${repo}`)} className="font-semibold text-primary-light hover:text-primary">{decisionPhrase(collection.decision).phrase} · {collection.trust_score}/100</Link> (its worst skill).</div>}
        </>}
        adoption={adoption}
        findingsIntro={
          <Reveal>
            <div className="mt-4 glass rounded-2xl p-6">
              <p className="text-[15px] leading-relaxed">{sum.paragraph}</p>
              {(sum.goodPractices.length > 0 || sum.risks.length > 0) && (
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
              )}
            </div>
          </Reveal>
        }
        allFindings={<CategoryFindings categoryScores={cats as Record<string, number>} findings={f} maxFindings={12} emptyMessage={coverageGapNotes(scan).length ? '✓ No risks found in what was read; see what we couldn’t check above.' : '✓ No risks found: clean across all categories.'} />}
        gapNotes={unconfirmed ? [unconfirmed] : undefined}
        install={install}
        watch={oneTimePrivate ? undefined : <WatchCTA owner={owner} repo={repo} />}
        badgeMarkdown={assets ? badgeMarkdownOf(assets) : undefined}
        keepWatching={{
          history: isPrivate ? undefined : <ScoreHistory history={adoptionData?.history ?? []} current={scan.trust_score} feedHref={`/api/v1${driftPath}`} />,
          adoption: isPrivate ? undefined : <AdoptionDetail data={adoptionScore} />,
          drift: isPrivate ? undefined : <DefinitionChanges path={driftPath} />,
          note: storedPrivate ? <p className="mt-3 text-[13px] text-text-muted">A private repo&apos;s history stays private; watch it and the GitHub App re-checks it for you.</p> : undefined,
        }}
        inside={<>
          {/* Behavioral deep scan — auto-runs for npm/PyPI; re-run on demand */}
          {isPrivate
            ? <EmptyPanel title="Behavioral analysis">The sandbox doesn&apos;t run private code.</EmptyPanel>
            : <BehavioralPanel owner={owner} repo={repo} surface={(scan as { package_coordinate?: { surface?: string } }).package_coordinate?.surface} auto={(scan as { behavioral?: BehavioralData | null }).behavioral} effect={(scan as { behavioral_score_effect?: ScoreEffect | null }).behavioral_score_effect} />}
          <InsideCommon scan={scan} kind="repo" what="repo" />
        </>}
        badgeClaimShare={<>
          <BadgeTabs assets={assets} unavailable="A private repo has no public badge until you publish it to search." />
          {/* claim / ownership — a one-time scan is ephemeral (report only, nothing stored) */}
          {oneTimePrivate ? (
            <Reveal>
              <div id="claim" className="mt-4 glass rounded-2xl p-6 border-l-4 border-warning/50 scroll-mt-24">
                <h3 className="text-[15px] font-bold">This is a one-time scan</h3>
                <p className="text-text-muted text-[13.5px] mt-1 max-w-[62ch]">Nothing is stored or listed. For continuous scanning + change alerts, connect the GitHub App on your <Link to={rp('/rebrand/tools')} className="text-primary-light hover:text-primary font-semibold">tools page</Link>.</p>
              </div>
            </Reveal>
          ) : (
            <OwnershipCTA owner={owner} repo={repo} />
          )}
          {/* a stored private repo publishes to search here (then animates into share) */}
          {storedPrivate && (
            <div className="mt-4 flex items-center justify-center gap-2 flex-wrap">
              <PrivateSearchSlot owner={owner} repo={repo} score={scan.trust_score} published={published} />
            </div>
          )}
          {storedPrivate && <PublishStoredCTA owner={owner} repo={repo} published={published} />}
          {!isPrivate && <SharePanel label={`${owner}/${repo}`} score={scan.trust_score} />}
        </>}
        proof={<VerifyPanel scan={scan} />}
        whatWeChecked={
          <div className="mt-4 rounded-xl border border-border/60 p-5">
            <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-2">What we checked</h3>
            <div className="flex flex-wrap gap-2">
              {sum.facts.map((fct) => <span key={fct} className="text-[12.5px] text-text-muted bg-surface border border-border rounded-full px-3 py-1">{fct}</span>)}
            </div>
          </div>
        }
      />
    </>
  )
}
