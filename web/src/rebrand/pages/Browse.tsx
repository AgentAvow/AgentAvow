import { useState, useEffect } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { rp } from '../basePath'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { fetchCatalog, fetchRecent, rowIdentity, type CatalogRow, type CatalogSandbox } from '../catalog'
import { ScorePairMini } from '../components/TrustMark'
import { DECISIONS, decide, decisionPhrase, getTrustTier } from '../../components/trust/gradeSystem'

import { RevealStagger } from '../components/motion'
import { useAnswerMix, type AnswerMix } from '../lib/answerMix'
import { PageHeader } from '../components/PageBits'
import SEOHead from '../../components/SEOHead'

/**
 * The "Yelp" browse catalog — LIVE from /public/scan-catalog.
 * Sticky category tabs, search, sort, severity. Grades from the shared getGradeInfo.
 * The expander is "Why this score" (signed evidence), not star reviews.
 * Mines the old /scans page for parity: summary strip, per-card findings/status,
 * result count, and pagination.
 */

// One row of kind pills, "All tools" first; MCP servers stays the default view.
const SURFACES = [
  { key: 'all', label: 'All tools' },
  { key: 'mcp', label: 'MCP servers' },
  { key: 'openclaw', label: 'Agent skills' },
  { key: 'npm', label: 'npm packages' },
  { key: 'pypi', label: 'Python packages' },
  { key: 'github', label: 'GitHub repos' },
  { key: 'crates', label: 'Rust crates' },
  { key: 'huggingface', label: 'Hugging Face models' },
  { key: 'docker', label: 'Container images' },
  { key: 'x402', label: 'x402 endpoints' },
  { key: 'community', label: 'All on-demand scans' },
]

const SORTS = [
  { key: 'adoption', label: 'Widely relied upon' },
  { key: 'score-desc', label: 'Highest trust' },
  { key: 'score-asc', label: 'Lowest trust' },
  { key: 'name', label: 'Name (A–Z)' },
]


const SEVERITIES = [
  { key: '', label: 'All findings' },
  { key: 'critical', label: 'Has critical' },
  { key: 'high', label: 'Has high+' },
  { key: 'clean', label: 'Clean only' },
  { key: 'skipped', label: 'Skipped / errored' },
]

// The three-phrase answer — what each tool reads as (src/scanner/verdict.decide).
const DECISION_OPTS = [
  { key: '', label: 'Any answer' },
  ...DECISIONS.map((d) => ({ key: d.value, label: d.phrase })),
]

// Tier floors are the API's (gradeSystem.ts TRUST_TIERS); the catalog filters on them.
const GRADES = [
  { key: '', label: 'Any score' },
  { key: 'certified', label: '✦ Certified' },
  { key: 'verified', label: '96+ · Verified' },
  { key: 'trusted', label: '81+ · Trusted' },
  { key: 'standard', label: '51+ · Standard' },
  { key: 'minimal', label: '31+ · Minimal' },
]

const PAGE_SIZE = 30

function whyLines(row: CatalogRow): string[] {
  const out: string[] = []
  if (row.critical) out.push(`${row.critical} critical finding${row.critical > 1 ? 's' : ''}`)
  if (row.high) out.push(`${row.high} high-severity finding${row.high > 1 ? 's' : ''}`)
  if (row.findings_count != null) out.push(`${row.findings_count} findings in total`)
  if (!out.length) out.push('No high or critical findings · signed clean')
  const sb = row.sandbox
  if (sb?.ran) {
    const parts = [sb.findings ? `${sb.findings} behavioral finding${sb.findings > 1 ? 's' : ''}` : 'no behavioral findings']
    if (sb.unexpected_egress) parts.push(`${sb.unexpected_egress} unexpected egress host${sb.unexpected_egress > 1 ? 's' : ''}`)
    if (sb.exercised === false) parts.push('server did not start')
    if (sb.timed_out) parts.push('ran partly (hit its time limit)')
    out.push(`Sandbox run: ${parts.join(', ')}`)
  }
  return out
}

/** Small neutral mark for a row whose package has a cached sandbox run. The sandbox is
 *  a runtime observation kept apart from the signed grade, so it never colors the chip. */
function sandboxMark(sb: CatalogSandbox | null | undefined): string | null {
  if (!sb?.ran) return null
  if (sb.findings) return `sandbox: ${sb.findings} finding${sb.findings > 1 ? 's' : ''}`
  if (sb.timed_out) return 'sandbox: partial'
  return 'sandbox ✓'
}

/** At-a-glance status chip on the card face — mirrors the old Scans status column. */
function statusChip(row: CatalogRow): { label: string; cls: string; title?: string } {
  if (row.skipped) return { label: 'skipped', cls: 'text-text-muted bg-surface-hover' }
  if (row.scan_error) return { label: 'fetch error', cls: 'text-warning bg-warning/15' }
  if (row.surface === 'x402') {
    return row.has_x402_header
      ? { label: `x402 ✓${row.http_status ? ` · ${row.http_status}` : ''}`, cls: 'text-success bg-success/15' }
      : { label: `${row.http_status ?? '—'}`, cls: 'text-text-muted bg-surface-hover' }
  }
  if (row.trust_score != null) {
    // Lead with the three-phrase short label (Safe / Review / Don't connect); Certified rides beside.
    const d = decisionPhrase(row.decision ?? decide({ trust_score: row.trust_score, findings: { critical: row.critical ?? 0, high: row.high ?? 0 } }).decision)
    const cls = d.value === 'safe' ? 'text-success bg-success/15' : d.value === 'review' ? 'text-warning bg-warning/15' : 'text-danger bg-danger/15'
    // Certified shows once, as the badge in the score slot, never as a second tag here.
    return { label: d.label, cls, title: row.decision_reason ? `${d.phrase} — ${row.decision_reason}` : d.phrase }
  }
  return { label: 'unscored', cls: 'text-text-muted bg-surface-hover' }
}

function findingsLine(row: CatalogRow): string | null {
  const parts: string[] = []
  if (row.critical) parts.push(`${row.critical}C`)
  if (row.high) parts.push(`${row.high}H`)
  if (!parts.length && row.findings_count) parts.push(`${row.findings_count} findings`)
  return parts.length ? parts.join(' · ') : null
}

// A listing links to its OWN surface page (with the install button), not always
// the GitHub repo endpoint: npm/PyPI → the package page, OpenClaw → the skill page.
const _SURFACE_BADGE: Record<string, string> = {
  npm: 'npm', pypi: 'PyPI', crates: 'crates', mcp: 'MCP', openclaw: 'Skill', x402: 'x402', community: 'repo',
}
function listingHref(row: CatalogRow): string | null {
  const fn = row.full_name
  if (
    (row.surface === 'npm' || row.surface === 'pypi' || row.surface === 'crates' ||
      row.surface === 'huggingface' || row.surface === 'docker') && row.name
  ) {
    return rp(`/rebrand/check/pkg/${row.surface}/${row.name}`)
  }
  if (row.surface === 'openclaw' && fn && fn.includes('/')) {
    return rp(`/rebrand/check/skill/${fn}`)
  }
  if (row.surface === 'mcp') {
    // Route to the LIVE MCP scan whenever we have an https endpoint — from
    // endpoint_url OR a name/full_name that IS the endpoint URL (community scans
    // store the endpoint there). Registry rows with no URL fall through to their
    // source repo (which now resolves the package 1-click) rather than handshaking
    // a non-URL registry name (which just errors "couldn't reach the server").
    const ep = [row.endpoint_url, row.name, fn].find((v) => v && /^https?:\/\//i.test(v))
    if (ep) return rp(`/rebrand/check/mcp?endpoint=${encodeURIComponent(ep)}`)
  }
  if (fn && fn.includes('/')) return rp(`/rebrand/check/${fn}`)
  return null
}

function ToolCard({ row }: { row: CatalogRow }) {
  const [open, setOpen] = useState(false)
  const { display, repoPath } = rowIdentity(row)
  const href = listingHref(row) ?? (repoPath ? rp(`/rebrand/check/${repoPath}`) : null)
  const surfaceBadge = _SURFACE_BADGE[row.surface]
  // Prefer the served letter grade (it applies the A+ certified gate); fall back
  // to deriving from score. This is why Browse no longer shows A+ on a 96+ repo
  // that isn't actually certified.
  const chip = statusChip(row)
  const fnd = findingsLine(row)
  const sbx = sandboxMark(row.sandbox)
  return (
    // The whole card opens the report: the "See report" link is stretched over the
    // card with an ::after overlay (a real <a>, so cmd/middle-click and keyboard
    // work). The "Why this score" toggle sits above the overlay (relative z-10).
    <div className={`glass card-hover rounded-xl p-[18px]${href ? ' relative cursor-pointer has-[a:focus-visible]:ring-2 has-[a:focus-visible]:ring-primary/60' : ''}`}>
      <div className="flex items-center justify-between gap-2.5">
        <span className="min-w-0 flex items-center gap-2">
          {surfaceBadge && <span className="font-mono text-[9.5px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-primary/12 text-primary-light shrink-0">{surfaceBadge}</span>}
          <span className="font-mono text-[13.5px] truncate min-w-0" title={display}>{display}</span>
        </span>
        {row.trust_score != null ? (
          <ScorePairMini row={row as unknown as Record<string, unknown> & { trust_score: number }} stack />
        ) : (
          <span className="font-mono text-[11px] px-2 py-0.5 rounded-lg shrink-0 text-text-muted bg-surface-hover">unscored</span>
        )}
      </div>
      {/* category — the curation row */}
      {row.category && (
        <div className="mt-2 flex items-center gap-2 flex-wrap">
          <span className="text-[10.5px] px-1.5 py-0.5 rounded bg-surface-hover text-text-muted">{row.category}</span>
        </div>
      )}
      {/* status + findings + language — the at-a-glance row Scans had */}
      <div className="mt-2 flex items-center gap-2 flex-wrap">
        <span className={`font-mono text-[10.5px] uppercase tracking-wide px-1.5 py-0.5 rounded ${chip.cls}`} title={chip.title}>{chip.label}</span>
        {fnd && <span className="font-mono text-[11px] text-text-muted tabular-nums">{fnd}</span>}
        {row.primary_language && <span className="font-mono text-[11px] text-text-muted">· {row.primary_language}</span>}
        {sbx && (
          <span
            className="font-mono text-[10.5px] px-1.5 py-0.5 rounded bg-surface-hover text-text-muted tabular-nums"
            title="Observed in the behavioral sandbox (gVisor) — a runtime observation, signed separately and counted in the score"
          >
            {sbx}
          </span>
        )}
      </div>
      <button
        type="button"
        aria-expanded={open}
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); setOpen(!open) }}
        className="relative z-10 mt-3 text-[12.5px] text-primary-light hover:text-primary"
      >
        {open ? 'Hide' : 'Why this score'} {open ? '▴' : '▾'}
      </button>
      {open && (
        <ul className="mt-2 pl-4 list-disc text-[12.5px] text-text-muted space-y-1">
          {whyLines(row).map((w) => <li key={w}>{w}</li>)}
        </ul>
      )}
      {href && (
        <div className="mt-3">
          <Link to={href} className="text-[12.5px] font-semibold text-primary-light hover:text-primary focus-visible:outline-none after:absolute after:inset-0 after:rounded-xl after:content-['']">
            {row.trust_score != null ? 'See report & install →' : 'View →'}
          </Link>
        </div>
      )}
    </div>
  )
}

/** Pill look for the one filter row: teal outline when selected. */
const pill = (on: boolean) => `shrink-0 whitespace-nowrap text-[13px] rounded-full border px-[13px] py-1.5 transition-colors ${
  on ? 'border-primary-light text-primary-light bg-primary/10' : 'border-border bg-surface text-text-muted hover:border-primary-light hover:text-primary-light'}`

const MIX_SEGMENTS = [
  { key: 'safe', dec: 'safe', phrase: 'Safe to connect', color: '#34d399' },
  { key: 'review', dec: 'review', phrase: 'Review before you connect', color: '#F59E0B' },
  { key: 'dnc', dec: 'do_not_connect', phrase: 'Do not connect', color: '#f43f5e' },
] as const

const share = (n: number, of: number) => (of > 0 ? Math.round((n / of) * 1000) / 10 : 0)

/**
 * How the catalog reads, as one graphic: the total and the answer mix (each bar
 * segment filters the list), then the Certified and Do not connect counts (both
 * filters, in place of the old quick pills) and the newest checks. Live numbers only.
 */
function CatalogGraphic({ mix, decision, certifiedOn, onDecision, onCertified, recent }: {
  mix: AnswerMix | undefined
  decision: string
  certifiedOn: boolean
  onDecision: (dec: string) => void
  onCertified: () => void
  recent: { name: string; full_name: string | null; surface: string; trust_score: number | null; href: string | null }[] | undefined
}) {
  const ready = mix && mix.total > 0
  const cell = 'flex flex-col gap-0.5 min-w-0 text-left px-3.5 pt-3 pb-0.5 border-l border-border/60'
  const kicker = 'font-mono text-[10.5px] tracking-[0.12em] uppercase text-primary-light'
  return (
    <div className="glass rounded-2xl border border-border/60 px-5 py-[18px]">
      <div className="flex flex-wrap justify-between items-end gap-x-5 gap-y-2">
        <div>
          <b className="block gradient-text font-extrabold leading-none tracking-[-.02em] tabular-nums text-[clamp(30px,5vw,40px)]">{ready ? mix.total.toLocaleString() : '—'}</b>
          <span className="block mt-1 text-[13.5px] text-text-muted">tools checked, and how they read</span>
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-1.5 text-[13px] text-text-muted">
          {MIX_SEGMENTS.map((s) => (
            <span key={s.key} className="inline-flex items-baseline">
              <i className="inline-block w-[9px] h-[9px] rounded-[2px] mr-1.5" style={{ background: s.color }} />
              <b className="text-text tabular-nums mr-1">{ready ? `${share(mix[s.key], mix.total)}%` : '—'}</b>{s.phrase}
            </span>
          ))}
        </div>
      </div>
      {ready ? (
        <div className="flex mt-3.5 h-[18px] rounded-full overflow-hidden bg-surface-hover" role="group"
          aria-label={MIX_SEGMENTS.map((s) => `${share(mix[s.key], mix.total)}% ${s.phrase}`).join(', ')}>
          {MIX_SEGMENTS.map((s) => (
            <button key={s.key} type="button" onClick={() => onDecision(s.dec)} aria-pressed={decision === s.dec}
              aria-label={`Show ${s.phrase}`} title={`Show ${s.phrase}`}
              className={`block h-full transition-opacity hover:opacity-80 ${decision && decision !== s.dec ? 'opacity-40' : ''}`}
              style={{ width: `${share(mix[s.key], mix.total)}%`, background: s.color }} />
          ))}
        </div>
      ) : <div className="mt-3.5 h-[18px] rounded-full bg-surface-hover animate-pulse" aria-hidden="true" />}
      <div className="grid grid-cols-2 sm:grid-cols-4 mt-3.5 border-t border-border/60">
        <button type="button" onClick={onCertified} aria-pressed={certifiedOn} className={`${cell} !border-l-0 !pl-0 group`}>
          <span className={kicker}>Certified</span>
          <b className={`text-[22px] font-extrabold leading-tight tabular-nums gradient-text ${certifiedOn ? 'underline decoration-primary-light underline-offset-4' : ''}`}>{ready ? mix.certified.toLocaleString() : '—'}</b>
          <small className="text-[12px] text-text-muted group-hover:text-text">{certifiedOn ? 'showing them · clear ×' : 'cleared the bar →'}</small>
        </button>
        <button type="button" onClick={() => onDecision('do_not_connect')} aria-pressed={decision === 'do_not_connect'} className={`${cell} group`}>
          <span className={kicker}>Do not connect</span>
          <b className={`text-[22px] font-extrabold leading-tight tabular-nums text-danger ${decision === 'do_not_connect' ? 'underline underline-offset-4' : ''}`}>{ready ? mix.dnc.toLocaleString() : '—'}</b>
          <small className="text-[12px] text-text-muted group-hover:text-text">{decision === 'do_not_connect' ? 'showing them · clear ×' : 'see them →'}</small>
        </button>
        <div className={`${cell} col-span-2 max-sm:!border-l-0 max-sm:!pl-0 max-sm:border-t max-sm:mt-1`}>
          <span className={kicker}>Just checked</span>
          <span className="text-[12.5px] text-text-muted [overflow-wrap:anywhere]">
            {recent?.length
              ? recent.map((it, i) => {
                  const label = <>{it.name || it.full_name}{it.trust_score != null && <b className="ml-1 text-[12.5px] tabular-nums" style={{ color: getTrustTier(it.trust_score).color }}>{it.trust_score}</b>}</>
                  return (
                    <span key={`${it.surface}:${it.name}`}>
                      {i > 0 && ' · '}
                      {it.href ? <Link to={it.href} className="hover:text-text">{label}</Link> : label}
                    </span>
                  )
                })
              : '—'}
          </span>
          <Link to={rp('/rebrand/index')} className="mt-0.5 text-[12.5px] font-semibold text-primary-light hover:text-primary">See the full Trust Index →</Link>
        </div>
      </div>
    </div>
  )
}

const DEFAULT_SURFACE = 'mcp'
const DEFAULT_SORT = 'adoption'

export default function RebrandBrowse() {
  // URL is the source of truth for every filter — so navigating into a tool and
  // hitting back restores the exact view, and any filtered view is shareable.
  const [sp, setSp] = useSearchParams()
  const surface = sp.get('surface') || DEFAULT_SURFACE
  const sort = sp.get('sort') || DEFAULT_SORT
  const severity = sp.get('sev') || ''
  const grade = sp.get('grade') || ''
  const decision = sp.get('dec') || ''
  const category = sp.get('cat') || ''
  const q = sp.get('q') || ''
  const page = Math.max(0, parseInt(sp.get('page') || '0', 10) || 0)
  const tab = Math.max(0, SURFACES.findIndex((s) => s.key === surface))

  const [qInput, setQInput] = useState(q)
  const [sheetOpen, setSheetOpen] = useState(false)
  // Keep the search box in sync when q changes from outside (back/forward, clear).
  useEffect(() => { setQInput(q) }, [q])

  // Merge changes into the URL. `replace` (default) so filter tweaks don't stack up
  // history entries — one Back from a tool returns to the last filtered Browse view.
  // Any change other than `page` resets to page 0.
  const patch = (changes: Record<string, string>, opts?: { push?: boolean }) => {
    const next = new URLSearchParams(sp)
    if (!('page' in changes)) next.delete('page')
    for (const [k, v] of Object.entries(changes)) {
      if (!v) next.delete(k)
      else next.set(k, v)
    }
    setSp(next, { replace: !opts?.push })
  }
  const setTab = (i: number) => patch({ surface: SURFACES[i].key === DEFAULT_SURFACE ? '' : SURFACES[i].key })
  const setSort = (v: string) => patch({ sort: v === DEFAULT_SORT ? '' : v })
  const setSeverity = (v: string) => patch({ sev: v })
  const setGrade = (v: string) => patch({ grade: v })
  const setDecision = (v: string) => patch({ dec: v })
  const setCategory = (v: string) => patch({ cat: v })
  const setPage = (updater: (p: number) => number) => patch({ page: String(updater(page)) })
  const applySearch = () => patch({ q: qInput.trim() })
  const clearSearch = () => { setQInput(''); patch({ q: '' }) }
  const clearAll = () => setSp(new URLSearchParams(surface !== DEFAULT_SURFACE ? { surface } : {}), { replace: true })

  const activeFilters = (decision ? 1 : 0) + (grade ? 1 : 0) + (severity ? 1 : 0) + (category ? 1 : 0) + (sort !== DEFAULT_SORT ? 1 : 0)

  // A search should find things anywhere — when q is set we drop the surface
  // filter so search spans the whole catalog, not just the active tab.
  const { data, isLoading, isError, isFetching } = useQuery({
    queryKey: ['rebrand-catalog', surface, sort, severity, grade, decision, category, q, page],
    queryFn: () => fetchCatalog({ surface: q || surface === 'all' ? '' : surface, sort, severity, grade, decision, category, q, limit: PAGE_SIZE, offset: page * PAGE_SIZE }),
    placeholderData: keepPreviousData,
  })
  // Category options come from the catalog's own breakdown (stable across filters).
  const CATEGORIES = [{ key: '', label: 'All categories' },
    ...Object.entries(data?.summary?.by_category ?? {}).map(([c, n]) => ({ key: c, label: `${c} (${n})` }))]

  const rows = data?.rows ?? []
  // The prerender keeps the page's totals but not its tool rows (see prerender-entry.tsx).
  const rowsLoading = isLoading || import.meta.env.SSR
  const matching = data?.total
  const { data: mix } = useAnswerMix()
  // The newest checks for the "Just checked" card. Kept out of the prerender, which
  // names no tool and its answer.
  const { data: recent } = useQuery({ queryKey: ['recent-scans', 3], queryFn: () => fetchRecent(3), staleTime: 60_000 })

  const totalPages = matching != null ? Math.ceil(matching / PAGE_SIZE) : 0

  return (
    <div>
      <SEOHead
        title="Find tools your agent can trust"
        description="The public catalog of scanned repos, packages, MCP servers, and skills — each with a signed trust score and adoption score you can recompute yourself."
        path="/browse"
      />
      <PageHeader eyebrow="Browse" title="Find tools your agent can trust." lede="Every tool we've checked, with its answer, trust score and adoption score." />

      {/* one graphic: the total and the answer mix, then Certified and Do not connect
          (both filters), then the newest checks. Then search. */}
      <div className="relative z-[2] max-w-[1080px] mx-auto px-6">
        <CatalogGraphic
          mix={mix}
          decision={decision}
          certifiedOn={grade === 'certified'}
          onDecision={(v) => patch(decision === v ? { dec: '' } : { dec: v, surface: 'all' })}
          onCertified={() => patch(grade === 'certified' ? { grade: '' } : { grade: 'certified', surface: 'all' })}
          recent={recent?.map((it) => ({ ...it, href: listingHref(it as unknown as CatalogRow) }))}
        />

        <form
          onSubmit={(e) => { e.preventDefault(); applySearch() }}
          className="glass mt-4 flex gap-2.5 rounded-2xl p-2 pl-4 shadow-lg shadow-primary/10"
        >
          <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5 self-center text-text-muted shrink-0" aria-hidden="true">
            <path d="M11 19a8 8 0 1 1 5.7-2.3L21 21" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
          </svg>
          <input
            value={qInput}
            onChange={(e) => setQInput(e.target.value)}
            placeholder="Search by name, package or server"
            aria-label="Search tools"
            className="flex-1 min-w-0 bg-transparent outline-none text-[15.5px] text-text placeholder:text-text-muted"
          />
          {qInput && <button type="button" onClick={clearSearch} aria-label="Clear search" className="text-text-muted hover:text-text px-1 text-[18px] leading-none">×</button>}
          <button type="submit" className="font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow whitespace-nowrap">Search</button>
        </form>
      </div>

      {/* ONE sticky filter row: the kind pills (one scrollable row), then the five
          dropdowns (a Filters bottom sheet on phones). Selected = teal outline. Solid
          background: no blur on a persistent element. */}
      <div className="sticky top-[62px] z-20 mt-3.5 bg-background relative after:absolute after:left-0 after:right-0 after:bottom-0 after:translate-y-full after:h-4 after:bg-gradient-to-b after:from-background/50 after:to-transparent after:pointer-events-none">
        <div className="max-w-[1080px] mx-auto px-4 sm:px-6 py-3 flex flex-col gap-2.5">
          {/* Desktop: the pills wrap inside the container. Phones: one scrollable row
              with a fade at the right edge as the overflow hint. */}
          <div className="relative">
            <div className="flex gap-1.5 max-sm:overflow-x-auto sm:flex-wrap pb-0.5 max-sm:-mx-1 max-sm:px-1 max-sm:pr-8 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden snap-x" role="group" aria-label="Kind of tool">
              {SURFACES.map((sf, i) => (
                <button key={sf.key} type="button" aria-pressed={tab === i} onClick={() => setTab(i)} className={`snap-start ${pill(tab === i)}`}>
                  {sf.label}
                </button>
              ))}
            </div>
            <span className="sm:hidden pointer-events-none absolute right-0 top-0 bottom-0.5 w-10 bg-gradient-to-l from-background to-transparent" aria-hidden="true" />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {/* desktop: inline filter dropdowns */}
            {[
              { label: 'Answer', v: decision, def: '', set: setDecision, opts: DECISION_OPTS },
              { label: 'Trust score', v: grade, def: '', set: setGrade, opts: GRADES },
              { label: 'Findings', v: severity, def: '', set: setSeverity, opts: SEVERITIES },
              { label: 'Category', v: category, def: '', set: setCategory, opts: CATEGORIES },
              { label: 'Sort', v: sort, def: DEFAULT_SORT, set: setSort, opts: SORTS },
            ].map((f) => (
              <select key={f.label} aria-label={f.label} value={f.v} onChange={(e) => f.set(e.target.value)}
                className={`hidden sm:block text-[13px] rounded-full border px-3 py-1.5 outline-none max-w-[190px] transition-colors ${f.v !== f.def ? 'border-primary-light text-primary-light bg-primary/10' : 'border-border bg-surface text-text-muted hover:border-primary-light'}`}>
                {f.opts.map((o) => <option key={o.key} value={o.key}>{o.label}</option>)}
              </select>
            ))}
            {/* mobile: one Filters button → bottom sheet */}
            <button type="button" onClick={() => setSheetOpen(true)} className={`sm:hidden flex items-center gap-1.5 ${pill(activeFilters > 0)}`}>
              <svg viewBox="0 0 24 24" fill="none" className="w-4 h-4" aria-hidden="true"><path d="M4 6h16M7 12h10M10 18h4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></svg>
              Filters{activeFilters > 0 && <span className="grid place-items-center min-w-[18px] h-[18px] text-[10px] font-bold rounded-full bg-primary text-white">{activeFilters}</span>}
            </button>
          </div>
        </div>
      </div>

      {/* mobile filter bottom sheet */}
      {sheetOpen && (
        <div className="sm:hidden fixed inset-0 z-40" role="dialog" aria-modal="true">
          <div className="absolute inset-0 bg-black/50" onClick={() => setSheetOpen(false)} />
          <div className="absolute left-0 right-0 bottom-0 bg-background border-t border-border rounded-t-2xl p-5 pb-8 max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-[16px] font-bold">Filters</h2>
              <button onClick={() => setSheetOpen(false)} aria-label="Close" className="text-text-muted text-[22px] leading-none">×</button>
            </div>
            {[{ label: 'Answer', v: decision, set: setDecision, opts: DECISION_OPTS }, { label: 'Trust score', v: grade, set: setGrade, opts: GRADES }, { label: 'Findings', v: severity, set: setSeverity, opts: SEVERITIES }, { label: 'Category', v: category, set: setCategory, opts: CATEGORIES }, { label: 'Sort', v: sort, set: setSort, opts: SORTS }].map((f) => (
              <div key={f.label} className="mb-5">
                <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted mb-2">{f.label}</div>
                <div className="flex flex-wrap gap-2">
                  {f.opts.map((o) => (
                    <button key={o.key} onClick={() => f.set(o.key)}
                      className={`text-[13.5px] px-3.5 py-2 rounded-lg border transition-colors ${f.v === o.key ? 'border-primary-light bg-primary/15 text-primary-light font-semibold' : 'border-border bg-surface text-text-muted'}`}>
                      {o.label}
                    </button>
                  ))}
                </div>
              </div>
            ))}
            <div className="flex gap-3 mt-2">
              <button onClick={clearAll} className="flex-1 py-2.5 rounded-xl border border-border text-text-muted font-semibold text-[14px]">Clear all</button>
              <button onClick={() => setSheetOpen(false)} className="flex-1 py-2.5 rounded-xl text-white font-semibold text-[14px] bg-gradient-to-r from-primary to-primary-dark">Show results</button>
            </div>
          </div>
        </div>
      )}

      {/* results */}
      <div className="max-w-[1080px] mx-auto px-6 py-8">
        {/* active-filter chips — see exactly what's applied, remove any one, or clear all */}
        {(() => {
          const chips: { key: string; label: string; onClear: () => void }[] = []
          if (q) chips.push({ key: 'q', label: `“${q}”`, onClear: clearSearch })
          if (category) chips.push({ key: 'cat', label: category, onClear: () => setCategory('') })
          if (decision) chips.push({ key: 'dec', label: DECISION_OPTS.find((x) => x.key === decision)?.label ?? decision, onClear: () => setDecision('') })
          if (grade) chips.push({ key: 'grade', label: GRADES.find((x) => x.key === grade)?.label ?? grade, onClear: () => setGrade('') })
          if (severity) chips.push({ key: 'sev', label: SEVERITIES.find((x) => x.key === severity)?.label ?? severity, onClear: () => setSeverity('') })
          if (sort !== DEFAULT_SORT) chips.push({ key: 'sort', label: SORTS.find((x) => x.key === sort)?.label ?? sort, onClear: () => setSort(DEFAULT_SORT) })
          if (!chips.length) return null
          return (
            <div className="flex items-center gap-2 flex-wrap mb-4">
              <span className="text-[12px] text-text-muted">Filters:</span>
              {chips.map((c) => (
                <button key={c.key} onClick={c.onClear}
                  className="group flex items-center gap-1.5 text-[12.5px] pl-3 pr-2 py-1 rounded-full border border-primary-light/40 bg-primary/10 text-primary-light hover:border-primary-light transition-colors">
                  {c.label}
                  <span className="grid place-items-center w-4 h-4 rounded-full bg-primary-light/20 group-hover:bg-primary-light/40 text-[11px] leading-none">×</span>
                </button>
              ))}
              <button onClick={clearAll} className="text-[12px] text-text-muted hover:text-text underline underline-offset-2">Clear all</button>
            </div>
          )
        })()}
        {/* result count + refreshing indicator (from Scans) */}
        {!isError && matching != null && (
          <div className="text-[13px] text-text-muted mb-4">
            {matching.toLocaleString()} matching {matching === 1 ? 'scan' : 'scans'}
            {q && <span> for “{q}” · <span className="text-primary-light">all surfaces</span></span>}
            {isFetching && <span className="text-primary-light"> · refreshing…</span>}
          </div>
        )}
        {isError ? (
          <div className="glass rounded-xl p-8 text-center text-text-muted text-[14px]">Couldn't load the catalog right now. Try again in a moment.</div>
        ) : rowsLoading && rows.length === 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
            {Array.from({ length: 9 }).map((_, i) => <div key={i} className="glass rounded-xl p-[18px] animate-pulse h-[128px]" />)}
          </div>
        ) : (
          <RevealStagger key={[surface, sort, severity, grade, decision, category, q, page].join('|')} className="grid grid-cols-1 md:grid-cols-3 gap-3.5" stagger={0.035}>
            {rows.map((row) => <ToolCard key={row.full_name || row.name} row={row} />)}
          </RevealStagger>
        )}
        {!rowsLoading && !isError && rows.length === 0 && (
          <div className="mt-2 text-center text-text-muted text-[14px]">No matches on this surface. Try another category or search.</div>
        )}

        {/* pagination (from Scans) */}
        {!isError && totalPages > 1 && (
          <div className="flex items-center justify-between mt-8">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="text-[13px] font-semibold rounded-full border border-border bg-surface px-4 py-1.5 disabled:opacity-40 disabled:cursor-not-allowed hover:border-primary-light"
            >
              ← Prev
            </button>
            <div className="text-[13px] text-text-muted tabular-nums">Page {page + 1} of {totalPages.toLocaleString()}</div>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={page + 1 >= totalPages}
              className="text-[13px] font-semibold rounded-full border border-border bg-surface px-4 py-1.5 disabled:opacity-40 disabled:cursor-not-allowed hover:border-primary-light"
            >
              Next →
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
