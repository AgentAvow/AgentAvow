import { useState, useEffect } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { rp } from '../basePath'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { fetchCatalog, rowIdentity, type CatalogRow, type CatalogSummary } from '../catalog'
import { TrustPill } from '../components/TrustMark'

import { Reveal, RevealStagger, CountUp } from '../components/motion'

/**
 * The "Yelp" browse catalog — LIVE from /public/scan-catalog.
 * Sticky category tabs, search, sort, severity. Grades from the shared getGradeInfo.
 * The expander is "Why this grade" (signed evidence), not star reviews.
 * Mines the old /scans page for parity: summary strip, per-card findings/status,
 * result count, and pagination.
 */

const SURFACES = [
  { key: 'mcp', label: 'MCP servers' },
  { key: 'openclaw', label: 'OpenClaw skills' },
  { key: 'npm', label: 'npm packages' },
  { key: 'pypi', label: 'Python packages' },
  { key: 'crates', label: 'Rust crates' },
  { key: 'huggingface', label: 'Hugging Face models' },
  { key: 'docker', label: 'Container images' },
  { key: 'x402', label: 'x402 endpoints' },
  { key: 'community', label: 'Community' },
]

const SORTS = [
  { key: 'score-desc', label: 'Highest trust' },
  { key: 'adoption', label: 'Widely relied upon' },
  { key: 'score-asc', label: 'Lowest trust' },
  { key: 'name', label: 'Name (A–Z)' },
]

/** Compact a big count for cards: 1.2M / 12.3k / 940. */
function compactNum(n: number): string {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M'
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k'
  return String(n)
}

const SEVERITIES = [
  { key: '', label: 'All findings' },
  { key: 'critical', label: 'Has critical' },
  { key: 'high', label: 'Has high+' },
  { key: 'clean', label: 'Clean only' },
  { key: 'skipped', label: 'Skipped / errored' },
]

const GRADES = [
  { key: '', label: 'Any grade' },
  { key: 'certified', label: '✦ Certified (A+)' },
  { key: 'A', label: 'A & up' },
  { key: 'B', label: 'B & up' },
  { key: 'C', label: 'C & up' },
]

const PAGE_SIZE = 30

function whyLines(row: CatalogRow): string[] {
  const out: string[] = []
  if (row.critical) out.push(`${row.critical} critical finding${row.critical > 1 ? 's' : ''}`)
  if (row.high) out.push(`${row.high} high-severity finding${row.high > 1 ? 's' : ''}`)
  if (row.findings_count != null) out.push(`${row.findings_count} total findings across 12 categories`)
  if (!out.length) out.push('No high or critical findings · signed clean')
  return out
}

/** At-a-glance status chip on the card face — mirrors the old Scans status column. */
function statusChip(row: CatalogRow): { label: string; cls: string } {
  if (row.skipped) return { label: 'skipped', cls: 'text-text-muted bg-surface-hover' }
  if (row.scan_error) return { label: 'fetch error', cls: 'text-warning bg-warning/15' }
  if (row.surface === 'x402') {
    return row.has_x402_header
      ? { label: `x402 ✓${row.http_status ? ` · ${row.http_status}` : ''}`, cls: 'text-success bg-success/15' }
      : { label: `${row.http_status ?? '—'}`, cls: 'text-text-muted bg-surface-hover' }
  }
  if (row.critical) return { label: 'critical', cls: 'text-danger bg-danger/15' }
  if (row.high) return { label: 'high', cls: 'text-warning bg-warning/15' }
  if (row.trust_score != null) return { label: 'clean', cls: 'text-success bg-success/15' }
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
  return (
    <div className="glass card-hover rounded-xl p-[18px]">
      <div className="flex items-center justify-between gap-2.5">
        <span className="min-w-0 flex items-center gap-2">
          {surfaceBadge && <span className="font-mono text-[9.5px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-primary/12 text-primary-light shrink-0">{surfaceBadge}</span>}
          <span className="font-mono text-[13.5px] break-all">{display}</span>
        </span>
        {row.trust_score != null ? (
          <TrustPill score={row.trust_score} />
        ) : (
          <span className="font-mono text-[11px] px-2 py-0.5 rounded-lg shrink-0 text-text-muted bg-surface-hover">unscored</span>
        )}
      </div>
      {/* category + adoption — the curation/at-a-glance row */}
      <div className="mt-2 flex items-center gap-2 flex-wrap">
        {row.category && <span className="text-[10.5px] px-1.5 py-0.5 rounded bg-surface-hover text-text-muted">{row.category}</span>}
        {row.adoption_count != null && row.adoption_count > 0 && (
          <span className="font-mono text-[11px] tabular-nums" style={{ color: '#F59E0B' }} title="Adoption — how widely relied upon">
            📈 {compactNum(row.adoption_count)} {row.adoption_unit || ''}
          </span>
        )}
      </div>
      {/* status + findings + language — the at-a-glance row Scans had */}
      <div className="mt-2 flex items-center gap-2 flex-wrap">
        <span className={`font-mono text-[10.5px] uppercase tracking-wide px-1.5 py-0.5 rounded ${chip.cls}`}>{chip.label}</span>
        {fnd && <span className="font-mono text-[11px] text-text-muted tabular-nums">{fnd}</span>}
        {row.primary_language && <span className="font-mono text-[11px] text-text-muted">· {row.primary_language}</span>}
        {row.trust_score != null && <span className="font-mono text-[11px] text-text-muted tabular-nums ml-auto">{row.trust_score}/100</span>}
      </div>
      <button onClick={() => setOpen(!open)} className="mt-3 text-[12.5px] text-primary-light hover:text-primary">
        {open ? 'Hide' : 'Why this grade'} {open ? '▴' : '▾'}
      </button>
      {open && (
        <ul className="mt-2 pl-4 list-disc text-[12.5px] text-text-muted space-y-1">
          {whyLines(row).map((w) => <li key={w}>{w}</li>)}
        </ul>
      )}
      {href && (
        <div className="mt-3">
          <Link to={href} className="text-[12.5px] font-semibold text-primary-light hover:text-primary">
            {row.trust_score != null ? 'Report & install →' : 'View →'}
          </Link>
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, hint }: { label: string; value: number; hint: string }) {
  return (
    <div className="glass rounded-xl p-4">
      <div className="font-mono text-[10.5px] uppercase tracking-wide text-text-muted mb-1">{label}</div>
      <CountUp value={value} className="block text-2xl font-bold tabular-nums gradient-text" />
      <div className="text-[11.5px] text-text-muted mt-1">{hint}</div>
    </div>
  )
}

function SummaryStrip({ s }: { s: CatalogSummary }) {
  const bs = s.by_surface || {}
  const bc = s.by_surface_critical || {}
  const bh = s.by_surface_high || {}
  const npmPypi = (bs.npm ?? 0) + (bs.pypi ?? 0)
  const npmPypiCrit = (bc.npm ?? 0) + (bc.pypi ?? 0)
  const npmPypiHigh = (bh.npm ?? 0) + (bh.pypi ?? 0)
  const x402Total = s.x402_endpoints_total ?? bs.x402 ?? 0
  return (
    <Reveal className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mt-6">
      <StatCard label="Total scans" value={s.total_scans} hint="across 5 surfaces" />
      <StatCard label="x402 endpoints" value={x402Total} hint={s.x402_compliant != null ? `${s.x402_compliant} compliant` : 'payment-gated APIs'} />
      <StatCard label="MCP servers" value={bs.mcp ?? 0} hint={`${bc.mcp ?? 0} critical · ${bh.mcp ?? 0} high`} />
      <StatCard label="OpenClaw skills" value={bs.openclaw ?? 0} hint={`${bc.openclaw ?? 0} critical · ${bh.openclaw ?? 0} high`} />
      <StatCard label="npm + PyPI" value={npmPypi} hint={`${npmPypiCrit} critical · ${npmPypiHigh} high`} />
    </Reveal>
  )
}

const DEFAULT_SURFACE = SURFACES[0].key
const DEFAULT_SORT = 'score-desc'

export default function RebrandBrowse() {
  // URL is the source of truth for every filter — so navigating into a tool and
  // hitting back restores the exact view, and any filtered view is shareable.
  const [sp, setSp] = useSearchParams()
  const surface = sp.get('surface') || DEFAULT_SURFACE
  const sort = sp.get('sort') || DEFAULT_SORT
  const severity = sp.get('sev') || ''
  const grade = sp.get('grade') || ''
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
  const setCategory = (v: string) => patch({ cat: v })
  const setPage = (updater: (p: number) => number) => patch({ page: String(updater(page)) })
  const applySearch = () => patch({ q: qInput.trim() })
  const clearSearch = () => { setQInput(''); patch({ q: '' }) }
  const clearAll = () => setSp(new URLSearchParams(surface !== DEFAULT_SURFACE ? { surface } : {}), { replace: true })

  const activeFilters = (grade ? 1 : 0) + (severity ? 1 : 0) + (category ? 1 : 0) + (sort !== DEFAULT_SORT ? 1 : 0)

  // A search should find things anywhere — when q is set we drop the surface
  // filter so search spans the whole catalog, not just the active tab.
  const { data, isLoading, isError, isFetching } = useQuery({
    queryKey: ['rebrand-catalog', surface, sort, severity, grade, category, q, page],
    queryFn: () => fetchCatalog({ surface: q ? '' : surface, sort, severity, grade, category, q, limit: PAGE_SIZE, offset: page * PAGE_SIZE }),
    placeholderData: keepPreviousData,
  })
  // Category options come from the catalog's own breakdown (stable across filters).
  const CATEGORIES = [{ key: '', label: 'All categories' },
    ...Object.entries(data?.summary?.by_category ?? {}).map(([c, n]) => ({ key: c, label: `${c} (${n})` }))]

  const rows = data?.rows ?? []
  const summary = data?.summary
  const total = summary?.total_scans
  const matching = data?.total
  const totalPages = matching != null ? Math.ceil(matching / PAGE_SIZE) : 0

  return (
    <div>
      {/* header block */}
      <div className="max-w-[1080px] mx-auto px-6 pt-14">
        <div className="max-w-[62ch]">
          <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Browse</span>
          <h1 className="mt-3 text-3xl md:text-4xl font-extrabold tracking-tight">Find tools your agent can trust</h1>
          <p className="mt-3 text-text-muted">
            Repos, npm &amp; PyPI packages, MCP servers, and skills — every listing carries a <span className="text-text">signed safety grade</span> you can recompute, and a one-click <span className="text-text">add to your agent</span>. Not star ratings; cryptographic evidence.{total != null && <> {total.toLocaleString()} graded so far.</>}
          </p>
          <p className="mt-2.5 text-[13.5px] text-text-muted">Own one of these? <Link to={rp("/rebrand/tools")} className="text-primary-light hover:text-primary font-medium">Claim it →</Link> to run private scans, get change alerts, and own how it appears.</p>
        </div>
        {summary && <SummaryStrip s={summary} />}
      </div>

      {/* sticky controls — search-first, scrollable surface chips, and a filter
          set that's inline dropdowns on desktop but a bottom sheet on mobile. */}
      <div className="sticky top-[62px] z-20 mt-6 bg-background/85 backdrop-blur-sm relative after:absolute after:left-0 after:right-0 after:bottom-0 after:translate-y-full after:h-4 after:bg-gradient-to-b after:from-background/50 after:to-transparent after:pointer-events-none">
        <div className="max-w-[1080px] mx-auto px-4 sm:px-6 py-3 flex flex-col gap-2.5">
          {/* row 1 — search (full-width on mobile) + inline filters on desktop */}
          <div className="flex items-center gap-2">
            <form
              onSubmit={(e) => { e.preventDefault(); applySearch() }}
              className="flex-1 sm:flex-none sm:w-[280px] flex items-center gap-2 rounded-full border border-border bg-surface pl-3.5 pr-1.5 py-1.5"
            >
              <svg viewBox="0 0 24 24" fill="none" className="w-4 h-4 text-text-muted shrink-0">
                <path d="M11 19a8 8 0 1 1 5.7-2.3L21 21" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
              </svg>
              <input
                value={qInput}
                onChange={(e) => setQInput(e.target.value)}
                placeholder="Search tools…"
                aria-label="Search the catalog"
                className="flex-1 min-w-0 bg-transparent outline-none text-[14px] text-text placeholder:text-text-muted"
              />
              {qInput && <button type="button" onClick={clearSearch} aria-label="Clear search" className="text-text-muted hover:text-text px-1 text-[15px] leading-none">×</button>}
              <button type="submit" className="text-[12px] font-semibold px-3 py-1 rounded-full text-white bg-primary/80 hover:bg-primary shrink-0">Go</button>
            </form>
            {/* desktop: inline filter dropdowns */}
            <div className="hidden sm:flex items-center gap-2 ml-auto">
              {[{ v: category, set: setCategory, opts: CATEGORIES }, { v: grade, set: setGrade, opts: GRADES }, { v: severity, set: setSeverity, opts: SEVERITIES }, { v: sort, set: setSort, opts: SORTS }].map((f, i) => (
                <select key={i} value={f.v} onChange={(e) => f.set(e.target.value)}
                  className="text-[13px] rounded-full border border-border bg-surface text-text-muted px-3 py-1.5 outline-none hover:border-primary-light max-w-[190px]">
                  {f.opts.map((o) => <option key={o.key} value={o.key}>{o.label}</option>)}
                </select>
              ))}
            </div>
            {/* mobile: one Filters button → bottom sheet */}
            <button onClick={() => setSheetOpen(true)} className="sm:hidden shrink-0 flex items-center gap-1.5 text-[13px] font-medium rounded-full border border-border bg-surface text-text px-3.5 py-2">
              <svg viewBox="0 0 24 24" fill="none" className="w-4 h-4"><path d="M4 6h16M7 12h10M10 18h4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></svg>
              Filters{activeFilters > 0 && <span className="grid place-items-center min-w-[18px] h-[18px] text-[10px] font-bold rounded-full bg-primary text-white">{activeFilters}</span>}
            </button>
          </div>
          {/* row 2 — surface chips: one scrollable row, never wraps */}
          <div className="flex gap-2 overflow-x-auto pb-0.5 -mx-1 px-1 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden snap-x">
            {SURFACES.map((sf, i) => (
              <button key={sf.key} onClick={() => setTab(i)}
                className={`snap-start shrink-0 whitespace-nowrap text-[13px] px-3.5 py-1.5 rounded-full border transition-colors ${
                  tab === i ? 'text-white border-transparent bg-gradient-to-r from-primary to-primary-dark' : 'text-text-muted border-border bg-surface hover:border-primary-light'
                }`}>
                {sf.label}
              </button>
            ))}
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
            {[{ label: 'Category', v: category, set: setCategory, opts: CATEGORIES }, { label: 'Grade', v: grade, set: setGrade, opts: GRADES }, { label: 'Findings', v: severity, set: setSeverity, opts: SEVERITIES }, { label: 'Sort', v: sort, set: setSort, opts: SORTS }].map((f) => (
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
        ) : isLoading && rows.length === 0 ? (
          <div className="grid md:grid-cols-3 gap-3.5">
            {Array.from({ length: 9 }).map((_, i) => <div key={i} className="glass rounded-xl p-[18px] animate-pulse h-[128px]" />)}
          </div>
        ) : (
          <RevealStagger key={`${surface}-${page}`} className="grid md:grid-cols-3 gap-3.5" stagger={0.035}>
            {rows.map((row) => <ToolCard key={row.full_name || row.name} row={row} />)}
          </RevealStagger>
        )}
        {!isLoading && !isError && rows.length === 0 && (
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
