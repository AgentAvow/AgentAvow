import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { fetchCatalog, rowIdentity, type CatalogRow, type CatalogSummary } from '../catalog'
import { getGradeInfo } from '../../components/trust/gradeSystem'
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
  { key: 'x402', label: 'x402 endpoints' },
  { key: 'community', label: 'Community' },
]

const SORTS = [
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

function ToolCard({ row }: { row: CatalogRow }) {
  const [open, setOpen] = useState(false)
  const { display, repoPath } = rowIdentity(row)
  const g = row.trust_score != null ? getGradeInfo(row.trust_score) : null
  const chip = statusChip(row)
  const fnd = findingsLine(row)
  return (
    <div className="glass card-hover rounded-xl p-[18px]">
      <div className="flex items-center justify-between gap-2.5">
        <span className="font-mono text-[13.5px] break-all">{display}</span>
        {g ? (
          <span className={`font-extrabold text-[13px] px-2.5 py-0.5 rounded-lg shrink-0 ${g.textClass} ${g.bgClass}`}>{g.grade}</span>
        ) : (
          <span className="font-mono text-[11px] px-2 py-0.5 rounded-lg shrink-0 text-text-muted bg-surface-hover">unscored</span>
        )}
      </div>
      {/* status + findings + language — the at-a-glance row Scans had */}
      <div className="mt-2.5 flex items-center gap-2 flex-wrap">
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
      {repoPath && (
        <div className="mt-3">
          <Link to={`/rebrand/check/${repoPath}`} className="text-[12.5px] font-semibold text-primary-light hover:text-primary">Full report →</Link>
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

export default function RebrandBrowse() {
  const [tab, setTab] = useState(0)
  const [sort, setSort] = useState('score-desc')
  const [severity, setSeverity] = useState('')
  const [qInput, setQInput] = useState('')
  const [q, setQ] = useState('')
  const [page, setPage] = useState(0)
  const surface = SURFACES[tab].key

  // A search should find things anywhere — when q is set we drop the surface
  // filter so search spans the whole catalog, not just the active tab.
  const { data, isLoading, isError, isFetching } = useQuery({
    queryKey: ['rebrand-catalog', surface, sort, severity, q, page],
    queryFn: () => fetchCatalog({ surface: q ? '' : surface, sort, severity, q, limit: PAGE_SIZE, offset: page * PAGE_SIZE }),
    placeholderData: keepPreviousData,
  })

  const rows = data?.rows ?? []
  const summary = data?.summary
  const total = summary?.total_scans
  const matching = data?.total
  const totalPages = matching != null ? Math.ceil(matching / PAGE_SIZE) : 0

  const reset = (fn: () => void) => { fn(); setPage(0) }

  return (
    <div>
      {/* header block */}
      <div className="max-w-[1080px] mx-auto px-6 pt-14">
        <div className="max-w-[62ch]">
          <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Browse</span>
          <h1 className="mt-3 text-3xl md:text-4xl font-extrabold tracking-tight">The trust catalog</h1>
          <p className="mt-3 text-text-muted">
            Browse tools by their signed safety grade. Instead of star ratings, every grade is backed by scan
            evidence anyone can recompute.{total != null && <> {total.toLocaleString()} scanned so far.</>}
          </p>
        </div>
        {summary && <SummaryStrip s={summary} />}
      </div>

      {/* sticky controls — mirrors the agentgraph pinned-bar blend: translucent bg + a
          soft gradient fade below (no hard bar), so content scrolls under it cleanly. */}
      <div className="sticky top-[62px] z-10 mt-6 bg-background/80 relative after:absolute after:left-0 after:right-0 after:bottom-0 after:translate-y-full after:h-4 after:bg-gradient-to-b after:from-background/50 after:to-transparent after:pointer-events-none">
        <div className="max-w-[1080px] mx-auto px-6 py-3 flex flex-wrap items-center gap-2">
          {SURFACES.map((sf, i) => (
            <button
              key={sf.key}
              onClick={() => reset(() => setTab(i))}
              className={`text-[13.5px] px-4 py-1.5 rounded-full border transition-colors ${
                tab === i
                  ? 'text-white border-transparent bg-gradient-to-r from-primary to-primary-dark'
                  : 'text-text-muted border-border bg-surface hover:border-primary-light'
              }`}
            >
              {sf.label}
            </button>
          ))}
          <form
            onSubmit={(e) => { e.preventDefault(); reset(() => setQ(qInput.trim())) }}
            className="ml-auto flex items-center gap-2 rounded-full border border-border bg-surface pl-3 pr-1 py-1"
          >
            <svg viewBox="0 0 24 24" fill="none" className="w-4 h-4 text-text-muted shrink-0">
              <path d="M11 19a8 8 0 1 1 5.7-2.3L21 21" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
            </svg>
            <input
              value={qInput}
              onChange={(e) => setQInput(e.target.value)}
              placeholder="Search…"
              className="w-[130px] bg-transparent outline-none text-[13px] text-text placeholder:text-text-muted"
            />
            <button type="submit" className="text-[12px] font-semibold px-3 py-1 rounded-full text-white bg-primary/80 hover:bg-primary">Go</button>
          </form>
          <select
            value={severity}
            onChange={(e) => reset(() => setSeverity(e.target.value))}
            className="text-[13px] rounded-full border border-border bg-surface text-text-muted px-3 py-1.5 outline-none hover:border-primary-light"
          >
            {SEVERITIES.map((sv) => <option key={sv.key} value={sv.key}>{sv.label}</option>)}
          </select>
          <select
            value={sort}
            onChange={(e) => reset(() => setSort(e.target.value))}
            className="text-[13px] rounded-full border border-border bg-surface text-text-muted px-3 py-1.5 outline-none hover:border-primary-light"
          >
            {SORTS.map((so) => <option key={so.key} value={so.key}>{so.label}</option>)}
          </select>
        </div>
      </div>

      {/* results */}
      <div className="max-w-[1080px] mx-auto px-6 py-8">
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
