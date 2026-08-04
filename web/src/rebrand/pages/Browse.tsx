import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { fetchCatalog, rowIdentity, type CatalogRow } from '../catalog'
import { getGradeInfo } from '../../components/trust/gradeSystem'

/**
 * The "Yelp" browse catalog — LIVE from /public/scan-catalog.
 * Sticky category tabs, search, sort. Grades from the shared getGradeInfo.
 * The expander is "Why this grade" (signed evidence), not star reviews.
 */

const SURFACES = [
  { key: 'mcp', label: 'MCP servers' },
  { key: 'openclaw', label: 'Agent skills' },
  { key: 'npm', label: 'npm packages' },
  { key: 'pypi', label: 'Python packages' },
  { key: 'x402', label: 'x402 endpoints' },
]

const SORTS = [
  { key: 'score-desc', label: 'Highest trust' },
  { key: 'score-asc', label: 'Lowest trust' },
  { key: 'name', label: 'Name (A–Z)' },
]

function whyLines(row: CatalogRow): string[] {
  const out: string[] = []
  if (row.critical) out.push(`${row.critical} critical finding${row.critical > 1 ? 's' : ''}`)
  if (row.high) out.push(`${row.high} high-severity finding${row.high > 1 ? 's' : ''}`)
  if (row.findings_count != null) out.push(`${row.findings_count} total findings across 12 categories`)
  if (!out.length) out.push('No high or critical findings · signed clean')
  return out
}

function ToolCard({ row }: { row: CatalogRow }) {
  const [open, setOpen] = useState(false)
  const { display, repoPath } = rowIdentity(row)
  const g = row.trust_score != null ? getGradeInfo(row.trust_score) : null
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

export default function RebrandBrowse() {
  const [tab, setTab] = useState(0)
  const [sort, setSort] = useState('score-desc')
  const [qInput, setQInput] = useState('')
  const [q, setQ] = useState('')
  const surface = SURFACES[tab].key

  const { data, isLoading, isError } = useQuery({
    queryKey: ['rebrand-catalog', surface, sort, q],
    queryFn: () => fetchCatalog({ surface, sort, q, limit: 30 }),
    placeholderData: keepPreviousData,
  })

  const rows = data?.rows ?? []
  const total = data?.summary?.total_scans

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
      </div>

      {/* sticky controls — tabs + search + sort pinned under the header */}
      <div className="sticky top-[62px] z-10 glass border-y border-border/50 mt-6">
        <div className="max-w-[1080px] mx-auto px-6 py-3 flex flex-wrap items-center gap-2">
          {SURFACES.map((sf, i) => (
            <button
              key={sf.key}
              onClick={() => setTab(i)}
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
            onSubmit={(e) => { e.preventDefault(); setQ(qInput.trim()) }}
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
            value={sort}
            onChange={(e) => setSort(e.target.value)}
            className="text-[13px] rounded-full border border-border bg-surface text-text-muted px-3 py-1.5 outline-none hover:border-primary-light"
          >
            {SORTS.map((so) => <option key={so.key} value={so.key}>{so.label}</option>)}
          </select>
        </div>
      </div>

      {/* results */}
      <div className="max-w-[1080px] mx-auto px-6 py-8">
        {isError ? (
          <div className="glass rounded-xl p-8 text-center text-text-muted text-[14px]">Couldn't load the catalog right now. Try again in a moment.</div>
        ) : (
          <div className="grid md:grid-cols-3 gap-3.5">
            {isLoading && rows.length === 0
              ? Array.from({ length: 9 }).map((_, i) => <div key={i} className="glass rounded-xl p-[18px] animate-pulse h-[92px]" />)
              : rows.map((row) => <ToolCard key={row.full_name || row.name} row={row} />)}
          </div>
        )}
        {!isLoading && !isError && rows.length === 0 && (
          <div className="mt-2 text-center text-text-muted text-[14px]">No matches on this surface. Try another category or search.</div>
        )}
      </div>
    </div>
  )
}
