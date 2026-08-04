import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { fetchCatalog, rowIdentity, type CatalogRow } from '../catalog'
import { getGradeInfo } from '../../components/trust/gradeSystem'

/**
 * The "Yelp" browse catalog — LIVE data from /public/scan-catalog.
 * Grades come from the shared getGradeInfo helper (same across the app).
 * The expander is "Why this grade" (signed evidence), not star reviews.
 */

const SURFACES = [
  { key: 'mcp', label: 'MCP servers' },
  { key: 'npm', label: 'npm packages' },
  { key: 'pypi', label: 'Python packages' },
  { key: 'openclaw', label: 'Agent skills' },
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

function CardSkeleton() {
  return <div className="glass rounded-xl p-[18px] animate-pulse h-[92px]" />
}

export default function RebrandBrowse() {
  const [tab, setTab] = useState(0)
  const surface = SURFACES[tab].key

  const { data, isLoading, isError } = useQuery({
    queryKey: ['rebrand-catalog', surface],
    queryFn: () => fetchCatalog({ surface, sort: 'safest', limit: 24 }),
    placeholderData: keepPreviousData,
  })

  const rows = data?.rows ?? []
  const total = data?.summary?.total_scans

  return (
    <div className="max-w-[1080px] mx-auto px-6 py-14">
      <div className="max-w-[60ch]">
        <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Browse</span>
        <h1 className="mt-3 text-3xl md:text-4xl font-extrabold tracking-tight">The trust catalog</h1>
        <p className="mt-3 text-text-muted">
          Every tool, graded and signed. The "review" of a tool is its scan evidence — recomputable, not a
          star rating. {total != null && <>Currently <b className="text-text">{total.toLocaleString()}</b> scanned.</>}
        </p>
      </div>

      <div className="flex flex-wrap gap-2 mt-7 mb-5">
        {SURFACES.map((s, i) => (
          <button
            key={s.key}
            onClick={() => setTab(i)}
            className={`text-[13.5px] px-4 py-1.5 rounded-full border transition-colors ${
              tab === i
                ? 'text-white border-transparent bg-gradient-to-r from-primary to-primary-dark'
                : 'text-text-muted border-border bg-surface hover:border-primary-light'
            }`}
          >
            {s.label}
          </button>
        ))}
      </div>

      {isError ? (
        <div className="glass rounded-xl p-8 text-center text-text-muted text-[14px]">
          Couldn't load the catalog right now. Try again in a moment.
        </div>
      ) : (
        <div className="grid md:grid-cols-3 gap-3.5">
          {isLoading && rows.length === 0
            ? Array.from({ length: 6 }).map((_, i) => <CardSkeleton key={i} />)
            : rows.map((row) => <ToolCard key={row.full_name || row.name} row={row} />)}
        </div>
      )}

      {!isLoading && !isError && rows.length === 0 && (
        <div className="mt-6 text-center text-text-muted text-[14px]">No scored tools on this surface yet.</div>
      )}
    </div>
  )
}
