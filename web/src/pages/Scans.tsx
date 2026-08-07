import { useState } from 'react'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { publicApi } from '../lib/scanApi'

type Surface = 'x402' | 'mcp' | 'npm' | 'pypi' | 'openclaw'
type Severity = 'critical' | 'high' | 'clean' | 'skipped'
type Sort = 'default' | 'score-asc' | 'score-desc' | 'name'

interface CatalogRow {
  surface: Surface
  name: string
  repository_url: string | null
  full_name: string | null
  endpoint_url: string | null
  trust_score: number | null
  critical: number | null
  high: number | null
  findings_count: number | null
  primary_language: string | null
  is_mcp_server: boolean | null
  scan_error: string | null
  skipped: string | null
  has_x402_header: boolean | null
  http_status: number | null
}

interface CatalogSummary {
  total_scans: number
  by_surface: Record<string, number>
  by_surface_critical: Record<string, number>
  by_surface_high: Record<string, number>
  repo_scans_total: number
  repo_scans_with_critical: number
  repo_scans_with_high: number
  x402_endpoints_total: number
  x402_compliant: number
}

interface CatalogResponse {
  summary: CatalogSummary
  rows: CatalogRow[]
  total: number
  offset: number
  limit: number
  surfaces: string[]
}

const PAGE_SIZE = 50

function gradeFromScore(score: number | null): string {
  if (score === null || score === undefined) return '—'
  if (score >= 96) return 'A+'
  if (score >= 81) return 'A'
  if (score >= 61) return 'B'
  if (score >= 41) return 'C'
  if (score >= 21) return 'D'
  return 'F'
}

function gradeColor(score: number | null): string {
  if (score === null) return 'text-text-muted'
  if (score >= 81) return 'text-emerald-400'
  if (score >= 61) return 'text-green-400'
  if (score >= 41) return 'text-amber-400'
  if (score >= 21) return 'text-orange-400'
  return 'text-red-400'
}

function ownerRepo(row: CatalogRow): { owner: string; repo: string } | null {
  const fn = row.full_name || ''
  if (fn.includes('/')) {
    const [owner, repo] = fn.split('/')
    if (owner && repo) return { owner, repo }
  }
  return null
}

export default function Scans() {
  const [surface, setSurface] = useState<Surface | ''>('')
  const [q, setQ] = useState('')
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [sort, setSort] = useState<Sort>('default')
  const [page, setPage] = useState(0)

  const { data, isLoading, isFetching } = useQuery<CatalogResponse>({
    queryKey: ['scan-catalog', surface, q, severity, sort, page],
    queryFn: async () => {
      const params: Record<string, string | number> = {
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      }
      if (surface) params.surface = surface
      if (q) params.q = q
      if (severity) params.severity = severity
      if (sort !== 'default') params.sort = sort
      const r = await publicApi.get<CatalogResponse>('/public/scan-catalog', { params })
      return r.data
    },
    placeholderData: keepPreviousData,
    staleTime: 60_000,
  })

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0

  return (
    <div className="min-h-screen text-text-primary">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-10">
        <header className="mb-10">
          <h1 className="text-4xl sm:text-5xl font-semibold tracking-tight mb-3">
            Scan catalog
          </h1>
          <p className="text-text-secondary text-lg max-w-3xl">
            Every scan we&rsquo;ve run, browseable. AgentAvow publishes the trail of
            launch-scan results — not a frozen PDF. Each row here is a real
            evidence record, signed and reproducible.
          </p>
          <Link
            to="/x402"
            className="inline-block mt-4 text-sm text-primary hover:underline"
          >
            Explore the live x402 trust surface &rarr;
          </Link>
        </header>

        {data && (
          <section className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-8">
            <SummaryCard
              label="Total scans"
              value={data.summary.total_scans.toLocaleString()}
              hint="across 5 surfaces"
            />
            <SummaryCard
              label="x402 endpoints"
              value={data.summary.x402_endpoints_total.toLocaleString()}
              hint={`${data.summary.x402_compliant} compliant · ${((data.summary.x402_compliant / Math.max(data.summary.x402_endpoints_total, 1)) * 100).toFixed(2)}%`}
            />
            <SummaryCard
              label="MCP servers"
              value={(data.summary.by_surface.mcp ?? 0).toLocaleString()}
              hint={`${data.summary.by_surface_critical.mcp ?? 0} critical · ${data.summary.by_surface_high.mcp ?? 0} high`}
            />
            <SummaryCard
              label="OpenClaw skills"
              value={(data.summary.by_surface.openclaw ?? 0).toLocaleString()}
              hint={`${data.summary.by_surface_critical.openclaw ?? 0} critical · ${data.summary.by_surface_high.openclaw ?? 0} high`}
            />
            <SummaryCard
              label="npm + PyPI"
              value={(
                (data.summary.by_surface.npm ?? 0) +
                (data.summary.by_surface.pypi ?? 0)
              ).toLocaleString()}
              hint={`${(data.summary.by_surface_critical.npm ?? 0) + (data.summary.by_surface_critical.pypi ?? 0)} critical · ${(data.summary.by_surface_high.npm ?? 0) + (data.summary.by_surface_high.pypi ?? 0)} high`}
            />
          </section>
        )}

        <section className="bg-surface-1 ring-1 ring-border rounded-xl p-4 mb-6 flex flex-col sm:flex-row gap-3 items-stretch sm:items-center">
          <input
            type="text"
            placeholder="Search by name…"
            value={q}
            onChange={(e) => {
              setQ(e.target.value)
              setPage(0)
            }}
            className="flex-1 bg-surface-2 ring-1 ring-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-primary"
          />
          <select
            value={surface}
            onChange={(e) => {
              setSurface(e.target.value as Surface | '')
              setPage(0)
            }}
            className="bg-surface-2 ring-1 ring-border rounded-lg px-3 py-2 text-sm"
          >
            <option value="">All surfaces</option>
            <option value="x402">x402 Bazaar</option>
            <option value="mcp">MCP Registry</option>
            <option value="openclaw">OpenClaw skills</option>
            <option value="npm">npm</option>
            <option value="pypi">PyPI</option>
          </select>
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value as Severity | '')
              setPage(0)
            }}
            className="bg-surface-2 ring-1 ring-border rounded-lg px-3 py-2 text-sm"
          >
            <option value="">All findings</option>
            <option value="critical">Has critical</option>
            <option value="high">Has high</option>
            <option value="clean">Clean (≥80)</option>
            <option value="skipped">Skipped / errored</option>
          </select>
          <select
            value={sort}
            onChange={(e) => {
              setSort(e.target.value as Sort)
              setPage(0)
            }}
            className="bg-surface-2 ring-1 ring-border rounded-lg px-3 py-2 text-sm"
          >
            <option value="default">Default order</option>
            <option value="score-desc">Score: high → low</option>
            <option value="score-asc">Score: low → high</option>
            <option value="name">Name A→Z</option>
          </select>
        </section>

        {isLoading && (
          <div className="text-text-muted text-center py-12">Loading catalog…</div>
        )}

        {data && data.rows.length === 0 && !isLoading && (
          <div className="text-text-muted text-center py-12">
            No scans match these filters.
          </div>
        )}

        {data && data.rows.length > 0 && (
          <>
            <div className="text-text-muted text-sm mb-3">
              {data.total.toLocaleString()} matching {data.total === 1 ? 'scan' : 'scans'}
              {isFetching && ' · refreshing…'}
            </div>
            <div className="bg-surface-1 ring-1 ring-border rounded-xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-surface-2 text-text-muted text-left text-xs uppercase tracking-wider">
                    <tr>
                      <th className="px-4 py-3">Surface</th>
                      <th className="px-4 py-3">Name</th>
                      <th className="px-4 py-3">Score</th>
                      <th className="px-4 py-3">Findings</th>
                      <th className="px-4 py-3 hidden md:table-cell">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {data.rows.map((row, i) => (
                      <CatalogRowComponent key={`${row.surface}-${row.name}-${i}`} row={row} />
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="flex items-center justify-between mt-6">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                className="bg-surface-2 ring-1 ring-border rounded-lg px-4 py-2 text-sm disabled:opacity-40 disabled:cursor-not-allowed hover:bg-surface-3"
              >
                ← Prev
              </button>
              <div className="text-text-muted text-sm">
                Page {page + 1} of {totalPages.toLocaleString()}
              </div>
              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={page + 1 >= totalPages}
                className="bg-surface-2 ring-1 ring-border rounded-lg px-4 py-2 text-sm disabled:opacity-40 disabled:cursor-not-allowed hover:bg-surface-3"
              >
                Next →
              </button>
            </div>
          </>
        )}

        <footer className="mt-12 text-text-muted text-xs">
          Catalog rebuilt from <code>data/launch-scans/*.json</code>. Each row links
          back to the per-repo timeline at <code>/check/owner/repo</code> where applicable.
          See the{' '}
          <Link to="/state-of-agent-security-2026" className="underline hover:text-text-secondary">
            launch landing page
          </Link>{' '}
          for narrative context.
        </footer>
      </div>
    </div>
  )
}

function SummaryCard({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="bg-surface-1 ring-1 ring-border rounded-xl p-4">
      <div className="text-text-muted text-xs uppercase tracking-wider mb-1">{label}</div>
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
      <div className="text-text-muted text-xs mt-1">{hint}</div>
    </div>
  )
}

function CatalogRowComponent({ row }: { row: CatalogRow }) {
  const or = ownerRepo(row)
  const linkTo = or ? `/check/${or.owner}/${or.repo}` : null

  const surfaceColor: Record<string, string> = {
    x402: 'bg-blue-500/15 text-blue-300',
    mcp: 'bg-purple-500/15 text-purple-300',
    openclaw: 'bg-pink-500/15 text-pink-300',
    npm: 'bg-red-500/15 text-red-300',
    pypi: 'bg-yellow-500/15 text-yellow-300',
  }

  const findingsParts: string[] = []
  if ((row.critical || 0) > 0) findingsParts.push(`${row.critical}C`)
  if ((row.high || 0) > 0) findingsParts.push(`${row.high}H`)
  if ((row.findings_count || 0) > 0 && findingsParts.length === 0) {
    findingsParts.push(`${row.findings_count}`)
  }

  let statusBadge = '—'
  let statusClass = 'text-text-muted'
  if (row.skipped) {
    statusBadge = `skipped: ${row.skipped}`
    statusClass = 'text-text-muted'
  } else if (row.scan_error) {
    statusBadge = 'fetch error'
    statusClass = 'text-orange-400'
  } else if (row.surface === 'x402') {
    if (row.has_x402_header) {
      statusBadge = `x402 ✓ (${row.http_status})`
      statusClass = 'text-emerald-400'
    } else {
      statusBadge = `${row.http_status ?? '—'}`
      statusClass = 'text-text-muted'
    }
  } else if ((row.critical || 0) > 0) {
    statusBadge = 'critical'
    statusClass = 'text-red-400'
  } else if ((row.high || 0) > 0) {
    statusBadge = 'high'
    statusClass = 'text-amber-400'
  } else if (row.trust_score !== null) {
    statusBadge = 'clean'
    statusClass = 'text-emerald-400'
  }

  return (
    <tr className="hover:bg-surface-2/50">
      <td className="px-4 py-3">
        <span className={`inline-block px-2 py-0.5 rounded text-xs font-mono ${surfaceColor[row.surface]}`}>
          {row.surface}
        </span>
      </td>
      <td className="px-4 py-3 max-w-md truncate">
        {linkTo ? (
          <Link to={linkTo} className="text-text-primary hover:underline">
            {row.name}
          </Link>
        ) : (
          <span className="text-text-primary">{row.name}</span>
        )}
        {row.primary_language && (
          <span className="ml-2 text-text-muted text-xs">{row.primary_language}</span>
        )}
      </td>
      <td className="px-4 py-3 tabular-nums">
        {row.trust_score !== null ? (
          <span className={gradeColor(row.trust_score)}>
            {gradeFromScore(row.trust_score)} {row.trust_score}
          </span>
        ) : (
          <span className="text-text-muted">—</span>
        )}
      </td>
      <td className="px-4 py-3 tabular-nums">
        {findingsParts.length > 0 ? (
          <span className="text-text-secondary">{findingsParts.join(' · ')}</span>
        ) : (
          <span className="text-text-muted">—</span>
        )}
      </td>
      <td className={`px-4 py-3 hidden md:table-cell text-xs ${statusClass}`}>{statusBadge}</td>
    </tr>
  )
}
