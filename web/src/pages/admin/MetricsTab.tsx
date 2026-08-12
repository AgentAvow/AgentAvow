import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import api from '../../lib/api'
import { InlineSkeleton } from '../../components/Skeleton'
import { StatCard } from './StatCard'

type Metrics = {
  window: string
  headline: Record<string, number>
  scans?: { grade_distribution?: Record<string, number> }
  catalog?: { by_surface?: Record<string, number>; by_category?: Record<string, number> }
  funnel?: { scanned: number; watched: number; claimed: number; installs: number }
  series?: Record<string, number[]>
  generated_at?: string
}

/** A tiny inline sparkline for a daily series. */
function Spark({ data }: { data: number[] }) {
  if (!data || data.length < 2) return null
  const w = 120, h = 28, max = Math.max(...data, 1)
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - (v / max) * h}`).join(' ')
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-7 mt-1" preserveAspectRatio="none" aria-hidden="true">
      <polyline points={pts} fill="none" stroke="var(--color-primary)" strokeWidth="1.5" />
    </svg>
  )
}

const HEADLINE: [string, string][] = [
  ['repos_scanned', 'Repos scanned'],
  ['new_repos', 'New repos'],
  ['watches_created', 'Watches created'],
  ['attestations_issued', 'Attestations issued'],
  ['adoption_hits', 'Adoption lookups'],
  ['install_clicks', '1-click installs'],
  ['force_rescans', 'Fresh re-scans'],
  ['badge_fetches', 'Badge fetches'],
  ['api_calls', 'API calls'],
]

/** Scan → watch → claim → install funnel with drop-off %. */
function Funnel({ f }: { f: NonNullable<Metrics['funnel']> }) {
  const steps: [string, number][] = [
    ['Scanned', f.scanned], ['Watched', f.watched], ['Claimed', f.claimed], ['Installed', f.installs],
  ]
  const max = Math.max(f.scanned, 1)
  return (
    <div>
      <div className="text-sm font-semibold mb-2">Engagement funnel (this window)</div>
      <div className="space-y-2">
        {steps.map(([label, n], i) => {
          const pct = Math.round((n / max) * 100)
          const prev = i > 0 ? steps[i - 1][1] : n
          const conv = prev > 0 ? Math.round((n / prev) * 100) : 0
          return (
            <div key={label} className="flex items-center gap-3">
              <div className="w-20 text-xs text-text-muted shrink-0">{label}</div>
              <div className="flex-1 h-6 bg-surface rounded overflow-hidden border border-border">
                <div className="h-full bg-primary/40" style={{ width: `${Math.max(pct, 2)}%` }} />
              </div>
              <div className="w-28 text-xs tabular-nums text-right shrink-0">
                {n.toLocaleString()}{i > 0 && <span className="text-text-muted/60"> · {conv}%</span>}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

const WINDOWS = ['today', '7d', '30d']

export default function MetricsTab() {
  const [window, setWindow] = useState('7d')
  const { data, isLoading } = useQuery<Metrics>({
    queryKey: ['admin-metrics', window],
    queryFn: async () => (await api.get('/admin/metrics', { params: { window } })).data,
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <h2 className="text-lg font-bold">Platform metrics</h2>
        <div className="ml-auto flex gap-1">
          {WINDOWS.map((w) => (
            <button
              key={w}
              onClick={() => setWindow(w)}
              className={`text-xs px-3 py-1.5 rounded-lg border ${window === w ? 'border-primary bg-primary/15 text-primary font-semibold' : 'border-border text-text-muted'}`}
            >{w}</button>
          ))}
        </div>
      </div>

      {isLoading || !data ? (
        <InlineSkeleton />
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {HEADLINE.map(([k, label]) => (
              <div key={k} className="bg-surface border border-border rounded-lg p-4">
                <div className="text-2xl font-bold">{(data.headline?.[k] ?? 0).toLocaleString()}</div>
                <div className="text-xs text-text-muted mt-1">{label}</div>
                {data.series?.[k] && <Spark data={data.series[k]} />}
              </div>
            ))}
          </div>

          {data.funnel && <Funnel f={data.funnel} />}

          {data.catalog?.by_category && Object.keys(data.catalog.by_category).length > 0 && (
            <div>
              <div className="text-sm font-semibold mb-2">Tools by type</div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {Object.entries(data.catalog.by_category)
                  .sort((a, b) => b[1] - a[1])
                  .map(([c, n]) => <StatCard key={c} label={c} value={n} />)}
              </div>
            </div>
          )}

          {data.scans?.grade_distribution && (
            <div>
              <div className="text-sm font-semibold mb-2">Grade distribution (all-time)</div>
              <div className="grid grid-cols-3 sm:grid-cols-6 gap-3">
                {['A+', 'A', 'B', 'C', 'D', 'F'].map((g) => (
                  <StatCard key={g} label={`Grade ${g}`} value={data.scans!.grade_distribution![g] ?? 0} />
                ))}
              </div>
            </div>
          )}

          {data.catalog?.by_surface && (
            <div>
              <div className="text-sm font-semibold mb-2">Catalog by surface</div>
              <div className="grid grid-cols-3 sm:grid-cols-6 gap-3">
                {Object.entries(data.catalog.by_surface).map(([s, n]) => (
                  <StatCard key={s} label={s} value={n} />
                ))}
              </div>
            </div>
          )}

          <div className="text-[11px] text-text-muted/60">Generated {data.generated_at ? new Date(data.generated_at).toLocaleString() : '—'} · window {data.window}</div>
        </>
      )}
    </div>
  )
}
