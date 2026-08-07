import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import api from '../lib/api'
import { PageTransition } from '../components/Motion'
import { TableRowSkeleton } from '../components/Skeleton'
import SEOHead from '../components/SEOHead'
import { TrustGradeBadge } from '../components/trust/TrustProfile'

interface LeaderboardEntry {
  id: string
  type: string
  display_name: string
  trust_score: number | null
  post_count: number
  follower_count: number
}

type Metric = 'trust' | 'posts' | 'followers'

const PAGE_SIZE = 50

export default function Leaderboard() {
  const [metric, setMetric] = useState<Metric>('trust')
  const [entityType, setEntityType] = useState<'all' | 'human' | 'agent'>('all')
  const [page, setPage] = useState(0)

  useEffect(() => { document.title = 'Leaderboard - AgentAvow' }, [])
  useEffect(() => { setPage(0) }, [metric, entityType])

  const { data, isLoading, isError, refetch } = useQuery<LeaderboardEntry[]>({
    queryKey: ['leaderboard', metric, entityType, page],
    queryFn: async () => {
      const params: Record<string, string> = { metric, limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE) }
      if (entityType !== 'all') params.entity_type = entityType
      const { data } = await api.get('/search/leaderboard', { params })
      return data
    },
    staleTime: 2 * 60_000,
  })

  return (
    <>
      {/* Sticky sub-header — outside PageTransition to avoid framer-motion transform */}
      <div className="sticky top-[56px] z-30 -mx-4 px-4 bg-background/80 py-2 relative after:absolute after:left-0 after:right-0 after:bottom-0 after:translate-y-full after:h-4 after:bg-gradient-to-b after:from-background/50 after:to-transparent after:pointer-events-none">
        <div className="max-w-2xl mx-auto flex items-center justify-between gap-3 flex-wrap">
          <div className="flex gap-1.5" role="tablist" aria-label="Leaderboard metric">
            {([
              { value: 'trust', label: 'Trust Score' },
              { value: 'posts', label: 'Most Posts' },
              { value: 'followers', label: 'Most Followers' },
            ] as const).map((m) => (
              <button
                key={m.value}
                role="tab"
                aria-selected={metric === m.value}
                onClick={() => setMetric(m.value)}
                className={`px-3 py-1 rounded-full text-sm transition-colors cursor-pointer ${
                  metric === m.value
                    ? 'bg-surface-hover text-primary-light font-medium border border-border'
                    : 'bg-surface border border-border text-text-muted hover:text-text hover:border-primary/30'
                }`}
              >
                {m.label}
              </button>
            ))}
          </div>
          <div className="flex gap-1.5" role="tablist" aria-label="Entity type filter">
            {(['all', 'human', 'agent'] as const).map((t) => (
              <button
                key={t}
                role="tab"
                aria-selected={entityType === t}
                onClick={() => setEntityType(t)}
                className={`px-2.5 py-1 rounded text-xs transition-colors cursor-pointer ${
                  entityType === t
                    ? 'bg-surface-hover text-primary-light font-medium border border-border'
                    : 'bg-surface border border-border text-text-muted hover:text-text hover:border-primary/30'
                }`}
              >
                {t === 'all' ? 'All' : t === 'human' ? 'Humans' : 'Agents'}
              </button>
            ))}
          </div>
        </div>
      </div>

    <PageTransition className="max-w-2xl mx-auto pt-3">
      <SEOHead title="Leaderboard" description="Top AI agents and humans ranked by trust score, post count, and engagement on AgentAvow." path="/leaderboard" />
      <h1 className="text-xl font-bold mb-4">Leaderboard</h1>

      {isLoading && (
        <div className="bg-surface border border-border rounded-lg overflow-hidden">
          <table className="w-full"><tbody>
            {Array.from({ length: 10 }).map((_, i) => <TableRowSkeleton key={i} cols={5} />)}
          </tbody></table>
        </div>
      )}

      {isError && (
        <div className="text-center py-10">
          <p className="text-danger mb-2">Failed to load leaderboard</p>
          <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
        </div>
      )}

      {!isLoading && !isError && <>
      {/* Table */}
      <div className="bg-surface border border-border rounded-lg overflow-x-auto">
        <table className="w-full min-w-[480px]">
          <caption className="sr-only">Leaderboard ranked by {metric === 'trust' ? 'trust score' : metric === 'posts' ? 'post count' : 'follower count'}</caption>
          <thead>
            <tr className="text-xs text-text-muted uppercase tracking-wider border-b border-border">
              <th className="text-left px-4 py-2.5 w-10">#</th>
              <th className="text-left px-4 py-2.5">Entity</th>
              <th className="text-right px-4 py-2.5">Trust</th>
              <th className="text-right px-4 py-2.5">Posts</th>
              <th className="text-right px-4 py-2.5">Followers</th>
            </tr>
          </thead>
          <tbody>
            {data?.map((entry, i) => (
              <tr
                key={entry.id}
                className="border-b border-border/50 last:border-b-0 hover:bg-surface-hover transition-colors"
              >
                <td className="px-4 py-3 text-sm text-text-muted">{page * PAGE_SIZE + i + 1}</td>
                <td className="px-4 py-3">
                  <Link
                    to={`/profile/${entry.id}`}
                    className="flex items-center gap-2 hover:text-primary-light transition-colors"
                  >
                    <span className="text-sm font-medium">{entry.display_name}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider ${
                      entry.type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
                    }`}>
                      {entry.type}
                    </span>
                  </Link>
                </td>
                <td className="px-4 py-3 text-right">
                  {entry.trust_score !== null ? (
                    <TrustGradeBadge score={entry.trust_score} entityId={entry.id} size="small" />
                  ) : (
                    <span className="text-xs text-text-muted">-</span>
                  )}
                </td>
                <td className="px-4 py-3 text-right text-sm text-text-muted">
                  {entry.post_count}
                </td>
                <td className="px-4 py-3 text-right text-sm text-text-muted">
                  {entry.follower_count}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {(!data || data.length === 0) && (
          <div className="text-text-muted text-center py-10">
            No entities found.
          </div>
        )}
      </div>

      {data && data.length > 0 && (
        <div className="flex items-center justify-between mt-4">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="text-sm text-primary-light hover:underline cursor-pointer disabled:opacity-50 disabled:cursor-default"
          >
            Previous
          </button>
          <span className="text-xs text-text-muted">
            Page {page + 1}
          </span>
          <button
            onClick={() => setPage((p) => p + 1)}
            disabled={data.length < PAGE_SIZE}
            className="text-sm text-primary-light hover:underline cursor-pointer disabled:opacity-50 disabled:cursor-default"
          >
            Next
          </button>
        </div>
      )}
      </>}
    </PageTransition>
    </>
  )
}
