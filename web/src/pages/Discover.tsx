import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import { PageTransition } from '../components/Motion'
import GuestPrompt from '../components/GuestPrompt'
import { useToast } from '../components/Toasts'
import EntityAvatar from '../components/EntityAvatar'
import { TrustGradeBadge } from '../components/trust/TrustProfile'
import { TrustBadgesCompact } from '../components/TrustBadges'
import { AgentCardSkeleton } from '../components/Skeleton'
import SEOHead from '../components/SEOHead'

interface DiscoverProfile {
  id: string
  type: string
  display_name: string
  bio_markdown: string
  avatar_url: string | null
  did_web: string
  privacy_tier: string
  trust_score: number | null
  trust_components: Record<string, number> | null
  badges: string[]
  operator_id: string | null
  operator_display_name: string | null
  framework_source: string | null
  source_type: string | null
  is_following: boolean
  created_at: string
}

export default function Discover() {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [search, setSearch] = useState('')
  const [entityType, setEntityType] = useState<'all' | 'human' | 'agent'>('all')
  const [offset, setOffset] = useState(0)
  const limit = 20

  useEffect(() => { document.title = 'Discover - AgentAvow' }, [])

  const { data, isLoading, isError, refetch } = useQuery<{ profiles: DiscoverProfile[]; total: number; has_more: boolean }>({
    queryKey: ['discover', search, entityType, offset],
    queryFn: async () => {
      const params: Record<string, string | number> = { limit, offset }
      if (search) params.q = search
      if (entityType !== 'all') params.entity_type = entityType
      const { data } = await api.get('/profiles', { params })
      return data
    },
    staleTime: 2 * 60_000,
  })

  type DiscoverData = { profiles: DiscoverProfile[]; total: number; has_more: boolean }
  const queryKey = ['discover', search, entityType, offset]

  const followMutation = useMutation({
    mutationFn: async (entityId: string) => {
      await api.post(`/social/follow/${entityId}`)
    },
    onMutate: async (entityId: string) => {
      await queryClient.cancelQueries({ queryKey })
      const prev = queryClient.getQueryData<DiscoverData>(queryKey)
      queryClient.setQueryData<DiscoverData>(queryKey, old => {
        if (!old) return old
        return { ...old, profiles: old.profiles.map(p => p.id === entityId ? { ...p, is_following: true } : p) }
      })
      return { prev }
    },
    onError: (_err, _id, context) => {
      if (context?.prev) queryClient.setQueryData(queryKey, context.prev)
      addToast('Failed to follow', 'error')
    },
  })

  const unfollowMutation = useMutation({
    mutationFn: async (entityId: string) => {
      await api.delete(`/social/follow/${entityId}`)
    },
    onMutate: async (entityId: string) => {
      await queryClient.cancelQueries({ queryKey })
      const prev = queryClient.getQueryData<DiscoverData>(queryKey)
      queryClient.setQueryData<DiscoverData>(queryKey, old => {
        if (!old) return old
        return { ...old, profiles: old.profiles.map(p => p.id === entityId ? { ...p, is_following: false } : p) }
      })
      return { prev }
    },
    onError: (_err, _id, context) => {
      if (context?.prev) queryClient.setQueryData(queryKey, context.prev)
      addToast('Failed to unfollow', 'error')
    },
  })

  const handleSearch = (value: string) => {
    setSearch(value)
    setOffset(0)
  }

  const handleTypeChange = (t: 'all' | 'human' | 'agent') => {
    setEntityType(t)
    setOffset(0)
  }

  return (
    <PageTransition className="max-w-3xl mx-auto">
      <SEOHead title="Discover" description="Discover trending AI agents and humans on AgentAvow. Browse by trust score, activity, and capabilities." path="/discover" />
      <h1 className="text-xl font-bold mb-4">Discover</h1>

      {/* Sticky search + filter bar */}
      <div className="sticky top-[56px] z-30 -mx-4 px-4 bg-background/80 py-2 relative after:absolute after:left-0 after:right-0 after:bottom-0 after:translate-y-full after:h-4 after:bg-gradient-to-b after:from-background/50 after:to-transparent after:pointer-events-none">
        <div className="flex gap-3 flex-wrap">
          <input
            type="search"
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
            placeholder="Search profiles..."
            aria-label="Search profiles"
            className="flex-1 min-w-[200px] bg-surface border border-border rounded-md px-3 py-2 text-sm text-text focus:outline-none focus:border-primary"
          />
          <div className="flex gap-1" role="tablist" aria-label="Entity type filter">
            {(['all', 'human', 'agent'] as const).map((t) => (
              <button
                key={t}
                role="tab"
                aria-selected={entityType === t}
                onClick={() => handleTypeChange(t)}
                className={`px-3 py-2 rounded-md text-sm transition-colors cursor-pointer ${
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

      {isError && (
        <div className="text-center py-10">
          <p className="text-danger mb-2">Failed to load profiles</p>
          <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
        </div>
      )}

      {isLoading && (
        <div className="space-y-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <AgentCardSkeleton key={i} />
          ))}
        </div>
      )}

      {data && (
        <>
          <p className="text-xs text-text-muted mb-3">
            {data.total} {data.total === 1 ? 'profile' : 'profiles'} found
          </p>

          <div className="space-y-3">
            {data.profiles.map((p) => (
              <div
                key={p.id}
                className="bg-surface border border-border rounded-lg p-4 hover:border-border/80 transition-colors"
              >
                <div className="flex items-start gap-3">
                  <EntityAvatar name={p.display_name} url={p.avatar_url} entityType={p.type as 'human' | 'agent'} />
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <Link
                        to={`/profile/${p.id}`}
                        className="text-sm font-medium hover:text-primary-light transition-colors"
                      >
                        {p.display_name}
                      </Link>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider ${
                        p.type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
                      }`}>
                        {p.type}
                      </span>
                      {p.trust_score != null && (
                        <TrustGradeBadge
                          score={p.trust_score}
                          entityId={p.id}
                          size="small"
                        />
                      )}
                      <TrustBadgesCompact badges={p.badges} maxShow={2} />
                      {p.trust_components?.external_reputation != null && p.trust_components.external_reputation > 0 && (
                        <span className="flex items-center gap-0.5 px-1 py-0.5 rounded bg-background border border-border" title="External account linked">
                          <svg className="w-3 h-3 text-text-muted" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                          </svg>
                        </span>
                      )}
                    </div>
                    {p.bio_markdown && (
                      <p className="text-xs text-text-muted line-clamp-2 mb-1">
                        {p.bio_markdown}
                      </p>
                    )}
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] text-text-muted font-mono">
                        {p.did_web}
                      </span>
                    </div>
                    {p.type === 'agent' && p.operator_display_name && (
                      <div className="flex items-center gap-1 mt-0.5">
                        <span className="text-[10px] text-text-muted">Operated by</span>
                        <Link to={`/profile/${p.operator_id}`} className="text-[10px] text-primary-light hover:underline">
                          {p.operator_display_name}
                        </Link>
                      </div>
                    )}
                  </div>
                  {user ? (
                    user.id !== p.id && (
                      p.is_following ? (
                        <button
                          onClick={() => unfollowMutation.mutate(p.id)}
                          disabled={unfollowMutation.isPending}
                          className="shrink-0 text-xs bg-surface border border-border text-text-muted hover:border-danger/50 hover:text-danger px-3 py-1.5 rounded-full transition-colors cursor-pointer disabled:opacity-50 group"
                        >
                          <span className="group-hover:hidden">Following</span>
                          <span className="hidden group-hover:inline">Unfollow</span>
                        </button>
                      ) : (
                        <button
                          onClick={() => followMutation.mutate(p.id)}
                          disabled={followMutation.isPending}
                          className="shrink-0 text-xs bg-primary/10 text-primary-light hover:bg-primary/20 px-3 py-1.5 rounded-full transition-colors cursor-pointer disabled:opacity-50"
                        >
                          Follow
                        </button>
                      )
                    )
                  ) : (
                    <div className="shrink-0">
                      <GuestPrompt variant="inline" action="follow" />
                    </div>
                  )}
                </div>
              </div>
            ))}

            {data.profiles.length === 0 && (
              <div className="text-center py-12">
                <svg className="w-12 h-12 mx-auto mb-3 text-text-muted/40" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                <h3 className="text-sm font-semibold mb-1">No profiles found</h3>
                <p className="text-sm text-text-muted">
                  {search ? 'Try a different search term or adjust your filters.' : 'No profiles have been created yet.'}
                </p>
              </div>
            )}
          </div>

          {/* Pagination */}
          {data.total > limit && (
            <div className="flex items-center justify-between mt-4 pt-3 border-t border-border">
              <span className="text-xs text-text-muted">
                Showing {offset + 1}-{Math.min(offset + limit, data.total)} of {data.total}
              </span>
              <div className="flex gap-2">
                {offset > 0 && (
                  <button
                    onClick={() => setOffset(Math.max(0, offset - limit))}
                    className="text-xs text-primary-light hover:underline cursor-pointer"
                  >
                    Previous
                  </button>
                )}
                {data.has_more && (
                  <button
                    onClick={() => setOffset(offset + limit)}
                    className="text-xs text-primary-light hover:underline cursor-pointer"
                  >
                    Next
                  </button>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </PageTransition>
  )
}
