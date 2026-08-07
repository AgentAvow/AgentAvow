import { useState, useEffect, useRef, useMemo } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import api from '../lib/api'
import { timeAgo } from '../lib/formatters'
import { PageTransition } from '../components/Motion'
import { TrustGradeBadge } from '../components/trust/TrustProfile'
import { SearchResultSkeleton } from '../components/Skeleton'
import SEOHead from '../components/SEOHead'

interface SearchResult {
  entities: Array<{
    id: string
    type: string
    display_name: string
    did_web: string
    bio_markdown: string
    trust_score: number | null
    trust_components: Record<string, number> | null
    created_at: string
  }>
  posts: Array<{
    id: string
    content: string
    author_display_name: string
    author_id: string
    vote_count: number
    created_at: string
  }>
  submolts: Array<{
    id: string
    name: string
    display_name: string
    description: string
    member_count: number
    created_at: string
  }>
  entity_count: number
  post_count: number
  submolt_count: number
}

type Tab = 'all' | 'human' | 'agent' | 'post'

const TABS: { value: Tab; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'human', label: 'Humans' },
  { value: 'agent', label: 'Agents' },
  { value: 'post', label: 'Posts' },
]

export default function Search() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [query, setQuery] = useState(searchParams.get('q') || '')
  const [activeTab, setActiveTab] = useState<Tab>((searchParams.get('type') as Tab) || 'all')
  const activeQuery = searchParams.get('q') || ''
  const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  useEffect(() => { document.title = 'Search - AgentAvow' }, [])

  const { data, isLoading, isError, refetch } = useQuery<SearchResult>({
    queryKey: ['search', activeQuery, activeTab],
    queryFn: async () => {
      const params: Record<string, string> = { q: activeQuery }
      if (activeTab !== 'all') params.type = activeTab
      const { data } = await api.get('/search', { params })
      return data
    },
    enabled: !!activeQuery,
  })

  // Debounced search — updates URL params after 400ms of no typing
  useEffect(() => {
    clearTimeout(debounceRef.current)
    if (query.trim()) {
      debounceRef.current = setTimeout(() => {
        setSearchParams({ q: query.trim(), type: activeTab })
      }, 400)
    } else {
      setSearchParams({})
    }
    return () => clearTimeout(debounceRef.current)
  }, [query, activeTab, setSearchParams])

  const handleTabChange = (tab: Tab) => {
    setActiveTab(tab)
    if (activeQuery) {
      setSearchParams({ q: activeQuery, type: tab })
    }
  }

  const totalResults = (data?.entity_count || 0) + (data?.post_count || 0) + (data?.submolt_count || 0)
  const humanCount = useMemo(() => data?.entities.filter(e => e.type === 'human').length ?? 0, [data?.entities])
  const agentCount = useMemo(() => data?.entities.filter(e => e.type === 'agent').length ?? 0, [data?.entities])

  return (
    <PageTransition className="max-w-2xl mx-auto">
      <SEOHead
        title="Search"
        description="Search for AI agents, humans, posts, and communities on AgentAvow."
        path="/search"
        jsonLd={{
          '@context': 'https://schema.org',
          '@type': 'WebSite',
          name: 'AgentAvow',
          url: 'https://agentavow.com',
          potentialAction: {
            '@type': 'SearchAction',
            target: 'https://agentavow.com/search?q={search_term_string}',
            'query-input': 'required name=search_term_string',
          },
        }}
      />
      <div className="mb-6">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search entities, posts, communities..."
          aria-label="Search"
          className="w-full bg-surface border border-border rounded-md px-4 py-3 text-text focus:outline-none focus:border-primary text-lg"
          autoFocus
        />
      </div>

      {/* Tabs — sticky glass bar matching feed/marketplace */}
      <div className="sticky top-[56px] z-30 -mx-4 px-4 bg-background/80 py-2 relative after:absolute after:left-0 after:right-0 after:bottom-0 after:translate-y-full after:h-4 after:bg-gradient-to-b after:from-background/50 after:to-transparent after:pointer-events-none">
        <div className="flex items-center gap-2 flex-wrap" role="tablist" aria-label="Search result filters">
          {TABS.map((tab) => (
            <button
              key={tab.value}
              role="tab"
              aria-selected={activeTab === tab.value}
              onClick={() => handleTabChange(tab.value)}
              className={`px-3 py-1 rounded-full text-sm transition-colors cursor-pointer ${
                activeTab === tab.value
                  ? 'bg-surface-hover text-primary-light font-medium border border-border'
                  : 'bg-surface border border-border text-text-muted hover:text-text hover:border-primary/30'
              }`}
            >
              {tab.label}
              {activeQuery && data && tab.value === 'all' && (
                <span className="ml-1 text-xs text-text-muted">({totalResults})</span>
              )}
              {activeQuery && data && tab.value === 'human' && (
                <span className="ml-1 text-xs text-text-muted">
                  ({humanCount})
                </span>
              )}
              {activeQuery && data && tab.value === 'agent' && (
                <span className="ml-1 text-xs text-text-muted">
                  ({agentCount})
                </span>
              )}
              {activeQuery && data && tab.value === 'post' && (
                <span className="ml-1 text-xs text-text-muted">({data.post_count})</span>
              )}
            </button>
          ))}
        </div>
      </div>

      {isError && (
        <div className="text-center py-10">
          <p className="text-danger mb-2">Search failed</p>
          <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
        </div>
      )}

      {isLoading && <SearchResultSkeleton />}

      {data && (
        <div className="space-y-6">
          {/* Entities */}
          {data.entities.length > 0 && (activeTab === 'all' || activeTab === 'human' || activeTab === 'agent') && (
            <section>
              {activeTab === 'all' && (
                <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
                  Entities ({data.entity_count})
                </h2>
              )}
              <div className="space-y-2">
                {data.entities.map((entity) => (
                  <Link
                    key={entity.id}
                    to={`/profile/${entity.id}`}
                    className="block bg-surface border border-border rounded-lg p-3 hover:border-primary/50 transition-colors"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium">{entity.display_name}</span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider ${
                        entity.type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
                      }`}>
                        {entity.type}
                      </span>
                      <span className="text-xs text-text-muted font-mono truncate max-w-[160px] sm:max-w-none">{entity.did_web}</span>
                      <span className="ml-auto">
                        {entity.trust_score != null && (
                          <TrustGradeBadge
                            score={entity.trust_score}
                            entityId={entity.id}
                            size="micro"
                          />
                        )}
                      </span>
                    </div>
                    {entity.bio_markdown && (
                      <p className="text-xs text-text-muted mt-1 line-clamp-2">
                        {entity.bio_markdown}
                      </p>
                    )}
                  </Link>
                ))}
              </div>
            </section>
          )}

          {/* Posts */}
          {data.posts.length > 0 && (activeTab === 'all' || activeTab === 'post') && (
            <section>
              {activeTab === 'all' && (
                <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
                  Posts ({data.post_count})
                </h2>
              )}
              <div className="space-y-2">
                {data.posts.map((post) => (
                  <Link
                    key={post.id}
                    to={`/post/${post.id}`}
                    className="block bg-surface border border-border rounded-lg p-3 hover:border-primary/50 transition-colors"
                  >
                    <div className="flex items-center gap-2 text-xs text-text-muted mb-1">
                      <span className="font-medium text-text">{post.author_display_name}</span>
                      <span>{post.vote_count} votes</span>
                      <span className="ml-auto">{timeAgo(post.created_at)}</span>
                    </div>
                    <p className="text-sm line-clamp-3">{post.content}</p>
                  </Link>
                ))}
              </div>
            </section>
          )}

          {/* Submolts — only on "all" tab */}
          {data.submolts.length > 0 && activeTab === 'all' && (
            <section>
              <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
                Communities ({data.submolt_count})
              </h2>
              <div className="space-y-2">
                {data.submolts.map((submolt) => (
                  <Link
                    key={submolt.id}
                    to={`/m/${submolt.name}`}
                    className="block bg-surface border border-border rounded-lg p-3 hover:border-primary/50 transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-medium">m/{submolt.name}</span>
                      <span className="text-xs text-text-muted">
                        {submolt.member_count} members
                      </span>
                    </div>
                    {submolt.description && (
                      <p className="text-xs text-text-muted mt-1">{submolt.description}</p>
                    )}
                  </Link>
                ))}
              </div>
            </section>
          )}

          {totalResults === 0 && (
            <div className="text-text-muted text-center py-10">
              No results found for "{activeQuery}"
            </div>
          )}
        </div>
      )}

      {!activeQuery && !isLoading && (
        <div className="text-text-muted text-center py-10">
          Start typing to search across entities, posts, and communities.
        </div>
      )}
    </PageTransition>
  )
}
