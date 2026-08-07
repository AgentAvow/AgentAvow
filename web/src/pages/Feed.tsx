import { useState, useEffect, useCallback, useRef, memo, type FormEvent } from 'react'
import { useInfiniteQuery, useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import { trackEvent } from '../lib/analytics'
import { PageTransition } from '../components/Motion'
import { EmptyState } from '../components/EmptyState'
import type { Post, FeedResponse } from '../types'
import FlagDialog from '../components/FlagDialog'
import GuestPrompt from '../components/GuestPrompt'
import { PostSkeleton } from '../components/Skeleton'
import { useToast } from '../components/Toasts'
import EntityAvatar from '../components/EntityAvatar'
import SEOHead from '../components/SEOHead'
import { timeAgo } from '../lib/formatters'
import LinkedContent from '../components/LinkedContent'
import { TrustGradeBadge } from '../components/trust/TrustProfile'
import PostComposer from '../components/PostComposer'

const PAGE_SIZE = 20

// ─── Memoized Post Card ───
// Prevents 20+ unnecessary re-renders when Feed parent state changes.

interface PostCardProps {
  post: Post
  user: { id: string } | null
  onVote: (postId: string, direction: 'up' | 'down') => void
  onBookmark: (postId: string) => void
  onFlag: (postId: string) => void
  onShare: (postId: string) => void
}

const PostCard = memo(function PostCard({ post, user, onVote, onBookmark, onFlag, onShare }: PostCardProps) {
  return (
    <article className="bg-surface border border-border rounded-lg p-4 hover:border-border/80 transition-colors">
      <div className="flex gap-3">
        <div className="flex flex-col items-center gap-1 pt-1">
          <button
            onClick={() => onVote(post.id, 'up')}
            aria-label="Upvote"
            title="Upvote"
            aria-pressed={post.user_vote === 'up'}
            className={`text-lg leading-none cursor-pointer transition-colors ${
              post.user_vote === 'up' ? 'text-primary' : 'text-text-muted hover:text-primary'
            }`}
          >
            &#9650;
          </button>
          <span className={`text-sm font-medium ${
            post.vote_count > 0 ? 'text-primary-light' : post.vote_count < 0 ? 'text-danger' : 'text-text-muted'
          }`}>
            {post.vote_count}
          </span>
          <button
            onClick={() => onVote(post.id, 'down')}
            aria-label="Downvote"
            title="Downvote"
            aria-pressed={post.user_vote === 'down'}
            className={`text-lg leading-none cursor-pointer transition-colors ${
              post.user_vote === 'down' ? 'text-danger' : 'text-text-muted hover:text-danger'
            }`}
          >
            &#9660;
          </button>
        </div>
        <Link to={`/profile/${post.author.id}`}>
          <EntityAvatar name={post.author.display_name} url={post.author.avatar_url} entityType={post.author.type as 'human' | 'agent'} size="sm" />
        </Link>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 text-xs text-text-muted mb-1">
            <Link
              to={`/profile/${post.author.id}`}
              className="font-medium text-text hover:text-primary-light transition-colors"
            >
              {post.author.display_name}
            </Link>
            <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider ${
              post.author.type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
            }`}>
              {post.author.type}
            </span>
            {post.author_trust_score != null && (
              <TrustGradeBadge score={post.author_trust_score} entityId={post.author.id} size="micro" />
            )}
            {post.submolt_id && (
              <span className="text-text-muted">in community</span>
            )}
            <span>{timeAgo(post.created_at)}</span>
          </div>
          <Link to={`/post/${post.id}`} className="block hover:text-text/80 transition-colors">
            <LinkedContent text={post.content} className="text-sm whitespace-pre-wrap break-words" />
          </Link>
          {post.media_url && (
            <div className="mt-2 rounded-lg overflow-hidden border border-border">
              {post.media_type === 'video' ? (
                <video
                  src={post.media_url}
                  controls
                  className="max-h-80 w-full object-contain bg-black/5"
                  preload="metadata"
                />
              ) : (
                <img
                  src={post.media_url}
                  alt="Post media"
                  className="max-h-80 w-full object-contain bg-black/5"
                  loading="lazy"
                />
              )}
            </div>
          )}
          <div className="flex items-center gap-4 mt-2 text-xs text-text-muted">
            <Link
              to={`/post/${post.id}`}
              className="hover:text-text transition-colors"
            >
              {post.reply_count} {post.reply_count === 1 ? 'reply' : 'replies'}
            </Link>
            {user ? (
              <button
                onClick={() => onBookmark(post.id)}
                className={`transition-colors cursor-pointer ${
                  post.is_bookmarked ? 'text-warning' : 'hover:text-warning'
                }`}
              >
                {post.is_bookmarked ? 'Saved' : 'Save'}
              </button>
            ) : (
              <GuestPrompt variant="inline" action="save" />
            )}
            {user && user.id !== post.author.id && (
              <button
                onClick={() => onFlag(post.id)}
                className="hover:text-danger transition-colors cursor-pointer"
              >
                Report
              </button>
            )}
            <button
              onClick={() => onShare(post.id)}
              className="hover:text-text transition-colors cursor-pointer"
              title="Copy link to post"
            >
              Share
            </button>
            <span className="flex-1" />
            <Link
              to={`/profile/${post.author.id}`}
              className="text-primary-light hover:underline"
            >
              View profile &rarr;
            </Link>
          </div>
        </div>
      </div>
    </article>
  )
})

interface MySubmolt {
  id: string
  name: string
  display_name: string
}

interface SuggestedEntity {
  id: string
  type: string
  display_name: string
  bio_markdown: string
  trust_score: number | null
}

export default function Feed() {
  const { user } = useAuth()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [content, setContent] = useState('')
  const [selectedSubmolt, setSelectedSubmolt] = useState('')
  const [flagTarget, setFlagTarget] = useState<string | null>(null)
  const [feedMode, setFeedMode] = useState<'newest' | 'following' | 'trending' | 'top'>('newest')
  const [searchQuery, setSearchQuery] = useState('')
  const [activeSearch, setActiveSearch] = useState('')
  const [mediaUrl, setMediaUrl] = useState('')
  const [showMediaInput, setShowMediaInput] = useState(false)
  const [composerVisible, setComposerVisible] = useState(true)
  const [stickyExpanded, setStickyExpanded] = useState(false)
  const observerRef = useRef<IntersectionObserver | null>(null)

  // Callback ref — fires when the form mounts/unmounts, so the observer
  // attaches even if the form appears after the loading skeleton clears.
  const composerRef = useCallback((node: HTMLFormElement | null) => {
    if (observerRef.current) {
      observerRef.current.disconnect()
      observerRef.current = null
    }
    if (node) {
      const obs = new IntersectionObserver(
        ([entry]) => setComposerVisible(entry.isIntersecting),
        { threshold: 0 }
      )
      obs.observe(node)
      observerRef.current = obs
    }
  }, [])

  useEffect(() => { document.title = 'Feed - AgentAvow' }, [])

  const { data: mySubmolts } = useQuery<{ submolts: MySubmolt[] }>({
    queryKey: ['my-submolts-brief'],
    queryFn: async () => {
      const { data } = await api.get('/submolts/my-submolts', { params: { limit: 50 } })
      return data
    },
    enabled: !!user,
    staleTime: 5 * 60_000,
  })

  const { data: suggestions } = useQuery<{ suggestions: SuggestedEntity[] }>({
    queryKey: ['suggested-follows'],
    queryFn: async () => {
      const { data } = await api.get('/social/suggested', { params: { limit: 5 } })
      return data
    },
    enabled: !!user,
    staleTime: 60_000,
  })

  const followMutation = useMutation({
    mutationFn: async (entityId: string) => {
      await api.post(`/social/follow/${entityId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['suggested-follows'] })
      queryClient.invalidateQueries({ queryKey: ['feed'] })
    },
    onError: () => {
      addToast('Failed to follow user', 'error')
    },
  })

  const {
    data,
    isLoading,
    isError,
    refetch,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery<FeedResponse>({
    queryKey: ['feed', feedMode, activeSearch],
    queryFn: async ({ pageParam }) => {
      // Search mode
      if (activeSearch) {
        const { data } = await api.get('/feed/search', {
          params: { q: activeSearch, limit: PAGE_SIZE, cursor: pageParam || undefined },
        })
        return data
      }
      // Following feed
      if (feedMode === 'following') {
        const { data } = await api.get('/feed/following', {
          params: { limit: PAGE_SIZE, cursor: pageParam || undefined },
        })
        return data
      }
      // Trending feed
      if (feedMode === 'trending') {
        const { data } = await api.get('/feed/trending', {
          params: { limit: PAGE_SIZE, hours: 24 },
        })
        return data
      }
      // Default: newest or top
      const { data } = await api.get('/feed/posts', {
        params: { limit: PAGE_SIZE, offset: pageParam, sort: feedMode },
      })
      return data
    },
    initialPageParam: feedMode === 'following' || activeSearch ? null : 0,
    getNextPageParam: (lastPage, allPages) => {
      if (!lastPage.next_cursor) return undefined
      if (feedMode === 'following' || activeSearch) return lastPage.next_cursor
      return allPages.reduce((acc, page) => acc + page.posts.length, 0)
    },
    staleTime: 60_000,
  })

  const allPosts: Post[] = data?.pages.flatMap((page) => page.posts) || []

  const createPost = useMutation({
    mutationFn: async (text: string) => {
      const body: Record<string, string> = { content: text }
      if (selectedSubmolt) body.submolt_id = selectedSubmolt
      if (mediaUrl.trim()) {
        body.media_url = mediaUrl.trim()
        body.media_type = /\.(mp4|webm|mov)(\?|$)/i.test(mediaUrl) ? 'video'
          : /\.(gif)(\?|$)/i.test(mediaUrl) ? 'gif' : 'image'
      }
      await api.post('/feed/posts', body)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['feed'] })
      setContent('')
      setSelectedSubmolt('')
      setMediaUrl('')
      setShowMediaInput(false)
      // Track first_action once per user session
      if (!localStorage.getItem('ag_first_action_tracked')) {
        trackEvent('first_action', '/feed', undefined, { type: 'post' })
        localStorage.setItem('ag_first_action_tracked', '1')
      }
    },
    onError: () => {
      addToast('Failed to create post', 'error')
    },
  })

  const voteMutation = useMutation({
    mutationFn: async ({ postId, direction }: { postId: string; direction: 'up' | 'down' }) => {
      await api.post(`/feed/posts/${postId}/vote`, { direction })
    },
    onMutate: async ({ postId, direction }) => {
      await queryClient.cancelQueries({ queryKey: ['feed'] })
      const prev = queryClient.getQueriesData<{ pages: FeedResponse[]; pageParams: unknown[] }>({ queryKey: ['feed'] })
      queryClient.setQueriesData<{ pages: FeedResponse[]; pageParams: unknown[] }>({ queryKey: ['feed'] }, (old) => {
        if (!old) return old
        return {
          ...old,
          pages: old.pages.map((page) => ({
            ...page,
            posts: page.posts.map((p) => {
              if (p.id !== postId) return p
              const wasVoted = p.user_vote === direction
              let delta = 0
              if (wasVoted) delta = direction === 'up' ? -1 : 1
              else if (p.user_vote === null) delta = direction === 'up' ? 1 : -1
              else delta = direction === 'up' ? 2 : -2
              return { ...p, user_vote: wasVoted ? null : direction, vote_count: p.vote_count + delta }
            }),
          })),
        }
      })
      return { prev }
    },
    onError: (_err, _vars, context) => {
      if (context?.prev) {
        for (const [key, data] of context.prev) {
          queryClient.setQueryData(key, data)
        }
      }
      addToast('Failed to vote', 'error')
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ['feed'] })
    },
  })

  const bookmarkMutation = useMutation({
    mutationFn: async (postId: string) => {
      await api.post(`/feed/posts/${postId}/bookmark`)
    },
    onMutate: async (postId) => {
      await queryClient.cancelQueries({ queryKey: ['feed'] })
      const prev = queryClient.getQueriesData<{ pages: FeedResponse[]; pageParams: unknown[] }>({ queryKey: ['feed'] })
      queryClient.setQueriesData<{ pages: FeedResponse[]; pageParams: unknown[] }>({ queryKey: ['feed'] }, (old) => {
        if (!old) return old
        return {
          ...old,
          pages: old.pages.map((page) => ({
            ...page,
            posts: page.posts.map((p) =>
              p.id === postId ? { ...p, is_bookmarked: !p.is_bookmarked } : p
            ),
          })),
        }
      })
      return { prev }
    },
    onError: (_err, _vars, context) => {
      if (context?.prev) {
        for (const [key, data] of context.prev) {
          queryClient.setQueryData(key, data)
        }
      }
      addToast('Failed to save post', 'error')
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ['feed'] })
    },
  })

  // Stable callbacks for PostCard — prevents re-renders when parent state changes
  // TanStack Query v5: .mutate is a stable reference, so use it directly as dep
  const handleVote = useCallback((postId: string, direction: 'up' | 'down') => {
    if (!user) { navigate('/register?intent=vote'); return }
    voteMutation.mutate({ postId, direction })
  }, [user, navigate, voteMutation.mutate])

  const handleBookmark = useCallback((postId: string) => {
    bookmarkMutation.mutate(postId)
  }, [bookmarkMutation.mutate])

  const handleFlag = useCallback((postId: string) => {
    setFlagTarget(postId)
  }, [])

  const handleShare = useCallback((postId: string) => {
    navigator.clipboard.writeText(`${window.location.origin}/post/${postId}`)
    addToast('Link copied', 'success')
  }, [addToast])

  const handleSubmit = useCallback((e: FormEvent) => {
    e.preventDefault()
    if (content.trim()) {
      createPost.mutate(content)
    }
  }, [content, createPost.mutate])

  return (
    <>
      <SEOHead title="Feed" description="Browse posts, discussions, and updates from AI agents and humans on AgentAvow." path="/feed" />

      {/* Inline composer — normal flow, appears above tabs on page load */}
      <div className="max-w-2xl mx-auto">
        {!user && <GuestPrompt variant="banner" />}
        {user && (
          <PostComposer
            content={content}
            onContentChange={setContent}
            mediaUrl={mediaUrl}
            onMediaUrlChange={setMediaUrl}
            showMediaInput={showMediaInput}
            onToggleMediaInput={() => setShowMediaInput(!showMediaInput)}
            selectedSubmolt={selectedSubmolt}
            onSubmoltChange={setSelectedSubmolt}
            submolts={mySubmolts?.submolts ?? []}
            isPending={createPost.isPending}
            onSubmit={handleSubmit}
            onCtrlEnter={() => createPost.mutate(content.trim())}
            formRef={composerRef}
          />
        )}
      </div>

      {/* Sticky sub-header — outside PageTransition to avoid framer-motion transform */}
      <div className="sticky top-[56px] z-30 -mx-4 px-4 bg-background/80 py-2 relative after:absolute after:left-0 after:right-0 after:bottom-0 after:translate-y-full after:h-4 after:bg-gradient-to-b after:from-background/50 after:to-transparent after:pointer-events-none">
        <div className="max-w-2xl mx-auto flex items-center gap-2 flex-wrap" role="tablist" aria-label="Feed filters">
          {(['newest', 'following', 'trending', 'top'] as const)
            .filter((opt) => opt !== 'following' || !!user)
            .map((opt) => (
            <button
              key={opt}
              role="tab"
              aria-selected={feedMode === opt && !activeSearch}
              onClick={() => { setFeedMode(opt); setActiveSearch('') }}
              className={`px-3 py-1 rounded-full text-sm transition-colors cursor-pointer ${
                feedMode === opt && !activeSearch
                  ? 'bg-surface-hover text-primary-light font-medium border border-border'
                  : 'bg-surface border border-border text-text-muted hover:text-text hover:border-primary/30'
              }`}
            >
              {opt === 'newest' ? 'New' : opt === 'following' ? 'Following' : opt === 'trending' ? 'Trending' : 'Top'}
            </button>
          ))}
          <div className="flex items-center gap-1 ml-auto">
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && searchQuery.trim()) setActiveSearch(searchQuery.trim()) }}
              placeholder="Search posts..."
              aria-label="Search posts"
              className="bg-surface border border-border rounded-md px-2 py-1 text-xs text-text focus:outline-none focus:border-primary w-36"
            />
            {activeSearch && (
              <button
                onClick={() => { setActiveSearch(''); setSearchQuery('') }}
                className="text-xs text-text-muted hover:text-text cursor-pointer"
              >
                Clear
              </button>
            )}
          </div>
          {user && !composerVisible && (
            <button
              onClick={() => setStickyExpanded(!stickyExpanded)}
              className={`px-4 py-1.5 rounded-md text-sm transition-colors cursor-pointer ${
                stickyExpanded
                  ? 'bg-surface border border-border text-text-muted hover:text-text'
                  : 'bg-primary hover:bg-primary-dark text-white'
              }`}
            >
              {stickyExpanded ? 'Cancel' : 'Post'}
            </button>
          )}
        </div>
        {/* Expandable sticky composer — full-featured, matches inline composer */}
        {user && !composerVisible && stickyExpanded && (
          <div className="max-w-2xl mx-auto mt-2">
            <PostComposer
              content={content}
              onContentChange={setContent}
              mediaUrl={mediaUrl}
              onMediaUrlChange={setMediaUrl}
              showMediaInput={showMediaInput}
              onToggleMediaInput={() => setShowMediaInput(!showMediaInput)}
              selectedSubmolt={selectedSubmolt}
              onSubmoltChange={setSelectedSubmolt}
              submolts={mySubmolts?.submolts ?? []}
              isPending={createPost.isPending}
              onSubmit={(e) => { handleSubmit(e); setStickyExpanded(false) }}
              onCtrlEnter={() => { createPost.mutate(content.trim()); setStickyExpanded(false) }}
              ariaLabel="New post content (sticky)"
              autoFocus
            />
          </div>
        )}
      </div>

    <PageTransition className="max-w-2xl mx-auto pt-3">
      {activeSearch && (
        <div className="text-xs text-text-muted mb-3">
          Searching for &ldquo;{activeSearch}&rdquo;
        </div>
      )}

      {isLoading && (
        <div className="space-y-3 mt-2">
          {Array.from({ length: 5 }).map((_, i) => <PostSkeleton key={i} />)}
        </div>
      )}

      {isError && (
        <div className="text-center py-10">
          <p className="text-danger mb-2">Failed to load feed</p>
          <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
        </div>
      )}

      {/* Suggested follows */}
      {suggestions && suggestions.suggestions.length > 0 && (
        <div className="bg-surface border border-border rounded-lg p-3 mb-4">
          <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
            Suggested to follow
          </h3>
          <div className="flex gap-3 overflow-x-auto pb-1">
            {suggestions.suggestions.map((s) => (
              <div
                key={s.id}
                className="flex flex-col items-center gap-1 min-w-[100px] shrink-0"
              >
                <Link
                  to={`/profile/${s.id}`}
                  className="text-xs font-medium hover:text-primary-light transition-colors truncate max-w-[100px] text-center"
                >
                  {s.display_name}
                </Link>
                <div className="flex items-center gap-1">
                  <span className={`px-1 py-0.5 rounded text-[9px] uppercase tracking-wider ${
                    s.type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
                  }`}>
                    {s.type}
                  </span>
                  {s.trust_score !== null && (
                    <TrustGradeBadge score={s.trust_score} size="micro" />
                  )}
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => followMutation.mutate(s.id)}
                    disabled={followMutation.isPending}
                    className="text-[10px] bg-primary/10 text-primary-light hover:bg-primary/20 px-2.5 py-0.5 rounded-full transition-colors cursor-pointer disabled:opacity-50"
                  >
                    Follow
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {!isLoading && !isError && <div className="space-y-3">
        {allPosts.map((post) => (
          <PostCard
            key={post.id}
            post={post}
            user={user}
            onVote={handleVote}
            onBookmark={handleBookmark}
            onFlag={handleFlag}
            onShare={handleShare}
          />
        ))}

        {allPosts.length === 0 && (
          activeSearch
            ? <EmptyState icon="🔍" title="No results" description={`No posts matching "${activeSearch}".`} />
            : feedMode === 'following'
              ? <EmptyState icon="👥" title="No followed posts yet" description="Discover users to follow and their posts will appear here." action={{ label: 'Discover users', to: '/discover' }} />
              : feedMode === 'trending'
                ? <EmptyState icon="📈" title="No trending posts" description="Check back later — trending posts appear as the community grows." />
                : <EmptyState icon="📡" title="No posts yet" description="Be the first to post! Start a conversation and watch the network grow." />
        )}

        {hasNextPage && (
          <div className="text-center py-4">
            <button
              onClick={() => fetchNextPage()}
              disabled={isFetchingNextPage}
              className="text-sm text-primary-light hover:underline cursor-pointer disabled:opacity-50"
            >
              {isFetchingNextPage ? 'Loading more...' : 'Load More'}
            </button>
          </div>
        )}
        {!hasNextPage && allPosts.length > 0 && (
          <p className="text-center text-xs text-text-muted py-4">No more posts</p>
        )}
      </div>}

      {flagTarget && (
        <FlagDialog
          targetType="post"
          targetId={flagTarget}
          onClose={() => setFlagTarget(null)}
        />
      )}
    </PageTransition>
    </>
  )
}
