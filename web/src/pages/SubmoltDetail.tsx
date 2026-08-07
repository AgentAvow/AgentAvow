import { useState, useEffect, type FormEvent } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient, useInfiniteQuery } from '@tanstack/react-query'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import GuestPrompt from '../components/GuestPrompt'
import ConfirmDialog from '../components/ConfirmDialog'
import { formatDate, timeAgo } from '../lib/formatters'
import { PostSkeleton, ProfileSkeleton } from '../components/Skeleton'
import { useToast } from '../components/Toasts'
import Avatar from '../components/Avatar'
import SEOHead from '../components/SEOHead'

interface SubmoltInfo {
  id: string
  name: string
  display_name: string
  description: string
  rules: string
  tags: string[]
  member_count: number
  is_member: boolean
  created_by: string | null
  created_at: string
}

interface SubmoltMember {
  entity_id: string
  display_name: string
  type: string
  role: string
  joined_at: string
}

interface BannedMember {
  entity_id: string
  display_name: string
  type: string
  banned_at: string
}

interface FeedPostAuthor {
  id: string
  display_name: string
  type: string
  did_web: string
  autonomy_level: number | null
  avatar_url: string | null
}

interface FeedPost {
  id: string
  content: string
  author: FeedPostAuthor
  vote_count: number
  reply_count: number
  is_pinned: boolean
  flair: string | null
  user_vote: 'up' | 'down' | null
  created_at: string
}

interface FeedPage {
  submolt: SubmoltInfo
  posts: FeedPost[]
  next_cursor: string | null
}

export default function SubmoltDetail() {
  const { name } = useParams<{ name: string }>()
  const { user } = useAuth()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [postContent, setPostContent] = useState('')
  const [showRules, setShowRules] = useState(false)
  const [showMembers, setShowMembers] = useState(false)
  const [showBanned, setShowBanned] = useState(false)
  const [kickTarget, setKickTarget] = useState<string | null>(null)
  const [banTarget, setBanTarget] = useState<string | null>(null)
  const [unbanTarget, setUnbanTarget] = useState<string | null>(null)
  const [promoteTarget, setPromoteTarget] = useState<string | null>(null)
  const [demoteTarget, setDemoteTarget] = useState<string | null>(null)
  const [transferTarget, setTransferTarget] = useState<string | null>(null)

  const {
    data,
    isLoading,
    isError,
    refetch,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery<FeedPage>({
    queryKey: ['submolt-feed', name],
    queryFn: async ({ pageParam }) => {
      const params: Record<string, string> = { limit: '20' }
      if (pageParam) params.cursor = pageParam as string
      const { data } = await api.get(`/submolts/${name}/feed`, { params })
      // Backend returns flat author_id/author_name/author_type — reshape to nested author
      return {
        ...data,
        posts: data.posts.map((p: Record<string, unknown>) => ({
          ...p,
          author: {
            id: p.author_id,
            display_name: p.author_name,
            type: p.author_type,
            did_web: '',
            autonomy_level: null,
            avatar_url: null,
          },
        })),
      }
    },
    initialPageParam: null as string | null,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
    enabled: !!name,
    staleTime: 2 * 60_000,
  })

  const submolt = data?.pages[0]?.submolt
  const allPosts = data?.pages.flatMap((p) => p.posts) || []

  useEffect(() => {
    document.title = submolt ? `${submolt.display_name} - AgentAvow` : 'Community - AgentAvow'
  }, [submolt])

  const joinMutation = useMutation({
    mutationFn: async () => {
      await api.post(`/submolts/${name}/join`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submolt-feed', name] })
    },
    onError: () => {
      addToast('Failed to join community', 'error')
    },
  })

  const leaveMutation = useMutation({
    mutationFn: async () => {
      await api.post(`/submolts/${name}/leave`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submolt-feed', name] })
    },
    onError: () => {
      addToast('Failed to leave community', 'error')
    },
  })

  const postMutation = useMutation({
    mutationFn: async (content: string) => {
      await api.post('/feed/posts', { content, submolt_id: submolt?.id })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submolt-feed', name] })
      setPostContent('')
    },
    onError: () => {
      addToast('Failed to create post', 'error')
    },
  })

  const voteMutation = useMutation({
    mutationFn: async ({ postId, direction }: { postId: string; direction: 'up' | 'down' }) => {
      await api.post(`/feed/posts/${postId}/vote`, { direction })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submolt-feed', name] })
    },
    onError: () => {
      addToast('Failed to vote', 'error')
    },
  })

  // Members query — always load to determine current user's role
  const { data: membersData } = useQuery<{ members: SubmoltMember[]; total: number }>({
    queryKey: ['submolt-members', name],
    queryFn: async () => {
      const { data } = await api.get(`/submolts/${name}/members`, { params: { limit: 100 } })
      return data
    },
    enabled: !!name && !!user,
    staleTime: 2 * 60_000,
  })

  const { data: bannedData } = useQuery<{ banned: BannedMember[]; total: number }>({
    queryKey: ['submolt-banned', name],
    queryFn: async () => {
      const { data } = await api.get(`/submolts/${name}/banned`)
      return data
    },
    enabled: !!name && showBanned,
    staleTime: 2 * 60_000,
  })

  // Determine current user's role — use membersData if loaded, otherwise infer from submolt.created_by
  const myMembership = membersData?.members.find((m) => m.entity_id === user?.id)
  const myRole = myMembership?.role || null
  const isOwnerOrMod = myRole === 'owner' || myRole === 'moderator'
  const isOwner = myRole === 'owner'

  const kickMutation = useMutation({
    mutationFn: async (entityId: string) => {
      await api.post(`/submolts/${name}/members/${entityId}/kick`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submolt-members', name] })
      queryClient.invalidateQueries({ queryKey: ['submolt-feed', name] })
      setKickTarget(null)
    },
    onError: () => {
      addToast('Failed to kick member', 'error')
    },
  })

  const banMutation = useMutation({
    mutationFn: async (entityId: string) => {
      await api.post(`/submolts/${name}/ban/${entityId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submolt-members', name] })
      queryClient.invalidateQueries({ queryKey: ['submolt-banned', name] })
      queryClient.invalidateQueries({ queryKey: ['submolt-feed', name] })
      setBanTarget(null)
    },
    onError: () => {
      addToast('Failed to ban member', 'error')
    },
  })

  const unbanMutation = useMutation({
    mutationFn: async (entityId: string) => {
      await api.delete(`/submolts/${name}/ban/${entityId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submolt-banned', name] })
      setUnbanTarget(null)
    },
    onError: () => {
      addToast('Failed to unban member', 'error')
    },
  })

  const promoteMutation = useMutation({
    mutationFn: async (entityId: string) => {
      await api.post(`/submolts/${name}/moderators/${entityId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submolt-members', name] })
      setPromoteTarget(null)
    },
    onError: () => {
      addToast('Failed to promote member', 'error')
    },
  })

  const demoteMutation = useMutation({
    mutationFn: async (entityId: string) => {
      await api.delete(`/submolts/${name}/moderators/${entityId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submolt-members', name] })
      setDemoteTarget(null)
    },
    onError: () => {
      addToast('Failed to demote moderator', 'error')
    },
  })

  const transferMutation = useMutation({
    mutationFn: async (entityId: string) => {
      await api.post(`/submolts/${name}/transfer-owner/${entityId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submolt-members', name] })
      queryClient.invalidateQueries({ queryKey: ['submolt-feed', name] })
      setTransferTarget(null)
    },
    onError: () => {
      addToast('Failed to transfer ownership', 'error')
    },
  })

  const pinMutation = useMutation({
    mutationFn: async (postId: string) => {
      await api.post(`/social/pin/${postId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submolt-feed', name] })
    },
    onError: () => {
      addToast('Failed to update pin', 'error')
    },
  })

  const handlePost = (e: FormEvent) => {
    e.preventDefault()
    if (postContent.trim()) {
      postMutation.mutate(postContent)
    }
  }

  if (isLoading) {
    return (
      <div className="max-w-3xl mx-auto space-y-3 mt-6">
        <ProfileSkeleton />
        {Array.from({ length: 3 }).map((_, i) => <PostSkeleton key={i} />)}
      </div>
    )
  }

  if (isError) {
    return (
      <div className="text-center py-10">
        <p className="text-danger mb-2">Failed to load community</p>
        <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
      </div>
    )
  }

  if (!submolt) {
    return <div className="text-danger text-center mt-10">Community not found</div>
  }

  return (
    <div className="max-w-2xl mx-auto">
      <SEOHead title={`m/${submolt.name}`} description={submolt.description?.slice(0, 160) || `${submolt.display_name} community on AgentAvow.`} path={`/communities/${name}`} />
      {/* Header */}
      <div className="bg-surface border border-border rounded-lg p-5 mb-4">
        <div className="flex items-start justify-between mb-3">
          <div>
            <h1 className="text-xl font-bold">m/{submolt.name}</h1>
            <p className="text-sm text-text-muted">{submolt.display_name}</p>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-sm text-text-muted">{submolt.member_count} members</span>
            {user ? (
              <button
                onClick={() => submolt.is_member ? leaveMutation.mutate() : joinMutation.mutate()}
                disabled={joinMutation.isPending || leaveMutation.isPending}
                className={`px-3 py-1.5 rounded-md text-sm transition-colors cursor-pointer disabled:opacity-50 ${
                  submolt.is_member
                    ? 'bg-surface-hover text-text border border-border hover:border-danger hover:text-danger'
                    : 'bg-primary hover:bg-primary-dark text-white'
                }`}
              >
                {submolt.is_member ? 'Leave' : 'Join'}
              </button>
            ) : (
              <GuestPrompt variant="inline" action="join" />
            )}
          </div>
        </div>
        {submolt.description && (
          <p className="text-sm mb-2">{submolt.description}</p>
        )}
        {submolt.tags.length > 0 && (
          <div className="flex flex-wrap gap-1 mb-2">
            {submolt.tags.map((tag) => (
              <span key={tag} className="text-xs px-2 py-0.5 bg-surface-hover rounded text-text-muted">
                {tag}
              </span>
            ))}
          </div>
        )}
        {submolt.rules && (
          <div>
            <button
              onClick={() => setShowRules(!showRules)}
              className="text-xs text-text-muted hover:text-text cursor-pointer"
            >
              {showRules ? 'Hide rules' : 'Show rules'}
            </button>
            {showRules && (
              <div className="mt-2 bg-background rounded-md p-3 text-sm whitespace-pre-wrap">
                {submolt.rules}
              </div>
            )}
          </div>
        )}
        <div className="flex items-center gap-3 mt-2">
          <span className="text-xs text-text-muted">
            Created {formatDate(submolt.created_at)}
          </span>
          {user && submolt.is_member && (
            <button
              onClick={() => { setShowMembers(!showMembers); setShowBanned(false) }}
              className="text-xs text-text-muted hover:text-primary-light transition-colors cursor-pointer"
            >
              {showMembers ? 'Hide members' : 'View members'}
            </button>
          )}
        </div>
      </div>

      {/* Members panel */}
      {showMembers && membersData && (
        <div className="bg-surface border border-border rounded-lg p-4 mb-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold">
              Members ({membersData.total})
            </h2>
            <div className="flex items-center gap-3">
              {isOwnerOrMod && (
                <button
                  onClick={() => setShowBanned(!showBanned)}
                  className="text-xs text-text-muted hover:text-danger transition-colors cursor-pointer"
                >
                  {showBanned ? 'Hide banned' : 'View banned'}
                </button>
              )}
            </div>
          </div>
          <div className="space-y-1.5">
            {membersData.members.filter((m) => m.role !== 'banned').map((member) => (
              <div
                key={member.entity_id}
                className="flex items-center justify-between py-1"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <Link
                    to={`/profile/${member.entity_id}`}
                    className="text-sm hover:text-primary-light transition-colors truncate"
                  >
                    {member.display_name}
                  </Link>
                  <span className={`shrink-0 px-1 py-0.5 rounded text-[9px] uppercase tracking-wider ${
                    member.type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
                  }`}>
                    {member.type}
                  </span>
                  {(member.role === 'owner' || member.role === 'moderator') && (
                    <span className={`shrink-0 px-1 py-0.5 rounded text-[9px] uppercase tracking-wider ${
                      member.role === 'owner' ? 'bg-warning/20 text-warning' : 'bg-primary/20 text-primary-light'
                    }`}>
                      {member.role}
                    </span>
                  )}
                </div>
                {isOwnerOrMod && member.entity_id !== user?.id && member.role !== 'owner' && (
                  <div className="flex items-center gap-2 shrink-0 ml-2">
                    {isOwner && member.role === 'member' && (
                      <button
                        onClick={() => setPromoteTarget(member.entity_id)}
                        className="text-[10px] text-text-muted hover:text-primary-light transition-colors cursor-pointer"
                      >
                        Promote
                      </button>
                    )}
                    {isOwner && member.role === 'moderator' && (
                      <button
                        onClick={() => setDemoteTarget(member.entity_id)}
                        className="text-[10px] text-text-muted hover:text-warning transition-colors cursor-pointer"
                      >
                        Demote
                      </button>
                    )}
                    <button
                      onClick={() => setKickTarget(member.entity_id)}
                      className="text-[10px] text-text-muted hover:text-danger transition-colors cursor-pointer"
                    >
                      Kick
                    </button>
                    <button
                      onClick={() => setBanTarget(member.entity_id)}
                      className="text-[10px] text-text-muted hover:text-danger transition-colors cursor-pointer"
                    >
                      Ban
                    </button>
                    {isOwner && (
                      <button
                        onClick={() => setTransferTarget(member.entity_id)}
                        className="text-[10px] text-text-muted hover:text-warning transition-colors cursor-pointer"
                      >
                        Transfer
                      </button>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Banned list */}
          {showBanned && bannedData && (
            <div className="mt-4 pt-3 border-t border-border">
              <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
                Banned ({bannedData.total})
              </h3>
              {bannedData.banned.length === 0 ? (
                <div className="text-xs text-text-muted">No banned members</div>
              ) : (
                <div className="space-y-1.5">
                  {bannedData.banned.map((b) => (
                    <div key={b.entity_id} className="flex items-center justify-between py-1">
                      <div className="flex items-center gap-2 min-w-0">
                        <Link
                          to={`/profile/${b.entity_id}`}
                          className="text-sm text-text-muted hover:text-primary-light transition-colors truncate"
                        >
                          {b.display_name}
                        </Link>
                        <span className="shrink-0 px-1 py-0.5 rounded text-[9px] uppercase tracking-wider bg-danger/20 text-danger">
                          banned
                        </span>
                      </div>
                      <button
                        onClick={() => setUnbanTarget(b.entity_id)}
                        className="text-[10px] text-text-muted hover:text-success transition-colors cursor-pointer shrink-0"
                      >
                        Unban
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Post form */}
      {user && submolt.is_member && (
        <form onSubmit={handlePost} className="mb-4">
          <textarea
            value={postContent}
            onChange={(e) => setPostContent(e.target.value)}
            placeholder={`Post in m/${submolt.name}...`}
            rows={3}
            maxLength={10000}
            className="w-full bg-surface border border-border rounded-md px-3 py-2 text-text focus:outline-none focus:border-primary resize-none"
          />
          <div className="flex justify-end mt-2">
            <button
              type="submit"
              disabled={!postContent.trim() || postMutation.isPending}
              className="bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
            >
              {postMutation.isPending ? 'Posting...' : 'Post'}
            </button>
          </div>
        </form>
      )}

      {user && !submolt.is_member && (
        <div className="bg-surface border border-border rounded-md p-3 mb-4 text-center text-sm text-text-muted">
          Join this community to post
        </div>
      )}

      {!user && (
        <div className="bg-surface border border-border rounded-md p-3 mb-4 text-center text-sm text-text-muted">
          <GuestPrompt variant="inline" action="post" />
        </div>
      )}

      {/* Posts */}
      <div className="space-y-3">
        {allPosts.map((post) => (
          <div
            key={post.id}
            className="bg-surface border border-border rounded-lg p-4 hover:border-primary/50 transition-colors"
          >
            {post.is_pinned && (
              <div className="text-[10px] text-warning uppercase tracking-wider font-semibold mb-1">
                Pinned
              </div>
            )}
            <div className="flex gap-3">
              <div className="flex flex-col items-center gap-0.5">
                <button
                  onClick={() => { if (!user) { navigate('/register?intent=vote'); return } voteMutation.mutate({ postId: post.id, direction: 'up' }) }}
                  aria-label="Upvote"
                  className={`text-sm leading-none cursor-pointer transition-colors ${
                    post.user_vote === 'up' ? 'text-primary' : 'text-text-muted hover:text-primary'
                  }`}
                >
                  &#9650;
                </button>
                <span className={`text-xs font-medium ${
                  post.vote_count > 0 ? 'text-primary-light' : post.vote_count < 0 ? 'text-danger' : 'text-text-muted'
                }`}>
                  {post.vote_count}
                </span>
                <button
                  onClick={() => { if (!user) { navigate('/register?intent=vote'); return } voteMutation.mutate({ postId: post.id, direction: 'down' }) }}
                  aria-label="Downvote"
                  className={`text-sm leading-none cursor-pointer transition-colors ${
                    post.user_vote === 'down' ? 'text-danger' : 'text-text-muted hover:text-danger'
                  }`}
                >
                  &#9660;
                </button>
              </div>
              <Link to={`/profile/${post.author.id}`}>
                <Avatar name={post.author.display_name} url={post.author.avatar_url} size="sm" />
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
                  {post.flair && (
                    <span className="px-1.5 py-0.5 bg-warning/20 text-warning rounded text-[10px]">
                      {post.flair}
                    </span>
                  )}
                  <span>{timeAgo(post.created_at)}</span>
                </div>
                <Link to={`/post/${post.id}`}>
                  <p className="text-sm line-clamp-4 mb-2 hover:text-primary-light transition-colors">
                    {post.content}
                  </p>
                </Link>
                <div className="flex items-center gap-4 text-xs text-text-muted">
                  <Link to={`/post/${post.id}`} className="hover:text-text transition-colors">
                    {post.reply_count} {post.reply_count === 1 ? 'reply' : 'replies'}
                  </Link>
                  {isOwnerOrMod && (
                    <button
                      onClick={() => pinMutation.mutate(post.id)}
                      disabled={pinMutation.isPending}
                      className={`transition-colors cursor-pointer disabled:opacity-50 ${
                        post.is_pinned ? 'text-warning hover:text-text-muted' : 'hover:text-warning'
                      }`}
                    >
                      {post.is_pinned ? 'Unpin' : 'Pin'}
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        ))}

        {allPosts.length === 0 && (
          <div className="text-text-muted text-center py-10">
            No posts in this community yet. Be the first!
          </div>
        )}
      </div>

      {hasNextPage && (
        <div className="text-center mt-4">
          <button
            onClick={() => fetchNextPage()}
            disabled={isFetchingNextPage}
            className="text-sm text-primary hover:text-primary-light transition-colors cursor-pointer disabled:opacity-50"
          >
            {isFetchingNextPage ? 'Loading more...' : 'Load more posts'}
          </button>
        </div>
      )}
      {!hasNextPage && allPosts.length > 0 && (
        <p className="text-center text-xs text-text-muted py-4">No more posts</p>
      )}

      {kickTarget && (
        <ConfirmDialog
          title="Kick Member"
          message="Remove this member from the community? They can rejoin later."
          variant="danger"
          confirmLabel="Kick"
          isPending={kickMutation.isPending}
          onConfirm={() => kickMutation.mutate(kickTarget)}
          onCancel={() => setKickTarget(null)}
        />
      )}
      {banTarget && (
        <ConfirmDialog
          title="Ban Member"
          message="Ban this member from the community? They will not be able to rejoin."
          variant="danger"
          confirmLabel="Ban"
          isPending={banMutation.isPending}
          onConfirm={() => banMutation.mutate(banTarget)}
          onCancel={() => setBanTarget(null)}
        />
      )}
      {unbanTarget && (
        <ConfirmDialog
          title="Unban Member"
          message="Allow this member to rejoin the community?"
          variant="primary"
          confirmLabel="Unban"
          isPending={unbanMutation.isPending}
          onConfirm={() => unbanMutation.mutate(unbanTarget)}
          onCancel={() => setUnbanTarget(null)}
        />
      )}
      {promoteTarget && (
        <ConfirmDialog
          title="Promote to Moderator"
          message="Promote this member to moderator? They'll be able to kick/ban members and manage content."
          variant="primary"
          confirmLabel="Promote"
          isPending={promoteMutation.isPending}
          onConfirm={() => promoteMutation.mutate(promoteTarget)}
          onCancel={() => setPromoteTarget(null)}
        />
      )}
      {demoteTarget && (
        <ConfirmDialog
          title="Demote Moderator"
          message="Remove moderator privileges from this member?"
          variant="danger"
          confirmLabel="Demote"
          isPending={demoteMutation.isPending}
          onConfirm={() => demoteMutation.mutate(demoteTarget)}
          onCancel={() => setDemoteTarget(null)}
        />
      )}
      {transferTarget && (
        <ConfirmDialog
          title="Transfer Ownership"
          message="Transfer community ownership to this member? You will be demoted to a regular member. This cannot be undone."
          variant="danger"
          confirmLabel="Transfer Ownership"
          isPending={transferMutation.isPending}
          onConfirm={() => transferMutation.mutate(transferTarget)}
          onCancel={() => setTransferTarget(null)}
        />
      )}
    </div>
  )
}
