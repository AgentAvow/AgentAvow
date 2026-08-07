import { useState, useEffect, useMemo, useRef } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient, useInfiniteQuery } from '@tanstack/react-query'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import type { Post, Profile as ProfileType } from '../types'
import { formatDate, timeAgo, formatPrice } from '../lib/formatters'
import EvolutionTimeline from '../components/EvolutionTimeline'
import Endorsements from '../components/Endorsements'
import { BadgesSection, AuditHistorySection } from '../components/VerificationBadges'
import ForkLineageTree from '../components/ForkLineageTree'
import TrustProfile from '../components/trust/TrustProfile'
import VerifiedTrustEnvelope from '../components/trust/VerifiedTrustEnvelope'
import EntityAvatar from '../components/EntityAvatar'
import { TrustBadgesFull } from '../components/TrustBadges'
import FlagDialog from '../components/FlagDialog'
import GuestPrompt from '../components/GuestPrompt'
import { ProfileSkeleton, ConnectionSkeleton } from '../components/Skeleton'
import { useToast } from '../components/Toasts'
import { useUnsavedChanges } from '../hooks/useUnsavedChanges'
// TrustExplainerTrigger available if needed — now integrated into TrustProfile
import SEOHead from '../components/SEOHead'
import { PageTransition } from '../components/Motion'
import LinkedContent from '../components/LinkedContent'
import SourceBadge from '../components/SourceBadge'
import SecurityScanCard, { ScanStatusBadge } from '../components/SecurityScanCard'
import ExternalSignals from '../components/ExternalSignals'

type ProfileTab = 'posts' | 'followers' | 'following' | 'activity' | 'reviews' | 'connections' | 'listings' | 'badges' | 'bots'

interface ActivityItem {
  type: string
  entity_id: string
  entity_name: string
  target_id: string | null
  summary: string
  created_at: string
}

const ACTIVITY_LABELS: Record<string, { label: string; color: string }> = {
  post: { label: 'Post', color: 'bg-primary/20 text-primary-light' },
  reply: { label: 'Reply', color: 'bg-accent/20 text-accent' },
  vote: { label: 'Vote', color: 'bg-surface-hover text-text-muted' },
  follow: { label: 'Follow', color: 'bg-success/20 text-success' },
  endorsement: { label: 'Endorsement', color: 'bg-warning/20 text-warning' },
  review: { label: 'Review', color: 'bg-danger/20 text-danger' },
}

interface ReviewItem {
  id: string
  target_entity_id: string
  reviewer_entity_id: string
  reviewer_display_name: string
  rating: number
  text: string | null
  created_at: string
  updated_at: string
}

interface ReviewSummary {
  average_rating: number | null
  review_count: number
  rating_distribution: Record<string, number>
}

interface FollowEntity {
  id: string
  display_name: string
  type: string
  did_web: string
}


interface ProfileListing {
  id: string
  title: string
  description: string
  category: string
  pricing_model: string
  price_cents: number
  average_rating: number | null
  review_count: number
  view_count: number
  is_featured: boolean
  created_at: string
}

// ─── Ego-graph types for Connections tab ───

interface EgoNode {
  id: string
  label: string
  type: string
  trust: number | null
}

interface EgoLink {
  source: string
  target: string
  relationship_type: string
}

const REL_LABELS: Record<string, string> = {
  follow: 'follows',
  operator_agent: 'operates',
  collaboration: 'collaborates with',
  service: 'provides service to',
}

function ConnectionList({ entityId }: { entityId: string }) {
  const { data, isLoading } = useQuery<{ nodes: EgoNode[]; links: EgoLink[] }>({
    queryKey: ['ego-graph', entityId],
    queryFn: async () => {
      const { data } = await api.get(`/graph/ego/${entityId}?depth=1`)
      return data
    },
    staleTime: 5 * 60_000,
  })

  if (isLoading) return (
    <div className="space-y-1">
      {Array.from({ length: 4 }).map((_, i) => <ConnectionSkeleton key={i} />)}
    </div>
  )
  if (!data || !data.nodes || data.nodes.length <= 1) return <div className="text-sm text-text-muted py-6 text-center">No connections yet</div>

  const connections = data.nodes.filter(n => n.id !== entityId)
  const linkMap = new Map<string, string>()
  for (const link of data.links ?? []) {
    const otherId = link.source === entityId ? link.target : link.source
    linkMap.set(otherId, link.relationship_type)
  }

  return (
    <div className="space-y-2">
      {connections.slice(0, 20).map((node) => (
        <Link
          key={node.id}
          to={`/profile/${node.id}`}
          className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-surface-hover/50 transition-colors group bg-surface border border-border"
        >
          <EntityAvatar name={node.label} entityType={node.type as 'human' | 'agent'} size="sm" />
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium truncate group-hover:text-primary-light transition-colors">
              {node.label}
            </div>
            <div className="text-[10px] text-text-muted">
              {node.type} {linkMap.get(node.id) ? `· ${REL_LABELS[linkMap.get(node.id)!] ?? linkMap.get(node.id)}` : ''}
            </div>
          </div>
          {node.trust != null && (
            <span className="text-xs text-text-muted">{Math.round(node.trust * 100)}%</span>
          )}
        </Link>
      ))}
      {connections.length > 20 && (
        <Link to="/graph" className="text-xs text-primary-light hover:underline block text-center pt-1">
          View full graph ({connections.length} connections)
        </Link>
      )}
    </div>
  )
}

// ─── Linked Account Badges ───

function LinkedAccountBadges({ entityId, isOwn }: { entityId: string; isOwn: boolean }) {
  const { data: accounts } = useQuery<{ provider: string; provider_username: string | null; verification_status: string; reputation_score: number }[]>({
    queryKey: ['linked-accounts', entityId],
    queryFn: async () => {
      const { data } = await api.get('/linked-accounts')
      return data
    },
    enabled: isOwn,
    staleTime: 60_000,
  })

  if (!accounts || accounts.length === 0) {
    if (isOwn) {
      return (
        <div className="mb-4">
          <Link to="/settings" className="text-xs text-primary-light hover:text-primary transition-colors">
            Connect GitHub to boost trust score
          </Link>
        </div>
      )
    }
    return null
  }

  return (
    <div className="mb-4 flex flex-wrap gap-2">
      {accounts.map(acct => (
        <div key={acct.provider} className="flex items-center gap-1.5 px-2 py-1 bg-background rounded border border-border">
          {acct.provider === 'github' && (
            <svg className="w-3.5 h-3.5 text-text-muted" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
            </svg>
          )}
          <span className="text-xs text-text-muted">{acct.provider_username || acct.provider}</span>
          {acct.verification_status.includes('verified') && (
            <svg className="w-3 h-3 text-success" viewBox="0 0 20 20" fill="currentColor" aria-label="verified">
              <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd"/>
            </svg>
          )}
        </div>
      ))}
    </div>
  )
}

export default function Profile() {
  const { entityId } = useParams<{ entityId: string }>()
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const { addToast } = useToast()
  const [editing, setEditing] = useState(false)
  const [bio, setBio] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [showFlag, setShowFlag] = useState(false)
  const [isBlocked, setIsBlocked] = useState(false)
  const [activeTab, setActiveTab] = useState<ProfileTab>('posts')
  const [showDid, setShowDid] = useState(false)
  const [showUnfollowConfirm, setShowUnfollowConfirm] = useState(false)
  const [showBlockConfirm, setShowBlockConfirm] = useState(false)
  const followRefetchTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [reviewRating, setReviewRating] = useState(5)
  const [reviewText, setReviewText] = useState('')
  const [showReviewForm, setShowReviewForm] = useState(false)

  useUnsavedChanges(editing)
  const [showAddService, setShowAddService] = useState(false)
  const [serviceId, setServiceId] = useState('')
  const [serviceType, setServiceType] = useState('')
  const [serviceEndpoint, setServiceEndpoint] = useState('')

  const { data: profile, isLoading, isError, refetch } = useQuery<ProfileType>({
    queryKey: ['profile', entityId],
    queryFn: async () => {
      const { data } = await api.get(`/profiles/${entityId}`)
      return data
    },
    enabled: !!entityId,
    staleTime: 5 * 60_000,
  })

  useEffect(() => {
    document.title = profile ? `${profile.display_name} - AgentAvow` : 'Profile - AgentAvow'
  }, [profile])

  // Operator profile for agents
  const { data: operatorProfile } = useQuery<{ display_name: string }>({
    queryKey: ['operator-profile', profile?.operator_id],
    queryFn: async () => {
      const { data } = await api.get(`/profiles/${profile!.operator_id}`)
      return data
    },
    enabled: !!profile?.operator_id,
    staleTime: 5 * 60_000,
  })

  // Operated bots (for human profiles)
  const { data: operatedBots } = useQuery<{ bots: { id: string; display_name: string; avatar_url: string | null; bio_markdown: string; trust_score: number | null; framework_source: string | null }[]; total: number }>({
    queryKey: ['operated-bots', entityId],
    queryFn: async () => {
      const { data } = await api.get(`/profiles/${entityId}/operated-bots`)
      return data
    },
    enabled: !!profile && profile.type === 'human',
    staleTime: 5 * 60_000,
  })

  const followMutation = useMutation({
    mutationFn: async () => {
      await api.post(`/social/follow/${entityId}`)
    },
    onMutate: async () => {
      if (followRefetchTimer.current) clearTimeout(followRefetchTimer.current)
      await queryClient.cancelQueries({ queryKey: ['profile', entityId] })
      const prev = queryClient.getQueryData(['profile', entityId])
      queryClient.setQueryData(['profile', entityId], (old: any) => old ? { ...old, is_following: true, follower_count: (old.follower_count ?? 0) + 1 } : old)
      return { prev }
    },
    onError: (_err, _vars, ctx) => {
      if (ctx?.prev) queryClient.setQueryData(['profile', entityId], ctx.prev)
      addToast('Failed to follow', 'error')
    },
    onSuccess: () => {
      followRefetchTimer.current = setTimeout(() => {
        followRefetchTimer.current = null
        queryClient.invalidateQueries({ queryKey: ['profile', entityId] })
      }, 500)
    },
  })

  // Check if we've blocked this user
  const { data: blockedData } = useQuery<{ blocked: Array<{ entity_id: string }> }>({
    queryKey: ['blocked-check', entityId],
    queryFn: async () => {
      const { data } = await api.get('/social/blocked', { params: { limit: 200 } })
      return data
    },
    enabled: !!user && !!entityId && user.id !== entityId,
    staleTime: 5 * 60_000,
  })

  useEffect(() => {
    if (blockedData) {
      setIsBlocked(blockedData.blocked.some((b) => b.entity_id === entityId))
    }
  }, [blockedData, entityId])

  const unfollowMutation = useMutation({
    mutationFn: async () => {
      await api.delete(`/social/follow/${entityId}`)
    },
    onMutate: async () => {
      if (followRefetchTimer.current) {
        clearTimeout(followRefetchTimer.current)
        followRefetchTimer.current = null
      }
      await queryClient.cancelQueries({ queryKey: ['profile', entityId] })
      const prev = queryClient.getQueryData(['profile', entityId])
      queryClient.setQueryData(['profile', entityId], (old: any) => old ? { ...old, is_following: false, follower_count: Math.max((old.follower_count ?? 1) - 1, 0) } : old)
      return { prev }
    },
    onError: (_err, _vars, ctx) => {
      if (ctx?.prev) queryClient.setQueryData(['profile', entityId], ctx.prev)
      addToast('Failed to unfollow', 'error')
    },
    onSuccess: () => {
      followRefetchTimer.current = setTimeout(() => {
        followRefetchTimer.current = null
        queryClient.invalidateQueries({ queryKey: ['profile', entityId] })
      }, 500)
    },
  })

  const blockMutation = useMutation({
    mutationFn: async () => {
      await api.post(`/social/block/${entityId}`)
    },
    onSuccess: () => {
      setIsBlocked(true)
      queryClient.invalidateQueries({ queryKey: ['profile', entityId] })
      queryClient.invalidateQueries({ queryKey: ['blocked-check', entityId] })
    },
    onError: () => {
      addToast('Failed to block user', 'error')
    },
  })

  const unblockMutation = useMutation({
    mutationFn: async () => {
      await api.delete(`/social/block/${entityId}`)
    },
    onSuccess: () => {
      setIsBlocked(false)
      queryClient.invalidateQueries({ queryKey: ['profile', entityId] })
      queryClient.invalidateQueries({ queryKey: ['blocked-check', entityId] })
    },
    onError: () => {
      addToast('Failed to unblock user', 'error')
    },
  })

  const [showClaimDialog, setShowClaimDialog] = useState(false)
  const [claimReason, setClaimReason] = useState('')
  const [showRemovalDialog, setShowRemovalDialog] = useState(false)
  const [removalReason, setRemovalReason] = useState('')

  const claimMutation = useMutation({
    mutationFn: async () => {
      await api.post(`/bots/${entityId}/claim`, { reason: claimReason })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['profile', entityId] })
      setShowClaimDialog(false)
      setClaimReason('')
      addToast('Profile claimed successfully! You are now the operator.', 'success')
    },
    onError: (err: any) => {
      addToast(err?.response?.data?.detail || 'Failed to claim profile', 'error')
    },
  })

  const removalMutation = useMutation({
    mutationFn: async () => {
      await api.post(`/profiles/${entityId}/request-removal`, { reason: removalReason })
    },
    onSuccess: () => {
      setShowRemovalDialog(false)
      setRemovalReason('')
      addToast('Removal request submitted. We\'ll review it within 48 hours.', 'success')
    },
    onError: (err: any) => {
      addToast(err?.response?.data?.detail || 'Failed to submit removal request', 'error')
    },
  })

  const updateProfile = useMutation({
    mutationFn: async () => {
      await api.patch(`/profiles/${entityId}`, {
        bio_markdown: bio,
        display_name: displayName,
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['profile', entityId] })
      setEditing(false)
      addToast('Profile updated', 'success')
    },
    onError: () => {
      addToast('Failed to update profile', 'error')
    },
  })

  const startEditing = () => {
    if (profile) {
      setBio(profile.bio_markdown || '')
      setDisplayName(profile.display_name || '')
      setEditing(true)
    }
  }

  const { data: postsData, fetchNextPage: fetchMorePosts, hasNextPage: hasMorePosts, isFetchingNextPage: loadingMorePosts } = useInfiniteQuery<{ posts: Post[]; has_more: boolean; next_cursor: string | null }>({
    queryKey: ['profile-posts', entityId],
    queryFn: async ({ pageParam }) => {
      const params: Record<string, string> = { limit: '20', author_id: entityId!, sort: 'newest', include_replies: 'true' }
      if (pageParam) params.cursor = pageParam as string
      const { data } = await api.get('/feed/posts', { params })
      return data
    },
    initialPageParam: null as string | null,
    getNextPageParam: (lastPage) => {
      if (!lastPage.has_more) return undefined
      return lastPage.next_cursor
    },
    enabled: !!entityId && activeTab === 'posts',
    staleTime: 5 * 60_000,
  })

  const { data: followersData, fetchNextPage: fetchMoreFollowers, hasNextPage: hasMoreFollowers, isFetchingNextPage: loadingMoreFollowers } = useInfiniteQuery<{ entities: FollowEntity[]; count: number; total: number }>({
    queryKey: ['profile-followers', entityId],
    queryFn: async ({ pageParam }) => {
      const { data } = await api.get(`/social/followers/${entityId}`, { params: { limit: 50, offset: pageParam } })
      return data
    },
    initialPageParam: 0,
    getNextPageParam: (_lastPage, allPages) => {
      const loaded = allPages.reduce((acc, p) => acc + p.entities.length, 0)
      const total = allPages[0]?.total || 0
      if (loaded >= total) return undefined
      return loaded
    },
    enabled: !!entityId && activeTab === 'followers',
    staleTime: 5 * 60_000,
  })

  const { data: followingDataPages, fetchNextPage: fetchMoreFollowing, hasNextPage: hasMoreFollowing, isFetchingNextPage: loadingMoreFollowing } = useInfiniteQuery<{ entities: FollowEntity[]; count: number; total: number }>({
    queryKey: ['profile-following', entityId],
    queryFn: async ({ pageParam }) => {
      const { data } = await api.get(`/social/following/${entityId}`, { params: { limit: 50, offset: pageParam } })
      return data
    },
    initialPageParam: 0,
    getNextPageParam: (_lastPage, allPages) => {
      const loaded = allPages.reduce((acc, p) => acc + p.entities.length, 0)
      const total = allPages[0]?.total || 0
      if (loaded >= total) return undefined
      return loaded
    },
    enabled: !!entityId && activeTab === 'following',
    staleTime: 5 * 60_000,
  })

  const { data: listingsData } = useQuery<{ listings: ProfileListing[]; total: number }>({
    queryKey: ['profile-listings', entityId],
    queryFn: async () => {
      const { data } = await api.get(`/marketplace/entity/${entityId}`)
      if (Array.isArray(data)) return { listings: data, total: data.length }
      return { listings: data.listings || [], total: data.total || 0 }
    },
    enabled: !!entityId && activeTab === 'listings',
    staleTime: 5 * 60_000,
  })

  const [activityFilter, setActivityFilter] = useState<string>('all')

  const { data: activityData, fetchNextPage: fetchMoreActivity, hasNextPage: hasMoreActivity, isFetchingNextPage: loadingMoreActivity } = useInfiniteQuery<{ activities: ActivityItem[]; count: number; next_cursor: string | null }>({
    queryKey: ['profile-activity', entityId],
    queryFn: async ({ pageParam }) => {
      const params: Record<string, string> = { limit: '30' }
      if (pageParam) params.before = pageParam as string
      const { data } = await api.get(`/activity/${entityId}`, { params })
      return data
    },
    initialPageParam: null as string | null,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
    enabled: !!entityId && activeTab === 'activity',
    staleTime: 5 * 60_000,
  })

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: didDoc } = useQuery<Record<string, any>>({
    queryKey: ['did-doc', entityId],
    queryFn: async () => {
      const { data } = await api.get(`/did/entity/${entityId}`)
      return data
    },
    enabled: !!entityId && showDid,
    staleTime: 5 * 60_000,
  })

  const { data: reviewsData } = useQuery<{ reviews: ReviewItem[]; total: number; average_rating: number | null }>({
    queryKey: ['entity-reviews', entityId],
    queryFn: async () => {
      const { data } = await api.get(`/entities/${entityId}/reviews`, { params: { limit: 20 } })
      return data
    },
    enabled: !!entityId && activeTab === 'reviews',
    staleTime: 5 * 60_000,
  })

  const { data: reviewSummary } = useQuery<ReviewSummary>({
    queryKey: ['entity-review-summary', entityId],
    queryFn: async () => {
      const { data } = await api.get(`/entities/${entityId}/reviews/summary`)
      return data
    },
    enabled: !!entityId && activeTab === 'reviews',
    staleTime: 5 * 60_000,
  })

  const createReviewMutation = useMutation({
    mutationFn: async () => {
      await api.post(`/entities/${entityId}/reviews`, {
        rating: reviewRating,
        text: reviewText || null,
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['entity-reviews', entityId] })
      queryClient.invalidateQueries({ queryKey: ['entity-review-summary', entityId] })
      setShowReviewForm(false)
      setReviewText('')
      setReviewRating(5)
      addToast('Review submitted', 'success')
    },
    onError: () => {
      addToast('Failed to submit review', 'error')
    },
  })

  const deleteReviewMutation = useMutation({
    mutationFn: async () => {
      await api.delete(`/entities/${entityId}/reviews`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['entity-reviews', entityId] })
      queryClient.invalidateQueries({ queryKey: ['entity-review-summary', entityId] })
    },
    onError: () => {
      addToast('Failed to delete review', 'error')
    },
  })

  const addServiceMutation = useMutation({
    mutationFn: async (service: { id: string; type: string; serviceEndpoint: string }) => {
      // Get existing services from current DID doc, append new one
      const existing = didDoc?.service?.filter(
        (s: { id: string }) => !s.id.endsWith('#agentgraph')
      ) || []
      await api.patch(`/did/entity/${entityId}`, {
        service: [...existing, service],
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['did-doc', entityId] })
      setShowAddService(false)
      setServiceId('')
      setServiceType('')
      setServiceEndpoint('')
    },
    onError: () => {
      addToast('Failed to add service endpoint', 'error')
    },
  })

  const allActivities = activityData?.pages.flatMap((p) => p.activities) || []
  const filteredActivities = useMemo(() =>
    activityFilter === 'all' ? allActivities : allActivities.filter((a) => a.type === activityFilter),
    [allActivities, activityFilter]
  )

  const allPosts = postsData?.pages.flatMap((p) => p.posts) || []

  if (isLoading) {
    return (
      <div className="max-w-2xl mx-auto">
        <ProfileSkeleton />
      </div>
    )
  }

  if (isError) {
    return (
      <div className="text-center py-10">
        <p className="text-danger mb-2">Failed to load profile</p>
        <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
      </div>
    )
  }

  if (!profile) {
    return <div className="text-danger text-center mt-10">Profile not found</div>
  }

  const isOwn = user?.id === entityId
  const isOperator = !isOwn && profile.type === 'agent' && profile.operator_id === user?.id
  const isAdmin = user?.is_admin === true

  return (
    <PageTransition className="max-w-2xl mx-auto">
      <SEOHead title={profile.display_name} description={profile.bio_markdown?.slice(0, 160) || `${profile.display_name} on AgentAvow`} path={`/profile/${entityId}`} type="profile" />
      <div className="bg-surface border border-border rounded-lg p-6">
        <div className="flex flex-col sm:flex-row items-start justify-between gap-3 mb-4">
          <div className="flex items-start gap-4">
            <div className="relative group shrink-0 w-16 h-16">
              <EntityAvatar
                name={profile.display_name}
                url={profile.avatar_url}
                entityType={profile.type as 'human' | 'agent'}
                size="lg"
              />
              {editing && (
                <Link
                  to="/avatar"
                  className="absolute inset-0 flex items-center justify-center bg-black/50 rounded-full opacity-0 pointer-events-none group-hover:opacity-100 group-hover:pointer-events-auto transition-opacity"
                  title="Change avatar"
                >
                  <svg className="w-6 h-6 text-white drop-shadow" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                  </svg>
                </Link>
              )}
            </div>
            <div>
            {editing ? (
              <input
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                aria-label="Display name"
                className="text-2xl font-bold bg-background border border-border rounded px-2 py-1 text-text focus:outline-none focus:border-primary"
              />
            ) : (
              <h1 className="text-2xl font-bold">{profile.display_name}</h1>
            )}
            <div className="flex items-center gap-2 mt-1 flex-wrap">
              <span className={`px-2 py-0.5 rounded text-xs uppercase tracking-wider ${
                profile.type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
              }`}>
                {profile.type}
              </span>
              <TrustBadgesFull badges={profile.badges} />
              {profile.type === 'agent' && entityId && <ScanStatusBadge entityId={entityId} />}
              <button
                onClick={() => setShowDid(!showDid)}
                className="text-xs text-text-muted font-mono hover:text-primary-light transition-colors cursor-pointer"
              >
                {profile.did_web}
              </button>
            </div>
{profile.type === 'agent' && profile.onboarding_data?.import_source && (
  <div className="mt-1">
    <SourceBadge
      sourceUrl={profile.onboarding_data.import_source.url}
      sourceType={profile.onboarding_data.import_source.type}
      communitySignals={profile.onboarding_data.import_source.community_signals}
      verified={!!profile.source_verified_at}
    />
  </div>
)}
          </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {(isOwn || isOperator) ? (
              editing ? (
                <>
                  <button
                    onClick={() => updateProfile.mutate()}
                    disabled={updateProfile.isPending}
                    className="bg-primary hover:bg-primary-dark text-white px-3 py-1.5 rounded-md text-sm transition-colors cursor-pointer disabled:opacity-50"
                  >
                    {updateProfile.isPending ? 'Saving...' : 'Save'}
                  </button>
                  <button
                    onClick={() => setEditing(false)}
                    className="bg-surface-hover text-text px-3 py-1.5 rounded-md text-sm border border-border cursor-pointer"
                  >
                    Cancel
                  </button>
                </>
              ) : (
                <>
                  <button
                    onClick={startEditing}
                    className="bg-surface-hover text-text px-3 py-1.5 rounded-md text-sm border border-border hover:border-primary transition-colors cursor-pointer"
                  >
                    Edit Profile
                  </button>
                  {profile.type === 'agent' && (
                    <Link
                      to={`/badges?agent=${entityId}`}
                      className="bg-surface-hover text-text px-3 py-1.5 rounded-md text-sm border border-border hover:border-primary transition-colors inline-flex items-center gap-1.5"
                    >
                      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                      Get Badge
                    </Link>
                  )}
                </>
              )
            ) : user ? (
              <>
                <button
                  onClick={() => profile.is_following ? setShowUnfollowConfirm(true) : followMutation.mutate()}
                  disabled={followMutation.isPending || unfollowMutation.isPending}
                  className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors cursor-pointer disabled:opacity-50 ${
                    profile.is_following
                      ? 'bg-surface-hover text-primary border border-primary/30 hover:bg-surface hover:border-primary/50'
                      : 'bg-primary hover:bg-primary-dark text-white hover:shadow-sm'
                  }`}
                >
                  {profile.is_following ? 'Following' : 'Follow'}
                </button>
                <button
                  onClick={() => navigate(`/messages?to=${entityId}`)}
                  className="px-3 py-1.5 rounded-md text-sm text-text-muted border border-border hover:border-primary hover:text-primary-light transition-colors cursor-pointer"
                >
                  Message
                </button>
                <button
                  onClick={() => isBlocked ? unblockMutation.mutate() : setShowBlockConfirm(true)}
                  disabled={blockMutation.isPending || unblockMutation.isPending}
                  className="px-2 py-1.5 rounded-md text-xs text-text-muted/60 hover:text-danger transition-colors cursor-pointer disabled:opacity-50"
                  title={isBlocked ? 'Unblock' : 'Block'}
                >
                  {isBlocked ? 'Unblock' : 'Block'}
                </button>
                <button
                  onClick={() => setShowFlag(true)}
                  className="px-2 py-1.5 rounded-md text-xs text-text-muted/60 hover:text-danger transition-colors cursor-pointer"
                  title="Report user"
                >
                  Report
                </button>
              </>
            ) : (
              <GuestPrompt variant="inline" action="follow" />
            )}
            <button
              onClick={() => {
                navigator.clipboard.writeText(window.location.origin + `/profile/${entityId}`)
                addToast('Profile link copied', 'success')
              }}
              className="px-2 py-1.5 rounded-md text-xs text-text-muted/60 hover:text-primary-light transition-colors cursor-pointer"
              title="Copy profile link"
            >
              Share
            </button>
          </div>
        </div>

        {/* Trust Profile — unified 3-dimension display with letter grades */}
        {profile.trust_score !== null && (
          <div className="mb-4">
            <TrustProfile
              components={profile.trust_components}
              overallScore={profile.trust_score}
              entityId={entityId}
              hasSecurityScan={profile.type === 'agent'}
            />
          </div>
        )}

        {/* Trust Score v2 — signed, verifiable methodology breakdown (design §6.1) */}
        {profile.did_web && <VerifiedTrustEnvelope did={profile.did_web} />}

        {/* Legacy OverallTrustHero + TrustTierBadge dual-axis display replaced by TrustProfile above */}

        {/* External Signals — linked accounts with live metrics */}
        {entityId && <ExternalSignals entityId={entityId} isOwn={isOwn} />}

        {/* Linked Account Badges */}
        {entityId && <LinkedAccountBadges entityId={entityId} isOwn={isOwn} />}

        {/* Autonomy Level — agents only */}
        {profile.type === 'agent' && profile.autonomy_level !== null && (
          <div className="mb-4">
            <div className="flex items-center gap-2">
              <span className="text-xs text-text-muted uppercase tracking-wider">Autonomy</span>
              <div className="flex gap-0.5">
                {[1, 2, 3, 4, 5].map((level) => (
                  <div
                    key={level}
                    className={`w-6 h-2 rounded-sm ${
                      level <= (profile.autonomy_level ?? 0)
                        ? level <= 2 ? 'bg-success' : level <= 4 ? 'bg-warning' : 'bg-danger'
                        : 'bg-background'
                    }`}
                  />
                ))}
              </div>
              <span className="text-xs text-text-muted">Level {profile.autonomy_level}/5</span>
            </div>
          </div>
        )}

        {/* Security Scan — full detail for operator/admin, compact for public */}
        {profile.type === 'agent' && entityId && (
          <div className="mb-4">
            <SecurityScanCard
              entityId={entityId}
              canManage={isOwn || isOperator || isAdmin}
              compact={!(isOwn || isOperator || isAdmin)}
            />
          </div>
        )}

        {/* Average Rating */}
        {profile.average_rating !== null && profile.review_count > 0 && (
          <div className="mb-4 flex items-center gap-2">
            <div className="flex">
              {[1, 2, 3, 4, 5].map((star) => (
                <span
                  key={star}
                  className={`text-sm ${star <= Math.round(profile.average_rating ?? 0) ? 'text-warning' : 'text-text-muted/30'}`}
                >
                  &#9733;
                </span>
              ))}
            </div>
            <span className="text-sm text-text-muted">
              {profile.average_rating?.toFixed(1)} ({profile.review_count} review{profile.review_count !== 1 ? 's' : ''})
            </span>
          </div>
        )}

        {/* Capabilities — agents only */}
        {profile.type === 'agent' && profile.capabilities && profile.capabilities.length > 0 && (
          <div className="mb-4">
            <div className="flex flex-wrap gap-1.5">
              {profile.capabilities.map((cap) => (
                <span
                  key={cap}
                  className="px-2 py-0.5 bg-accent/10 text-accent text-xs rounded-full"
                >
                  {cap}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Operated by — agents only */}
        {profile.type === 'agent' && profile.operator_id && (
          <div className="mb-4 flex items-center gap-2">
            <span className="text-xs text-text-muted">Operated by</span>
            <Link to={`/profile/${profile.operator_id}`} className="text-sm text-primary-light hover:underline">
              {operatorProfile?.display_name || 'Loading...'}
            </Link>
          </div>
        )}

        {/* Verified Owner badge — shown when claim was approved */}
        {profile.type === 'agent' && profile.onboarding_data?.ownership_claim?.status === 'approved' && profile.operator_id === user?.id && (
          <div className="mb-4 flex items-center gap-2">
            <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-success/20 text-success text-xs rounded-full font-medium">
              <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd"/></svg>
              Verified Owner
            </span>
          </div>
        )}

        {/* Imported profile banner — shown for provisional unclaimed bots */}
        {profile.type === 'agent' && profile.is_provisional && !profile.operator_id && (
          <div className="mb-4 bg-primary/5 border border-primary/20 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <svg className="w-5 h-5 text-primary-light mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-text mb-2">
                  This profile was imported{profile.source_type ? ` from ${profile.source_type}` : ''}. If you operate this bot, you can claim and verify this profile.
                </p>
                <div className="flex flex-wrap items-center gap-3">
                  {user && user.id !== entityId && (
                    <button
                      onClick={() => setShowClaimDialog(true)}
                      className="inline-flex items-center gap-2 px-3 py-1.5 bg-primary text-white rounded-md text-sm font-medium hover:bg-primary-dark transition-colors cursor-pointer"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                      Claim this profile
                    </button>
                  )}
                  <button
                    onClick={() => setShowRemovalDialog(true)}
                    className="text-sm text-text-muted hover:text-danger transition-colors cursor-pointer underline underline-offset-2"
                  >
                    Not your bot? Request removal
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Bio */}
        <div className="mb-4">
          {editing ? (
            <div>
              <textarea
                value={bio}
                onChange={(e) => setBio(e.target.value)}
                rows={4}
                maxLength={5000}
                placeholder="Write something about yourself..."
                aria-label="Bio"
                className="w-full bg-background border border-border rounded-md px-3 py-2 text-text focus:outline-none focus:border-primary resize-none"
              />
              <span className="text-[10px] text-text-muted">{bio.length}/5000</span>
            </div>
          ) : (
            <LinkedContent text={profile.bio_markdown || 'No bio yet.'} className="text-sm whitespace-pre-wrap" />
          )}
        </div>

        {/* Stats removed — counts shown in tab labels below */}
      </div>

      {/* DID Document */}
      {showDid && (
        <div className="bg-surface border border-border rounded-lg p-4 mt-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">
              DID Document
            </h3>
            <button
              onClick={() => setShowDid(false)}
              className="text-xs text-text-muted hover:text-text cursor-pointer"
            >
              Close
            </button>
          </div>
          {didDoc ? (
            <>
              <pre className="text-xs text-text-muted bg-background rounded-md p-3 overflow-x-auto max-h-60 overflow-y-auto whitespace-pre-wrap">
                {JSON.stringify(didDoc, null, 2)}
              </pre>
              {isOwn && (
                <div className="mt-3">
                  {showAddService ? (
                    <div className="space-y-2 bg-background rounded-md p-3">
                      <p className="text-xs font-medium">Add Service Endpoint</p>
                      <input
                        value={serviceId}
                        onChange={(e) => setServiceId(e.target.value)}
                        placeholder="Service ID (e.g. mcp-server)"
                        className="w-full bg-surface border border-border rounded-md px-2 py-1.5 text-xs text-text focus:outline-none focus:border-primary"
                      />
                      <input
                        value={serviceType}
                        onChange={(e) => setServiceType(e.target.value)}
                        placeholder="Type (e.g. MCPServer, AgentAPI)"
                        className="w-full bg-surface border border-border rounded-md px-2 py-1.5 text-xs text-text focus:outline-none focus:border-primary"
                      />
                      <input
                        value={serviceEndpoint}
                        onChange={(e) => setServiceEndpoint(e.target.value)}
                        placeholder="https://your-service-url.com"
                        className="w-full bg-surface border border-border rounded-md px-2 py-1.5 text-xs text-text focus:outline-none focus:border-primary"
                      />
                      <div className="flex gap-2">
                        <button
                          onClick={() => addServiceMutation.mutate({
                            id: `${profile.did_web}#${serviceId}`,
                            type: serviceType,
                            serviceEndpoint,
                          })}
                          disabled={!serviceId || !serviceType || !serviceEndpoint.startsWith('https://') || addServiceMutation.isPending}
                          className="bg-primary hover:bg-primary-dark text-white px-3 py-1 rounded-md text-xs transition-colors disabled:opacity-50 cursor-pointer"
                        >
                          {addServiceMutation.isPending ? 'Adding...' : 'Add'}
                        </button>
                        <button
                          onClick={() => setShowAddService(false)}
                          className="text-xs text-text-muted hover:text-text cursor-pointer"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  ) : (
                    <button
                      onClick={() => setShowAddService(true)}
                      className="text-xs text-primary-light hover:underline cursor-pointer"
                    >
                      + Add Service Endpoint
                    </button>
                  )}
                </div>
              )}
            </>
          ) : (
            <p className="text-xs text-text-muted">Loading DID document...</p>
          )}
        </div>
      )}

      {/* Capabilities & Endorsements — above tabs */}
      {entityId && (
        <Endorsements entityId={entityId} isAgent={profile.type === 'agent'} />
      )}

      {/* Tabs */}
      <div className="flex border-b border-border mt-4 overflow-x-auto" role="tablist" aria-label="Profile sections">
        {(profile.type === 'agent'
          ? ['posts', 'followers', 'following', 'activity', 'reviews', 'connections', 'listings', 'badges'] as ProfileTab[]
          : [
              ...(['posts', 'followers', 'following', 'activity', 'reviews', 'listings', 'badges'] as ProfileTab[]),
              ...((operatedBots?.total ?? 0) > 0 ? ['bots' as ProfileTab] : []),
            ]
        ).map((tab) => (
          <button
            key={tab}
            role="tab"
            aria-selected={activeTab === tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2.5 text-sm font-medium transition-colors cursor-pointer whitespace-nowrap ${
              activeTab === tab
                ? 'border-b-2 border-primary text-text'
                : 'text-text-muted hover:text-text'
            }`}
          >
            {tab === 'posts' && `Posts (${profile.post_count})`}
            {tab === 'followers' && `Followers (${profile.follower_count})`}
            {tab === 'following' && `Following (${profile.following_count})`}
            {tab === 'reviews' && 'Reviews'}
            {tab === 'connections' && 'Connections'}
            {tab === 'listings' && 'Listings'}
            {tab === 'activity' && 'Activity'}
            {tab === 'badges' && 'Badges'}
            {tab === 'bots' && `Bots (${operatedBots?.total ?? 0})`}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'posts' && (
        <div className="mt-3 space-y-3">
          {allPosts.map((post) => (
            <Link
              key={post.id}
              to={`/post/${post.id}`}
              className="block bg-surface border border-border rounded-lg p-4 hover:border-primary/30 transition-colors"
            >
              <p className="text-sm whitespace-pre-wrap break-words line-clamp-4">{post.content}</p>
              <div className="flex items-center gap-4 mt-2 text-xs text-text-muted">
                <span>{post.vote_count} votes</span>
                <span>{post.reply_count} replies</span>
                {post.submolt_id && <span>in community</span>}
                <span>{timeAgo(post.created_at)}</span>
              </div>
            </Link>
          ))}
          {allPosts.length === 0 && (
            <p className="text-center text-text-muted text-sm py-6">No posts yet</p>
          )}
          {hasMorePosts && (
            <div className="text-center py-2">
              <button
                onClick={() => fetchMorePosts()}
                disabled={loadingMorePosts}
                className="text-sm text-primary-light hover:underline cursor-pointer disabled:opacity-50"
              >
                {loadingMorePosts ? 'Loading...' : 'Load more'}
              </button>
            </div>
          )}
        </div>
      )}

      {activeTab === 'followers' && (
        <div className="mt-3 space-y-2">
          {followersData?.pages.flatMap((p) => p.entities).map((f) => (
            <Link
              key={f.id}
              to={`/profile/${f.id}`}
              className="flex items-center justify-between bg-surface border border-border rounded-lg px-4 py-3 hover:border-primary/30 transition-colors"
            >
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">{f.display_name}</span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider ${
                  f.type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
                }`}>
                  {f.type}
                </span>
              </div>
              <span className="text-xs text-text-muted font-mono truncate max-w-[200px]">
                {f.did_web}
              </span>
            </Link>
          ))}
          {followersData && followersData.pages[0]?.entities.length === 0 && (
            <p className="text-center text-text-muted text-sm py-6">No followers yet</p>
          )}
          {hasMoreFollowers && (
            <div className="text-center py-2">
              <button
                onClick={() => fetchMoreFollowers()}
                disabled={loadingMoreFollowers}
                className="text-sm text-primary-light hover:underline cursor-pointer disabled:opacity-50"
              >
                {loadingMoreFollowers ? 'Loading...' : 'Load more'}
              </button>
            </div>
          )}
        </div>
      )}

      {activeTab === 'following' && (
        <div className="mt-3 space-y-2">
          {followingDataPages?.pages.flatMap((p) => p.entities).map((f) => (
            <Link
              key={f.id}
              to={`/profile/${f.id}`}
              className="flex items-center justify-between bg-surface border border-border rounded-lg px-4 py-3 hover:border-primary/30 transition-colors"
            >
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">{f.display_name}</span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider ${
                  f.type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
                }`}>
                  {f.type}
                </span>
              </div>
              <span className="text-xs text-text-muted font-mono truncate max-w-[200px]">
                {f.did_web}
              </span>
            </Link>
          ))}
          {followingDataPages && followingDataPages.pages[0]?.entities.length === 0 && (
            <p className="text-center text-text-muted text-sm py-6">Not following anyone yet</p>
          )}
          {hasMoreFollowing && (
            <div className="text-center py-2">
              <button
                onClick={() => fetchMoreFollowing()}
                disabled={loadingMoreFollowing}
                className="text-sm text-primary-light hover:underline cursor-pointer disabled:opacity-50"
              >
                {loadingMoreFollowing ? 'Loading...' : 'Load more'}
              </button>
            </div>
          )}
        </div>
      )}

      {activeTab === 'reviews' && (
        <div className="mt-3">
          {/* Review Summary */}
          {reviewSummary && reviewSummary.review_count > 0 && (
            <div className="bg-surface border border-border rounded-lg p-4 mb-4">
              <div className="flex items-center gap-4">
                <div className="text-center">
                  <div className="text-3xl font-bold text-primary-light">
                    {reviewSummary.average_rating?.toFixed(1) ?? '—'}
                  </div>
                  <div className="text-xs text-text-muted">{reviewSummary.review_count} review{reviewSummary.review_count !== 1 ? 's' : ''}</div>
                </div>
                <div className="flex-1 space-y-1">
                  {[5, 4, 3, 2, 1].map((star) => {
                    const count = reviewSummary.rating_distribution[String(star)] || 0
                    const pct = reviewSummary.review_count > 0 ? (count / reviewSummary.review_count) * 100 : 0
                    return (
                      <div key={star} className="flex items-center gap-2">
                        <span className="text-xs text-text-muted w-3">{star}</span>
                        <div className="flex-1 bg-background rounded-full h-2">
                          <div
                            className="bg-warning h-2 rounded-full transition-all"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <span className="text-xs text-text-muted w-6 text-right">{count}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          )}

          {/* Write Review */}
          {user && user.id !== entityId && (
            <div className="mb-4">
              {showReviewForm ? (
                <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
                  <div>
                    <label className="block text-sm text-text-muted mb-1">Rating</label>
                    <div className="flex gap-1">
                      {[1, 2, 3, 4, 5].map((star) => (
                        <button
                          key={star}
                          type="button"
                          onClick={() => setReviewRating(star)}
                          className={`text-2xl cursor-pointer transition-colors ${
                            star <= reviewRating ? 'text-warning' : 'text-text-muted/30'
                          }`}
                        >
                          &#9733;
                        </button>
                      ))}
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm text-text-muted mb-1">Review (optional)</label>
                    <textarea
                      value={reviewText}
                      onChange={(e) => setReviewText(e.target.value)}
                      maxLength={5000}
                      rows={3}
                      placeholder="Share your experience..."
                      className="w-full bg-background border border-border rounded-md px-3 py-2 text-text text-sm focus:outline-none focus:border-primary resize-none"
                    />
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => createReviewMutation.mutate()}
                      disabled={createReviewMutation.isPending}
                      className="bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
                    >
                      {createReviewMutation.isPending ? 'Submitting...' : 'Submit Review'}
                    </button>
                    <button
                      onClick={() => { setShowReviewForm(false); setReviewRating(5); setReviewText('') }}
                      className="text-sm text-text-muted hover:text-text cursor-pointer"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  onClick={() => setShowReviewForm(true)}
                  className="text-sm text-primary-light hover:underline cursor-pointer"
                >
                  Write a review
                </button>
              )}
            </div>
          )}

          {/* Reviews List */}
          <div className="space-y-2">
            {reviewsData?.reviews.map((review) => (
              <div key={review.id} className="bg-surface border border-border rounded-lg p-4">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <Link
                      to={`/profile/${review.reviewer_entity_id}`}
                      className="text-sm font-medium hover:text-primary-light transition-colors"
                    >
                      {review.reviewer_display_name}
                    </Link>
                    <div className="flex">
                      {[1, 2, 3, 4, 5].map((star) => (
                        <span
                          key={star}
                          className={`text-sm ${star <= review.rating ? 'text-warning' : 'text-text-muted/30'}`}
                        >
                          &#9733;
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-text-muted">{timeAgo(review.created_at)}</span>
                    {user?.id === review.reviewer_entity_id && (
                      <button
                        onClick={() => deleteReviewMutation.mutate()}
                        disabled={deleteReviewMutation.isPending}
                        className="text-xs text-danger hover:underline cursor-pointer disabled:opacity-50"
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </div>
                {review.text && (
                  <p className="text-sm text-text-muted whitespace-pre-wrap">{review.text}</p>
                )}
              </div>
            ))}
            {reviewsData && reviewsData.reviews.length === 0 && (
              <p className="text-center text-text-muted text-sm py-6">No reviews yet</p>
            )}
          </div>
        </div>
      )}

      {activeTab === 'listings' && (
        <div className="mt-3 grid grid-cols-1 gap-3">
          {listingsData?.listings.map((listing) => (
            <Link
              key={listing.id}
              to={`/marketplace/${listing.id}`}
              className="bg-surface border border-border rounded-lg p-4 hover:border-primary/30 transition-colors block"
            >
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-1.5 min-w-0">
                  {listing.is_featured && (
                    <span className="text-warning text-xs shrink-0" title="Featured">&#9733;</span>
                  )}
                  <h3 className="font-medium line-clamp-1">{listing.title}</h3>
                </div>
                <span className="text-sm font-medium text-primary-light whitespace-nowrap ml-2">
                  {formatPrice(listing.price_cents, listing.pricing_model)}
                </span>
              </div>
              <p className="text-xs text-text-muted line-clamp-2 mb-2">{listing.description}</p>
              <div className="flex items-center justify-between text-xs text-text-muted">
                <div className="flex items-center gap-2">
                  <span className="px-1.5 py-0.5 rounded bg-surface-hover capitalize">{listing.category}</span>
                  {listing.average_rating !== null && (
                    <span className="flex items-center gap-0.5">
                      <span className="text-warning text-[10px]">
                        {'★'.repeat(Math.round(listing.average_rating))}{'☆'.repeat(5 - Math.round(listing.average_rating))}
                      </span>
                      <span>({listing.review_count})</span>
                    </span>
                  )}
                </div>
                <span>{listing.view_count} views</span>
              </div>
            </Link>
          ))}
          {listingsData && listingsData.listings.length === 0 && (
            <p className="text-center text-text-muted text-sm py-6">No marketplace listings</p>
          )}
        </div>
      )}

      {activeTab === 'activity' && (
        <div className="mt-3">
          <div className="flex gap-1.5 mb-3 flex-wrap">
            {['all', 'post', 'reply', 'vote', 'follow', 'endorsement', 'review'].map((f) => (
              <button
                key={f}
                onClick={() => setActivityFilter(f)}
                className={`px-2 py-0.5 text-xs rounded-full border transition-colors capitalize cursor-pointer ${
                  activityFilter === f
                    ? 'border-primary text-primary bg-primary/10'
                    : 'border-border text-text-muted hover:border-primary hover:text-primary'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
          <div className="space-y-2">
            {filteredActivities.map((act, i) => {
              const info = ACTIVITY_LABELS[act.type] || { label: act.type, color: 'bg-surface-hover text-text-muted' }
              return (
                <div key={`${act.type}-${act.target_id}-${i}`} className="bg-surface border border-border rounded-lg px-4 py-3 flex items-start gap-3">
                  <span className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider mt-0.5 ${info.color}`}>
                    {info.label}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm truncate">{act.summary}</p>
                    <span className="text-[10px] text-text-muted">{timeAgo(act.created_at)}</span>
                  </div>
                  {act.target_id && (act.type === 'post' || act.type === 'reply' || act.type === 'vote') && (
                    <Link
                      to={`/post/${act.target_id}`}
                      className="text-[10px] text-text-muted hover:text-primary-light transition-colors shrink-0"
                    >
                      View
                    </Link>
                  )}
                  {act.target_id && (act.type === 'follow' || act.type === 'endorsement' || act.type === 'review') && (
                    <Link
                      to={`/profile/${act.target_id}`}
                      className="text-[10px] text-text-muted hover:text-primary-light transition-colors shrink-0"
                    >
                      View
                    </Link>
                  )}
                </div>
              )
            })}
            {filteredActivities.length === 0 && (
              <p className="text-center text-text-muted text-sm py-6">No activity yet</p>
            )}
          </div>
          {hasMoreActivity && (
            <div className="text-center py-2 mt-2">
              <button
                onClick={() => fetchMoreActivity()}
                disabled={loadingMoreActivity}
                className="text-sm text-primary-light hover:underline cursor-pointer disabled:opacity-50"
              >
                {loadingMoreActivity ? 'Loading...' : 'Load more'}
              </button>
            </div>
          )}
        </div>
      )}

      {activeTab === "badges" && entityId && (
        <div className="mt-3 space-y-3">
          {/* Security Scan — agents only */}
          {profile.type === 'agent' && (
            <SecurityScanCard
              entityId={entityId}
              canManage={isOwn || isOperator || isAdmin}
            />
          )}

          {/* Embed badge — for operators of this agent */}
          {(isOwn || isOperator) && profile.type === 'agent' && (
            <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
              <h3 className="text-sm font-semibold text-text-muted uppercase tracking-wider">Embed Trust Badge</h3>
              <p className="text-xs text-text-muted">Add this to your GitHub README or documentation:</p>
              <div className="bg-background border border-border rounded p-3 inline-block">
                <img
                  src={`/api/v1/badges/trust/${entityId}.svg?style=detailed`}
                  alt="AgentAvow Trust Score"
                  className="h-7"
                />
              </div>
              <div className="space-y-2">
                <label className="block text-xs text-text-muted uppercase tracking-wider">Markdown + HTML (recommended)</label>
                <div className="relative">
                  <pre className="bg-background border border-border rounded px-3 py-2 text-xs font-mono break-all whitespace-pre-wrap select-all">
{`<a href="https://agentavow.com/profile/${entityId}">
  <img src="https://agentavow.com/api/v1/badges/trust/${entityId}.svg?style=detailed&scale=1.5" alt="AgentAvow Trust Score" />
</a>

<sub>Verified on <a href="https://agentavow.com">AgentAvow</a> — trust infrastructure for AI agents. <a href="https://agentavow.com/profile/${entityId}">View profile</a></sub>`}
                  </pre>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(
                        `<a href="https://agentavow.com/profile/${entityId}">\n  <img src="https://agentavow.com/api/v1/badges/trust/${entityId}.svg?style=detailed&scale=1.5" alt="AgentAvow Trust Score" />\n</a>\n\n<sub>Verified on <a href="https://agentavow.com">AgentAvow</a> — trust infrastructure for AI agents. <a href="https://agentavow.com/profile/${entityId}">View profile</a></sub>`
                      )
                    }}
                    className="absolute top-2 right-2 px-2 py-1 rounded text-xs font-medium bg-primary text-white hover:bg-primary/90 transition-colors"
                  >
                    Copy
                  </button>
                </div>
              </div>
              <p className="text-xs text-text-muted">
                Want more styles?{' '}
                <Link to={`/badges?agent=${entityId}`} className="text-primary hover:underline">
                  Open Badge Studio
                </Link>
              </p>
            </div>
          )}

          <h3 className="text-sm font-semibold text-text-muted uppercase tracking-wider">Verification Badges</h3>
          <BadgesSection entityId={entityId} />
          <h3 className="mt-4 text-sm font-semibold text-text-muted uppercase tracking-wider">Audit History</h3>
          <AuditHistorySection entityId={entityId} />
        </div>
      )}

      {activeTab === 'connections' && entityId && (
        <div className="mt-3">
          <ConnectionList entityId={entityId} />
        </div>
      )}

      {activeTab === 'bots' && operatedBots && (
        <div className="mt-3 space-y-3">
          {operatedBots.bots.length === 0 ? (
            <p className="text-sm text-text-muted py-4 text-center">No operated bots.</p>
          ) : (
            operatedBots.bots.map((bot) => (
              <Link
                key={bot.id}
                to={`/profile/${bot.id}`}
                className="flex items-center gap-3 p-3 bg-surface border border-border rounded-lg hover:border-primary/30 transition-colors"
              >
                <EntityAvatar name={bot.display_name} url={bot.avatar_url} entityType="agent" size="md" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium truncate">{bot.display_name}</span>
                    <span className="px-1.5 py-0.5 rounded text-[9px] uppercase tracking-wider bg-blue-400/20 text-blue-400">agent</span>
                    {bot.trust_score !== null && (
                      <span className="text-[10px] text-text-muted">Trust: {Math.round(bot.trust_score)}</span>
                    )}
                  </div>
                  {bot.bio_markdown && (
                    <p className="text-xs text-text-muted line-clamp-1 mt-0.5">{bot.bio_markdown}</p>
                  )}
                  {bot.framework_source && (
                    <span className="text-[10px] text-text-muted">{bot.framework_source}</span>
                  )}
                </div>
              </Link>
            ))
          )}
        </div>
      )}

      {profile.type === 'agent' && entityId && (
        <>
          <EvolutionTimeline entityId={entityId} />
          <div className="mt-2">
            <Link
              to={`/evolution/${entityId}`}
              className="text-xs text-primary-light hover:underline"
            >
              View full evolution timeline &amp; diff
            </Link>
          </div>
          <ForkLineageTree entityId={entityId} />
        </>
      )}

      <div className="mt-4 text-xs text-text-muted">
        Joined {formatDate(profile.created_at)}
      </div>

      {showFlag && entityId && (
        <FlagDialog
          targetType="entity"
          targetId={entityId}
          onClose={() => setShowFlag(false)}
        />
      )}

      {showUnfollowConfirm && profile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setShowUnfollowConfirm(false)}>
          <div className="bg-surface border border-border rounded-lg p-6 max-w-sm mx-4 shadow-xl" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-base font-semibold text-text mb-2">Unfollow {profile.display_name}?</h3>
            <p className="text-sm text-text-muted mb-5">Their posts will no longer appear in your feed.</p>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setShowUnfollowConfirm(false)}
                className="px-4 py-2 text-sm rounded-md border border-border text-text-muted hover:text-text transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  unfollowMutation.mutate()
                  setShowUnfollowConfirm(false)
                }}
                className="px-4 py-2 text-sm rounded-md bg-danger text-white hover:bg-danger/80 transition-colors cursor-pointer"
              >
                Unfollow
              </button>
            </div>
          </div>
        </div>
      )}
      {showBlockConfirm && profile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setShowBlockConfirm(false)}>
          <div className="bg-surface border border-border rounded-lg p-6 max-w-sm mx-4 shadow-xl" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-base font-semibold text-text mb-2">Block {profile.display_name}?</h3>
            <p className="text-sm text-text-muted mb-5">They won&apos;t be able to follow you, message you, or see your posts.</p>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setShowBlockConfirm(false)}
                className="px-4 py-2 text-sm rounded-md border border-border text-text-muted hover:text-text transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  blockMutation.mutate()
                  setShowBlockConfirm(false)
                }}
                className="px-4 py-2 text-sm rounded-md bg-danger text-white hover:bg-danger/80 transition-colors cursor-pointer"
              >
                Block
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Claim Bot dialog */}
      {showClaimDialog && profile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setShowClaimDialog(false)}>
          <div className="bg-surface border border-border rounded-lg p-6 max-w-md mx-4 shadow-xl" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-base font-semibold text-text mb-2">Claim {profile.display_name}</h3>
            <p className="text-sm text-text-muted mb-4">
              Claim ownership of this imported profile. You will immediately become the operator of this bot.
            </p>
            <textarea
              value={claimReason}
              onChange={(e) => setClaimReason(e.target.value)}
              rows={3}
              maxLength={1000}
              placeholder="Why do you believe you operate this bot? (optional)"
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm text-text focus:outline-none focus:border-primary resize-none mb-4"
            />
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => { setShowClaimDialog(false); setClaimReason('') }}
                className="px-4 py-2 text-sm rounded-md border border-border text-text-muted hover:text-text transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={() => claimMutation.mutate()}
                disabled={claimMutation.isPending}
                className="px-4 py-2 text-sm rounded-md bg-primary text-white hover:bg-primary-dark transition-colors cursor-pointer disabled:opacity-50"
              >
                {claimMutation.isPending ? 'Claiming...' : 'Claim Profile'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Request Removal dialog */}
      {showRemovalDialog && profile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setShowRemovalDialog(false)}>
          <div className="bg-surface border border-border rounded-lg p-6 max-w-md mx-4 shadow-xl" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-base font-semibold text-text mb-2">Request Removal</h3>
            <p className="text-sm text-text-muted mb-4">
              Request removal of this imported profile. Our team will review your request within 48 hours.
            </p>
            <textarea
              value={removalReason}
              onChange={(e) => setRemovalReason(e.target.value)}
              rows={3}
              maxLength={2000}
              placeholder="Why should this profile be removed? (optional)"
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm text-text focus:outline-none focus:border-primary resize-none mb-4"
            />
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => { setShowRemovalDialog(false); setRemovalReason('') }}
                className="px-4 py-2 text-sm rounded-md border border-border text-text-muted hover:text-text transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={() => removalMutation.mutate()}
                disabled={removalMutation.isPending}
                className="px-4 py-2 text-sm rounded-md bg-danger text-white hover:bg-danger/80 transition-colors cursor-pointer disabled:opacity-50"
              >
                {removalMutation.isPending ? 'Submitting...' : 'Submit Request'}
              </button>
            </div>
          </div>
        </div>
      )}
    </PageTransition>
  )
}
