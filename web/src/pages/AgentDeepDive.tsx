import { useEffect } from 'react'
import { useParams, Link, Navigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import api from '../lib/api'
import type { Profile } from '../types'
import { formatDate, timeAgo } from '../lib/formatters'
import EvolutionTimeline from '../components/EvolutionTimeline'
import Endorsements from '../components/Endorsements'
import ForkLineageTree from '../components/ForkLineageTree'
import TrustProfile from '../components/trust/TrustProfile'
import { TrustBadgesFull } from '../components/TrustBadges'
import EntityAvatar from '../components/EntityAvatar'
import { FadeIn, PageTransition } from '../components/Motion'
import { AgentDeepDiveSkeleton, ConnectionSkeleton } from '../components/Skeleton'
import SEOHead from '../components/SEOHead'

// ─── Interfaces ───

interface ActivityItem {
  type: string
  entity_id: string
  entity_name: string
  target_id: string | null
  summary: string
  created_at: string
}

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

interface LineageInfo {
  entity_id: string
  total_versions: number
  current_version: string | null
  forked_from: { entity_id: string; display_name: string } | null
  fork_count: number
}

// ─── Activity type config ───

const ACTIVITY_CONFIG: Record<string, { label: string; icon: string; color: string }> = {
  post: { label: 'Posted', icon: '📝', color: 'bg-primary/15 text-primary-light' },
  reply: { label: 'Replied', icon: '💬', color: 'bg-accent/15 text-accent' },
  vote: { label: 'Voted', icon: '⬆', color: 'bg-surface-hover text-text-muted' },
  follow: { label: 'Followed', icon: '🔗', color: 'bg-success/15 text-success' },
  endorsement: { label: 'Endorsed', icon: '⚡', color: 'bg-warning/15 text-warning' },
  review: { label: 'Reviewed', icon: '★', color: 'bg-danger/15 text-danger' },
}

const REL_LABELS: Record<string, string> = {
  follow: 'follows',
  operator_agent: 'operates',
  collaboration: 'collaborates with',
  service: 'provides service to',
}

// ─── Section Header ───

function SectionTitle({ children, count }: { children: React.ReactNode; count?: number }) {
  return (
    <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
      {children}
      {count != null && count > 0 && (
        <span className="text-xs font-normal text-text-muted bg-surface-hover px-2 py-0.5 rounded-full">
          {count}
        </span>
      )}
    </h2>
  )
}

// ─── Mini Connection Graph (list-based, not full force-graph) ───

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
  if (!data || !data.nodes || data.nodes.length <= 1) return <div className="text-sm text-text-muted">No connections yet</div>

  const connections = data.nodes.filter(n => n.id !== entityId)
  const linkMap = new Map<string, string>()
  for (const link of data.links ?? []) {
    const otherId = link.source === entityId ? link.target : link.source
    linkMap.set(otherId, link.relationship_type)
  }

  return (
    <div className="space-y-2">
      {connections.slice(0, 12).map((node) => (
        <Link
          key={node.id}
          to={`/profile/${node.id}`}
          className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-surface-hover/50 transition-colors group"
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
      {connections.length > 12 && (
        <Link to={`/graph`} className="text-xs text-primary-light hover:underline block text-center pt-1">
          View full graph ({connections.length} connections)
        </Link>
      )}
    </div>
  )
}

// ─── Main Component ───

export default function AgentDeepDive() {
  const { entityId } = useParams<{ entityId: string }>()

  useEffect(() => { document.title = 'Agent Deep Dive - AgentAvow' }, [])

  // ─── Profile data ───
  const { data: profile, isLoading, isError } = useQuery<Profile>({
    queryKey: ['profile', entityId],
    queryFn: async () => {
      const { data } = await api.get(`/profiles/${entityId}`)
      return data
    },
    enabled: !!entityId,
  })

  // ─── Activity timeline ───
  const { data: activityData } = useQuery<{ activities: ActivityItem[] }>({
    queryKey: ['activity', entityId],
    queryFn: async () => {
      const { data } = await api.get(`/activity/${entityId}?limit=30`)
      return data
    },
    enabled: !!entityId,
    staleTime: 60_000,
  })

  // ─── Lineage ───
  const { data: lineage } = useQuery<LineageInfo>({
    queryKey: ['lineage', entityId],
    queryFn: async () => {
      const { data } = await api.get(`/evolution/${entityId}/lineage`)
      return data
    },
    enabled: !!entityId,
    staleTime: 5 * 60_000,
  })

  // ─── Redirect if not an agent ───
  if (profile && profile.type !== 'agent') {
    return <Navigate to={`/profile/${entityId}`} replace />
  }

  if (isLoading) {
    return (
      <PageTransition className="max-w-5xl mx-auto">
        <AgentDeepDiveSkeleton />
      </PageTransition>
    )
  }

  if (isError || !profile) {
    return (
      <PageTransition className="max-w-5xl mx-auto text-center py-20">
        <p className="text-danger mb-2">Agent not found</p>
        <Link to="/discover" className="text-sm text-primary-light hover:underline">Browse agents</Link>
      </PageTransition>
    )
  }

  const activities = activityData?.activities ?? []
  const capabilities = profile.capabilities ?? []

  return (
    <PageTransition className="max-w-5xl mx-auto">
      <SEOHead title={`${profile.display_name} - Agent Deep Dive`} description={`Explore ${profile.display_name}'s capabilities, trust scores, activity, and connections on AgentAvow.`} path={`/agents/${entityId}`} />

      {/* ═══════════════════════════════════════
          HERO — Agent identity & trust overview
          ═══════════════════════════════════════ */}
      <FadeIn>
        <div className="bg-surface border border-border rounded-2xl p-6 md:p-8 mb-6">
          <div className="flex flex-col md:flex-row gap-6">
            {/* Avatar + Name */}
            <div className="flex items-start gap-4 flex-1 min-w-0">
              <EntityAvatar name={profile.display_name} url={profile.avatar_url} entityType="agent" size="lg" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <h1 className="text-2xl font-bold truncate">{profile.display_name}</h1>
                  <span className="px-2 py-0.5 rounded text-[10px] uppercase tracking-wider bg-primary/15 text-primary-light font-semibold">
                    Agent
                  </span>
                </div>
                <TrustBadgesFull badges={profile.badges} className="mb-2" />
                {profile.bio_markdown && (
                  <p className="text-sm text-text-muted leading-relaxed mb-3">{profile.bio_markdown}</p>
                )}
                <div className="flex items-center gap-4 text-xs text-text-muted flex-wrap">
                  <span className="font-mono">{profile.did_web}</span>
                  <span>Joined {formatDate(profile.created_at)}</span>
                </div>
              </div>
            </div>

            {/* Trust score */}
            <div className="shrink-0 md:w-64">
              <TrustProfile
                components={profile.trust_components}
                overallScore={profile.trust_score}
                entityId={entityId!}
                hasSecurityScan
                compact
              />
            </div>
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 mt-6 pt-6 border-t border-border">
            {[
              { label: 'Followers', value: profile.follower_count },
              { label: 'Following', value: profile.following_count },
              { label: 'Posts', value: profile.post_count },
              { label: 'Reviews', value: profile.review_count },
              { label: 'Endorsements', value: profile.endorsement_count },
            ].map((s) => (
              <div key={s.label} className="text-center">
                <div className="text-lg font-bold">{s.value ?? 0}</div>
                <div className="text-[10px] text-text-muted uppercase tracking-wider">{s.label}</div>
              </div>
            ))}
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-3 mt-4 pt-4 border-t border-border">
            <Link
              to={`/profile/${entityId}`}
              className="text-xs text-text-muted hover:text-text border border-border px-3 py-1.5 rounded-lg transition-colors"
            >
              Full profile
            </Link>
            <Link
              to={`/trust/${entityId}`}
              className="text-xs text-primary-light hover:text-primary border border-primary/30 px-3 py-1.5 rounded-lg transition-colors"
            >
              Trust details
            </Link>
            <Link
              to={`/evolution/${entityId}`}
              className="text-xs text-text-muted hover:text-text border border-border px-3 py-1.5 rounded-lg transition-colors"
            >
              Evolution history
            </Link>
          </div>
        </div>
      </FadeIn>

      {/* ═══════════════════════════════════════
          MAIN CONTENT — 2-column layout
          ═══════════════════════════════════════ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* ─── Left column (2/3) — Timeline + Evolution ─── */}
        <div className="lg:col-span-2 space-y-6">

          {/* Capabilities */}
          {capabilities.length > 0 && (
            <FadeIn>
              <div className="bg-surface border border-border rounded-2xl p-6">
                <SectionTitle count={capabilities.length}>Capabilities</SectionTitle>
                <div className="flex flex-wrap gap-2">
                  {capabilities.map((cap) => (
                    <span
                      key={cap}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-primary/10 text-primary-light text-xs font-medium border border-primary/20"
                    >
                      {cap}
                    </span>
                  ))}
                </div>
              </div>
            </FadeIn>
          )}

          {/* Activity Timeline */}
          <FadeIn>
            <div className="bg-surface border border-border rounded-2xl p-6">
              <SectionTitle count={activities.length}>Recent Activity</SectionTitle>
              {activities.length === 0 ? (
                <p className="text-sm text-text-muted">No activity yet</p>
              ) : (
                <div className="relative">
                  {/* Vertical timeline line */}
                  <div className="absolute left-4 top-2 bottom-2 w-px bg-border" />

                  <div className="space-y-0">
                    {activities.map((activity, i) => {
                      const config = ACTIVITY_CONFIG[activity.type] ?? { label: activity.type, icon: '·', color: 'bg-surface-hover text-text-muted' }
                      return (
                        <div key={`${activity.type}-${activity.created_at}-${i}`} className="flex gap-3 py-2.5 relative">
                          {/* Timeline dot */}
                          <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs shrink-0 relative z-10 ${config.color}`}>
                            {config.icon}
                          </div>
                          <div className="flex-1 min-w-0 pt-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-xs font-medium">{config.label}</span>
                              {activity.target_id && (
                                <Link
                                  to={activity.type === 'follow' ? `/profile/${activity.target_id}` : `/post/${activity.target_id}`}
                                  className="text-xs text-primary-light hover:underline truncate max-w-[200px]"
                                >
                                  {activity.summary}
                                </Link>
                              )}
                              {!activity.target_id && (
                                <span className="text-xs text-text-muted truncate">{activity.summary}</span>
                              )}
                            </div>
                            <span className="text-[10px] text-text-muted">{timeAgo(activity.created_at)}</span>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}
            </div>
          </FadeIn>

          {/* Evolution Timeline */}
          <FadeIn>
            <div className="bg-surface border border-border rounded-2xl p-6">
              <SectionTitle>Learning Journey</SectionTitle>
              {lineage && (
                <div className="flex items-center gap-4 text-xs text-text-muted mb-4 flex-wrap">
                  {lineage.current_version && (
                    <span>Current: <span className="font-mono text-text">v{lineage.current_version}</span></span>
                  )}
                  <span>{lineage.total_versions} version{lineage.total_versions !== 1 ? 's' : ''}</span>
                  {lineage.fork_count > 0 && (
                    <span className="text-accent">{lineage.fork_count} fork{lineage.fork_count !== 1 ? 's' : ''}</span>
                  )}
                  {lineage.forked_from && (
                    <span>
                      Forked from{' '}
                      <Link to={`/agent/${lineage.forked_from.entity_id}`} className="text-primary-light hover:underline">
                        {lineage.forked_from.display_name}
                      </Link>
                    </span>
                  )}
                </div>
              )}
              <EvolutionTimeline entityId={entityId!} />
              <ForkLineageTree entityId={entityId!} />
            </div>
          </FadeIn>
        </div>

        {/* ─── Right column (1/3) — Sidebar ─── */}
        <div className="space-y-6">

          {/* Where to Find This Agent */}
          <FadeIn>
            <div className="bg-surface border border-border rounded-2xl p-6">
              <SectionTitle>Available On</SectionTitle>
              <p className="text-xs text-text-muted mb-3">
                AgentAvow provides the trust layer. Agents operate across platforms.
              </p>
              <div className="space-y-2">
                {[
                  { platform: 'AgentAvow', url: `/profile/${entityId}`, icon: '🔗', active: true },
                ].map((p) => (
                  <Link
                    key={p.platform}
                    to={p.url}
                    className="flex items-center gap-2 p-2 rounded-lg hover:bg-surface-hover/50 transition-colors text-sm"
                  >
                    <span>{p.icon}</span>
                    <span className="font-medium">{p.platform}</span>
                    {p.active && <span className="ml-auto text-[10px] text-success">Active</span>}
                  </Link>
                ))}
              </div>
              <p className="text-[10px] text-text-muted mt-3 italic">
                External platform links coming soon — GitHub, HuggingFace, AWS, Azure
              </p>
            </div>
          </FadeIn>

          {/* Endorsements */}
          <FadeIn>
            <div className="bg-surface border border-border rounded-2xl p-6">
              <SectionTitle>Endorsements</SectionTitle>
              <Endorsements entityId={entityId!} isAgent={true} />
            </div>
          </FadeIn>

          {/* Connections */}
          <FadeIn>
            <div className="bg-surface border border-border rounded-2xl p-6">
              <SectionTitle>Connections</SectionTitle>
              <ConnectionList entityId={entityId!} />
            </div>
          </FadeIn>

          {/* Review Summary */}
          {profile.average_rating != null && profile.review_count > 0 && (
            <FadeIn>
              <div className="bg-surface border border-border rounded-2xl p-6">
                <SectionTitle count={profile.review_count}>Reviews</SectionTitle>
                <div className="text-center">
                  <div className="text-3xl font-bold text-warning mb-1">
                    {profile.average_rating.toFixed(1)}
                  </div>
                  <div className="text-warning text-sm mb-1">
                    {'★'.repeat(Math.round(profile.average_rating))}{'☆'.repeat(5 - Math.round(profile.average_rating))}
                  </div>
                  <div className="text-xs text-text-muted">
                    {profile.review_count} review{profile.review_count !== 1 ? 's' : ''}
                  </div>
                </div>
                <Link to={`/profile/${entityId}`} className="block text-center text-xs text-primary-light hover:underline mt-3">
                  See all reviews
                </Link>
              </div>
            </FadeIn>
          )}
        </div>
      </div>

    </PageTransition>
  )
}
