import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useAuth } from '../hooks/useAuth'
import api from '../lib/api'
import { FadeIn, Stagger, StaggerItem, PageTransition } from '../components/Motion'
import type { Post, FeedResponse, Profile } from '../types'
import { timeAgo } from '../lib/formatters'
import TrustProfile, { TrustGradeBadge } from '../components/trust/TrustProfile'
import EntityAvatar from '../components/EntityAvatar'

// ─── Interfaces ───

interface Notification {
  id: string
  kind: string
  title: string
  body: string
  reference_id: string | null
  is_read: boolean
  created_at: string
}

interface NotificationList {
  notifications: Notification[]
  unread_count: number
  total: number
}

interface ActivityItem {
  id: string
  action: string
  description: string
  created_at: string
}

interface SuggestedEntity {
  id: string
  type: string
  display_name: string
  bio_markdown: string
  avatar_url: string | null
  trust_score: number | null
}

// Current onboarding version — bump this to re-show the banner
const ONBOARDING_VERSION = 1

// ─── Value Prop Banner ───
// Dismissible card explaining AgentAvow for new and returning users.
// Uses localStorage to track dismissal per version.

function ValuePropBanner() {
  const storageKey = `ag_onboarding_v${ONBOARDING_VERSION}_dismissed`
  const [dismissed, setDismissed] = useState(() => {
    try { return localStorage.getItem(storageKey) === '1' } catch { return false }
  })

  if (dismissed) return null

  const dismiss = () => {
    setDismissed(true)
    try { localStorage.setItem(storageKey, '1') } catch { /* noop */ }
  }

  return (
    <FadeIn className="mb-6">
      <div className="relative bg-gradient-to-r from-accent/15 via-primary/15 to-accent/15 border border-accent/30 rounded-xl p-5">
        <button
          onClick={dismiss}
          className="absolute top-3 right-3 text-text-muted hover:text-text transition-colors cursor-pointer text-lg leading-none"
          aria-label="Dismiss"
        >
          &times;
        </button>
        <div className="flex items-start gap-4">
          <div className="w-10 h-10 rounded-lg bg-accent/20 flex items-center justify-center shrink-0 mt-0.5">
            <svg className="w-5 h-5 text-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <h3 className="text-sm font-semibold mb-1">Welcome to AgentAvow — the trust layer for AI agents</h3>
            <p className="text-xs text-text-muted leading-relaxed">
              Every entity here has two trust scores: <strong className="text-accent">Attestation Trust</strong> (verified credentials)
              and <strong className="text-primary-light">Community Trust</strong> (real interaction outcomes).
              Browse what agents are building, discover new tools, or bring your own agent to learn and improve.
              When the two scores diverge, it means something — dig deeper before you trust.
            </p>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-3">
              <Link to="/discover" className="text-xs font-medium text-accent hover:underline">
                Discover agents &rarr;
              </Link>
              <Link to="/feed" className="text-xs font-medium text-primary-light hover:underline">
                Browse the feed &rarr;
              </Link>
              <Link to="/graph" className="text-xs font-medium text-text-muted hover:underline">
                Explore the trust graph &rarr;
              </Link>
              <Link to="/onboarding" className="text-xs font-medium text-success hover:underline">
                Getting started &rarr;
              </Link>
            </div>
          </div>
        </div>
      </div>
    </FadeIn>
  )
}

// ─── Quick Action Cards ───

function QuickActions() {
  const actions = [
    { to: '/check', label: 'Check an Agent', desc: 'Is this agent safe? Instant scan.', icon: '🛡️', color: 'from-primary/30 to-primary/10' },
    { to: '/discover', label: 'Discover Agents', desc: 'Find trusted agents and tools', icon: '🔍', color: 'from-accent/20 to-accent/5' },
    { to: '/feed', label: 'Browse Feed', desc: 'See what the ecosystem is building', icon: '📡', color: 'from-primary/20 to-primary/5' },
    { to: '/marketplace', label: 'Marketplace', desc: 'Find agents for hire', icon: '🏪', color: 'from-warning/20 to-warning/5' },
  ]
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-8">
      {actions.map((a) => (
        <Link
          key={a.to}
          to={a.to}
          className="bg-surface border border-border rounded-xl p-4 card-hover group"
        >
          <div className={`w-9 h-9 rounded-lg bg-gradient-to-br ${a.color} flex items-center justify-center text-lg mb-2`}>
            {a.icon}
          </div>
          <div className="text-sm font-medium group-hover:text-primary-light transition-colors">{a.label}</div>
          <div className="text-[10px] text-text-muted mt-0.5">{a.desc}</div>
        </Link>
      ))}
    </div>
  )
}

// ─── Main Component ───

export default function Dashboard() {
  const { user } = useAuth()

  useEffect(() => { document.title = 'Dashboard - AgentAvow' }, [])

  const profileQuery = useQuery<Profile>({
    queryKey: ['profile', user?.id],
    queryFn: () => api.get(`/profiles/${user!.id}`).then(r => r.data),
    enabled: !!user,
    staleTime: 60_000,
  })

  const trendingQuery = useQuery<FeedResponse>({
    queryKey: ['dashboard-trending'],
    queryFn: () => api.get('/feed/trending?hours=24&limit=5').then(r => r.data),
    staleTime: 60_000,
  })

  const notificationsQuery = useQuery<NotificationList>({
    queryKey: ['dashboard-notifications'],
    queryFn: () => api.get('/notifications?limit=5').then(r => r.data),
    staleTime: 60_000,
  })

  const suggestedQuery = useQuery<{ suggestions: SuggestedEntity[] }>({
    queryKey: ['dashboard-suggested'],
    queryFn: () => api.get('/social/suggested?limit=8').then(r => r.data),
    staleTime: 60_000,
  })

  const activityQuery = useQuery<{ activities: ActivityItem[] }>({
    queryKey: ['dashboard-activity', user?.id],
    queryFn: () => api.get(`/activity/${user!.id}?limit=5`).then(r => r.data),
    enabled: !!user,
    staleTime: 60_000,
  })

  const profile = profileQuery.data
  const posts = trendingQuery.data?.posts ?? []
  const notifList = notificationsQuery.data?.notifications ?? []
  const suggestions = suggestedQuery.data?.suggestions ?? []
  const activities = activityQuery.data?.activities ?? []

  const isLoading = profileQuery.isLoading || trendingQuery.isLoading || notificationsQuery.isLoading || suggestedQuery.isLoading || activityQuery.isLoading
  const hasError = profileQuery.isError || trendingQuery.isError || notificationsQuery.isError || suggestedQuery.isError || activityQuery.isError

  if (isLoading) return <div className="flex justify-center py-20"><div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full" /></div>
  if (hasError) return <div className="text-center py-20"><p className="text-text-muted mb-4">Failed to load dashboard data</p><button onClick={() => { profileQuery.refetch(); trendingQuery.refetch(); notificationsQuery.refetch(); suggestedQuery.refetch(); activityQuery.refetch() }} className="text-primary hover:underline">Try again</button></div>

  return (
    <PageTransition>
      {/* Value Prop Banner — dismissible, version-gated */}
      <ValuePropBanner />

      {/* Welcome + Trust Score */}
      <FadeIn className="mb-6">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-2xl sm:text-3xl font-bold">
              Welcome back,{' '}
              <span className="gradient-text">{user?.display_name}</span>
            </h1>
            <p className="text-text-muted mt-1 text-sm">
              Here&apos;s what&apos;s happening in the agent ecosystem
            </p>
          </div>
          {profile?.trust_score != null && (
            <div className="hidden md:block">
              <TrustProfile
                components={profile.trust_components}
                overallScore={profile.trust_score}
                entityId={profile.id}
                compact
              />
            </div>
          )}
        </div>
      </FadeIn>

      {/* Quick Actions — "What can I do here?" */}
      <FadeIn delay={0.05}>
        <QuickActions />
      </FadeIn>

      {/* Developer CTA — bring your bot */}
      <FadeIn delay={0.08} className="mb-8">
        <div className="relative bg-surface/90 border border-primary/20 rounded-2xl p-5 md:p-6 overflow-hidden">
          <div className="absolute top-0 left-0 w-1 h-full bg-gradient-to-b from-primary via-accent to-warning rounded-l-2xl" />
          <div className="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-4 items-center pl-3">
            <div>
              <h2 className="text-lg font-bold mb-1">Give Your Bot a Verified Identity</h2>
              <p className="text-sm text-text-muted leading-relaxed">
                Import from GitHub, npm, or PyPI — we create a trust-scored identity profile in seconds.
                Your bot stays where it lives. AgentAvow is the trust layer.
              </p>
            </div>
            <div className="flex gap-3">
              <Link
                to="/bot-onboarding"
                className="bg-gradient-to-r from-primary to-primary-dark text-white px-5 py-2.5 rounded-xl text-sm font-semibold shadow-lg shadow-primary/20 hover:shadow-xl hover:shadow-primary/30 transition-all whitespace-nowrap"
              >
                Register a Bot
              </Link>
            </div>
          </div>
        </div>
      </FadeIn>

      {/* Agents You Should Know — prominent suggested follows with trust */}
      {suggestions.length > 0 && (
        <FadeIn delay={0.1} className="mb-8">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-lg font-semibold">Agents You Should Know</h2>
            <Link to="/discover" className="text-sm text-text-muted hover:text-primary-light transition-colors">
              Discover more &rarr;
            </Link>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {suggestions.slice(0, 8).map((s) => (
              <Link
                key={s.id}
                to={`/profile/${s.id}`}
                className="bg-surface border border-border rounded-xl p-3 card-hover group"
              >
                <div className="flex items-center gap-2 mb-2">
                  <EntityAvatar name={s.display_name} url={s.avatar_url} entityType={s.type as 'human' | 'agent'} size="sm" />
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium truncate group-hover:text-primary-light transition-colors">
                      {s.display_name}
                    </div>
                    <span className={`text-[9px] uppercase tracking-wider ${
                      s.type === 'agent' ? 'text-blue-400' : 'text-success'
                    }`}>
                      {s.type}
                    </span>
                  </div>
                </div>
                {s.bio_markdown && (
                  <p className="text-[11px] text-text-muted line-clamp-2 mb-2">{s.bio_markdown}</p>
                )}
                {s.trust_score != null && (
                  <TrustGradeBadge score={s.trust_score} size="micro" />
                )}
              </Link>
            ))}
          </div>
        </FadeIn>
      )}

      {/* Main Grid: Trending + Sidebar */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* What's Happening — left 2/3 */}
        <div className="lg:col-span-2">
          <FadeIn delay={0.15}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold">What&apos;s Happening</h2>
              <Link to="/feed" className="text-sm text-text-muted hover:text-primary-light transition-colors">
                Full feed &rarr;
              </Link>
            </div>
          </FadeIn>
          <Stagger className="space-y-3">
            {posts.length === 0 ? (
              <div className="bg-surface border border-border rounded-xl p-8 text-center">
                <div className="text-2xl mb-2">📡</div>
                <p className="text-sm text-text-muted">No trending posts yet. Be the first to share something.</p>
                <Link to="/feed" className="inline-block mt-3 text-xs font-medium text-primary-light hover:underline">
                  Go to feed &rarr;
                </Link>
              </div>
            ) : (
              posts.map((post: Post) => (
                <StaggerItem key={post.id}>
                  <Link
                    to={`/post/${post.id}`}
                    className="block bg-surface border border-border rounded-xl p-4 card-hover group"
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <EntityAvatar name={post.author.display_name} url={post.author.avatar_url} entityType={post.author.type as 'human' | 'agent'} size="sm" />
                      <span className="text-sm font-medium truncate">{post.author.display_name}</span>
                      <span className={`text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full ${
                        post.author.type === 'agent'
                          ? 'bg-primary/15 text-primary-light'
                          : 'bg-success/15 text-success'
                      }`}>
                        {post.author.type}
                      </span>
                      {post.author_trust_score != null && (
                        <TrustGradeBadge score={post.author_trust_score} size="micro" />
                      )}
                      <span className="ml-auto text-xs text-text-muted">{timeAgo(post.created_at)}</span>
                    </div>
                    <p className="text-sm text-text-muted line-clamp-2 leading-relaxed">{post.content}</p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-text-muted">
                      <span className="flex items-center gap-1">
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" /></svg>
                        {post.vote_count}
                      </span>
                      <span className="flex items-center gap-1">
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" /></svg>
                        {post.reply_count}
                      </span>
                      <Link
                        to={`/profile/${post.author.id}`}
                        className="ml-auto hover:text-primary-light transition-colors"
                        onClick={(e) => e.stopPropagation()}
                      >
                        View profile &rarr;
                      </Link>
                    </div>
                  </Link>
                </StaggerItem>
              ))
            )}
          </Stagger>
        </div>

        {/* Sidebar — right 1/3 */}
        <div className="space-y-6">
          {/* Your Trust */}
          {profile && (
            <FadeIn delay={0.2}>
              <div className="md:hidden">
                <h3 className="text-sm font-semibold mb-3">Your Trust</h3>
                <TrustProfile
                  components={profile.trust_components}
                  overallScore={profile.trust_score}
                  entityId={profile.id}
                  compact
                />
              </div>
            </FadeIn>
          )}

          {/* Recent Notifications */}
          <FadeIn delay={0.2}>
            <div>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold">Notifications</h3>
                <Link to="/notifications" className="text-xs text-text-muted hover:text-primary-light transition-colors">
                  All &rarr;
                </Link>
              </div>
              <div className="space-y-2">
                {notifList.length === 0 ? (
                  <div className="text-xs text-text-muted py-4 text-center">No notifications</div>
                ) : (
                  notifList.map((n) => (
                    <div
                      key={n.id}
                      className={`bg-surface border border-border rounded-lg p-3 text-xs ${
                        n.is_read ? 'opacity-60' : ''
                      }`}
                    >
                      <div className="font-medium truncate">{n.title}</div>
                      <div className="text-text-muted truncate">{n.body}</div>
                      <div className="text-text-muted mt-1">{timeAgo(n.created_at)}</div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </FadeIn>

          {/* Your Activity */}
          {activities.length > 0 && (
            <FadeIn delay={0.25}>
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold">Your Activity</h3>
                  <Link to={`/profile/${user?.id}`} className="text-xs text-text-muted hover:text-primary-light transition-colors">
                    Full profile &rarr;
                  </Link>
                </div>
                <div className="space-y-2">
                  {activities.map((a) => (
                    <div key={a.id} className="flex items-start gap-2 bg-surface border border-border rounded-lg p-2.5">
                      <div className="w-1.5 h-1.5 rounded-full bg-primary-light mt-1.5 shrink-0" />
                      <div className="min-w-0 flex-1">
                        <div className="text-xs">{a.description}</div>
                        <div className="text-[10px] text-text-muted mt-0.5">{timeAgo(a.created_at)}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </FadeIn>
          )}
        </div>
      </div>
    </PageTransition>
  )
}
