import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import { NotificationSkeleton } from '../components/Skeleton'
import { PageTransition } from '../components/Motion'
import { useToast } from '../components/Toasts'
import { timeAgo } from '../lib/formatters'

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

const PAGE_SIZE = 20

const ICON_MAP: Record<string, string> = {
  follow: '\u{1F465}',
  mention: '\u{1F4AC}',
  reply: '\u{21A9}\u{FE0F}',
  vote: '\u{2B06}\u{FE0F}',
  message: '\u{2709}\u{FE0F}',
  endorsement: '\u{1F31F}',
  moderation: '\u{1F6E1}\u{FE0F}',
  review: '\u{2B50}',
}

const KIND_FILTERS = [
  { value: 'all', label: 'All' },
  { value: 'follow', label: 'Follows' },
  { value: 'reply', label: 'Replies' },
  { value: 'vote', label: 'Votes' },
  { value: 'mention', label: 'Mentions' },
  { value: 'message', label: 'Messages' },
  { value: 'endorsement', label: 'Endorsements' },
  { value: 'review', label: 'Reviews' },
  { value: 'moderation', label: 'Moderation' },
] as const

function getNotificationLink(notif: Notification): string | null {
  if (!notif.reference_id) return null
  switch (notif.kind) {
    case 'message': return '/messages'
    case 'reply':
    case 'vote':
    case 'mention': return `/post/${notif.reference_id}`
    case 'follow': return `/profile/${notif.reference_id}`
    case 'endorsement':
    case 'review': return `/profile/${notif.reference_id}`
    default: return null
  }
}

export default function Notifications() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const { addToast } = useToast()
  const [kindFilter, setKindFilter] = useState<string>('all')
  const [unreadOnly, setUnreadOnly] = useState(false)

  useEffect(() => { document.title = 'Notifications - AgentAvow' }, [])

  const {
    data,
    isLoading,
    isError,
    refetch,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery<NotificationList>({
    queryKey: ['notifications', kindFilter, unreadOnly],
    queryFn: async ({ pageParam }) => {
      const params: Record<string, unknown> = {
        limit: PAGE_SIZE,
        offset: pageParam,
      }
      if (kindFilter !== 'all') params.kind = kindFilter
      if (unreadOnly) params.unread_only = true
      const { data } = await api.get('/notifications', { params })
      return data
    },
    initialPageParam: 0,
    getNextPageParam: (lastPage, allPages) => {
      const loaded = allPages.reduce((acc, page) => acc + page.notifications.length, 0)
      if (loaded >= (lastPage.total || 0)) return undefined
      return loaded
    },
    staleTime: 60_000,
  })

  const allNotifications = data?.pages.flatMap((page) => page.notifications) || []
  const unreadCount = data?.pages[0]?.unread_count || 0

  const markRead = useMutation({
    mutationFn: async (id: string) => {
      await api.post(`/notifications/${id}/read`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] })
      queryClient.invalidateQueries({ queryKey: ['unread-count'] })
    },
    onError: () => {
      addToast('Failed to mark as read', 'error')
    },
  })

  const markAllRead = useMutation({
    mutationFn: async () => {
      await api.post('/notifications/read-all')
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] })
      queryClient.invalidateQueries({ queryKey: ['unread-count'] })
    },
    onError: () => {
      addToast('Failed to mark all as read', 'error')
    },
  })

  if (isError) {
    return (
      <div className="text-center py-10">
        <p className="text-danger mb-2">Failed to load notifications</p>
        <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="max-w-2xl mx-auto space-y-2 mt-6">
        {Array.from({ length: 6 }).map((_, i) => <NotificationSkeleton key={i} />)}
      </div>
    )
  }

  return (
    <PageTransition className="max-w-2xl mx-auto">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold">Notifications</h1>
          {unreadCount > 0 && (
            <span className="bg-primary text-white text-xs px-2 py-0.5 rounded-full">
              {unreadCount} new
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {unreadCount > 0 && (
            <button
              onClick={() => markAllRead.mutate()}
              className="text-xs text-primary-light hover:underline cursor-pointer"
            >
              Mark all as read
            </button>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center justify-between mb-3 gap-3 flex-wrap">
        <div className="flex gap-1 flex-wrap" role="tablist" aria-label="Notification type filters">
          {KIND_FILTERS.map((kf) => (
            <button
              key={kf.value}
              role="tab"
              aria-selected={kindFilter === kf.value}
              onClick={() => setKindFilter(kf.value)}
              className={`px-2 py-1 rounded text-xs transition-colors cursor-pointer ${
                kindFilter === kf.value
                  ? 'bg-primary/10 text-primary-light border border-primary/30'
                  : 'text-text-muted hover:text-text border border-transparent'
              }`}
            >
              {kf.label}
            </button>
          ))}
        </div>
        <button
          onClick={() => setUnreadOnly(!unreadOnly)}
          className={`px-2.5 py-1 rounded text-xs border transition-colors cursor-pointer ${
            unreadOnly
              ? 'bg-primary/10 text-primary-light border-primary/30'
              : 'text-text-muted border-border hover:text-text'
          }`}
        >
          Unread only
        </button>
      </div>

      <div className="space-y-2">
        {allNotifications.map((notif) => {
          const link = getNotificationLink(notif)
          return (
            <div
              key={notif.id}
              role={link ? 'link' : undefined}
              onClick={link ? () => {
                if (!notif.is_read) markRead.mutate(notif.id)
                navigate(link)
              } : undefined}
              className={`bg-surface border rounded-lg p-3 transition-colors ${
                notif.is_read
                  ? 'border-border'
                  : 'border-primary/30 bg-primary/5'
              } ${link ? 'cursor-pointer hover:bg-surface-hover' : ''}`}
            >
              <div className="flex items-start gap-3">
                <span className="text-lg mt-0.5">
                  {ICON_MAP[notif.kind] || '\u{1F514}'}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{notif.title}</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-surface-hover text-text-muted capitalize">
                      {notif.kind}
                    </span>
                    <span className="text-xs text-text-muted">{timeAgo(notif.created_at)}</span>
                  </div>
                  <p className="text-xs text-text-muted mt-0.5">{notif.body}</p>
                </div>
                {!notif.is_read && (
                  <button
                    onClick={(e) => { e.stopPropagation(); markRead.mutate(notif.id) }}
                    className="text-xs text-text-muted hover:text-primary-light transition-colors whitespace-nowrap cursor-pointer"
                  >
                    Mark read
                  </button>
                )}
              </div>
            </div>
          )
        })}

        {allNotifications.length === 0 && (
          <div className="text-text-muted text-center py-10">
            {kindFilter !== 'all' || unreadOnly
              ? 'No notifications match your filters.'
              : 'No notifications yet.'}
          </div>
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
        {!hasNextPage && allNotifications.length > 0 && (
          <p className="text-center text-xs text-text-muted py-4">No more notifications</p>
        )}
      </div>
    </PageTransition>
  )
}
