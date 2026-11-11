/** Notifications tab of the account shell: tool-safety alerts only (watch alerts and
 * good news, fetched by kind server-side), each row with the tool's artwork. */
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import api from '../../lib/api'
import { rp } from '../basePath'
import { NotifRow, type Notif } from '../components/NotificationBits'
import { RELEVANT_KIND_PARAM } from '../lib/notifKinds'
import { ALERT_QUERY_KEYS } from '../lib/useUnreadAlerts'
import { AccList, AccSection, EmptyCard, LoadError, SkeletonRows, btnGhostSm } from '../components/AccountBits'

type Filter = 'all' | 'unread' | 'watch_alert' | 'watch_good_news'
const FILTERS: [Filter, string][] = [['all', 'All'], ['unread', 'Unread'], ['watch_alert', 'Alerts'], ['watch_good_news', 'Good news']]

function NotificationsBody() {
  const qc = useQueryClient()
  const [filter, setFilter] = useState<Filter>('all')
  const invalidate = () => ALERT_QUERY_KEYS.forEach((k) => qc.invalidateQueries({ queryKey: [k] }))

  const { data, isLoading, isError, refetch, isRefetching } = useQuery({
    queryKey: ['rebrand-all-notifs'],
    queryFn: async () => (await api.get<{ notifications: Notif[] }>('/notifications', { params: { kind: RELEVANT_KIND_PARAM, limit: 100 } })).data,
  })
  const markRead = useMutation({ mutationFn: (id: string) => api.post(`/notifications/${id}/read`), onSuccess: invalidate })
  const remove = useMutation({ mutationFn: (id: string) => api.delete(`/notifications/${id}`), onSuccess: invalidate })
  // One request marks every unread alert of these kinds read (not N requests).
  const markAll = useMutation({
    mutationFn: () => api.post('/notifications/read-all', null, { params: { kind: RELEVANT_KIND_PARAM } }),
    onSuccess: invalidate,
  })

  const all = useMemo(() => data?.notifications ?? [], [data])
  const items = useMemo(() => {
    const rows = filter === 'unread' ? all.filter((n) => !n.is_read)
      : filter === 'all' ? all : all.filter((n) => n.kind === filter)
    return [...rows].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
  }, [all, filter])
  const unread = all.filter((n) => !n.is_read).length

  return (
    <AccSection
      title={<>Alerts{unread > 0 && ` · ${unread} unread`}</>}
      right={unread > 0 && (
        <button type="button" onClick={() => markAll.mutate()} disabled={markAll.isPending} className={btnGhostSm}>
          {markAll.isPending ? 'Marking…' : 'Mark all read'}
        </button>
      )}
    >
      {all.length > 0 && (
        <div className="mb-2.5 inline-flex rounded-lg border border-border overflow-hidden" role="group" aria-label="Show">
          {FILTERS.map(([k, label]) => (
            <button key={k} type="button" aria-pressed={filter === k} onClick={() => setFilter(k)}
              className={`px-2.5 py-1 text-[12.5px] transition-colors ${filter === k ? 'bg-primary/15 text-primary-light font-semibold' : 'text-text-muted hover:text-text'}`}>{label}</button>
          ))}
        </div>
      )}
      {isLoading ? <SkeletonRows n={3} />
        : isError ? <LoadError what="notifications" note={'This isn’t “all caught up”.'} onRetry={() => void refetch()} retrying={isRefetching} />
          : all.length === 0 ? (
            <EmptyCard title="No alerts yet" action={<Link to={rp('/rebrand/account')} className={btnGhostSm}>Go to Watches &amp; alerts</Link>}>
              Watch a tool to get one when it changes: its answer gets worse, its score drops, or its tool definitions change.
            </EmptyCard>
          ) : items.length === 0 ? (
            <p className="text-text-muted text-[14px] py-6 text-center">Nothing here with this filter.</p>
          ) : (
            <AccList>
              {items.map((n) => <NotifRow key={n.id} n={n} onRead={markRead.mutate} onDelete={remove.mutate} />)}
            </AccList>
          )}
    </AccSection>
  )
}

/** Rendered inside AccountLayout (the shared header and tabs), see App.tsx. */
export default function Notifications() {
  return <NotificationsBody />
}
