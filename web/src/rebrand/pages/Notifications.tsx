/** Dedicated notifications view — tool-safety alerts only (not the social firehose),
 * with the score-change visual + manage (mark read / delete). */
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { useAuth } from '../../hooks/useAuth'
import api from '../../lib/api'
import { rp } from '../basePath'
import { Reveal } from '../components/motion'
import { NotifRow, isRelevant, type Notif } from '../components/NotificationBits'

type Filter = 'all' | 'unread' | 'watch_alert' | 'watch_good_news'

export default function Notifications() {
  const { user, isLoading } = useAuth()
  const qc = useQueryClient()
  const [filter, setFilter] = useState<Filter>('all')
  const invalidate = () => ['rebrand-all-notifs', 'rebrand-unread-watch', 'rebrand-notifs']
    .forEach((k) => qc.invalidateQueries({ queryKey: [k] }))

  const { data, isLoading: loading } = useQuery({
    queryKey: ['rebrand-all-notifs'],
    queryFn: async () => (await api.get<{ notifications: Notif[] }>('/notifications', { params: { limit: 100 } })).data,
    enabled: !!user,
  })
  const markRead = useMutation({ mutationFn: (id: string) => api.post(`/notifications/${id}/read`), onSuccess: invalidate })
  const remove = useMutation({ mutationFn: (id: string) => api.delete(`/notifications/${id}`), onSuccess: invalidate })
  const markAll = useMutation({
    mutationFn: async (ids: string[]) => { await Promise.all(ids.map((id) => api.post(`/notifications/${id}/read`))) },
    onSuccess: invalidate,
  })

  // Only tool-safety notifications — the account also holds old social-era ones.
  const relevant = (data?.notifications ?? []).filter(isRelevant)
  const items = useMemo(() => {
    const rows = filter === 'unread' ? relevant.filter((n) => !n.is_read)
      : filter === 'all' ? relevant : relevant.filter((n) => n.kind === filter)
    return [...rows].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
  }, [relevant, filter])
  const unreadIds = relevant.filter((n) => !n.is_read).map((n) => n.id)

  if (isLoading) return <div className="max-w-[860px] mx-auto px-6 py-24 text-center text-text-muted">Loading…</div>
  if (!user) return (
    <div className="max-w-[560px] mx-auto px-6 py-24 text-center">
      <h1 className="text-2xl font-extrabold tracking-tight">Sign in to see your notifications</h1>
      <Link to={rp('/rebrand/login')} className="mt-4 inline-block text-primary-light hover:text-primary font-semibold">Sign in →</Link>
    </div>
  )

  const tabs: [Filter, string][] = [['all', 'All'], ['unread', 'Unread'], ['watch_alert', 'Alerts'], ['watch_good_news', 'Good news']]
  return (
    <div className="max-w-[860px] mx-auto px-6 py-14">
      <Reveal>
        <div className="flex items-end justify-between gap-4 flex-wrap">
          <div>
            <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Notifications</span>
            <h1 className="mt-1 text-2xl md:text-3xl font-extrabold tracking-tight">Your alerts</h1>
            <p className="mt-1.5 text-text-muted text-[13.5px]">When a tool you watch changes — a score drops, a signed definition changes, or it gets safer.</p>
          </div>
          {!!unreadIds.length && (
            <button onClick={() => markAll.mutate(unreadIds)} disabled={markAll.isPending} className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg border border-border text-text-muted hover:text-text disabled:opacity-60">Mark all read ({unreadIds.length})</button>
          )}
        </div>
      </Reveal>

      <div className="mt-6 flex gap-1 border-b border-border/60">
        {tabs.map(([k, lbl]) => (
          <button key={k} onClick={() => setFilter(k)} className={`px-3.5 py-2 text-[13.5px] font-semibold border-b-2 -mb-px transition-colors ${filter === k ? 'border-primary text-text' : 'border-transparent text-text-muted hover:text-text'}`}>{lbl}</button>
        ))}
      </div>

      <div className="mt-5 flex flex-col gap-2">
        {loading && [0, 1, 2].map((i) => <div key={i} className="glass rounded-xl h-[92px] animate-pulse" />)}
        {!loading && !items.length && <p className="text-text-muted text-[14px] py-10 text-center">Nothing here — you&apos;re all caught up.</p>}
        {items.map((n) => <NotifRow key={n.id} n={n} onRead={markRead.mutate} onDelete={remove.mutate} />)}
      </div>
    </div>
  )
}
