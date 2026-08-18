/** Dedicated notifications view — full list + manage (mark read / delete). Linked from
 * the header bell and the Account "recent alerts" preview. */
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { useAuth } from '../../hooks/useAuth'
import api from '../../lib/api'
import { rp } from '../basePath'
import { Reveal } from '../components/motion'

interface Notif { id: string; kind: string; title: string; body: string; reference_id: string | null; is_read: boolean; created_at: string }
type Filter = 'all' | 'unread' | 'watch_alert'

const ago = (iso: string) => {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 3600) return `${Math.max(1, Math.floor(s / 60))}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}
const KIND_LABEL: Record<string, string> = { watch_alert: 'Watch alert' }

export default function Notifications() {
  const { user, isLoading } = useAuth()
  const qc = useQueryClient()
  const [filter, setFilter] = useState<Filter>('all')
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['rebrand-all-notifs'] })
    qc.invalidateQueries({ queryKey: ['rebrand-unread-watch'] }) // header bell count
    qc.invalidateQueries({ queryKey: ['rebrand-notifs'] })        // account preview
  }

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

  const all = data?.notifications ?? []
  const items = useMemo(() => {
    const rows = filter === 'unread' ? all.filter((n) => !n.is_read)
      : filter === 'watch_alert' ? all.filter((n) => n.kind === 'watch_alert')
        : all
    return [...rows].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
  }, [all, filter])
  const unreadIds = all.filter((n) => !n.is_read).map((n) => n.id)

  if (isLoading) return <div className="max-w-[760px] mx-auto px-6 py-24 text-center text-text-muted">Loading…</div>
  if (!user) return (
    <div className="max-w-[560px] mx-auto px-6 py-24 text-center">
      <h1 className="text-2xl font-extrabold tracking-tight">Sign in to see your notifications</h1>
      <Link to={rp('/rebrand/login')} className="mt-4 inline-block text-primary-light hover:text-primary font-semibold">Sign in →</Link>
    </div>
  )

  return (
    <div className="max-w-[760px] mx-auto px-6 py-14">
      <Reveal>
        <div className="flex items-end justify-between gap-4 flex-wrap">
          <div>
            <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Notifications</span>
            <h1 className="mt-1 text-2xl md:text-3xl font-extrabold tracking-tight">Your alerts</h1>
          </div>
          {!!unreadIds.length && (
            <button onClick={() => markAll.mutate(unreadIds)} disabled={markAll.isPending} className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg border border-border text-text-muted hover:text-text disabled:opacity-60">Mark all read ({unreadIds.length})</button>
          )}
        </div>
      </Reveal>

      <div className="mt-6 flex gap-1 border-b border-border/60">
        {([['all', 'All'], ['unread', 'Unread'], ['watch_alert', 'Watch alerts']] as const).map(([k, lbl]) => (
          <button key={k} onClick={() => setFilter(k)} className={`px-3.5 py-2 text-[13.5px] font-semibold border-b-2 -mb-px transition-colors ${filter === k ? 'border-primary text-text' : 'border-transparent text-text-muted hover:text-text'}`}>{lbl}</button>
        ))}
      </div>

      <div className="mt-5 flex flex-col gap-2">
        {loading && [0, 1, 2].map((i) => <div key={i} className="glass rounded-xl h-[80px] animate-pulse" />)}
        {!loading && !items.length && <p className="text-text-muted text-[14px] py-10 text-center">Nothing here — you&apos;re all caught up.</p>}
        {items.map((n) => (
          <div key={n.id} className={`glass rounded-xl px-4 py-3 border-l-4 ${n.is_read ? 'border-border/60' : 'border-warning'}`}>
            <div className="flex items-start gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  {!n.is_read && <span className="h-1.5 w-1.5 rounded-full bg-warning shrink-0" />}
                  <span className="text-[14px] font-semibold">{n.title}</span>
                  <span className="font-mono text-[10.5px] px-1.5 py-0.5 rounded bg-surface text-text-muted">{KIND_LABEL[n.kind] || n.kind}</span>
                  <span className="text-[11.5px] text-text-muted/70 ml-auto">{ago(n.created_at)}</span>
                </div>
                <div className="text-[13px] text-text-muted mt-1">{n.body}</div>
                <div className="mt-2 flex gap-3 text-[12.5px] font-semibold">
                  {n.reference_id && <Link to={rp(`/rebrand/check/${n.reference_id}`)} className="text-primary-light hover:text-primary">Re-check →</Link>}
                  {!n.is_read && <button onClick={() => markRead.mutate(n.id)} className="text-text-muted hover:text-text">Mark read</button>}
                  <button onClick={() => remove.mutate(n.id)} className="text-text-muted hover:text-danger">Delete</button>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
