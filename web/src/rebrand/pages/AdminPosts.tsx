/** All marketing posts — sortable + searchable history (excludes reply-guy noise).
 * Linked from the admin dashboard's Recent posts card. */
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { useAuth } from '../../hooks/useAuth'
import api from '../../lib/api'
import { rp } from '../basePath'

interface Item { id: string; platform: string; content_preview: string; status: string; topic: string | null; external_url: string | null; posted_at: string | null; created_at: string; metrics: Record<string, number> | null }
type Key = 'date' | 'platform' | 'likes' | 'comments' | 'shares' | 'impressions'

const fmt = (n?: number) => (n ?? 0).toLocaleString()
const when = (iso: string | null) => iso ? new Date(iso).toLocaleString() : '—'

export default function AdminPosts() {
  const { user, isLoading } = useAuth()
  const [q, setQ] = useState('')
  const [sort, setSort] = useState<Key>('date')
  const [asc, setAsc] = useState(false)
  const { data } = useQuery<{ posted: Item[]; failed: Item[]; pending_review: Item[] }>({
    queryKey: ['admin-all-posts'],
    queryFn: async () => (await api.get('/admin/marketing/activity', { params: { limit: 200 } })).data,
    enabled: !!user?.is_admin,
  })

  const rows = useMemo(() => {
    const all = [...(data?.posted || []), ...(data?.pending_review || []), ...(data?.failed || [])]
    const filtered = q.trim() ? all.filter((r) => `${r.platform} ${r.topic} ${r.content_preview}`.toLowerCase().includes(q.toLowerCase())) : all
    const val = (r: Item): number | string => sort === 'date' ? new Date(r.posted_at || r.created_at || 0).getTime()
      : sort === 'platform' ? r.platform
        : (r.metrics?.[sort] ?? 0)
    return [...filtered].sort((a, b) => { const x = val(a), y = val(b); const c = x < y ? -1 : x > y ? 1 : 0; return asc ? c : -c })
  }, [data, q, sort, asc])

  if (isLoading) return <div className="max-w-[1080px] mx-auto px-6 py-24 text-center text-text-muted">Loading…</div>
  if (!user?.is_admin) return <div className="max-w-[560px] mx-auto px-6 py-24 text-center"><h1 className="text-2xl font-extrabold">Admins only</h1></div>

  const th = (k: Key, label: string, right = false) => (
    <th className={`py-1.5 px-2 font-mono cursor-pointer select-none hover:text-text ${right ? 'text-right' : 'text-left'}`} onClick={() => { if (sort === k) setAsc(!asc); else { setSort(k); setAsc(false) } }}>
      {label}{sort === k ? (asc ? ' ↑' : ' ↓') : ''}
    </th>
  )

  return (
    <div className="max-w-[1080px] mx-auto px-6 py-14">
      <div className="flex items-baseline justify-between gap-3 flex-wrap">
        <div>
          <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Marketing</span>
          <h1 className="mt-2 text-3xl font-extrabold tracking-tight">All posts</h1>
        </div>
        <Link to={rp('/rebrand/admin-dashboard')} className="text-[12.5px] text-text-muted hover:text-text font-semibold">← Dashboard</Link>
      </div>
      <p className="mt-2 text-text-muted text-[13.5px]">Full marketing history — sort by any column, search across platform/topic/content. Reply-guy is excluded to keep this clean (see the dashboard for that).</p>

      <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search platform, topic, or content…" className="mt-5 w-full max-w-[420px] text-[13.5px] rounded-xl bg-surface border border-border px-3.5 py-2" />

      <div className="mt-4 glass rounded-2xl p-4 overflow-x-auto">
        <table className="w-full text-[12.5px]">
          <thead><tr className="text-text-muted/70">{th('date', 'when')}{th('platform', 'platform')}<th className="py-1.5 px-2 font-mono text-left">post</th>{th('likes', '♥', true)}{th('comments', '💬', true)}{th('shares', '🔁', true)}{th('impressions', '👁', true)}</tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-t border-border/40">
                <td className="py-1.5 px-2 text-text-muted whitespace-nowrap">{when(r.posted_at)}</td>
                <td className="py-1.5 px-2 font-mono">{r.platform}{r.status !== 'posted' && <span className="ml-1 text-text-muted/60">({r.status})</span>}</td>
                <td className="py-1.5 px-2 text-text-muted max-w-[380px] truncate">{r.external_url ? <a href={r.external_url} target="_blank" rel="noopener" className="hover:text-primary-light">{r.content_preview?.slice(0, 100)} ↗</a> : r.content_preview?.slice(0, 100)}</td>
                <td className="py-1.5 px-2 tabular-nums text-right">{fmt(r.metrics?.likes)}</td>
                <td className="py-1.5 px-2 tabular-nums text-right">{fmt(r.metrics?.comments)}</td>
                <td className="py-1.5 px-2 tabular-nums text-right">{fmt(r.metrics?.shares)}</td>
                <td className="py-1.5 px-2 tabular-nums text-right text-text-muted">{fmt(r.metrics?.impressions)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length && <p className="text-text-muted text-[13px] py-6 text-center">No posts match.</p>}
      </div>
      <p className="mt-2 text-[11.5px] text-text-muted/60">Showing up to 200 most recent. Deeper history + pagination can be added if you need it.</p>
    </div>
  )
}
