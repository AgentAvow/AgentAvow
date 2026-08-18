/** All reply-guy replies — sortable + searchable history. Linked from the dashboard. */
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { useAuth } from '../../hooks/useAuth'
import api from '../../lib/api'
import { rp } from '../basePath'

interface Row { id: string; platform: string; draft_content?: string; post_uri?: string; reply_url?: string | null; posted_at?: string | null; engagement_count?: number; target?: { handle?: string | null } }
type Key = 'date' | 'platform' | 'engagement'

const fmt = (n?: number) => (n ?? 0).toLocaleString()
const when = (iso?: string | null) => iso ? new Date(iso).toLocaleString() : '—'

export default function AdminReplies() {
  const { user, isLoading } = useAuth()
  const [q, setQ] = useState('')
  const [sort, setSort] = useState<Key>('date')
  const [asc, setAsc] = useState(false)
  const { data } = useQuery<{ items: Row[] }>({
    queryKey: ['admin-all-replies'],
    queryFn: async () => (await api.get('/admin/engagement/queue', { params: { status: 'posted', sort: 'recent', limit: 200 } })).data,
    enabled: !!user?.is_admin,
  })

  const rows = useMemo(() => {
    const all = data?.items || []
    const filtered = q.trim() ? all.filter((r) => `${r.platform} ${r.target?.handle} ${r.draft_content}`.toLowerCase().includes(q.toLowerCase())) : all
    const val = (r: Row): number | string => sort === 'date' ? new Date(r.posted_at || 0).getTime() : sort === 'platform' ? r.platform : (r.engagement_count ?? 0)
    return [...filtered].sort((a, b) => { const x = val(a), y = val(b); const c = x < y ? -1 : x > y ? 1 : 0; return asc ? c : -c })
  }, [data, q, sort, asc])

  if (isLoading) return <div className="max-w-[1080px] mx-auto px-6 py-24 text-center text-text-muted">Loading…</div>
  if (!user?.is_admin) return <div className="max-w-[560px] mx-auto px-6 py-24 text-center"><h1 className="text-2xl font-extrabold">Admins only</h1></div>

  const th = (k: Key, label: string, right = false) => (
    <th className={`py-1.5 px-2 font-mono cursor-pointer select-none hover:text-text ${right ? 'text-right' : 'text-left'}`} onClick={() => { if (sort === k) setAsc(!asc); else { setSort(k); setAsc(false) } }}>{label}{sort === k ? (asc ? ' ↑' : ' ↓') : ''}</th>
  )

  return (
    <div className="max-w-[1080px] mx-auto px-6 py-14">
      <div className="flex items-baseline justify-between gap-3 flex-wrap">
        <div>
          <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Reply-guy</span>
          <h1 className="mt-2 text-3xl font-extrabold tracking-tight">All replies</h1>
        </div>
        <Link to={rp('/rebrand/admin-dashboard?tab=marketing')} className="text-[12.5px] text-text-muted hover:text-text font-semibold">← Dashboard</Link>
      </div>
      <p className="mt-2 text-text-muted text-[13.5px]">Every reply reply-guy has posted — sort by column, search across platform/handle/content, click to see it live.</p>

      <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search platform, handle, or content…" className="mt-5 w-full max-w-[420px] text-[13.5px] rounded-xl bg-surface border border-border px-3.5 py-2" />

      <div className="mt-4 glass rounded-2xl p-4 overflow-x-auto">
        <table className="w-full text-[12.5px]">
          <thead><tr className="text-text-muted/70">{th('date', 'when')}{th('platform', 'platform')}<th className="py-1.5 px-2 font-mono text-left">reply</th>{th('engagement', '♥ engagement', true)}<th className="py-1.5 px-2 font-mono text-right">link</th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-t border-border/40">
                <td className="py-1.5 px-2 text-text-muted whitespace-nowrap">{when(r.posted_at)}</td>
                <td className="py-1.5 px-2 font-mono">{r.platform}{r.target?.handle && <span className="text-text-muted/60"> @{r.target.handle}</span>}</td>
                <td className="py-1.5 px-2 text-text-muted max-w-[420px] truncate">{r.draft_content}</td>
                <td className="py-1.5 px-2 tabular-nums text-right">{fmt(r.engagement_count)}</td>
                <td className="py-1.5 px-2 text-right">{r.reply_url ? <a href={r.reply_url} target="_blank" rel="noopener" className="text-primary-light hover:text-primary">view ↗</a> : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length && <p className="text-text-muted text-[13px] py-6 text-center">No replies match.</p>}
      </div>
      <p className="mt-2 text-[11.5px] text-text-muted/60">Showing up to 200 most recent.</p>
    </div>
  )
}
