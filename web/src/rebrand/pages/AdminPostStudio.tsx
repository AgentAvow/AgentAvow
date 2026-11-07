/** Post Studio: Claude drafts a post, Kenne reviews and accepts it, posts it by hand,
 * and records the link so it can be tracked. Nothing here publishes anything. */
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import api from '../../lib/api'

interface Studio {
  id: string; platform: string; topic: string | null; content: string; status: string
  why: string; sources: { label: string; url: string }[]; checks: string[]
  campaign: string; target_url: string; edited: boolean
  history: { at: string; action: string; by: string; note?: string }[]
  external_url: string | null; metrics: Record<string, number>; visits: number
  created_at: string; posted_at: string | null
}
type Action = { action: string; content?: string; reason?: string; url?: string; metrics?: Record<string, number> }

const LIMITS: Record<string, number> = { x: 280, linkedin: 3000 }
const METRICS = ['impressions', 'likes', 'comments', 'shares', 'clicks']
const LABELS: Record<string, string> = { x: 'X', linkedin: 'LinkedIn', reddit: 'Reddit', github: 'GitHub', hackernews: 'Hacker News', other: 'Other' }
const btn = 'px-3 py-1.5 rounded-lg border border-border text-text-muted disabled:opacity-60'
const primary = 'px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60'
const field = 'w-full text-[13px] rounded-lg bg-surface border border-border p-2'

function composer(p: Studio): string | null {
  const text = encodeURIComponent(p.content)
  if (p.platform === 'x') return `https://x.com/intent/post?text=${text}`
  if (p.platform === 'linkedin') return 'https://www.linkedin.com/feed/?shareActive=true'
  if (p.platform === 'hackernews') return 'https://news.ycombinator.com/submit'
  return null
}

function Evidence({ p }: { p: Studio }) {
  if (!p.why && !p.sources.length && !p.checks.length) return null
  return (
    <div className="mt-3 rounded-lg border border-border/60 p-3 text-[12.5px] text-text-muted">
      {p.why && <p><span className="font-semibold text-text">Why this post: </span>{p.why}</p>}
      {p.checks.length > 0 && <ul className="mt-2 list-disc pl-4">{p.checks.map((c) => <li key={c}>{c}</li>)}</ul>}
      {p.sources.length > 0 && (
        <p className="mt-2">Sources: {p.sources.map((s, i) => (
          <span key={s.url}>{i > 0 && ' · '}<a href={s.url} target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary">{s.label}</a></span>
        ))}</p>
      )}
    </div>
  )
}

function PostCard({ p, onDone }: { p: Studio; onDone: () => void }) {
  const [text, setText] = useState(p.content)
  const [reason, setReason] = useState('')
  const [rejecting, setRejecting] = useState(false)
  const [url, setUrl] = useState('')
  const [copied, setCopied] = useState(false)
  const [nums, setNums] = useState<Record<string, string>>(
    Object.fromEntries(METRICS.map((m) => [m, p.metrics[m] != null ? String(p.metrics[m]) : ''])),
  )
  const act = useMutation<unknown, { response?: { data?: { detail?: string } } }, Action>({
    mutationFn: (body) => api.post(`/admin/marketing/studio/posts/${p.id}`, body),
    onSuccess: onDone,
  })
  const limit = LIMITS[p.platform]
  // X counts every link as 23 characters, however long the tracking link is.
  const length = p.platform === 'x' ? text.replace(/https?:\/\/\S+/g, 'x'.repeat(23)).length : text.length
  const over = limit != null && length > limit
  const link = composer(p)
  const copy = async () => {
    await navigator.clipboard.writeText(p.content)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  const saveMetrics = () => act.mutate({
    action: 'metrics',
    metrics: Object.fromEntries(Object.entries(nums).filter(([, v]) => v !== '').map(([k, v]) => [k, Number(v)])),
  })

  return (
    <div className="glass rounded-xl p-4">
      <div className="flex items-center gap-2 text-[11.5px] font-mono text-text-muted mb-2 flex-wrap">
        <span className="px-1.5 py-0.5 rounded bg-primary/15 text-primary-light">{LABELS[p.platform] || p.platform}</span>
        {p.topic && <span>{p.topic}</span>}
        {p.edited && <span className="px-1.5 py-0.5 rounded bg-warning/15 text-warning">edited by you</span>}
        <span className="ml-auto">{new Date(p.posted_at || p.created_at).toLocaleDateString()}</span>
      </div>

      {p.status === 'studio_review' ? (
        <>
          <textarea value={text} onChange={(e) => setText(e.target.value)} rows={Math.min(16, Math.max(5, text.split('\n').length + 2))} className={field} />
          <div className={`mt-1 text-[11.5px] font-mono ${over ? 'text-danger' : 'text-text-muted/70'}`}>{length}{limit ? ` / ${limit}` : ''} characters</div>
        </>
      ) : <p className="text-[13.5px] text-text whitespace-pre-wrap">{p.content}</p>}

      <Evidence p={p} />

      {p.status === 'studio_review' && (
        <div className="mt-3 flex gap-2 flex-wrap text-[12.5px] font-semibold">
          <button onClick={() => act.mutate({ action: 'accept', content: text })} disabled={act.isPending || over} className={primary}>Accept</button>
          <button onClick={() => act.mutate({ action: 'edit', content: text })} disabled={act.isPending || text === p.content} className={btn}>Save edit</button>
          <button onClick={() => setRejecting(!rejecting)} className={`${btn} hover:text-danger`}>Reject</button>
        </div>
      )}
      {rejecting && (
        <div className="mt-2 flex gap-2">
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="What should change? Claude reads this for the next draft." className={field} />
          <button onClick={() => act.mutate({ action: 'reject', reason })} disabled={act.isPending} className={btn}>Confirm</button>
        </div>
      )}

      {p.status === 'studio_accepted' && (
        <>
          <div className="mt-3 flex gap-2 flex-wrap text-[12.5px] font-semibold">
            <button onClick={copy} className={primary}>{copied ? 'Copied' : 'Copy text'}</button>
            {link && <a href={link} target="_blank" rel="noopener noreferrer" className={btn}>Open {LABELS[p.platform]}</a>}
            <button onClick={() => act.mutate({ action: 'reopen' })} disabled={act.isPending} className={btn}>Back to review</button>
          </div>
          <div className="mt-2 flex gap-2">
            <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Paste the link to the live post" className={field} />
            <button onClick={() => act.mutate({ action: 'mark_posted', url })} disabled={act.isPending || !url.trim()} className={`${btn} whitespace-nowrap`}>I posted it</button>
          </div>
        </>
      )}

      {p.status === 'posted' && (
        <div className="mt-3">
          <div className="text-[12.5px] text-text-muted">
            {p.external_url && <a href={p.external_url} target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary font-semibold">Live post</a>}
            {p.campaign && <span>{p.external_url && ' · '}{p.visits} site visits from this link</span>}
          </div>
          <div className="mt-2 grid grid-cols-2 sm:grid-cols-5 gap-2">
            {METRICS.map((m) => (
              <label key={m} className="text-[11.5px] text-text-muted capitalize">{m}
                <input type="number" min={0} value={nums[m]} onChange={(e) => setNums({ ...nums, [m]: e.target.value })} className={field} />
              </label>
            ))}
          </div>
          <button onClick={saveMetrics} disabled={act.isPending} className={`${btn} mt-2 text-[12.5px] font-semibold`}>Save numbers</button>
        </div>
      )}

      {p.status === 'studio_rejected' && (
        <div className="mt-3 flex items-center gap-3 text-[12.5px] text-text-muted">
          <span>{p.history.filter((h) => h.action === 'rejected').slice(-1)[0]?.note || 'No reason given'}</span>
          <button onClick={() => act.mutate({ action: 'reopen' })} disabled={act.isPending} className={`${btn} font-semibold`}>Back to review</button>
        </div>
      )}

      {act.isError && <p className="mt-2 text-[12.5px] text-danger">{act.error.response?.data?.detail || 'That did not save. Try again.'}</p>}
    </div>
  )
}

const GROUPS = [
  { status: 'studio_review', title: 'To review', empty: 'Nothing waiting for you.' },
  { status: 'studio_accepted', title: 'Ready to post', empty: 'Nothing accepted yet.' },
  { status: 'posted', title: 'Posted', empty: 'Nothing posted yet.' },
  { status: 'studio_rejected', title: 'Rejected', empty: 'Nothing rejected.' },
]

export default function PostStudioTab() {
  const qc = useQueryClient()
  const posts = useQuery<Studio[]>({
    queryKey: ['admin-post-studio'],
    queryFn: async () => (await api.get('/admin/marketing/studio/posts')).data,
  })
  const onDone = () => qc.invalidateQueries({ queryKey: ['admin-post-studio'] })
  if (posts.isError) return <p className="mt-10 text-danger text-[13px]">Posts did not load. Refresh to try again.</p>
  if (posts.isLoading) return <p className="mt-10 text-text-muted text-[13px]">Loading…</p>
  return (
    <div>
      <p className="mt-6 text-text-muted text-[13px] max-w-[70ch]">Claude writes drafts here. Nothing is published from this page: accept a post, post it yourself, then paste the link so it can be tracked.</p>
      {GROUPS.map((g) => {
        const rows = (posts.data || []).filter((p) => p.status === g.status)
        return (
          <section key={g.status} className="mt-8">
            <h2 className="text-lg font-bold">{g.title} <span className="text-text-muted font-normal text-[14px]">{rows.length}</span></h2>
            <div className="mt-3 flex flex-col gap-3">
              {rows.length ? rows.map((p) => <PostCard key={`${p.id}-${p.status}`} p={p} onDone={onDone} />) : <p className="text-text-muted text-[13px]">{g.empty}</p>}
            </div>
          </section>
        )
      })}
    </div>
  )
}
