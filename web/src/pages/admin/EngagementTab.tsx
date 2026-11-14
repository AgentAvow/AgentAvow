import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../../lib/api'
import { useToast } from '../../components/Toasts'
import { StatCard } from './StatCard'
import type { ReplyTarget, ReplyOpportunity, EngagementStats } from './types'

type SubTab = 'queue' | 'history' | 'targets' | 'stats'

function urgencyColor(postTimestamp: string | null): string {
  if (!postTimestamp) return 'text-text-muted'
  const mins = (Date.now() - new Date(postTimestamp).getTime()) / 60_000
  if (mins < 15) return 'text-success'
  if (mins < 60) return 'text-warning'
  return 'text-danger'
}

function relativeTime(ts: string | null): string {
  if (!ts) return 'unknown'
  const secs = Math.floor((Date.now() - new Date(ts).getTime()) / 1000)
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

const TIER_STYLES: Record<number, string> = {
  1: 'bg-danger/10 text-danger',
  2: 'bg-warning/10 text-warning',
  3: 'bg-surface-hover text-text-muted',
}

const TIER_LABELS: Record<number, string> = { 1: 'High', 2: 'Medium', 3: 'Low' }

function AvatarCircle({ handle, platform }: { handle: string | null; platform: string | null }) {
  const letter = (handle || '?')[0].toUpperCase()
  const hue = (handle || '').split('').reduce((a, c) => a + c.charCodeAt(0), 0) % 360
  return (
    <div
      className="w-9 h-9 rounded-full flex items-center justify-center text-sm font-bold text-white shrink-0"
      style={{ backgroundColor: `hsl(${hue}, 55%, 45%)` }}
      title={`${platform || ''}: ${handle || ''}`}
    >
      {letter}
    </div>
  )
}

/* ───────── Queue Section ───────── */
function QueueSection() {
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [platformFilter, setPlatformFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('drafted')
  const [offset, setOffset] = useState(0)
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const limit = 20

  const { data, isLoading } = useQuery<{ items: ReplyOpportunity[]; total: number }>({
    queryKey: ['engagement-queue', platformFilter, statusFilter, offset],
    queryFn: async () => {
      const params: Record<string, string | number> = { limit, offset }
      if (platformFilter) params.platform = platformFilter
      if (statusFilter) params.status = statusFilter
      return (await api.get('/admin/engagement/queue', { params })).data
    },
    staleTime: 15_000,
  })

  const actionMutation = useMutation({
    mutationFn: async ({ id, action, draft_content }: { id: string; action: string; draft_content?: string }) =>
      (await api.post(`/admin/engagement/queue/${id}/action`, { action, draft_content })).data,
    onSuccess: (_d, vars) => {
      addToast(`Reply ${vars.action === 'approve' ? 'approved' : 'skipped'}`, 'success')
      queryClient.invalidateQueries({ queryKey: ['engagement-queue'] })
      queryClient.invalidateQueries({ queryKey: ['engagement-stats'] })
    },
    onError: () => addToast('Action failed', 'error'),
  })

  const items = data?.items || []
  const total = data?.total || 0

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex gap-3 items-center flex-wrap">
        <select
          value={platformFilter}
          onChange={(e) => { setPlatformFilter(e.target.value); setOffset(0) }}
          className="bg-background border border-border rounded px-3 py-2 text-sm"
        >
          <option value="">All Platforms</option>
          <option value="bluesky">Bluesky</option>
          <option value="twitter">Twitter</option>
        </select>
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setOffset(0) }}
          className="bg-background border border-border rounded px-3 py-2 text-sm"
        >
          <option value="drafted">Drafted</option>
          <option value="new">New</option>
          <option value="posted">Posted</option>
          <option value="skipped">Skipped</option>
        </select>
        <span className="text-text-muted text-sm ml-auto">{total} total</span>
      </div>

      {isLoading && <div className="text-text-muted text-sm py-10 text-center">Loading queue...</div>}

      {!isLoading && items.length === 0 && (
        <div className="text-center text-text-muted py-16">
          <p className="text-lg font-medium mb-1">No reply opportunities in queue</p>
          <p className="text-sm">Add target accounts to start monitoring.</p>
        </div>
      )}

      {items.map((opp) => {
        const editedDraft = drafts[opp.id] ?? opp.draft_content ?? ''
        return (
          <div key={opp.id} className="bg-surface border border-border rounded-lg p-4">
            <div className="flex gap-3 items-start">
              {/* Left: avatar + handle */}
              <div className="flex flex-col items-center gap-1 min-w-[80px]">
                <AvatarCircle handle={opp.target.handle} platform={opp.target.platform} />
                <span className="text-xs font-medium truncate max-w-[80px]">{opp.target.handle || 'unknown'}</span>
                {opp.target.follower_count > 0 && (
                  <span className="text-[10px] text-text-muted">{opp.target.follower_count.toLocaleString()} followers</span>
                )}
              </div>

              {/* Middle: post content + time */}
              <div className="flex-1 min-w-0">
                <p className="text-sm mb-1 line-clamp-3">
                  {opp.post_content ? (opp.post_content.length > 200 ? opp.post_content.slice(0, 200) + '...' : opp.post_content) : <span className="text-text-muted italic">No content preview</span>}
                </p>
                <span className={`text-xs ${urgencyColor(opp.post_timestamp)}`}>
                  {relativeTime(opp.post_timestamp)}
                </span>

                {/* Draft reply textarea */}
                <textarea
                  className="mt-2 w-full bg-background border border-border rounded px-3 py-2 text-sm resize-y min-h-[60px]"
                  value={editedDraft}
                  onChange={(e) => setDrafts((d) => ({ ...d, [opp.id]: e.target.value }))}
                  placeholder="Draft reply..."
                />
              </div>

              {/* Right: urgency + actions */}
              <div className="flex flex-col items-end gap-2 shrink-0">
                <span className="text-xs font-bold bg-primary/10 text-primary px-2 py-1 rounded">
                  {opp.urgency_score.toFixed(1)}
                </span>
                <button
                  onClick={() => actionMutation.mutate({
                    id: opp.id,
                    action: drafts[opp.id] && drafts[opp.id] !== opp.draft_content ? 'edit' : 'approve',
                    draft_content: drafts[opp.id] || undefined,
                  })}
                  disabled={actionMutation.isPending}
                  className="bg-success/10 text-success hover:bg-success/20 px-3 py-1.5 rounded text-sm cursor-pointer"
                >
                  Approve
                </button>
                <button
                  onClick={() => actionMutation.mutate({ id: opp.id, action: 'skip' })}
                  disabled={actionMutation.isPending}
                  className="bg-danger/10 text-danger hover:bg-danger/20 px-3 py-1.5 rounded text-sm cursor-pointer"
                >
                  Skip
                </button>
              </div>
            </div>
          </div>
        )
      })}

      {/* Load more */}
      {items.length > 0 && offset + limit < total && (
        <button
          onClick={() => setOffset((o) => o + limit)}
          className="bg-primary text-white px-3 py-1.5 rounded text-sm cursor-pointer w-full"
        >
          Load more ({total - offset - limit} remaining)
        </button>
      )}
    </div>
  )
}

/* ───────── History Section ───────── */
function HistorySection() {
  const [platformFilter, setPlatformFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('posted')
  const [offset, setOffset] = useState(0)
  const limit = 20

  const { data, isLoading } = useQuery<{ items: ReplyOpportunity[]; total: number }>({
    queryKey: ['engagement-history', platformFilter, statusFilter, offset],
    queryFn: async () => {
      const params: Record<string, string | number> = { limit, offset, status: statusFilter }
      if (platformFilter) params.platform = platformFilter
      return (await api.get('/admin/engagement/queue', { params })).data
    },
    staleTime: 30_000,
  })

  const items = data?.items || []
  const total = data?.total || 0

  return (
    <div className="space-y-4">
      <div className="flex gap-3 items-center flex-wrap">
        <select
          value={platformFilter}
          onChange={(e) => { setPlatformFilter(e.target.value); setOffset(0) }}
          className="bg-background border border-border rounded px-3 py-2 text-sm"
        >
          <option value="">All Platforms</option>
          <option value="bluesky">Bluesky</option>
          <option value="twitter">Twitter</option>
        </select>
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setOffset(0) }}
          className="bg-background border border-border rounded px-3 py-2 text-sm"
        >
          <option value="posted">Posted</option>
          <option value="skipped">Skipped</option>
        </select>
        <span className="text-text-muted text-sm ml-auto">{total} total</span>
      </div>

      {isLoading && <div className="text-text-muted text-sm py-10 text-center">Loading history...</div>}

      {!isLoading && items.length === 0 && (
        <div className="text-center text-text-muted py-16">
          <p className="text-lg font-medium mb-1">No reply history yet</p>
          <p className="text-sm">Approved replies will appear here.</p>
        </div>
      )}

      {items.map((opp) => (
        <div key={opp.id} className="bg-surface border border-border rounded-lg p-4">
          <div className="flex gap-3 items-start">
            <div className="flex flex-col items-center gap-1 min-w-[80px]">
              <AvatarCircle handle={opp.target.handle} platform={opp.target.platform} />
              <span className="text-xs font-medium truncate max-w-[80px]">{opp.target.handle || 'unknown'}</span>
              <span className="text-[10px] text-text-muted capitalize">{opp.platform}</span>
            </div>

            <div className="flex-1 min-w-0">
              {/* Original post */}
              <p className="text-xs text-text-muted mb-2 line-clamp-2">
                {opp.post_content ? (opp.post_content.length > 150 ? opp.post_content.slice(0, 150) + '...' : opp.post_content) : <span className="italic">No content preview</span>}
              </p>

              {/* Reply content */}
              {opp.draft_content && (
                <div className="bg-background border border-border/50 rounded p-3 mb-2">
                  <p className="text-sm whitespace-pre-wrap">{opp.draft_content}</p>
                </div>
              )}

              <div className="flex items-center gap-3 text-xs text-text-muted">
                {opp.posted_at && <span>{relativeTime(opp.posted_at)}</span>}
                {opp.status === 'posted' && <span className="text-success font-medium">Posted</span>}
                {opp.status === 'skipped' && <span className="text-text-muted font-medium">Skipped</span>}
              </div>
            </div>

            <div className="flex flex-col items-end gap-2 shrink-0">
              {opp.reply_url && (
                <a
                  href={opp.reply_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs bg-primary/10 text-primary hover:bg-primary/20 px-3 py-1.5 rounded inline-flex items-center gap-1"
                >
                  View Reply
                </a>
              )}
              {opp.post_uri && (
                <a
                  href={opp.post_uri.startsWith('http') ? opp.post_uri : `https://bsky.app/profile/${opp.target.handle}/post/${opp.post_uri.split('/').pop()}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs bg-surface-hover text-text-muted hover:text-text px-3 py-1.5 rounded inline-flex items-center gap-1"
                >
                  Original Post
                </a>
              )}
            </div>
          </div>
        </div>
      ))}

      {items.length > 0 && offset + limit < total && (
        <button
          onClick={() => setOffset((o) => o + limit)}
          className="bg-primary text-white px-3 py-1.5 rounded text-sm cursor-pointer w-full"
        >
          Load more ({total - offset - limit} remaining)
        </button>
      )}
    </div>
  )
}

/* ───────── Targets Section ───────── */
function TargetsSection() {
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [showForm, setShowForm] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)
  const [form, setForm] = useState({ platform: 'bluesky', handle: '', display_name: '', follower_count: '', priority_tier: '2', topics: '' })

  const { data: targets, isLoading } = useQuery<ReplyTarget[]>({
    queryKey: ['engagement-targets'],
    queryFn: async () => (await api.get('/admin/engagement/targets')).data,
    staleTime: 30_000,
  })

  const createMutation = useMutation({
    mutationFn: async (body: Record<string, unknown>) => (await api.post('/admin/engagement/targets', body)).data,
    onSuccess: () => {
      addToast('Target added', 'success')
      queryClient.invalidateQueries({ queryKey: ['engagement-targets'] })
      resetForm()
    },
    onError: () => addToast('Failed to add target', 'error'),
  })

  const updateMutation = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      (await api.patch(`/admin/engagement/targets/${id}`, body)).data,
    onSuccess: () => {
      addToast('Target updated', 'success')
      queryClient.invalidateQueries({ queryKey: ['engagement-targets'] })
      resetForm()
    },
    onError: () => addToast('Failed to update target', 'error'),
  })

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => (await api.delete(`/admin/engagement/targets/${id}`)).data,
    onSuccess: () => {
      addToast('Target deleted', 'success')
      queryClient.invalidateQueries({ queryKey: ['engagement-targets'] })
    },
    onError: () => addToast('Failed to delete target', 'error'),
  })

  const toggleMutation = useMutation({
    mutationFn: async ({ id, is_active }: { id: string; is_active: boolean }) =>
      (await api.patch(`/admin/engagement/targets/${id}`, { is_active })).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['engagement-targets'] }),
    onError: () => addToast('Failed to toggle target', 'error'),
  })

  function resetForm() {
    setShowForm(false)
    setEditId(null)
    setForm({ platform: 'bluesky', handle: '', display_name: '', follower_count: '', priority_tier: '2', topics: '' })
  }

  function startEdit(t: ReplyTarget) {
    setEditId(t.id)
    setShowForm(true)
    setForm({
      platform: t.platform,
      handle: t.handle,
      display_name: t.display_name || '',
      follower_count: String(t.follower_count || ''),
      priority_tier: String(t.priority_tier),
      topics: t.topics.join(', '),
    })
  }

  function submitForm() {
    const body: Record<string, unknown> = {
      platform: form.platform,
      handle: form.handle,
      display_name: form.display_name || undefined,
      follower_count: form.follower_count ? Number(form.follower_count) : undefined,
      priority_tier: Number(form.priority_tier),
      topics: form.topics ? form.topics.split(',').map((s) => s.trim()).filter(Boolean) : undefined,
    }
    if (editId) {
      updateMutation.mutate({ id: editId, body })
    } else {
      createMutation.mutate(body)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-sm font-semibold">Monitored Accounts</h3>
        <button
          onClick={() => { if (showForm) resetForm(); else setShowForm(true) }}
          className="bg-primary text-white px-3 py-1.5 rounded text-sm cursor-pointer"
        >
          {showForm ? 'Cancel' : 'Add Target'}
        </button>
      </div>

      {/* Inline form */}
      {showForm && (
        <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <select value={form.platform} onChange={(e) => setForm((f) => ({ ...f, platform: e.target.value }))} className="bg-background border border-border rounded px-3 py-2 text-sm">
              <option value="bluesky">Bluesky</option>
              <option value="twitter">Twitter</option>
            </select>
            <input placeholder="Handle" value={form.handle} onChange={(e) => setForm((f) => ({ ...f, handle: e.target.value }))} className="bg-background border border-border rounded px-3 py-2 text-sm" />
            <input placeholder="Display Name" value={form.display_name} onChange={(e) => setForm((f) => ({ ...f, display_name: e.target.value }))} className="bg-background border border-border rounded px-3 py-2 text-sm" />
            <input placeholder="Follower Count" type="number" value={form.follower_count} onChange={(e) => setForm((f) => ({ ...f, follower_count: e.target.value }))} className="bg-background border border-border rounded px-3 py-2 text-sm" />
            <select value={form.priority_tier} onChange={(e) => setForm((f) => ({ ...f, priority_tier: e.target.value }))} className="bg-background border border-border rounded px-3 py-2 text-sm">
              <option value="1">Tier 1 (High)</option>
              <option value="2">Tier 2 (Medium)</option>
              <option value="3">Tier 3 (Low)</option>
            </select>
            <input placeholder="Topics (comma-separated)" value={form.topics} onChange={(e) => setForm((f) => ({ ...f, topics: e.target.value }))} className="bg-background border border-border rounded px-3 py-2 text-sm" />
          </div>
          <button onClick={submitForm} disabled={!form.handle || createMutation.isPending || updateMutation.isPending} className="bg-primary text-white px-3 py-1.5 rounded text-sm cursor-pointer disabled:opacity-50">
            {editId ? 'Update' : 'Add'}
          </button>
        </div>
      )}

      {isLoading && <div className="text-text-muted text-sm py-10 text-center">Loading targets...</div>}

      {/* Table */}
      {targets && targets.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-text-muted border-b border-border">
                <th className="py-2 pr-3">Platform</th>
                <th className="py-2 pr-3">Handle</th>
                <th className="py-2 pr-3">Name</th>
                <th className="py-2 pr-3">Followers</th>
                <th className="py-2 pr-3">Tier</th>
                <th className="py-2 pr-3">Topics</th>
                <th className="py-2 pr-3">Active</th>
                <th className="py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((t) => (
                <tr key={t.id} className="border-b border-border/50">
                  <td className="py-2 pr-3 capitalize">{t.platform}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{t.handle}</td>
                  <td className="py-2 pr-3">{t.display_name || '-'}</td>
                  <td className="py-2 pr-3">{t.follower_count.toLocaleString()}</td>
                  <td className="py-2 pr-3">
                    <span className={`px-2 py-0.5 rounded text-xs ${TIER_STYLES[t.priority_tier] || TIER_STYLES[3]}`}>
                      {TIER_LABELS[t.priority_tier] || 'Low'}
                    </span>
                  </td>
                  <td className="py-2 pr-3">
                    <div className="flex gap-1 flex-wrap">
                      {t.topics.map((topic) => (
                        <span key={topic} className="bg-surface-hover text-text-muted px-1.5 py-0.5 rounded text-[10px]">{topic}</span>
                      ))}
                    </div>
                  </td>
                  <td className="py-2 pr-3">
                    <button
                      onClick={() => toggleMutation.mutate({ id: t.id, is_active: !t.is_active })}
                      className={`w-8 h-4 rounded-full relative cursor-pointer transition-colors ${t.is_active ? 'bg-success' : 'bg-surface-hover'}`}
                    >
                      <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-transform ${t.is_active ? 'left-4' : 'left-0.5'}`} />
                    </button>
                  </td>
                  <td className="py-2">
                    <div className="flex gap-2">
                      <button onClick={() => startEdit(t)} className="text-primary text-xs hover:underline cursor-pointer">Edit</button>
                      <button
                        onClick={() => { if (confirm(`Delete ${t.handle}?`)) deleteMutation.mutate(t.id) }}
                        className="text-danger text-xs hover:underline cursor-pointer"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {targets && targets.length === 0 && !isLoading && (
        <div className="text-center text-text-muted py-10 text-sm">No targets yet. Click "Add Target" to start monitoring accounts.</div>
      )}
    </div>
  )
}

/* ───────── Stats Section ───────── */
function StatsSection() {
  const { data: stats, isLoading } = useQuery<EngagementStats>({
    queryKey: ['engagement-stats'],
    queryFn: async () => (await api.get('/admin/engagement/stats')).data,
    staleTime: 30_000,
  })

  if (isLoading || !stats) return <div className="text-text-muted text-sm py-10 text-center">Loading stats...</div>

  const counts = stats.status_counts || {}
  const totalPosted = counts.posted || 0
  const barEntries = Object.entries(counts).filter(([, v]) => v > 0)
  const barTotal = barEntries.reduce((s, [, v]) => s + v, 0)

  const statusColors: Record<string, string> = {
    new: 'bg-blue-500',
    drafted: 'bg-warning',
    approved: 'bg-primary',
    posted: 'bg-success',
    skipped: 'bg-surface-hover',
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard label="Posted Today" value={stats.posted_today} />
        <StatCard label="Queue Size" value={stats.queue_size} sub="drafted + new" />
        <StatCard label="Active Targets" value={stats.active_targets} />
        <StatCard label="Total Posted" value={totalPosted} sub="all time" />
      </div>

      {barTotal > 0 && (
        <div>
          <h3 className="text-sm font-semibold mb-2">Status Breakdown</h3>
          <div className="flex h-6 rounded overflow-hidden">
            {barEntries.map(([status, count]) => (
              <div
                key={status}
                className={`${statusColors[status] || 'bg-surface-hover'} relative group`}
                style={{ width: `${(count / barTotal) * 100}%` }}
                title={`${status}: ${count}`}
              >
                <span className="absolute inset-0 flex items-center justify-center text-[10px] text-white font-medium opacity-0 group-hover:opacity-100 transition-opacity">
                  {status} ({count})
                </span>
              </div>
            ))}
          </div>
          <div className="flex gap-4 mt-2 flex-wrap">
            {barEntries.map(([status, count]) => (
              <div key={status} className="flex items-center gap-1.5 text-xs text-text-muted">
                <span className={`w-2.5 h-2.5 rounded-sm ${statusColors[status] || 'bg-surface-hover'}`} />
                <span className="capitalize">{status}</span>
                <span className="font-medium text-text">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

/* ───────── Main Component ───────── */
export default function EngagementTab() {
  const [subTab, setSubTab] = useState<SubTab>('queue')

  const subTabs: { value: SubTab; label: string }[] = [
    { value: 'queue', label: 'Queue' },
    { value: 'history', label: 'History' },
    { value: 'targets', label: 'Targets' },
    { value: 'stats', label: 'Stats' },
  ]

  return (
    <div>
      {/* Sub-tab toggle */}
      <div className="flex gap-1 mb-5 bg-surface-hover/50 rounded-lg p-1 w-fit">
        {subTabs.map((t) => (
          <button
            key={t.value}
            onClick={() => setSubTab(t.value)}
            className={`px-4 py-1.5 rounded text-sm cursor-pointer transition-colors ${
              subTab === t.value ? 'bg-surface text-text font-medium shadow-sm' : 'text-text-muted hover:text-text'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {subTab === 'queue' && <QueueSection />}
      {subTab === 'history' && <HistorySection />}
      {subTab === 'targets' && <TargetsSection />}
      {subTab === 'stats' && <StatsSection />}
    </div>
  )
}
