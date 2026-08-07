import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../../lib/api'
import { useToast } from '../../components/Toasts'
import { timeAgo } from '../../lib/formatters'
import { InlineSkeleton } from '../../components/Skeleton'
import { StatCard } from './StatCard'
import { PLATFORM_DESTINATIONS } from './types'
import type {
  MarketingDashboard,
  MarketingDraft,
  MarketingHealth,
  CampaignProposal,
  CampaignDetail,
  ActivityItem,
  BotActivity,
} from './types'

// Platforms where the human posts manually (we never auto-post via an API):
// content is authored/approved here, then posted by hand and marked posted.
const MANUAL_POST_PLATFORMS = ['reddit', 'hackernews', 'producthunt', 'linkedin']

function renderPlaybookValue(val: unknown) {
  if (Array.isArray(val)) {
    return (
      <ul className="list-disc list-inside space-y-0.5">
        {val.map((item, i) => {
          if (item && typeof item === 'object' && 'url' in (item as Record<string, unknown>)) {
            const o = item as { url: string; anchor?: string }
            return (
              <li key={i}>
                <a href={o.url} target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary-light hover:underline">{o.anchor || o.url}</a>
              </li>
            )
          }
          return <li key={i} className="text-text/70">{String(item)}</li>
        })}
      </ul>
    )
  }
  const s = String(val)
  if (/^https?:\/\//.test(s)) {
    return <a href={s} target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary-light hover:underline">{s}</a>
  }
  return <span className="text-text/70 whitespace-pre-wrap">{s}</span>
}

// Hacker News submissions need a strict shape or they get flagged: a Show HN
// title (≤80 chars), the URL in the *url* field, an (almost always empty) body,
// and a substantive first comment. This renders that contract explicitly so the
// format can't drift back into "paste this body" (which gets insta-flagged).
const HN_FIELD_KEYS = ['title', 'url', 'body', 'first_comment']

function HNContract({ playbook }: { playbook: Record<string, unknown> }) {
  const title = playbook.title != null ? String(playbook.title) : ''
  const url = playbook.url != null ? String(playbook.url) : ''
  const body = playbook.body != null ? String(playbook.body) : ''
  const firstComment = playbook.first_comment != null ? String(playbook.first_comment) : ''
  const titleOver = title.length > 80
  const refEntries = Object.entries(playbook).filter(([k]) => !HN_FIELD_KEYS.includes(k))

  const Copy = ({ text }: { text: string }) =>
    text ? (
      <button
        type="button"
        onClick={() => navigator.clipboard?.writeText(text)}
        className="text-[10px] text-blue-400 hover:text-blue-300 ml-2"
      >copy</button>
    ) : null

  return (
    <div className="mb-3 bg-orange-500/5 border border-orange-500/25 rounded-lg px-3 py-2.5 space-y-2.5">
      <p className="text-[10px] text-orange-400 uppercase tracking-wider">🟠 Hacker News — Show HN submission</p>

      {/* 1. Title */}
      <div>
        <div className="flex items-center justify-between">
          <p className="text-[10px] text-text-muted uppercase tracking-wider">1 · Title (the headline)</p>
          <span className={`text-[10px] font-mono ${titleOver ? 'text-red-400' : 'text-text-muted'}`}>{title.length}/80{titleOver ? ' — TOO LONG' : ''}</span>
        </div>
        <div className="flex items-start">
          <p className="text-xs font-mono whitespace-pre-wrap flex-1 text-text/90">{title || <span className="text-text-muted italic">— not set —</span>}</p>
          <Copy text={title} />
        </div>
      </div>

      {/* 2. URL */}
      <div>
        <p className="text-[10px] text-text-muted uppercase tracking-wider">2 · URL (goes in HN's "url" field — not the body)</p>
        <div className="flex items-center">
          {url
            ? <a href={url} target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline flex-1 break-all">{url}</a>
            : <span className="text-xs text-text-muted italic flex-1">— not set —</span>}
          <Copy text={url} />
        </div>
      </div>

      {/* 3. Body */}
      <div>
        <p className="text-[10px] text-text-muted uppercase tracking-wider">3 · Post body</p>
        {body.trim()
          ? <div className="flex items-start"><p className="text-xs whitespace-pre-wrap flex-1 text-text/80">{body}</p><Copy text={body} /></div>
          : <p className="text-xs text-green-400/80 italic">Leave empty ✓ — Show HN with a URL doesn&apos;t need body copy (and body copy reads as promo → flagged).</p>}
      </div>

      {/* 4. First comment */}
      <div>
        <p className="text-[10px] text-text-muted uppercase tracking-wider">4 · First comment (post immediately — this is where the substance goes)</p>
        <div className="flex items-start">
          <p className="text-xs whitespace-pre-wrap flex-1 text-text/80">{firstComment || <span className="text-text-muted italic">— not set —</span>}</p>
          <Copy text={firstComment} />
        </div>
      </div>

      {/* Reference (alternatives, pre-scanned, talking points, checklist) */}
      {refEntries.length > 0 && (
        <details className="pt-1 border-t border-orange-500/15">
          <summary className="text-[10px] text-text-muted uppercase tracking-wider cursor-pointer">Reference (alternatives, pre-scanned, talking points, checklist)</summary>
          <div className="space-y-2 mt-2">
            {refEntries.map(([key, val]) => (
              <div key={key}>
                <p className="text-[10px] text-text-muted uppercase tracking-wider mb-0.5">{key.replace(/_/g, ' ')}</p>
                <div className="text-xs">{renderPlaybookValue(val)}</div>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  )
}

// Renders per-platform posting guidance. HN gets the strict 4-field contract
// above; every other platform gets the generic key/value list.
function PlaybookBox({ playbook, platform }: { playbook?: Record<string, unknown> | null; platform?: string }) {
  if (!playbook || Object.keys(playbook).length === 0) return null
  if (platform === 'hackernews') return <HNContract playbook={playbook} />
  return (
    <div className="mb-3 bg-blue-400/5 border border-blue-400/20 rounded-lg px-3 py-2">
      <p className="text-[10px] text-blue-400 uppercase tracking-wider mb-1.5">📋 Posting playbook</p>
      <div className="space-y-2">
        {Object.entries(playbook).map(([key, val]) => (
          <div key={key}>
            <p className="text-[10px] text-text-muted uppercase tracking-wider mb-0.5">{key.replace(/_/g, ' ')}</p>
            <div className="text-xs">{renderPlaybookValue(val)}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function MarketingTab() {
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [draftEditContent, setDraftEditContent] = useState('')
  const [editingDraftId, setEditingDraftId] = useState<string | null>(null)
  const [draftPlatformFilter, setDraftPlatformFilter] = useState<string>('')
  const [draftStatusFilter, setDraftStatusFilter] = useState<string>('human_review')
  const [previewDraft, setPreviewDraft] = useState<MarketingDraft | null>(null)
  const [expandedCampaignId, setExpandedCampaignId] = useState<string | null>(null)
  const [campaignDeselected, setCampaignDeselected] = useState<Set<number>>(new Set())
  const [rejectFeedback, setRejectFeedback] = useState('')
  const [rejectingCampaignId, setRejectingCampaignId] = useState<string | null>(null)
  const [activityFilter, setActivityFilter] = useState<'all' | 'posted' | 'pending' | 'failed'>('all')
  const [markPostedId, setMarkPostedId] = useState<string | null>(null)
  const [markPostedUrl, setMarkPostedUrl] = useState('')

  const { data: mktDashboard, isLoading: mktLoading } = useQuery<MarketingDashboard>({
    queryKey: ['admin-marketing-dashboard'],
    queryFn: async () => (await api.get('/admin/marketing/dashboard')).data,
    staleTime: 2 * 60_000,
  })

  const { data: mktDrafts } = useQuery<MarketingDraft[]>({
    queryKey: ['admin-marketing-drafts', draftPlatformFilter, draftStatusFilter],
    queryFn: async () => {
      const params: Record<string, string> = {}
      if (draftPlatformFilter) params.platform = draftPlatformFilter
      if (draftStatusFilter) params.status = draftStatusFilter
      else params.status = 'human_review,draft,planned'
      return (await api.get('/admin/marketing/drafts', { params })).data
    },
    staleTime: 30_000,
  })

  const { data: mktHealth } = useQuery<MarketingHealth>({
    queryKey: ['admin-marketing-health'],
    queryFn: async () => (await api.get('/admin/marketing/health')).data,
    staleTime: 60_000,
  })

  const draftActionMutation = useMutation({
    mutationFn: async ({ postId, action, content, posted_url }: { postId: string; action: string; content?: string; posted_url?: string }) => {
      return (await api.post(`/admin/marketing/drafts/${postId}`, { action, content, posted_url })).data
    },
    onSuccess: (_data, vars) => {
      const msg = vars.action === 'approve' ? 'approved' : vars.action === 'reject' ? 'rejected' : vars.action === 'mark_posted' ? 'marked as posted' : 'edited & approved'
      addToast(`Draft ${msg}`, 'success')
      setEditingDraftId(null)
      setDraftEditContent('')
      setMarkPostedId(null)
      setMarkPostedUrl('')
      queryClient.invalidateQueries({ queryKey: ['admin-marketing-drafts'] })
      queryClient.invalidateQueries({ queryKey: ['admin-marketing-dashboard'] })
    },
    onError: () => { addToast('Failed to update draft', 'error') },
  })

  const triggerMarketingMutation = useMutation({
    mutationFn: async () => (await api.post('/admin/marketing/trigger')).data,
    onSuccess: () => {
      addToast('Marketing tick triggered', 'success')
      queryClient.invalidateQueries({ queryKey: ['admin-marketing-dashboard'] })
      queryClient.invalidateQueries({ queryKey: ['admin-marketing-drafts'] })
    },
    onError: () => { addToast('Failed to trigger marketing tick', 'error') },
  })

  const triggerPlatformMutation = useMutation({
    mutationFn: async (platform: string) => (await api.post(`/admin/marketing/trigger/${platform}`)).data,
    onSuccess: (data: Record<string, unknown>, platform: string) => {
      addToast(`Draft created for ${platform}`, 'success')
      queryClient.invalidateQueries({ queryKey: ['admin-marketing-drafts'] })
      queryClient.invalidateQueries({ queryKey: ['admin-marketing-dashboard'] })
      // Show preview modal if draft content was returned
      if (data.draft && typeof data.draft === 'object') {
        const d = data.draft as Record<string, unknown>
        setPreviewDraft({
          id: String(d.id ?? ''),
          platform: String(d.platform ?? ''),
          content: String(d.content ?? ''),
          topic: d.topic ? String(d.topic) : null,
          post_type: String(d.post_type ?? ''),
          status: String(d.status ?? ''),
          llm_model: d.llm_model ? String(d.llm_model) : null,
          created_at: String(d.created_at ?? ''),
          image_url: d.image_url ? String(d.image_url) : null,
          destination: d.destination ? String(d.destination) : null,
          parent_external_id: d.parent_external_id ? String(d.parent_external_id) : null,
          scheduled_day: d.scheduled_day ? String(d.scheduled_day) : null,
          thread_url: d.thread_url ? String(d.thread_url) : null,
          thread_title: d.thread_title ? String(d.thread_title) : null,
        })
      }
    },
    onError: (_err, platform) => { addToast(`Failed to trigger ${platform}`, 'error') },
  })

  const { data: proposedCampaigns, refetch: refetchCampaigns } = useQuery<CampaignProposal[]>({
    queryKey: ['admin-campaigns-proposed'],
    queryFn: async () => (await api.get('/admin/marketing/campaigns/proposed')).data,
    staleTime: 30_000,
  })

  const { data: expandedCampaign } = useQuery<CampaignDetail>({
    queryKey: ['admin-campaign-detail', expandedCampaignId],
    queryFn: async () => (await api.get(`/admin/marketing/campaigns/${expandedCampaignId}`)).data,
    enabled: !!expandedCampaignId,
    staleTime: 30_000,
  })

  const generateCampaignMutation = useMutation({
    mutationFn: async () => (await api.post('/admin/marketing/campaigns/generate', {}, { timeout: 120_000 })).data,
    onSuccess: () => {
      addToast('Campaign plan generated', 'success')
      queryClient.invalidateQueries({ queryKey: ['admin-campaigns-proposed'] })
      queryClient.invalidateQueries({ queryKey: ['admin-marketing-dashboard'] })
    },
    onError: () => { addToast('Failed to generate campaign plan', 'error') },
  })

  const approveCampaignMutation = useMutation({
    mutationFn: async ({ campaignId, approvedIndices }: { campaignId: string; approvedIndices?: number[] }) => {
      return (await api.post(`/admin/marketing/campaigns/${campaignId}/approve`, approvedIndices ? { approved_post_indices: approvedIndices } : {})).data
    },
    onSuccess: () => {
      addToast('Campaign approved', 'success')
      setExpandedCampaignId(null)
      setCampaignDeselected(new Set())
      refetchCampaigns()
      queryClient.invalidateQueries({ queryKey: ['admin-marketing-dashboard'] })
    },
    onError: () => { addToast('Failed to approve campaign', 'error') },
  })

  const rejectCampaignMutation = useMutation({
    mutationFn: async ({ campaignId, feedback }: { campaignId: string; feedback: string }) => {
      return (await api.post(`/admin/marketing/campaigns/${campaignId}/reject`, { feedback })).data
    },
    onSuccess: () => {
      addToast('Campaign rejected', 'success')
      setExpandedCampaignId(null)
      setRejectingCampaignId(null)
      setRejectFeedback('')
      refetchCampaigns()
    },
    onError: () => { addToast('Failed to reject campaign', 'error') },
  })

  // ─── Bot Activity query ───

  const { data: botActivity, isLoading: activityLoading } = useQuery<BotActivity>({
    queryKey: ['admin-bot-activity'],
    queryFn: async () => (await api.get('/admin/marketing/activity')).data,
    staleTime: 30_000,
  })

  const { data: engage } = useQuery<{
    news: { title: string; source: string; url: string; summary: string; angle: string; draft: string }[]
    posts: { platform: string; handle: string; snippet: string; url: string; angle: string; draft: string }[]
  }>({
    queryKey: ['admin-marketing-comment-worthy'],
    queryFn: async () => (await api.get('/admin/marketing/comment-worthy')).data,
    staleTime: 5 * 60_000,
  })

  return (
    <div className="space-y-6">
      {mktLoading ? (
        <div className="py-10"><InlineSkeleton /></div>
      ) : (
        <>
          {/* Health & Controls */}
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => triggerMarketingMutation.mutate()}
              disabled={triggerMarketingMutation.isPending}
              className="bg-primary hover:bg-primary-dark text-white px-4 py-2 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
            >
              {triggerMarketingMutation.isPending ? 'Running...' : 'Trigger Marketing Tick'}
            </button>
            {mktHealth && (
              <div className="flex flex-wrap gap-2 text-xs">
                <span className={`px-2 py-1 rounded ${mktHealth.marketing_enabled ? 'bg-success/10 text-success' : 'bg-danger/10 text-danger'}`}>
                  {mktHealth.marketing_enabled ? 'Enabled' : 'Disabled'}
                </span>
                <span className={`px-2 py-1 rounded ${mktHealth.anthropic_configured ? 'bg-success/10 text-success' : 'bg-warning/10 text-warning'}`}>
                  {mktHealth.anthropic_configured ? 'Anthropic OK' : 'No Anthropic Key'}
                </span>
                <span className={`px-2 py-1 rounded ${mktHealth.ollama_available ? 'bg-success/10 text-success' : 'bg-surface-hover text-text-muted'}`}>
                  {mktHealth.ollama_available ? 'Ollama OK' : 'Ollama Offline'}
                </span>
                <span className="px-2 py-1 rounded bg-surface-hover text-text-muted">
                  Today: ${mktHealth.daily_spend_usd.toFixed(4)}
                </span>
                <span className="px-2 py-1 rounded bg-surface-hover text-text-muted">
                  Month: ${mktHealth.monthly_spend_usd.toFixed(4)}
                </span>
              </div>
            )}
          </div>

          {/* Engage — comment-worthy this week (personal engagement, the high-ROI lever) */}
          {engage && ((engage.news?.length ?? 0) > 0 || (engage.posts?.length ?? 0) > 0) ? (
            <div>
              <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-1">💬 Engage — comment-worthy this week</h2>
              <p className="text-xs text-text-muted mb-3">Your <b>personal</b> voice on these beats another scheduled post — post a take on LinkedIn or comment in-thread. (No LinkedIn post-search API, so these are events + tracked-account activity to engage with, not LinkedIn posts.)</p>
              <div className="grid gap-3 md:grid-cols-2">
                <div className="bg-emerald-400/5 border border-emerald-400/20 rounded-lg p-3">
                  <p className="text-[10px] uppercase tracking-wider text-emerald-400 mb-2">📰 News — post a take</p>
                  <ul className="space-y-2">
                    {(engage.news ?? []).map((n, i) => (
                      <li key={i} className="text-xs">
                        <a href={n.url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline font-medium">{n.title}</a>
                        {n.source ? <span className="text-text-muted"> · {n.source}</span> : null}
                        {n.angle ? <p className="text-emerald-300/80 italic mt-0.5">↳ {n.angle}</p> : null}
                        {n.draft ? (
                          <div className="mt-1 bg-black/20 rounded p-2">
                            <p className="text-text/80 whitespace-pre-wrap">{n.draft}</p>
                            <button onClick={() => navigator.clipboard?.writeText(n.draft)} className="text-[10px] text-emerald-400 hover:text-emerald-300 mt-1 cursor-pointer">📋 copy</button>
                          </div>
                        ) : (n.summary ? <p className="text-text/70 mt-0.5">{n.summary}</p> : null)}
                      </li>
                    ))}
                    {(engage.news?.length ?? 0) === 0 ? <li className="text-xs text-text-muted">No fresh news signals.</li> : null}
                  </ul>
                </div>
                <div className="bg-emerald-400/5 border border-emerald-400/20 rounded-lg p-3">
                  <p className="text-[10px] uppercase tracking-wider text-emerald-400 mb-2">💬 Posts to comment on</p>
                  <ul className="space-y-2">
                    {(engage.posts ?? []).map((p, i) => (
                      <li key={i} className="text-xs">
                        <span className="font-medium">[{p.platform}] {p.handle}</span>
                        {p.url ? <a href={p.url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline ml-1">open</a> : null}
                        {p.snippet ? <p className="text-text/70 mt-0.5">“{p.snippet}…”</p> : null}
                        {p.angle ? <p className="text-emerald-300/80 italic mt-0.5">↳ {p.angle}</p> : null}
                        {p.draft ? (
                          <div className="mt-1 bg-black/20 rounded p-2">
                            <p className="text-text/80 whitespace-pre-wrap">{p.draft}</p>
                            <button onClick={() => navigator.clipboard?.writeText(p.draft)} className="text-[10px] text-emerald-400 hover:text-emerald-300 mt-1 cursor-pointer">📋 copy</button>
                          </div>
                        ) : null}
                      </li>
                    ))}
                    {(engage.posts?.length ?? 0) === 0 ? <li className="text-xs text-text-muted">No flagged posts right now.</li> : null}
                  </ul>
                </div>
              </div>
            </div>
          ) : null}

          {/* Campaign Planner */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider">Campaign Planner</h2>
              <button
                onClick={() => generateCampaignMutation.mutate()}
                disabled={generateCampaignMutation.isPending}
                className="text-xs bg-primary/10 text-primary hover:bg-primary/20 px-3 py-1.5 rounded cursor-pointer disabled:opacity-50"
              >
                {generateCampaignMutation.isPending ? 'Generating...' : 'Generate Weekly Plan'}
              </button>
            </div>

            {proposedCampaigns && proposedCampaigns.length > 0 ? (
              <div className="space-y-3">
                {proposedCampaigns.map((campaign) => (
                  <div key={campaign.id} className="bg-surface border border-border rounded-lg overflow-hidden">
                    {/* Campaign header */}
                    <button
                      onClick={() => {
                        if (expandedCampaignId === campaign.id) {
                          setExpandedCampaignId(null)
                        } else {
                          setExpandedCampaignId(campaign.id)
                          setCampaignDeselected(new Set())
                          setRejectingCampaignId(null)
                        }
                      }}
                      className="w-full flex items-center justify-between p-4 text-left hover:bg-surface-hover/50 transition-colors cursor-pointer"
                    >
                      <div>
                        <div className="text-sm font-medium">{campaign.name}</div>
                        <div className="text-xs text-text-muted mt-0.5">
                          {campaign.platforms.map(p => p.charAt(0).toUpperCase() + p.slice(1)).join(', ')}
                          {campaign.start_date && <span className="ml-2">| Starts {campaign.start_date}</span>}
                        </div>
                      </div>
                      <span className="text-xs px-2 py-1 rounded bg-warning/10 text-warning">Proposed</span>
                    </button>

                    {/* Expanded campaign detail */}
                    {expandedCampaignId === campaign.id && expandedCampaign && (
                      <div className="border-t border-border p-4 space-y-4">
                        {/* Strategy summary */}
                        {expandedCampaign.schedule_config?.strategy_summary && (
                          <div className="text-sm text-text-muted bg-surface-hover/50 rounded-lg p-3">
                            {expandedCampaign.schedule_config.strategy_summary}
                          </div>
                        )}

                        {/* News hooks */}
                        {expandedCampaign.schedule_config?.news_hooks && expandedCampaign.schedule_config.news_hooks.length > 0 && (
                          <div>
                            <div className="text-xs font-semibold text-text-muted mb-2">News Hooks</div>
                            <div className="flex flex-wrap gap-2">
                              {expandedCampaign.schedule_config.news_hooks.map((h, i) => (
                                <span key={i} className="text-[10px] px-2 py-1 rounded bg-primary/10 text-primary">{h.title}</span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Planned posts with checkboxes */}
                        {expandedCampaign.schedule_config?.posts && (
                          <div>
                            <div className="text-xs font-semibold text-text-muted mb-2">
                              Planned Posts ({expandedCampaign.schedule_config.posts.length - campaignDeselected.size} of {expandedCampaign.schedule_config.posts.length} selected)
                            </div>
                            <div className="space-y-2">
                              {expandedCampaign.schedule_config.posts.map((post, idx) => (
                                <label key={idx} className={`flex gap-3 p-3 rounded-lg border transition-colors cursor-pointer ${campaignDeselected.has(idx) ? 'border-border/50 opacity-50' : 'border-border bg-surface-hover/30'}`}>
                                  <input
                                    type="checkbox"
                                    checked={!campaignDeselected.has(idx)}
                                    onChange={() => {
                                      const next = new Set(campaignDeselected)
                                      if (next.has(idx)) next.delete(idx)
                                      else next.add(idx)
                                      setCampaignDeselected(next)
                                    }}
                                    className="mt-0.5 accent-primary"
                                  />
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 flex-wrap">
                                      <span className="text-xs font-medium capitalize bg-primary/10 text-primary px-1.5 py-0.5 rounded">{post.platform}</span>
                                      {post.day && <span className="text-[10px] text-text-muted capitalize">{post.day}</span>}
                                      {post.value_type && <span className="text-[10px] text-text-muted/60">{post.value_type.replace('_', ' ')}</span>}
                                    </div>
                                    <div className="text-sm mt-1">{post.topic}</div>
                                    <div className="text-xs text-text-muted mt-0.5">{post.angle}</div>
                                    {post.why && <div className="text-[10px] text-text-muted/60 mt-1 italic">{post.why}</div>}
                                  </div>
                                </label>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Budget + avoid */}
                        <div className="flex flex-wrap gap-4 text-xs text-text-muted">
                          {expandedCampaign.schedule_config?.budget_estimate_usd != null && (
                            <span>Est. budget: ${expandedCampaign.schedule_config.budget_estimate_usd.toFixed(2)}</span>
                          )}
                          {expandedCampaign.schedule_config?.avoid_this_week && expandedCampaign.schedule_config.avoid_this_week.length > 0 && (
                            <span>Avoiding: {expandedCampaign.schedule_config.avoid_this_week.length} topics</span>
                          )}
                        </div>

                        {/* Reject feedback */}
                        {rejectingCampaignId === campaign.id && (
                          <div className="flex gap-2">
                            <input
                              type="text"
                              value={rejectFeedback}
                              onChange={e => setRejectFeedback(e.target.value)}
                              placeholder="Feedback for regeneration..."
                              className="flex-1 text-sm bg-surface-hover border border-border rounded px-3 py-1.5"
                            />
                            <button
                              onClick={() => rejectCampaignMutation.mutate({ campaignId: campaign.id, feedback: rejectFeedback })}
                              disabled={!rejectFeedback.trim() || rejectCampaignMutation.isPending}
                              className="text-xs bg-danger/10 text-danger hover:bg-danger/20 px-3 py-1.5 rounded cursor-pointer disabled:opacity-50"
                            >
                              Confirm Reject
                            </button>
                            <button
                              onClick={() => { setRejectingCampaignId(null); setRejectFeedback('') }}
                              className="text-xs text-text-muted hover:text-text px-2 py-1.5 cursor-pointer"
                            >
                              Cancel
                            </button>
                          </div>
                        )}

                        {/* Approve / Reject buttons */}
                        {rejectingCampaignId !== campaign.id && (
                          <div className="flex gap-2">
                            <button
                              onClick={() => {
                                const totalPosts = expandedCampaign.schedule_config?.posts?.length ?? 0
                                const approvedIndices = Array.from({ length: totalPosts }, (_, i) => i).filter(i => !campaignDeselected.has(i))
                                approveCampaignMutation.mutate({
                                  campaignId: campaign.id,
                                  approvedIndices: campaignDeselected.size > 0 ? approvedIndices : undefined,
                                })
                              }}
                              disabled={approveCampaignMutation.isPending}
                              className="text-xs bg-success/10 text-success hover:bg-success/20 px-4 py-2 rounded cursor-pointer disabled:opacity-50"
                            >
                              {approveCampaignMutation.isPending ? 'Approving...' : `Approve${campaignDeselected.size > 0 ? ` (${(expandedCampaign.schedule_config?.posts?.length ?? 0) - campaignDeselected.size} posts)` : ' All'}`}
                            </button>
                            <button
                              onClick={() => setRejectingCampaignId(campaign.id)}
                              className="text-xs bg-danger/10 text-danger hover:bg-danger/20 px-4 py-2 rounded cursor-pointer"
                            >
                              Reject
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-text-muted bg-surface border border-border rounded-lg p-4 text-center">
                No proposed campaigns. Generate a weekly plan to get started.
              </div>
            )}
          </div>

          {/* Drafts Queue */}
          <div>
            <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
              <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider">
                Drafts Queue {mktDrafts ? `(${mktDrafts.length})` : ''}
              </h2>
              <div className="flex gap-2">
                <select
                  value={draftStatusFilter}
                  onChange={e => setDraftStatusFilter(e.target.value)}
                  className="text-xs bg-surface-hover border border-border rounded px-2 py-1"
                >
                  <option value="human_review">Needs Review</option>
                  <option value="human_review,draft">Review + Draft</option>
                  <option value="draft">Draft Only</option>
                  <option value="">All</option>
                </select>
                <select
                  value={draftPlatformFilter}
                  onChange={e => setDraftPlatformFilter(e.target.value)}
                  className="text-xs bg-surface-hover border border-border rounded px-2 py-1"
                >
                  <option value="">All Platforms</option>
                  {mktHealth && Object.keys(mktHealth.adapters).map(p => (
                    <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>
                  ))}
                </select>
              </div>
            </div>
            {mktDrafts && mktDrafts.length > 0 ? (
              <div className="space-y-3">
                {mktDrafts.map((draft) => (
                  <div key={draft.id} className="bg-surface border border-border rounded-lg p-4">
                    {/* Header: platform badge + destination + status + time */}
                    <div className="flex flex-wrap items-center gap-2 mb-2">
                      <span className="font-medium capitalize text-xs bg-primary/10 text-primary px-2 py-0.5 rounded">{draft.platform}</span>
                      {draft.platform === 'reddit' ? (
                        <span className="text-[10px] flex gap-1.5">
                          {['artificial', 'MachineLearning', 'LangChain', 'LocalLLaMA'].map(sub => (
                            <a key={sub} href={`https://www.reddit.com/r/${sub}/submit`} target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary-light hover:underline">r/{sub}</a>
                          ))}
                        </span>
                      ) : (
                        <span className="text-[10px] text-text-muted">{PLATFORM_DESTINATIONS[draft.platform] ?? draft.platform}</span>
                      )}
                      {draft.topic && <span className="text-[10px] bg-surface-hover text-text-muted px-1.5 py-0.5 rounded capitalize">{draft.topic}</span>}
                      {draft.post_type === 'reactive' && <span className="text-[10px] bg-warning/10 text-warning px-1.5 py-0.5 rounded">Reply</span>}
                      <span className={`ml-auto text-[10px] px-1.5 py-0.5 rounded ${
                        draft.status === 'human_review' ? 'bg-warning/10 text-warning' :
                        draft.status === 'planned' ? 'bg-blue-400/10 text-blue-400' :
                        draft.status === 'draft' ? 'bg-surface-hover text-text-muted' :
                        'bg-primary/10 text-primary'
                      }`}>
                        {draft.status === 'human_review' ? 'Needs Review' : draft.status === 'planned' ? 'Planned' : draft.status}
                      </span>
                      {draft.scheduled_day && (
                        <span className="text-[10px] text-blue-400">{draft.scheduled_day}</span>
                      )}
                      <span className="text-[10px] text-text-muted">{timeAgo(draft.created_at)}</span>
                    </div>

                    {/* Thread link for reactive posts */}
                    {draft.thread_url && (
                      <div className="mb-2 bg-primary/5 border border-primary/20 rounded-lg px-3 py-2">
                        <p className="text-[10px] text-text-muted uppercase tracking-wider mb-1">Reply to this thread:</p>
                        <a href={draft.thread_url} target="_blank" rel="noopener noreferrer" className="text-sm text-primary hover:text-primary-light hover:underline font-medium">
                          {draft.thread_title || draft.thread_url}
                        </a>
                      </div>
                    )}

                    {/* Card image preview */}
                    {draft.image_url && (
                      <div className="mb-3">
                        <p className="text-[10px] text-text-muted mb-1.5">Post card image:</p>
                        <img src={draft.image_url} alt="Post card" className="w-full max-w-[400px] rounded-lg border border-border" />
                      </div>
                    )}

                    {/* Content preview */}
                    <pre className="text-sm whitespace-pre-wrap font-sans leading-relaxed text-text/80 max-h-[200px] overflow-y-auto bg-surface-hover rounded-lg p-3">{draft.content}</pre>

                    {/* Per-platform posting playbook (HN talking points, LinkedIn featured links, etc.) */}
                    <div className="mt-3"><PlaybookBox playbook={draft.playbook} platform={draft.platform} /></div>

                    {/* Actions */}
                    <div className="flex flex-wrap gap-2 mt-3 pt-3 border-t border-border/50">
                      {MANUAL_POST_PLATFORMS.includes(draft.platform) ? (
                        <>
                          {markPostedId === draft.id ? (
                            <div className="flex items-center gap-2 w-full">
                              <input
                                type="url"
                                placeholder="Paste the URL where you posted (optional)"
                                value={markPostedUrl}
                                onChange={e => setMarkPostedUrl(e.target.value)}
                                className="flex-1 text-xs bg-surface-hover border border-border rounded px-2 py-1.5 focus:outline-none focus:border-primary"
                              />
                              <button
                                onClick={() => draftActionMutation.mutate({ postId: draft.id, action: 'mark_posted', posted_url: markPostedUrl || undefined })}
                                disabled={draftActionMutation.isPending}
                                className="text-xs bg-success/10 text-success hover:bg-success/20 px-3 py-1.5 rounded cursor-pointer disabled:opacity-50 whitespace-nowrap"
                              >
                                Confirm
                              </button>
                              <button
                                onClick={() => { setMarkPostedId(null); setMarkPostedUrl('') }}
                                className="text-xs text-text-muted hover:text-text px-2 py-1.5 cursor-pointer"
                              >
                                Cancel
                              </button>
                            </div>
                          ) : (
                            <button
                              onClick={() => setMarkPostedId(draft.id)}
                              className="text-xs bg-success/10 text-success hover:bg-success/20 px-3 py-1.5 rounded cursor-pointer disabled:opacity-50"
                            >
                              Manually Posted
                            </button>
                          )}
                        </>
                      ) : (
                        <button
                          onClick={() => draftActionMutation.mutate({ postId: draft.id, action: 'approve' })}
                          disabled={draftActionMutation.isPending}
                          className="text-xs bg-success/10 text-success hover:bg-success/20 px-3 py-1.5 rounded cursor-pointer disabled:opacity-50"
                        >
                          Approve & Post
                        </button>
                      )}
                      <button
                        onClick={() => { setEditingDraftId(draft.id); setDraftEditContent(draft.content) }}
                        className="text-xs bg-surface-hover text-text-muted hover:text-text px-3 py-1.5 rounded cursor-pointer"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => draftActionMutation.mutate({ postId: draft.id, action: 'reject' })}
                        disabled={draftActionMutation.isPending}
                        className="text-xs bg-danger/10 text-danger hover:bg-danger/20 px-3 py-1.5 rounded cursor-pointer disabled:opacity-50"
                      >
                        Reject
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-text-muted bg-surface border border-border rounded-lg p-4 text-center">
                No drafts matching the current filter.
              </div>
            )}

            {/* Edit Draft Modal — full-size editor */}
            {editingDraftId && (
              <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => { setEditingDraftId(null); setDraftEditContent('') }}>
                <div className="bg-surface border border-border rounded-lg shadow-xl w-full max-w-3xl max-h-[85vh] overflow-hidden m-4 flex flex-col" onClick={e => e.stopPropagation()}>
                  <div className="flex items-center justify-between p-4 border-b border-border">
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-semibold">Edit Draft</h3>
                      {(() => { const d = mktDrafts?.find(x => x.id === editingDraftId); return d ? (
                        <>
                          <span className="text-xs font-medium capitalize bg-primary/10 text-primary px-2 py-0.5 rounded">{d.platform}</span>
                          <span className="text-[10px] text-text-muted">{PLATFORM_DESTINATIONS[d.platform] ?? ''}</span>
                        </>
                      ) : null; })()}
                    </div>
                    <button onClick={() => { setEditingDraftId(null); setDraftEditContent('') }} className="text-text-muted hover:text-text text-lg cursor-pointer">&times;</button>
                  </div>
                  <div className="flex-1 p-4 overflow-y-auto">
                    <textarea
                      value={draftEditContent}
                      onChange={e => setDraftEditContent(e.target.value)}
                      className="w-full text-sm bg-surface-hover border border-border rounded p-3 min-h-[300px] resize-y font-sans leading-relaxed focus:outline-none focus:border-primary"
                      autoFocus
                    />
                    <div className="text-xs text-text-muted mt-2">{draftEditContent.length} characters</div>
                  </div>
                  <div className="flex gap-2 p-4 border-t border-border">
                    <button
                      onClick={() => { draftActionMutation.mutate({ postId: editingDraftId, action: 'edit_approve', content: draftEditContent }); setEditingDraftId(null); setDraftEditContent('') }}
                      disabled={draftActionMutation.isPending || !draftEditContent.trim()}
                      className="text-xs bg-success/10 text-success hover:bg-success/20 px-4 py-2 rounded cursor-pointer disabled:opacity-50"
                    >
                      Save & Approve
                    </button>
                    <button
                      onClick={() => { setEditingDraftId(null); setDraftEditContent('') }}
                      className="text-xs bg-surface-hover text-text-muted hover:text-text px-4 py-2 rounded cursor-pointer"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Bot Activity Feed */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider">Bot Activity</h2>
              <div className="flex gap-1">
                {(['all', 'posted', 'pending', 'failed'] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => setActivityFilter(f)}
                    className={`text-[10px] px-2 py-1 rounded cursor-pointer transition-colors ${
                      activityFilter === f
                        ? 'bg-primary/20 text-primary'
                        : 'bg-surface-hover text-text-muted hover:text-text'
                    }`}
                  >
                    {f === 'all' ? `All${botActivity ? ` (${botActivity.total})` : ''}` :
                     f === 'posted' ? `Posted${botActivity ? ` (${botActivity.posted.length})` : ''}` :
                     f === 'pending' ? `Pending${botActivity ? ` (${botActivity.pending_review.length})` : ''}` :
                     `Failed${botActivity ? ` (${botActivity.failed.length})` : ''}`}
                  </button>
                ))}
              </div>
            </div>
            {activityLoading ? (
              <div className="py-6"><InlineSkeleton /></div>
            ) : botActivity ? (() => {
              const items: ActivityItem[] =
                activityFilter === 'posted' ? botActivity.posted :
                activityFilter === 'pending' ? botActivity.pending_review :
                activityFilter === 'failed' ? botActivity.failed :
                [...botActivity.posted, ...botActivity.pending_review, ...botActivity.failed]
                  .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
              const platformColors: Record<string, string> = {
                twitter: 'bg-blue-500/10 text-blue-400',
                reddit: 'bg-orange-500/10 text-orange-400',
                bluesky: 'bg-sky-400/10 text-sky-400',
                huggingface: 'bg-yellow-400/10 text-yellow-400',
                devto: 'bg-gray-400/10 text-gray-400',
                discord: 'bg-indigo-500/10 text-indigo-400',
                linkedin: 'bg-blue-600/10 text-blue-500',
                telegram: 'bg-cyan-500/10 text-cyan-400',
                hashnode: 'bg-blue-400/10 text-blue-300',
                hackernews: 'bg-orange-600/10 text-orange-500',
                github_discussions: 'bg-gray-500/10 text-gray-300',
              }
              const statusBadge = (s: string) =>
                s === 'posted' ? 'bg-success/10 text-success' :
                s === 'human_review' ? 'bg-warning/10 text-warning' :
                s === 'failed' ? 'bg-danger/10 text-danger' :
                'bg-surface-hover text-text-muted'
              return items.length > 0 ? (
                <div className="space-y-2">
                  {items.map((item) => (
                    <div key={item.id} className="bg-surface border border-border rounded-lg p-3 flex items-start gap-3">
                      <div className="flex-shrink-0 mt-0.5">
                        <span className={`text-[10px] font-medium capitalize px-1.5 py-0.5 rounded ${platformColors[item.platform] || 'bg-surface-hover text-text-muted'}`}>
                          {item.platform}
                        </span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-xs leading-relaxed text-text/80 line-clamp-2">{item.content_preview}</div>
                        <div className="flex flex-wrap gap-2 mt-1.5 text-[10px] text-text-muted">
                          <span className={`px-1.5 py-0.5 rounded ${statusBadge(item.status)}`}>
                            {item.status === 'human_review' ? 'Pending Review' : item.status}
                          </span>
                          {item.topic && <span className="bg-surface-hover px-1.5 py-0.5 rounded capitalize">{item.topic}</span>}
                          <span>{timeAgo(item.created_at)}</span>
                        </div>
                      </div>
                      {item.external_id && (
                        <a
                          href={
                            item.external_url ? item.external_url :
                            item.platform === 'twitter' ? `https://twitter.com/i/web/status/${item.external_id}` :
                            item.platform === 'bluesky' ? `https://bsky.app/profile/agentavow.bsky.social/post/${item.external_id}` :
                            item.platform === 'reddit' ? `https://old.reddit.com${item.external_id}` :
                            item.platform === 'devto' ? `https://dev.to/agentavow` :
                            item.platform === 'github_discussions' ? `https://github.com/AgentAvow/AgentAvow/discussions` :
                            item.platform === 'huggingface' ? `https://huggingface.co/agentavow` :
                            '#'
                          }
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex-shrink-0 text-[10px] text-primary hover:text-primary-light"
                        >
                          View
                        </a>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-text-muted bg-surface border border-border rounded-lg p-4 text-center">
                  No activity in this category.
                </div>
              )
            })() : null}
          </div>

          {/* Stats Cards */}
          {mktDashboard && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <StatCard label="Total Posts" value={mktDashboard.recent_posts.length} sub="Last 7 days" />
              <StatCard label="Pending Drafts" value={mktDashboard.pending_drafts} sub={mktDashboard.pending_drafts > 0 ? 'Needs review' : 'All clear'} />
              <StatCard label="LLM Spend (today)" value={`$${mktDashboard.cost.daily_spend_usd.toFixed(4)}`} sub={`Month: $${mktDashboard.cost.monthly_spend_usd.toFixed(4)}`} />
              <StatCard
                label="Engagement"
                value={(mktDashboard.engagement.total_likes + mktDashboard.engagement.total_comments + mktDashboard.engagement.total_shares).toLocaleString()}
                sub="Likes + comments + shares"
              />
            </div>
          )}

          {/* Platform Adapters */}
          {mktHealth && (
            <div>
              <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">Platform Adapters</h2>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                {Object.entries(mktHealth.adapters).map(([name, info]) => (
                  <div key={name} className="bg-surface border border-border rounded-lg p-3 text-center">
                    <div className="text-xs font-medium capitalize">{name}</div>
                    <div className="mt-1">
                      {info.configured ? (
                        <span className={`text-[10px] px-1.5 py-0.5 rounded ${info.healthy ? 'bg-success/10 text-success' : 'bg-warning/10 text-warning'}`}>
                          {info.healthy ? 'Healthy' : 'Unhealthy'}
                        </span>
                      ) : (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-hover text-text-muted">Not configured</span>
                      )}
                    </div>
                    {info.configured && (
                      <button
                        onClick={() => triggerPlatformMutation.mutate(name)}
                        disabled={triggerPlatformMutation.isPending}
                        className="mt-2 text-[10px] bg-primary/10 text-primary hover:bg-primary/20 px-2 py-1 rounded cursor-pointer disabled:opacity-50"
                      >
                        Generate Draft
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Posts by Platform */}
          {mktDashboard && mktDashboard.platform_stats.length > 0 && (
            <div>
              <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">Posts by Platform</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                {mktDashboard.platform_stats.map((ps) => (
                  <div key={ps.platform} className="bg-surface border border-border rounded-lg p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-medium capitalize">{ps.platform}</span>
                      <span className="text-sm font-medium">{ps.total}</span>
                    </div>
                    <div className="flex gap-2 text-[10px] text-text-muted">
                      <span className="text-success">{ps.posted} posted</span>
                      {ps.failed > 0 && <span className="text-danger">{ps.failed} failed</span>}
                      {ps.pending_review > 0 && <span className="text-warning">{ps.pending_review} review</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Cost Breakdown */}
          {mktDashboard && mktDashboard.cost.breakdown.length > 0 && (
            <div>
              <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">LLM Cost Breakdown</h2>
              <div className="bg-surface border border-border rounded-lg overflow-x-auto">
                <table className="w-full min-w-[400px]">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left text-xs text-text-muted px-4 py-2">Model</th>
                      <th className="text-right text-xs text-text-muted px-4 py-2">Calls</th>
                      <th className="text-right text-xs text-text-muted px-4 py-2">Cost</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mktDashboard.cost.breakdown.map((m) => (
                      <tr key={m.model} className="border-b border-border/50">
                        <td className="text-xs px-4 py-2">{m.model}</td>
                        <td className="text-xs px-4 py-2 text-right">{m.calls}</td>
                        <td className="text-xs px-4 py-2 text-right">${m.cost_usd.toFixed(4)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Draft Preview Modal — kept for trigger-generated drafts */}
          {previewDraft && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setPreviewDraft(null)}>
              <div className="bg-surface border border-border rounded-lg shadow-xl w-full max-w-3xl max-h-[85vh] overflow-y-auto m-4" onClick={e => e.stopPropagation()}>
                <div className="flex items-center justify-between p-4 border-b border-border">
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-semibold">Draft Preview</h3>
                    <span className="text-xs font-medium capitalize bg-primary/10 text-primary px-2 py-0.5 rounded">{previewDraft.platform}</span>
                    <span className="text-[10px] text-text-muted">{PLATFORM_DESTINATIONS[previewDraft.platform] ?? ''}</span>
                    {previewDraft.topic && <span className="text-[10px] bg-surface-hover text-text-muted px-1.5 py-0.5 rounded capitalize">{previewDraft.topic}</span>}
                  </div>
                  <button onClick={() => setPreviewDraft(null)} className="text-text-muted hover:text-text text-lg cursor-pointer">&times;</button>
                </div>
                <div className="p-4 space-y-4">
                  {previewDraft.image_url && (
                    <img src={previewDraft.image_url} alt="Post card" className="w-full max-w-[500px] rounded-lg border border-border" />
                  )}
                  <pre className="text-sm whitespace-pre-wrap font-sans leading-relaxed bg-surface-hover rounded-lg p-3">{previewDraft.content}</pre>
                </div>
                <div className="flex gap-2 p-4 border-t border-border">
                  <button
                    onClick={() => { draftActionMutation.mutate({ postId: previewDraft.id, action: 'approve' }); setPreviewDraft(null) }}
                    disabled={draftActionMutation.isPending}
                    className="text-xs bg-success/10 text-success hover:bg-success/20 px-4 py-2 rounded cursor-pointer disabled:opacity-50"
                  >
                    Approve & Post
                  </button>
                  <button
                    onClick={() => { setEditingDraftId(previewDraft.id); setDraftEditContent(previewDraft.content); setPreviewDraft(null) }}
                    className="text-xs bg-surface-hover text-text-muted hover:text-text px-4 py-2 rounded cursor-pointer"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => { draftActionMutation.mutate({ postId: previewDraft.id, action: 'reject' }); setPreviewDraft(null) }}
                    disabled={draftActionMutation.isPending}
                    className="text-xs bg-danger/10 text-danger hover:bg-danger/20 px-4 py-2 rounded cursor-pointer disabled:opacity-50"
                  >
                    Reject
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Recent Posts */}
          {mktDashboard && mktDashboard.recent_posts.length > 0 && (
            <div>
              <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">Recent Posts</h2>
              <div className="bg-surface border border-border rounded-lg overflow-x-auto">
                <table className="w-full min-w-[600px]">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left text-xs text-text-muted px-4 py-2">Platform</th>
                      <th className="text-left text-xs text-text-muted px-4 py-2">Content</th>
                      <th className="text-left text-xs text-text-muted px-4 py-2">Topic</th>
                      <th className="text-left text-xs text-text-muted px-4 py-2">Model</th>
                      <th className="text-right text-xs text-text-muted px-4 py-2">Cost</th>
                      <th className="text-left text-xs text-text-muted px-4 py-2">When</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mktDashboard.recent_posts.map((post) => (
                      <tr key={post.id} className="border-b border-border/50">
                        <td className="text-xs px-4 py-2 capitalize">{post.platform}</td>
                        <td className="text-xs px-4 py-2 max-w-[200px] truncate">{post.url ? <a href={post.url} target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:text-indigo-300 hover:underline">{post.content}</a> : post.content}</td>
                        <td className="text-xs px-4 py-2 capitalize">{post.topic ?? '—'}</td>
                        <td className="text-xs px-4 py-2 text-text-muted">{post.llm_model ?? 'template'}</td>
                        <td className="text-xs px-4 py-2 text-right">${(post.llm_cost_usd ?? 0).toFixed(4)}</td>
                        <td className="text-xs px-4 py-2 text-text-muted">{post.posted_at ? timeAgo(post.posted_at) : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Empty state */}
          {mktDashboard && mktDashboard.recent_posts.length === 0 && (!mktDrafts || mktDrafts.length === 0) && (
            <div className="text-text-muted text-center py-10">
              No marketing activity yet. Configure platform API keys and trigger a marketing tick to get started.
            </div>
          )}
        </>
      )}
    </div>
  )
}
