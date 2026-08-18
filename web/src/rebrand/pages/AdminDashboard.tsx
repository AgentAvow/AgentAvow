/**
 * AgentAvow admin dashboard — Kenne's day-to-day ops tool, rebrand-styled.
 *
 * Two tabs: Metrics (product/adoption + traffic funnel, with today/7d/30d + trends)
 * and Marketing (health, weekly campaign planner, interactive draft queue, reply-guy,
 * cost, recent posts). Consumes the SAME existing admin endpoints as the legacy admin,
 * which is left fully intact (footer Community → /feed → /admin, and a link here).
 */
import type { ReactNode } from 'react'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { useAuth } from '../../hooks/useAuth'
import api from '../../lib/api'
import { rp } from '../basePath'
import { Reveal } from '../components/motion'

// ── shared types (loose — endpoints already validated server-side) ──────────
type Win = 'today' | '7d' | '30d'
interface Metrics {
  headline?: Record<string, number>
  series?: Record<string, number[]>
  days?: string[]
  scans?: { grade_distribution?: Record<string, number>; unique_repos_total?: number; scans_total_alltime?: number }
  watches?: { active?: number; total?: number }
  claims?: { verified_total?: number; public?: number; private?: number }
  attestations?: { issued_total?: number; verification_badges_active?: number }
  badges?: { readme_renders_window?: number; leaderboard?: { repo: string; renders: number }[] }
  catalog?: { by_surface?: Record<string, number>; by_category?: Record<string, number>; size_total?: number }
  funnel?: { scanned?: number; watched?: number; claimed?: number; installs?: number }
}
interface Draft { id: string; platform: string; content: string; topic: string | null; status: string; created_at: string; post_type?: string; llm_model?: string | null }
interface Health { marketing_enabled?: boolean; anthropic_configured?: boolean; ollama_available?: boolean; daily_spend_usd?: number; monthly_spend_usd?: number; adapters?: Record<string, { configured: boolean; healthy: boolean }> }
interface MktDash {
  engagement?: { total_likes: number; total_comments: number; total_shares: number; total_impressions: number }
  cost?: { daily_spend_usd: number; monthly_spend_usd: number; breakdown: { model: string; calls: number; cost_usd: number }[] }
  recent_posts?: { id: string; platform: string; content: string; url: string | null; posted_at: string | null; metrics: Record<string, number> | null; llm_model: string | null; llm_cost_usd: number | null }[]
  pending_drafts?: number
  platform_stats?: { platform: string; total: number; posted: number; failed: number; pending_review: number }[]
}
interface Campaign { id: string; name: string; topic: string; platforms: string[]; status: string; start_date?: string }
interface ReplyStats { status_counts?: Record<string, number>; posted_today?: number; active_targets?: number; queue_size?: number }
interface ReplyRow { id: string; platform: string; post_uri?: string; reply_url?: string | null; draft_content?: string; drafted_at?: string | null; posted_at?: string | null; engagement_count?: number; target?: { handle?: string | null } }
const REPLY_TTL_H = 48

// ── helpers ─────────────────────────────────────────────────────────────────
const fmt = (n: number | undefined | null) => (n ?? 0).toLocaleString()
const usd = (n: number | undefined | null) => `$${(n ?? 0).toFixed(2)}`
const ago = (iso?: string | null) => {
  if (!iso) return '—'
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 3600) return `${Math.floor(s / 60)}m`
  if (s < 86400) return `${Math.floor(s / 3600)}h`
  return `${Math.floor(s / 86400)}d`
}

function Sparkline({ data }: { data?: number[] }) {
  if (!data || data.length < 2) return null
  const max = Math.max(...data, 1)
  const w = 100, h = 24
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - (v / max) * h}`).join(' ')
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-6 mt-2" preserveAspectRatio="none">
      <polyline points={pts} fill="none" stroke="url(#spark)" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
      <defs><linearGradient id="spark" x1="0" x2="1"><stop offset="0" stopColor="#2dd4bf" /><stop offset="1" stopColor="#818cf8" /></linearGradient></defs>
    </svg>
  )
}

function Stat({ label, value, sub, series }: { label: string; value: string | number; sub?: string; series?: number[] }) {
  return (
    <div className="glass rounded-2xl p-5 min-w-0">
      <div className="text-[24px] font-extrabold leading-none tabular-nums gradient-text">{value}</div>
      <div className="mt-1.5 text-[11.5px] font-mono uppercase tracking-wide text-text-muted">{label}</div>
      {sub && <div className="mt-0.5 text-[11px] text-text-muted/70">{sub}</div>}
      <Sparkline data={series} />
    </div>
  )
}

function Section({ title, note, right, children }: { title: string; note?: string; right?: ReactNode; children: ReactNode }) {
  return (
    <Reveal>
      <section className="mt-10">
        <div className="flex items-baseline justify-between gap-3 flex-wrap">
          <div>
            <h2 className="text-lg font-bold">{title}</h2>
            {note && <p className="mt-1 text-text-muted text-[13px] max-w-[64ch]">{note}</p>}
          </div>
          {right}
        </div>
        <div className="mt-4">{children}</div>
      </section>
    </Reveal>
  )
}

function WindowToggle({ win, setWin }: { win: Win; setWin: (w: Win) => void }) {
  return (
    <div className="flex gap-1 font-mono text-[12px]">
      {(['today', '7d', '30d'] as Win[]).map((w) => (
        <button key={w} onClick={() => setWin(w)} className={`px-2.5 py-1 rounded-lg transition-colors ${win === w ? 'bg-primary/15 text-primary-light' : 'text-text-muted hover:text-text'}`}>
          {w === 'today' ? 'L1' : w === '7d' ? 'L7' : 'L30'}
        </button>
      ))}
    </div>
  )
}

interface Conversion { funnel?: { event_type: string; count: number; conversion_rate: number }[]; top_pages?: { page: string; count: number }[]; total_events?: number }
const FUNNEL_LABEL: Record<string, string> = { guest_page_view: 'Page views', guest_cta_click: 'CTA clicks', register_start: 'Register start', register_complete: 'Registered', first_action: 'First action' }

// ── METRICS TAB ──────────────────────────────────────────────────────────────
function MetricsTab() {
  const [win, setWin] = useState<Win>('7d')
  const { data } = useQuery<Metrics>({
    queryKey: ['admin-dash-metrics', win],
    queryFn: async () => (await api.get('/admin/metrics', { params: { window: win } })).data,
  })
  const traffic = useQuery<Conversion>({
    queryKey: ['admin-dash-traffic'],
    queryFn: async () => { try { return (await api.get('/analytics/conversion')).data } catch { return {} } },
  })
  const tf = traffic.data?.funnel || []
  const tmax = Math.max(...tf.map((r) => r.count), 1)
  const h = data?.headline || {}
  const s = data?.series || {}
  const f = data?.funnel || {}
  const board = data?.badges?.leaderboard || []
  const grades = data?.scans?.grade_distribution || {}
  const surfaces = data?.catalog?.by_surface || {}
  const funnelSteps: [string, number][] = [['Scanned', f.scanned ?? 0], ['Watched', f.watched ?? 0], ['Claimed', f.claimed ?? 0], ['Installed', f.installs ?? 0]]
  const fmax = Math.max(...funnelSteps.map(([, n]) => n), 1)

  return (
    <>
      <Section title="Product & adoption" note="Everything the product surfaces — the full set, not a slice." right={<WindowToggle win={win} setWin={setWin} />}>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
          <Stat label="Repos scanned" value={fmt(h.repos_scanned)} sub={`${fmt(h.new_repos)} new`} series={s.repos_scanned} />
          <Stat label="Badge fetches" value={fmt(h.badge_fetches)} sub={`${fmt(h.readme_renders)} in READMEs`} series={s.badge_fetches} />
          <Stat label="Watches created" value={fmt(h.watches_created)} series={s.watches_created} />
          <Stat label="Unique checkers" value={fmt(h.unique_checkers)} />
          <Stat label="Adoption lookups" value={fmt(h.adoption_hits)} series={s.adoption_hits} />
          <Stat label="Install clicks" value={fmt(h.install_clicks)} series={s.install_clicks} />
          <Stat label="Fresh re-scans" value={fmt(h.force_rescans)} series={s.force_rescans} />
          <Stat label="API calls" value={fmt(h.api_calls)} series={s.api_calls} />
          <Stat label="Attestations" value={fmt(h.attestations_issued)} />
          <Stat label="Active watches" value={fmt(data?.watches?.active)} sub={`${fmt(data?.watches?.total)} all-time`} />
          <Stat label="Verified claims" value={fmt(data?.claims?.verified_total)} sub={`${fmt(data?.claims?.public)} public · ${fmt(data?.claims?.private)} private`} />
          <Stat label="Active badges" value={fmt(data?.attestations?.verification_badges_active)} />
        </div>
      </Section>

      <Section title="Traffic funnel — where users drop off" note="Scan → watch → claim → install, with step-to-step conversion (this window).">
        <div className="glass rounded-2xl p-6 flex flex-col gap-3">
          {funnelSteps.map(([label, n], i) => {
            const prev = i === 0 ? n : funnelSteps[i - 1][1]
            const conv = prev > 0 ? Math.round((n / prev) * 100) : 0
            return (
              <div key={label}>
                <div className="flex justify-between text-[12.5px] mb-1"><span className="font-mono">{label}</span><span className="tabular-nums text-text-muted">{fmt(n)}{i > 0 && <span className="ml-2 text-[11px]">({conv}%)</span>}</span></div>
                <div className="h-2.5 rounded-full bg-surface overflow-hidden"><div className="h-full rounded-full" style={{ width: `${(n / fmax) * 100}%`, background: 'linear-gradient(90deg,#2dd4bf,#818cf8)' }} /></div>
              </div>
            )
          })}
          <p className="text-[11.5px] text-text-muted/70 mt-1">Product-action funnel (scan → watch → claim → install).</p>
        </div>
      </Section>

      <Section title="Site traffic — sessions & drop-off" note="Anonymous page-view sessions through the signup funnel (the Cloudflare replacement — in one place, here).">
        <div className="glass rounded-2xl p-6">
          {tf.length ? (
            <div className="flex flex-col gap-3">
              {tf.map((r, i) => (
                <div key={r.event_type}>
                  <div className="flex justify-between text-[12.5px] mb-1"><span className="font-mono">{FUNNEL_LABEL[r.event_type] || r.event_type}</span><span className="tabular-nums text-text-muted">{fmt(r.count)}{i > 0 && <span className="ml-2 text-[11px]">({Math.round(r.conversion_rate)}%)</span>}</span></div>
                  <div className="h-2.5 rounded-full bg-surface overflow-hidden"><div className="h-full rounded-full" style={{ width: `${(r.count / tmax) * 100}%`, background: 'linear-gradient(90deg,#f59e0b,#e879f9)' }} /></div>
                </div>
              ))}
              {!!traffic.data?.top_pages?.length && (
                <div className="mt-2 pt-3 border-t border-border/40">
                  <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-1.5">Top pages</div>
                  {traffic.data.top_pages.slice(0, 8).map((p) => <div key={p.page} className="flex justify-between text-[12px] py-0.5"><span className="font-mono text-text-muted truncate">{p.page}</span><span className="tabular-nums text-text-muted/70 ml-3">{fmt(p.count)}</span></div>)}
                </div>
              )}
            </div>
          ) : (
            <p className="text-[13px] text-text-muted">No session data yet — page-view tracking was just turned on for the live site. This funnel (views → CTA → register → first action, with drop-off %) fills in within a day.</p>
          )}
        </div>
      </Section>

      <div className="grid md:grid-cols-2 gap-4">
        <Section title="Grade distribution" note="Live scanned corpus, all-time.">
          <div className="glass rounded-2xl p-5 flex flex-col gap-2">
            {['A+', 'A', 'B', 'C', 'D', 'F'].map((g) => {
              const n = grades[g] ?? 0
              const tot = Object.values(grades).reduce((a, b) => a + b, 0) || 1
              return <div key={g} className="flex items-center gap-3 text-[13px]"><span className="font-mono w-8">{g}</span><div className="flex-1 h-2 rounded-full bg-surface overflow-hidden"><div className="h-full bg-primary/60" style={{ width: `${(n / tot) * 100}%` }} /></div><span className="tabular-nums text-text-muted w-16 text-right">{fmt(n)}</span></div>
            })}
          </div>
        </Section>
        <Section title="Badges in READMEs" note="Adoption proof + warmest re-outreach list.">
          <div className="glass rounded-2xl p-5">
            {board.length ? <div className="flex flex-col divide-y divide-border/40">{board.slice(0, 10).map((r) => (<div key={r.repo} className="flex justify-between py-1.5 text-[12.5px]"><a href={`https://github.com/${r.repo}`} target="_blank" rel="noopener" className="font-mono text-text hover:text-primary-light truncate">{r.repo}</a><span className="font-mono tabular-nums text-text-muted ml-3">{fmt(r.renders)}</span></div>))}</div> : <p className="text-text-muted text-[13px]">No README renders yet.</p>}
          </div>
        </Section>
      </div>

      <Section title="Catalog by surface">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {Object.entries(surfaces).sort((a, b) => b[1] - a[1]).map(([k, v]) => <Stat key={k} label={k} value={fmt(v)} />)}
        </div>
      </Section>
    </>
  )
}

// ── MARKETING TAB ──────────────────────────────────────────────────────────
function DraftCard({ d, onDone }: { d: Draft; onDone: () => void }) {
  const [editing, setEditing] = useState(false)
  const [text, setText] = useState(d.content)
  const [postedUrl, setPostedUrl] = useState('')
  const [showPosted, setShowPosted] = useState(false)
  const manual = ['reddit', 'hackernews', 'producthunt', 'linkedin'].includes(d.platform)
  const act = useMutation({
    mutationFn: (body: { action: string; content?: string; posted_url?: string }) => api.post(`/admin/marketing/drafts/${d.id}`, body),
    onSuccess: onDone,
  })
  return (
    <div className="glass rounded-xl p-4">
      <div className="flex items-center gap-2 text-[11.5px] font-mono text-text-muted mb-2">
        <span className="px-1.5 py-0.5 rounded bg-primary/15 text-primary-light">{d.platform}</span>
        {d.post_type === 'reactive' && <span className="px-1.5 py-0.5 rounded bg-warning/15 text-warning">reply</span>}
        {d.topic && <span>{d.topic}</span>}
        <span className="ml-auto">{ago(d.created_at)} ago · {d.status}</span>
      </div>
      {editing
        ? <textarea value={text} onChange={(e) => setText(e.target.value)} rows={5} className="w-full text-[13px] rounded-lg bg-surface border border-border p-2 font-mono" />
        : <p className="text-[13px] text-text whitespace-pre-wrap">{d.content}</p>}
      {showPosted && <input value={postedUrl} onChange={(e) => setPostedUrl(e.target.value)} placeholder="URL where you posted it (optional)" className="mt-2 w-full text-[12.5px] rounded-lg bg-surface border border-border px-2 py-1.5" />}
      <div className="mt-3 flex gap-2 flex-wrap text-[12.5px] font-semibold">
        {editing ? (
          <>
            <button onClick={() => act.mutate({ action: 'edit_approve', content: text })} disabled={act.isPending} className="px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">Save &amp; {manual ? 'keep' : 'post'}</button>
            <button onClick={() => setEditing(false)} className="px-3 py-1.5 rounded-lg border border-border text-text-muted">Cancel</button>
          </>
        ) : manual ? (
          <>
            {showPosted
              ? <button onClick={() => act.mutate({ action: 'mark_posted', posted_url: postedUrl || undefined })} disabled={act.isPending} className="px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-success to-primary disabled:opacity-60">Confirm posted</button>
              : <button onClick={() => setShowPosted(true)} className="px-3 py-1.5 rounded-lg border border-primary/50 text-primary-light">I posted this</button>}
            <button onClick={() => setEditing(true)} className="px-3 py-1.5 rounded-lg border border-border text-text-muted">Edit</button>
            <button onClick={() => act.mutate({ action: 'reject' })} disabled={act.isPending} className="px-3 py-1.5 rounded-lg border border-border text-text-muted hover:text-danger">Reject</button>
          </>
        ) : (
          <>
            <button onClick={() => act.mutate({ action: 'approve' })} disabled={act.isPending} className="px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">Approve &amp; post</button>
            <button onClick={() => setEditing(true)} className="px-3 py-1.5 rounded-lg border border-border text-text-muted">Edit</button>
            <button onClick={() => act.mutate({ action: 'reject' })} disabled={act.isPending} className="px-3 py-1.5 rounded-lg border border-border text-text-muted hover:text-danger">Reject</button>
          </>
        )}
      </div>
      {act.isError && <p className="mt-2 text-[12px] text-danger">Action failed — try again.</p>}
    </div>
  )
}

function MarketingTab() {
  const qc = useQueryClient()
  const invalidate = () => { ['admin-mkt-drafts', 'admin-mkt-planned', 'admin-mkt-dash', 'admin-mkt-reply-considering', 'admin-mkt-reply-sent'].forEach((k) => qc.invalidateQueries({ queryKey: [k] })) }
  const health = useQuery<Health>({ queryKey: ['admin-mkt-health'], queryFn: async () => (await api.get('/admin/marketing/health')).data })
  const dash = useQuery<MktDash>({ queryKey: ['admin-mkt-dash'], queryFn: async () => (await api.get('/admin/marketing/dashboard')).data })
  // Queue 1: things I must post by hand (human_review). Queue 2: scheduled campaign posts (planned).
  const manual = useQuery<Draft[]>({ queryKey: ['admin-mkt-drafts'], queryFn: async () => (await api.get('/admin/marketing/drafts', { params: { status: 'human_review,draft', limit: 40 } })).data })
  const planned = useQuery<Draft[]>({ queryKey: ['admin-mkt-planned'], queryFn: async () => (await api.get('/admin/marketing/drafts', { params: { status: 'planned', limit: 60 } })).data })
  const campaigns = useQuery<Campaign[]>({ queryKey: ['admin-mkt-campaigns'], queryFn: async () => { try { return (await api.get('/admin/marketing/campaigns/proposed')).data } catch { return [] } } })
  const reply = useQuery<ReplyStats>({ queryKey: ['admin-mkt-reply'], queryFn: async () => (await api.get('/admin/engagement/stats')).data })
  // Queue 3: replies it's considering next (drafted). Feed: replies already sent.
  // Sorted by urgency (default) — the ones it'll try to post first.
  const considering = useQuery<{ items: ReplyRow[] }>({ queryKey: ['admin-mkt-reply-considering'], queryFn: async () => (await api.get('/admin/engagement/queue', { params: { status: 'drafted', limit: 20 } })).data })
  const replySent = useQuery<{ items: ReplyRow[] }>({ queryKey: ['admin-mkt-reply-sent'], queryFn: async () => (await api.get('/admin/engagement/queue', { params: { status: 'posted', sort: 'recent', limit: 20 } })).data })
  const byDate = <T extends { created_at?: string; posted_at?: string | null; drafted_at?: string | null }>(a: T[]) => [...a].sort((x, y) => new Date(y.posted_at || y.drafted_at || y.created_at || 0).getTime() - new Date(x.posted_at || x.drafted_at || x.created_at || 0).getTime())

  const genCampaign = useMutation({ mutationFn: () => api.post('/admin/marketing/campaigns/generate', {}, { timeout: 120_000 }), onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-mkt-campaigns'] }) })
  const trigger = useMutation({ mutationFn: () => api.post('/admin/marketing/trigger', {}), onSuccess: invalidate })

  const h = health.data
  const eng = dash.data?.engagement
  const cost = dash.data?.cost
  const rc = reply.data?.status_counts || {}

  return (
    <>
      <Section title="Health & spend" right={<button onClick={() => trigger.mutate()} disabled={trigger.isPending} className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg border border-primary/50 text-primary-light disabled:opacity-60">{trigger.isPending ? 'Running…' : 'Trigger marketing tick'}</button>}>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <Stat label="Engine" value={h?.marketing_enabled ? 'On' : 'Off'} sub={h?.anthropic_configured ? 'Anthropic ✓' : 'no key'} />
          <Stat label="Spend today" value={usd(cost?.daily_spend_usd ?? h?.daily_spend_usd)} />
          <Stat label="Spend this month" value={usd(cost?.monthly_spend_usd ?? h?.monthly_spend_usd)} sub="all LLM usage" />
          <Stat label="Engagement (7d)" value={fmt((eng?.total_likes ?? 0) + (eng?.total_comments ?? 0) + (eng?.total_shares ?? 0))} sub={`${fmt(eng?.total_impressions)} impressions`} />
        </div>
        {cost?.breakdown?.length ? (
          <div className="glass rounded-2xl p-4 mt-3 overflow-x-auto">
            <div className="text-[12px] font-mono uppercase tracking-wide text-text-muted mb-1">LLM cost by model (attributed)</div>
            <table className="w-full text-[12.5px]"><tbody>{cost.breakdown.map((b) => <tr key={b.model} className="border-t border-border/40"><td className="py-1 font-mono">{b.model}</td><td className="py-1 tabular-nums text-right text-text-muted">{fmt(b.calls)} calls</td><td className="py-1 tabular-nums text-right">{usd(b.cost_usd)}</td></tr>)}</tbody></table>
            <p className="text-[11px] text-text-muted/60 mt-1">Note: the monthly figure counts all LLM usage (incl. reply-guy drafts); this table is only spend attributed to stored posts — the two differ until cost tracking is unified.</p>
          </div>
        ) : null}
      </Section>

      <RecentPostsCard posts={dash.data?.recent_posts || []} />

      {(() => {
        const posts = dash.data?.recent_posts || []
        const scored = posts.map((p) => ({ p, e: (p.metrics?.likes || 0) + (p.metrics?.comments || 0) + (p.metrics?.shares || 0) })).filter((x) => x.e > 0).sort((a, b) => b.e - a.e)
        if (!scored.length) return null
        const top = scored[0]
        return (
          <Reveal><div className="mt-6 glass rounded-2xl p-5 border-l-4 border-success/60">
            <div className="text-[12px] font-mono uppercase tracking-wide text-text-muted">What's working 💡</div>
            <p className="mt-1.5 text-[13.5px]">Best-performing recent post ({top.e} engagements) on <span className="font-mono">{top.p.platform}</span>{top.p.url && <> — <a href={top.p.url} target="_blank" rel="noopener" className="text-primary-light hover:text-primary">open ↗</a></>}: <span className="text-text-muted">"{top.p.content.slice(0, 120)}…"</span></p>
            <p className="mt-1 text-[11.5px] text-text-muted/70">The engine can weight future posts toward what earns engagement — closed-loop self-tuning is the next step (staged).</p>
          </div></Reveal>
        )
      })()}

      <Section title="Weekly campaign planner" note="Generate a week of posts, review, approve or reject. Approved posts land in the draft queue below." right={<button onClick={() => genCampaign.mutate()} disabled={genCampaign.isPending} className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">{genCampaign.isPending ? 'Generating…' : 'Generate weekly plan'}</button>}>
        {campaigns.data?.length ? (
          <div className="flex flex-col gap-2">
            {campaigns.data.map((c) => (
              <div key={c.id} className="glass rounded-xl p-4 flex items-center justify-between gap-3 flex-wrap">
                <div><div className="font-semibold text-[14px]">{c.name}</div><div className="text-[12px] text-text-muted font-mono">{c.platforms?.join(' · ')} · {c.status}{c.start_date ? ` · starts ${c.start_date}` : ''}</div></div>
                <div className="flex gap-2 text-[12.5px] font-semibold">
                  <CampaignActions id={c.id} onDone={() => qc.invalidateQueries({ queryKey: ['admin-mkt-campaigns'] })} />
                </div>
              </div>
            ))}
          </div>
        ) : <p className="text-text-muted text-[13px]">No proposed campaigns. Generate a weekly plan to review one.</p>}
      </Section>

      <Section title="Queue 1 · To post by hand" note="Drafts on manual-post platforms (LinkedIn/Reddit/HN/Product Hunt) awaiting you — edit, mark posted, or reject. Newest first.">
        {(() => { const q = byDate((manual.data || []).filter((d) => ['linkedin', 'reddit', 'hackernews', 'producthunt'].includes(d.platform))); return q.length ? <div className="flex flex-col gap-2">{q.map((d) => <DraftCard key={d.id} d={d} onDone={invalidate} />)}</div> : <p className="text-text-muted text-[13px]">Nothing to post by hand right now.</p> })()}
      </Section>

      <Section title="Queue 2 · Scheduled this week" note="What the weekly campaign will auto-post, and when. You'll likely never touch this — edit if you want to.">
        {byDate(planned.data || []).length ? (
          <div className="flex flex-col gap-2">
            {byDate(planned.data || []).map((d) => (
              <div key={d.id} className="glass rounded-xl p-4">
                <div className="flex items-center gap-2 text-[11.5px] font-mono text-text-muted">
                  <span className="px-1.5 py-0.5 rounded bg-primary/15 text-primary-light">{d.platform}</span>
                  {(d as Draft & { scheduled_day?: string }).scheduled_day && <span>📅 {(d as Draft & { scheduled_day?: string }).scheduled_day}</span>}
                  {d.topic && <span>{d.topic}</span>}
                  <a href={`/admin`} className="ml-auto text-primary-light hover:text-primary">edit ↗</a>
                </div>
                <p className="mt-2 text-[12.5px] text-text-muted whitespace-pre-wrap">{d.content.slice(0, 180)}{d.content.length > 180 ? '…' : ''}</p>
              </div>
            ))}
          </div>
        ) : <p className="text-text-muted text-[13px]">No scheduled campaign posts. Generate a weekly plan above.</p>}
      </Section>

      <Section title="Queue 3 · Reply-guy is considering" note="Drafted replies for X + Bluesky, most-urgent first (what it'll try next). Each fades out after 48h. Edit, or post it now.">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3">
          <Stat label="Posted today" value={fmt(reply.data?.posted_today)} />
          <Stat label="Active targets" value={fmt(reply.data?.active_targets)} />
          <Stat label="Considering" value={fmt(reply.data?.queue_size)} sub="drafted+new" />
          <Stat label="Sent (all-time)" value={fmt(rc.posted)} sub={`${fmt(rc.posting_error)} errors`} />
        </div>
        {considering.data?.items?.length ? <div className="flex flex-col gap-2">{considering.data.items.map((r) => <ReplyConsideringCard key={r.id} r={r} onDone={invalidate} />)}</div> : <p className="text-text-muted text-[13px]">Nothing queued to reply to right now.</p>}
      </Section>

      <Section title="Reply-guy · Sent" note="Everything reply-guy has posted, newest first — click to see it live.">
        {replySent.data?.items?.length ? (
          <div className="glass rounded-2xl p-4">
            <div className="flex flex-col divide-y divide-border/40">
              {replySent.data.items.map((r) => (
                <div key={r.id} className="flex items-center gap-3 py-2 text-[12.5px]">
                  <span className="font-mono text-[10.5px] px-1.5 py-0.5 rounded bg-primary/15 text-primary-light">{r.platform}</span>
                  <span className="flex-1 min-w-0 truncate text-text-muted">{r.draft_content || r.post_uri}</span>
                  {typeof r.engagement_count === 'number' && r.engagement_count > 0 && <span className="tabular-nums text-text-muted/70">♥ {r.engagement_count}</span>}
                  <span className="text-text-muted/60 shrink-0">{ago(r.posted_at)}</span>
                  {r.reply_url && <a href={r.reply_url} target="_blank" rel="noopener" className="text-primary-light hover:text-primary shrink-0">view ↗</a>}
                </div>
              ))}
            </div>
          </div>
        ) : <p className="text-text-muted text-[13px]">No replies sent yet.</p>}
      </Section>

    </>
  )
}

function RecentPostsCard({ posts }: { posts: NonNullable<MktDash['recent_posts']> }) {
  return (
    <Section title="Recent posts" note="Your manual + weekly-campaign posts, newest first — click any to open, with engagement.">
      {posts.length ? (
        <>
          <div className="glass rounded-2xl p-4 overflow-x-auto">
            <table className="w-full text-[12.5px]">
              <thead><tr className="text-text-muted/70 text-left font-mono"><th className="py-1 pr-3">when</th><th className="py-1 pr-3">platform</th><th className="py-1 pr-3">post</th><th className="py-1 pr-2 text-right">♥</th><th className="py-1 pr-2 text-right">💬</th><th className="py-1 pr-2 text-right">🔁</th><th className="py-1 pr-2 text-right">👁</th><th className="py-1 text-right">cost</th></tr></thead>
              <tbody>{[...posts].sort((a, b) => new Date(b.posted_at || 0).getTime() - new Date(a.posted_at || 0).getTime()).slice(0, 15).map((p) => (
                <tr key={p.id} className="border-t border-border/40">
                  <td className="py-1.5 pr-3 text-text-muted whitespace-nowrap">{ago(p.posted_at)}</td>
                  <td className="py-1.5 pr-3 font-mono">{p.platform}</td>
                  <td className="py-1.5 pr-3 text-text-muted max-w-[360px] truncate">{p.url ? <a href={p.url} target="_blank" rel="noopener" className="hover:text-primary-light">{p.content.slice(0, 90)} ↗</a> : p.content.slice(0, 90)}</td>
                  <td className="py-1.5 pr-2 tabular-nums text-right">{fmt(p.metrics?.likes)}</td>
                  <td className="py-1.5 pr-2 tabular-nums text-right">{fmt(p.metrics?.comments)}</td>
                  <td className="py-1.5 pr-2 tabular-nums text-right">{fmt(p.metrics?.shares)}</td>
                  <td className="py-1.5 pr-2 tabular-nums text-right text-text-muted">{fmt(p.metrics?.impressions)}</td>
                  <td className="py-1.5 tabular-nums text-right text-text-muted">{usd(p.llm_cost_usd)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          <div className="mt-2 text-[12.5px]"><Link to={rp('/rebrand/admin-posts')} className="text-primary-light hover:text-primary font-semibold">View all posts — sort & search →</Link></div>
        </>
      ) : <p className="text-text-muted text-[13px]">No recent posts.</p>}
    </Section>
  )
}

function ReplyConsideringCard({ r, onDone }: { r: ReplyRow; onDone: () => void }) {
  const [editing, setEditing] = useState(false)
  const [text, setText] = useState(r.draft_content || '')
  const act = useMutation({
    mutationFn: (body: { action: string; draft_content?: string }) => api.post(`/admin/engagement/queue/${r.id}/action`, body),
    onSuccess: onDone,
  })
  const ageH = r.drafted_at ? (Date.now() - new Date(r.drafted_at).getTime()) / 3.6e6 : 0
  const leftH = Math.max(0, REPLY_TTL_H - ageH)
  return (
    <div className="glass rounded-xl p-4">
      <div className="flex items-center gap-2 text-[11.5px] font-mono text-text-muted mb-2">
        <span className="px-1.5 py-0.5 rounded bg-primary/15 text-primary-light">{r.platform}</span>
        {r.target?.handle && <span>@{r.target.handle}</span>}
        {r.post_uri && <a href={r.post_uri} target="_blank" rel="noopener" className="hover:text-primary-light">the post ↗</a>}
        <span className={`ml-auto ${leftH < 6 ? 'text-warning' : ''}`}>fades in {Math.round(leftH)}h · posts in the next 14:00-UTC window</span>
      </div>
      {editing
        ? <textarea value={text} onChange={(e) => setText(e.target.value)} rows={3} className="w-full text-[13px] rounded-lg bg-surface border border-border p-2 font-mono" />
        : <p className="text-[13px] text-text whitespace-pre-wrap">{r.draft_content}</p>}
      <div className="mt-3 flex gap-2 flex-wrap text-[12.5px] font-semibold">
        {editing ? (
          <>
            <button onClick={() => { act.mutate({ action: 'edit', draft_content: text }); setEditing(false) }} className="px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark">Save</button>
            <button onClick={() => setEditing(false)} className="px-3 py-1.5 rounded-lg border border-border text-text-muted">Cancel</button>
          </>
        ) : (
          <>
            <button onClick={() => act.mutate({ action: 'approve' })} disabled={act.isPending} className="px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-success to-primary disabled:opacity-60">Post it now</button>
            <button onClick={() => setEditing(true)} className="px-3 py-1.5 rounded-lg border border-border text-text-muted">Edit</button>
            <button onClick={() => act.mutate({ action: 'skip' })} disabled={act.isPending} className="px-3 py-1.5 rounded-lg border border-border text-text-muted hover:text-danger">Skip</button>
          </>
        )}
      </div>
    </div>
  )
}

function CampaignActions({ id, onDone }: { id: string; onDone: () => void }) {
  const [rejecting, setRejecting] = useState(false)
  const [fb, setFb] = useState('')
  const approve = useMutation({ mutationFn: () => api.post(`/admin/marketing/campaigns/${id}/approve`, {}), onSuccess: onDone })
  const reject = useMutation({ mutationFn: () => api.post(`/admin/marketing/campaigns/${id}/reject`, { feedback: fb }), onSuccess: onDone })
  if (rejecting) return (
    <div className="flex gap-2 items-center">
      <input value={fb} onChange={(e) => setFb(e.target.value)} placeholder="why?" className="text-[12px] rounded-lg bg-surface border border-border px-2 py-1" />
      <button onClick={() => reject.mutate()} disabled={reject.isPending} className="px-3 py-1.5 rounded-lg border border-border text-danger">Confirm</button>
    </div>
  )
  return (
    <>
      <button onClick={() => approve.mutate()} disabled={approve.isPending} className="px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">Approve</button>
      <button onClick={() => setRejecting(true)} className="px-3 py-1.5 rounded-lg border border-border text-text-muted">Reject</button>
    </>
  )
}

// ── SHELL ────────────────────────────────────────────────────────────────
export default function AdminDashboard() {
  const { user, isLoading } = useAuth()
  const [tab, setTab] = useState<'metrics' | 'marketing'>('metrics')

  if (isLoading) return <div className="max-w-[1080px] mx-auto px-6 py-24 text-center text-text-muted">Loading…</div>
  if (!user?.is_admin) return (
    <div className="max-w-[560px] mx-auto px-6 py-24 text-center">
      <h1 className="text-2xl font-extrabold tracking-tight">Admins only</h1>
      <p className="mt-3 text-text-muted text-[14px]">This dashboard is restricted. <Link to={rp('/rebrand')} className="text-primary-light hover:text-primary font-semibold">← Back home</Link></p>
    </div>
  )

  return (
    <div className="max-w-[1080px] mx-auto px-6 py-14">
      <Reveal>
        <div className="flex items-baseline justify-between gap-3 flex-wrap">
          <div>
            <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Operations</span>
            <h1 className="mt-2 text-3xl md:text-4xl font-extrabold tracking-tight">Admin dashboard</h1>
          </div>
          <a href="/admin" className="text-[12.5px] text-text-muted hover:text-text font-semibold">Legacy admin ↗</a>
        </div>
        <div className="mt-6 flex gap-1 border-b border-border/60">
          {(['metrics', 'marketing'] as const).map((t) => (
            <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 text-[14px] font-semibold capitalize border-b-2 -mb-px transition-colors ${tab === t ? 'border-primary text-text' : 'border-transparent text-text-muted hover:text-text'}`}>{t}</button>
          ))}
        </div>
      </Reveal>
      {tab === 'metrics' ? <MetricsTab /> : <MarketingTab />}
    </div>
  )
}
