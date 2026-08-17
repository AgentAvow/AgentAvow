/**
 * AgentAvow admin dashboard — the useful, rebrand-styled operations view.
 *
 * Consolidates what Kenne actually uses: platform metrics (scans / badges /
 * README adoption), marketing performance + cost, the draft review queue, and
 * reply-guy status + metrics. Consumes the SAME existing admin endpoints as the
 * legacy admin (which is left untouched, reachable via the footer's Community →
 * /feed → /admin). The account menu's "Admin" link points HERE.
 */
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { useAuth } from '../../hooks/useAuth'
import api from '../../lib/api'
import { rp } from '../basePath'
import { Reveal } from '../components/motion'

interface MetricsResp {
  headline?: Record<string, number>
  badges?: { readme_renders_window?: number; leaderboard?: { repo: string; renders: number }[] }
}
interface MktDashboard {
  engagement?: { total_likes: number; total_comments: number; total_shares: number; total_impressions: number }
  cost?: { daily_spend_usd: number; monthly_spend_usd: number; breakdown: { model: string; calls: number; cost_usd: number }[] }
  recent_posts?: { id: string; platform: string; content: string; url: string | null; posted_at: string | null; metrics: Record<string, number> | null; llm_cost_usd: number | null }[]
  pending_drafts?: number
  platform_stats?: { platform: string; total: number; posted: number; failed: number; pending_review: number }[]
}
interface Draft { id: string; platform: string; content: string; topic: string | null; status: string; created_at: string }
interface ReplyStats { status_counts?: Record<string, number>; posted_today?: number; active_targets?: number; queue_size?: number }

const fmt = (n: number | undefined | null) => (n ?? 0).toLocaleString()
const usd = (n: number | undefined | null) => `$${(n ?? 0).toFixed(2)}`
const ago = (iso: string | null) => {
  if (!iso) return '—'
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

function Stat({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="glass rounded-2xl p-5 min-w-0">
      <div className="text-[26px] font-extrabold leading-none tabular-nums gradient-text">{value}</div>
      <div className="mt-1.5 text-[12px] font-mono uppercase tracking-wide text-text-muted">{label}</div>
      {sub && <div className="mt-0.5 text-[11.5px] text-text-muted/70">{sub}</div>}
    </div>
  )
}

function Section({ title, note, children }: { title: string; note?: string; children: ReactNode }) {
  return (
    <Reveal>
      <section className="mt-10">
        <h2 className="text-lg font-bold">{title}</h2>
        {note && <p className="mt-1 text-text-muted text-[13.5px] max-w-[64ch]">{note}</p>}
        <div className="mt-4">{children}</div>
      </section>
    </Reveal>
  )
}

export default function AdminDashboard() {
  const { user, isLoading: authLoading } = useAuth()

  const metrics = useQuery<MetricsResp>({
    queryKey: ['admin-dash-metrics'],
    queryFn: async () => (await api.get('/admin/metrics', { params: { window: '7d' } })).data,
    enabled: !!user?.is_admin,
  })
  const mkt = useQuery<MktDashboard>({
    queryKey: ['admin-dash-marketing'],
    queryFn: async () => (await api.get('/admin/marketing/dashboard')).data,
    enabled: !!user?.is_admin,
  })
  const drafts = useQuery<Draft[]>({
    queryKey: ['admin-dash-drafts'],
    queryFn: async () => (await api.get('/admin/marketing/drafts', { params: { status: 'human_review', limit: 20 } })).data,
    enabled: !!user?.is_admin,
  })
  const reply = useQuery<ReplyStats>({
    queryKey: ['admin-dash-reply'],
    queryFn: async () => (await api.get('/admin/engagement/stats')).data,
    enabled: !!user?.is_admin,
  })

  if (authLoading) return <div className="max-w-[1080px] mx-auto px-6 py-24 text-center text-text-muted">Loading…</div>
  if (!user?.is_admin) {
    return (
      <div className="max-w-[560px] mx-auto px-6 py-24 text-center">
        <h1 className="text-2xl font-extrabold tracking-tight">Admins only</h1>
        <p className="mt-3 text-text-muted text-[14px]">This dashboard is restricted. <Link to={rp('/rebrand')} className="text-primary-light hover:text-primary font-semibold">← Back home</Link></p>
      </div>
    )
  }

  const h = metrics.data?.headline || {}
  const eng = mkt.data?.engagement
  const cost = mkt.data?.cost
  const board = metrics.data?.badges?.leaderboard || []
  const rc = reply.data?.status_counts || {}

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
      </Reveal>

      {/* PLATFORM METRICS */}
      <Section title="Platform (last 7 days)" note="Scans, badge adoption, and downstream reliance from the live product.">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
          <Stat label="Repos scanned" value={fmt(h.repos_scanned)} sub={`${fmt(h.new_repos)} new`} />
          <Stat label="Badge fetches" value={fmt(h.badge_fetches)} sub={`${fmt(h.readme_renders)} in READMEs`} />
          <Stat label="Watches created" value={fmt(h.watches_created)} />
          <Stat label="Unique checkers" value={fmt(h.unique_checkers)} />
          <Stat label="Attestations" value={fmt(h.attestations_issued)} />
          <Stat label="API calls" value={fmt(h.api_calls)} />
          <Stat label="Force re-scans" value={fmt(h.force_rescans)} />
          <Stat label="Install clicks" value={fmt(h.install_clicks)} />
        </div>
        <div className="glass rounded-2xl p-5 mt-3">
          <div className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Badges rendering in READMEs — adoption leaderboard</div>
          {board.length ? (
            <div className="mt-3 flex flex-col divide-y divide-border/40">
              {board.map((r) => (
                <div key={r.repo} className="flex items-center justify-between py-2 text-[13px]">
                  <a href={`https://github.com/${r.repo}`} target="_blank" rel="noopener" className="font-mono text-text hover:text-primary-light truncate">{r.repo}</a>
                  <span className="font-mono tabular-nums text-text-muted shrink-0 ml-3">{fmt(r.renders)}</span>
                </div>
              ))}
            </div>
          ) : <p className="mt-2 text-text-muted text-[13px]">No README renders recorded yet — counts accrue as maintainers embed the badge.</p>}
        </div>
      </Section>

      {/* MARKETING PERFORMANCE + COST */}
      <Section title="Marketing" note="How the social engine is performing, and what it costs.">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <Stat label="Likes (window)" value={fmt(eng?.total_likes)} />
          <Stat label="Comments" value={fmt(eng?.total_comments)} />
          <Stat label="Shares" value={fmt(eng?.total_shares)} />
          <Stat label="Impressions" value={fmt(eng?.total_impressions)} />
          <Stat label="Spend today" value={usd(cost?.daily_spend_usd)} />
          <Stat label="Spend this month" value={usd(cost?.monthly_spend_usd)} />
          <Stat label="Pending drafts" value={fmt(mkt.data?.pending_drafts)} sub="awaiting review" />
          <Stat label="LLM models" value={fmt(cost?.breakdown?.length)} />
        </div>
        {(eng && (eng.total_likes + eng.total_comments + eng.total_shares) === 0) && (
          <p className="mt-3 text-[12.5px] text-warning">⚠ Near-zero engagement across posts — reach is the bottleneck, not volume.</p>
        )}
        {!!mkt.data?.recent_posts?.length && (
          <div className="glass rounded-2xl p-5 mt-3 overflow-x-auto">
            <div className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-2">Recent posts</div>
            <table className="w-full text-[12.5px]">
              <thead><tr className="text-text-muted/70 text-left"><th className="py-1 pr-3 font-mono">when</th><th className="py-1 pr-3 font-mono">platform</th><th className="py-1 pr-3 font-mono">post</th><th className="py-1 pr-3 font-mono text-right">♥</th><th className="py-1 font-mono text-right">cost</th></tr></thead>
              <tbody>
                {mkt.data.recent_posts.slice(0, 10).map((p) => (
                  <tr key={p.id} className="border-t border-border/40">
                    <td className="py-1.5 pr-3 text-text-muted whitespace-nowrap">{ago(p.posted_at)}</td>
                    <td className="py-1.5 pr-3 font-mono">{p.platform}</td>
                    <td className="py-1.5 pr-3 text-text-muted max-w-[380px] truncate">{p.url ? <a href={p.url} target="_blank" rel="noopener" className="hover:text-primary-light">{p.content.slice(0, 90)}</a> : p.content.slice(0, 90)}</td>
                    <td className="py-1.5 pr-3 tabular-nums text-right">{fmt(p.metrics?.likes)}</td>
                    <td className="py-1.5 tabular-nums text-right text-text-muted">{usd(p.llm_cost_usd)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {/* DRAFTS QUEUE */}
      <Section title="Draft review queue" note="Human-review drafts awaiting approval. Full approve/edit tools live in the legacy admin.">
        {drafts.data?.length ? (
          <div className="flex flex-col gap-2">
            {drafts.data.map((d) => (
              <div key={d.id} className="glass rounded-xl p-4">
                <div className="flex items-center gap-2 text-[11.5px] font-mono text-text-muted">
                  <span className="px-1.5 py-0.5 rounded bg-primary/15 text-primary-light">{d.platform}</span>
                  {d.topic && <span>{d.topic}</span>}
                  <span className="ml-auto">{ago(d.created_at)}</span>
                </div>
                <p className="mt-2 text-[13px] text-text whitespace-pre-wrap">{d.content.slice(0, 300)}{d.content.length > 300 ? '…' : ''}</p>
              </div>
            ))}
          </div>
        ) : <p className="text-text-muted text-[13px]">No drafts awaiting review.</p>}
      </Section>

      {/* REPLY GUY */}
      <Section title="Reply-guy" note="Auto-replies to target accounts. Twitter is hard-capped to protect the monthly X API quota; Bluesky carries volume.">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <Stat label="Posted today" value={fmt(reply.data?.posted_today)} />
          <Stat label="Active targets" value={fmt(reply.data?.active_targets)} />
          <Stat label="Queue (drafted+new)" value={fmt(reply.data?.queue_size)} />
          <Stat label="Posted (all-time)" value={fmt(rc.posted)} sub={`${fmt(rc.posting_error)} errors`} />
        </div>
      </Section>

      <div className="mt-12 text-[12px] text-text-muted/60">
        Data from the same endpoints as the legacy admin. This view is read-first; use the legacy admin for destructive/edit actions.
      </div>
    </div>
  )
}
