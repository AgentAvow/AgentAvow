/** Ads and campaigns: cost per result by channel (utm_source: reddit, x, google and any
 * other), the per-campaign funnel (visits → landed (lp_view) → copied the install command
 * (copy_plugin_cmd), by utm_source / utm_campaign / utm_content), the spend Kenne enters
 * per channel, and cost per result per ad. Uses the page's time window. Reads
 * /analytics/attribution/campaigns (first-touch UTM tags, bots left out) and
 * /admin/ad-spend. Spend entry is admin only (the server 403s everyone else). */
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import api from '../../lib/api'
import { useAdminAccess } from './adminAccess'
import { Info } from './AdminGlossary'
import { useDashWindow } from './adminMetricsUtil'

const DEFAULT_CAMPAIGN = '2026-11-test-dev'
/** The campaign name each channel's ad links carry (utm_campaign), used as the default
 *  when entering that channel's spend. */
const CAMPAIGN_BY_CHANNEL: Record<string, string> = { reddit: '2026-11-test-dev', x: '2026-11-test-x', google: '2026-11-test-google' }
const CHANNEL_LABEL: Record<string, string> = { reddit: 'Reddit', x: 'X', google: 'Google', '(no utm_source)': 'No channel tag' }
const ALL = '__all__'

interface CampaignRow {
  source: string | null; medium: string | null; campaign: string | null
  content: string | null; term: string | null
  sessions: number; lp_view: number; check_submit: number; result_view: number
  copy_plugin_cmd: number; open_plugin_dir: number; add_claude: number; add_chatgpt: number
  badge_copied: number; contact_submit: number
}
interface CostRow {
  utm_content: string | null; spend_usd: number; impressions: number; clicks: number
  sessions: number; lp_view: number; copy_plugin_cmd: number
  cost_per_lp_view: number | null; cost_per_copy_plugin_cmd: number | null
}
interface CostView { rows: CostRow[]; total: Omit<CostRow, 'utm_content' | 'impressions' | 'clicks'> }
type ChannelRow = Omit<CostRow, 'utm_content'> & { channel: string }
interface ChannelView { rows: ChannelRow[]; total: CostView['total']; previous?: CostView['total'] }
interface SpendRow { id: string; day: string; utm_source: string | null; utm_campaign: string; utm_content: string | null; spend_usd: number; impressions: number | null; clicks: number | null; source: string }

const fmt = (n: number | null | undefined) => (n ?? 0).toLocaleString()
const usd = (n: number | null | undefined) => (n == null ? '—' : `$${n.toFixed(2)}`)
const rate = (num: number, den: number) => (den ? `${((num / den) * 100).toFixed(1)}%` : '—')
const todayUtc = () => new Date().toISOString().slice(0, 10)
const th = 'py-1.5 pr-3 text-left font-mono text-[11px] uppercase tracking-wide text-text-muted/70'
const td = 'py-1.5 pr-3 tabular-nums'

export default function CampaignPanel() {
  const qc = useQueryClient()
  // The page window (7 / 30 / 90). These endpoints count visits up to now, so today
  // so far is included here; the scope line says so.
  const { days } = useDashWindow()
  const [campaign, setCampaign] = useState<string>(DEFAULT_CAMPAIGN)
  const campaignParam = campaign === ALL ? undefined : campaign

  const funnel = useQuery<{ campaigns: CampaignRow[] }>({
    queryKey: ['admin-campaign-funnel', days],
    queryFn: async () => (await api.get('/analytics/attribution/campaigns', { params: { days } })).data,
  })
  // Every channel, no campaign filter. Same query as the summary strip's cost tile.
  const channels = useQuery<ChannelView>({
    queryKey: ['admin-campaign-channels', days, 'previous'],
    queryFn: async () => { try { return (await api.get('/admin/ad-spend/cost-per-action', { params: { days, group_by: 'source', previous: true } })).data } catch { return { rows: [], total: { spend_usd: 0, sessions: 0, lp_view: 0, copy_plugin_cmd: 0, cost_per_lp_view: null, cost_per_copy_plugin_cmd: null } } } },
  })
  const cost = useQuery<CostView>({
    queryKey: ['admin-campaign-cost', days, campaignParam],
    queryFn: async () => (await api.get('/admin/ad-spend/cost-per-action', { params: { days, campaign: campaignParam } })).data,
  })
  // The spend rows and the editor are admin-only; a read-only viewer sees the funnel and
  // cost per action (the server 403s a viewer on /admin/ad-spend and its writes).
  const { isAdmin } = useAdminAccess()
  const spend = useQuery<{ rows: SpendRow[]; total_usd: number }>({
    queryKey: ['admin-ad-spend'],
    queryFn: async () => (await api.get('/admin/ad-spend', { params: { days: 60 } })).data,
    enabled: isAdmin,
  })
  const refresh = () => ['admin-campaign-cost', 'admin-ad-spend', 'admin-campaign-channels'].forEach((k) => qc.invalidateQueries({ queryKey: [k] }))

  const all = funnel.data?.campaigns || []
  const campaigns = [...new Set([...Object.values(CAMPAIGN_BY_CHANNEL), ...all.map((r) => r.campaign).filter((c): c is string => !!c)])].sort()
  const rows = campaign === ALL ? all : all.filter((r) => r.campaign === campaign)
  const tot = rows.reduce((a, r) => ({ sessions: a.sessions + r.sessions, lp: a.lp + r.lp_view, copy: a.copy + r.copy_plugin_cmd }), { sessions: 0, lp: 0, copy: 0 })

  return (
    <section className="mt-10">
      <div className="flex items-baseline justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-lg font-bold">Ads and campaigns</h2>
          <p className="mt-0.5 font-mono text-[11.5px] text-primary-light/90">Last {days} days up to now (UTC), today so far included: this panel counts visits and spend, not whole days</p>
          <p className="mt-1 text-text-muted text-[13px] max-w-[72ch]">
            Visits → landed on a landing page → copied the /plugin install command, by the campaign tags on the link that first brought each visitor in. A return visit counts toward the campaign that first brought the visitor. Crawlers and headless browsers are left out (from Nov 11 on; older visits all count). Plugin directory and /plugin installs can't be tied to a campaign: these are clicks and copies, not installs.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-[12px]">
          <select value={campaign} onChange={(e) => setCampaign(e.target.value)} className="bg-surface rounded-lg px-2 py-1">
            <option value={ALL}>All campaigns</option>
            {campaigns.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
      </div>

      <div className="glass rounded-2xl p-5 mt-4 overflow-x-auto">
        <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">By channel<Info k="channel" /> · every campaign</div>
        <table className="w-full text-[12.5px]">
          <thead><tr>
            <th className={th}>Channel</th><th className={`${th} text-right`}>Spend</th><th className={`${th} text-right`}>Impressions</th><th className={`${th} text-right`}>Clicks</th>
            <th className={`${th} text-right`}>Visits</th><th className={`${th} text-right`}>Landed</th><th className={`${th} text-right`}>Copied install cmd</th>
            <th className={`${th} text-right`}>$ per landed visit</th><th className={`${th} text-right`}>$ per copy<Info k="cost_per_copy" /></th>
          </tr></thead>
          <tbody>
            {(channels.data?.rows || []).map((r) => (
              <tr key={r.channel} className={`border-t border-border/40${!r.spend_usd && !r.sessions ? ' opacity-50' : ''}`}>
                <td className="py-1.5 pr-3">{CHANNEL_LABEL[r.channel] ?? <span className="font-mono">{r.channel}</span>}</td>
                <td className={`${td} text-right`}>{usd(r.spend_usd)}</td>
                <td className={`${td} text-right text-text-muted`}>{fmt(r.impressions)}</td>
                <td className={`${td} text-right text-text-muted`}>{fmt(r.clicks)}</td>
                <td className={`${td} text-right`}>{fmt(r.sessions)}</td>
                <td className={`${td} text-right`}>{fmt(r.lp_view)}</td>
                <td className={`${td} text-right`}>{fmt(r.copy_plugin_cmd)}</td>
                <td className={`${td} text-right`}>{usd(r.cost_per_lp_view)}</td>
                <td className={`${td} text-right font-semibold`}>{usd(r.cost_per_copy_plugin_cmd)}</td>
              </tr>
            ))}
            {channels.data?.total && (
              <tr className="border-t border-border/60 font-semibold">
                <td className="py-1.5 pr-3">all channels</td><td className={`${td} text-right`}>{usd(channels.data.total.spend_usd)}</td><td /><td />
                <td className={`${td} text-right`}>{fmt(channels.data.total.sessions)}</td><td className={`${td} text-right`}>{fmt(channels.data.total.lp_view)}</td><td className={`${td} text-right`}>{fmt(channels.data.total.copy_plugin_cmd)}</td>
                <td className={`${td} text-right`}>{usd(channels.data.total.cost_per_lp_view)}</td><td className={`${td} text-right`}>{usd(channels.data.total.cost_per_copy_plugin_cmd)}</td>
              </tr>
            )}
          </tbody>
        </table>
        <p className="mt-2 text-[11px] text-text-muted/60">Visits count only visitors whose first link carried campaign tags. Reddit, X and Google are always listed; any other utm_source that brought a visit or has spend shows too. A cost shows once its count is above zero.</p>
      </div>

      <div className="glass rounded-2xl p-5 mt-3 overflow-x-auto">
        <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">
          Funnel · {fmt(tot.sessions)} visits · {fmt(tot.lp)} landed · {fmt(tot.copy)} copied the install command ({rate(tot.copy, tot.lp)} of landed)
        </div>
        {rows.length ? (
          <table className="w-full text-[12.5px]">
            <thead><tr>
              <th className={th}>Channel / medium</th>{campaign === ALL && <th className={th}>Campaign</th>}<th className={th} title="utm_content on the ad's link">Ad</th><th className={th} title="utm_term on the ad's link">Keyword</th>
              <th className={`${th} text-right`}>Visits</th><th className={`${th} text-right`}>Landed</th><th className={`${th} text-right`}>Ran a check</th>
              <th className={`${th} text-right`}>Copied install cmd</th><th className={`${th} text-right`}>Copy rate</th><th className={`${th} text-right`}>Opened plugin directory</th>
              <th className={`${th} text-right`}>Add Claude</th><th className={`${th} text-right`}>Add ChatGPT</th>
            </tr></thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i} className="border-t border-border/40">
                  <td className="py-1.5 pr-3 font-mono">{r.source || '—'}{r.medium ? ` / ${r.medium}` : ''}</td>
                  {campaign === ALL && <td className="py-1.5 pr-3 font-mono">{r.campaign || '—'}</td>}
                  <td className="py-1.5 pr-3 font-mono">{r.content || '—'}</td>
                  <td className="py-1.5 pr-3 font-mono text-text-muted">{r.term || '—'}</td>
                  <td className={`${td} text-right`}>{fmt(r.sessions)}</td>
                  <td className={`${td} text-right`}>{fmt(r.lp_view)}</td>
                  <td className={`${td} text-right text-text-muted`}>{fmt(r.check_submit)}</td>
                  <td className={`${td} text-right font-semibold`}>{fmt(r.copy_plugin_cmd)}</td>
                  <td className={`${td} text-right`}>{rate(r.copy_plugin_cmd, r.lp_view)}</td>
                  <td className={`${td} text-right text-text-muted`}>{fmt(r.open_plugin_dir)}</td>
                  <td className={`${td} text-right text-text-muted`}>{fmt(r.add_claude)}</td>
                  <td className={`${td} text-right text-text-muted`}>{fmt(r.add_chatgpt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p className="text-[12.5px] text-text-muted/70">{funnel.isLoading ? 'Loading…' : `No visits tagged ${campaign === ALL ? 'with any campaign' : campaign} in the last ${days} days.`}</p>}
      </div>

      <div className="glass rounded-2xl p-5 mt-3 overflow-x-auto">
        <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Cost per result · by ad</div>
        {cost.data?.rows.length ? (
          <table className="w-full text-[12.5px]">
            <thead><tr>
              <th className={th} title="utm_content on the ad's link">Ad</th><th className={`${th} text-right`}>Spend</th><th className={`${th} text-right`}>Impressions</th><th className={`${th} text-right`}>Clicks</th>
              <th className={`${th} text-right`}>Landed</th><th className={`${th} text-right`}>Copied install cmd</th>
              <th className={`${th} text-right`}>$ per landed visit</th><th className={`${th} text-right`}>$ per copy</th>
            </tr></thead>
            <tbody>
              {cost.data.rows.map((r) => (
                <tr key={r.utm_content ?? ''} className="border-t border-border/40">
                  <td className="py-1.5 pr-3 font-mono">{r.utm_content || '(no ad tag)'}</td>
                  <td className={`${td} text-right`}>{usd(r.spend_usd)}</td>
                  <td className={`${td} text-right text-text-muted`}>{fmt(r.impressions)}</td>
                  <td className={`${td} text-right text-text-muted`}>{fmt(r.clicks)}</td>
                  <td className={`${td} text-right`}>{fmt(r.lp_view)}</td>
                  <td className={`${td} text-right`}>{fmt(r.copy_plugin_cmd)}</td>
                  <td className={`${td} text-right`}>{usd(r.cost_per_lp_view)}</td>
                  <td className={`${td} text-right font-semibold`}>{usd(r.cost_per_copy_plugin_cmd)}</td>
                </tr>
              ))}
              <tr className="border-t border-border/60 font-semibold">
                <td className="py-1.5 pr-3">total</td><td className={`${td} text-right`}>{usd(cost.data.total.spend_usd)}</td><td /><td />
                <td className={`${td} text-right`}>{fmt(cost.data.total.lp_view)}</td><td className={`${td} text-right`}>{fmt(cost.data.total.copy_plugin_cmd)}</td>
                <td className={`${td} text-right`}>{usd(cost.data.total.cost_per_lp_view)}</td><td className={`${td} text-right`}>{usd(cost.data.total.cost_per_copy_plugin_cmd)}</td>
              </tr>
            </tbody>
          </table>
        ) : <p className="text-[12.5px] text-text-muted/70">No spend or visits for this campaign in the window.{isAdmin ? ' Enter spend below.' : ''}</p>}
        <p className="mt-2 text-[11px] text-text-muted/60">Spend is summed over the last {days} UTC days, today included; the funnel covers visits active in the last {days} × 24 hours. A cost shows once its count is above zero.</p>
      </div>

      {isAdmin && <SpendEditor rows={spend.data?.rows || []} onChange={refresh} />}
    </section>
  )
}

const CHANNELS = ['reddit', 'x', 'google'] as const
const OTHER = '__other__'

function SpendEditor({ rows, onChange }: { rows: SpendRow[]; onChange: () => void }) {
  const [day, setDay] = useState(todayUtc())
  // The channel this spend belongs to (sent as utm_source). Picking one fills in its
  // campaign name; "other" takes any utm_source.
  const [channelPick, setChannelPick] = useState<string>('reddit')
  const [otherChannel, setOtherChannel] = useState('')
  const channel = channelPick === OTHER ? otherChannel.trim().toLowerCase() : channelPick
  const [utmCampaign, setUtmCampaign] = useState(CAMPAIGN_BY_CHANNEL.reddit)
  const pickChannel = (c: string) => { setChannelPick(c); if (CAMPAIGN_BY_CHANNEL[c]) setUtmCampaign(CAMPAIGN_BY_CHANNEL[c]) }
  const [content, setContent] = useState('')
  const [amount, setAmount] = useState('')
  const [impressions, setImpressions] = useState('')
  const [clicks, setClicks] = useState('')
  const [csv, setCsv] = useState('')
  const [showCsv, setShowCsv] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)
  const optInt = (v: string) => (v.trim() ? Number(v.replace(/[^0-9]/g, '')) : null)

  const put = useMutation({
    mutationFn: async () => (await api.put('/admin/ad-spend', {
      day, utm_campaign: utmCampaign.trim(), utm_content: content.trim() || null, utm_source: channel,
      spend_usd: Number(amount).toFixed(2), impressions: optInt(impressions), clicks: optInt(clicks),
    })).data,
    onSuccess: () => { setAmount(''); setImpressions(''); setClicks(''); setMsg('saved'); onChange() },
    onError: (e: unknown) => {
      const r = (e as { response?: { status?: number; data?: { detail?: unknown } } })?.response
      setMsg(r?.status === 409 && typeof r.data?.detail === 'string' ? r.data.detail : 'could not save: check the date, campaign and amount')
    },
  })
  const importCsv = useMutation<{ imported: number; errors: string[] }>({
    mutationFn: async () => (await api.post('/admin/ad-spend/import', { csv, utm_campaign: utmCampaign.trim() || null, utm_source: channel })).data,
    onSuccess: (d) => { setMsg(`imported ${d.imported} rows${d.errors.length ? `; skipped: ${d.errors.slice(0, 3).join(' ')}` : ''}`); if (d.imported) setCsv(''); onChange() },
    onError: () => setMsg('could not import the CSV'),
  })
  const del = useMutation({ mutationFn: (id: string) => api.delete(`/admin/ad-spend/${id}`), onSuccess: onChange })
  const input = 'bg-surface rounded-lg px-2 py-1 font-mono'

  return (
    <div className="glass rounded-2xl p-5 mt-3">
      <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Enter ad spend · one row per day per ad, for any channel</div>
      <form className="flex items-center gap-2 flex-wrap text-[12px]" onSubmit={(e) => { e.preventDefault(); setMsg(null); put.mutate() }}>
        <select value={channelPick} onChange={(e) => pickChannel(e.target.value)} aria-label="Channel" className={input}>
          {CHANNELS.map((c) => <option key={c} value={c}>{CHANNEL_LABEL[c]}</option>)}
          <option value={OTHER}>Other…</option>
        </select>
        {channelPick === OTHER && <input value={otherChannel} onChange={(e) => setOtherChannel(e.target.value)} placeholder="channel (utm_source)" className={`${input} w-36`} />}
        <input type="date" value={day} onChange={(e) => setDay(e.target.value)} aria-label="Day (UTC)" className={input} />
        <input value={utmCampaign} onChange={(e) => setUtmCampaign(e.target.value)} placeholder="campaign (utm_campaign)" className={`${input} min-w-[12rem]`} />
        <input value={content} onChange={(e) => setContent(e.target.value)} placeholder="ad tag (utm_content)" className={`${input} min-w-[10rem]`} />
        <input value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" placeholder="spend $" className={`${input} w-24`} />
        <input value={impressions} onChange={(e) => setImpressions(e.target.value)} inputMode="numeric" placeholder="impressions" className={`${input} w-28`} />
        <input value={clicks} onChange={(e) => setClicks(e.target.value)} inputMode="numeric" placeholder="clicks" className={`${input} w-20`} />
        <button type="submit" disabled={put.isPending || !channel || !utmCampaign.trim() || !amount.trim() || Number.isNaN(Number(amount))} className="px-2.5 py-1 rounded-lg font-mono bg-primary/15 text-primary-light hover:bg-primary/25 disabled:opacity-50">save</button>
        <button type="button" onClick={() => setShowCsv(!showCsv)} className="px-2.5 py-1 rounded-lg font-mono text-text-muted hover:text-text">{showCsv ? 'hide CSV' : `paste ${CHANNEL_LABEL[channel] ?? channel} ads CSV`}</button>
        {msg && <span className="text-text-muted">{msg}</span>}
      </form>
      {showCsv && (
        <div className="mt-2">
          <textarea value={csv} onChange={(e) => setCsv(e.target.value)} rows={5} placeholder="Date,Campaign Name,Ad Group Name,Ad Name,Impressions,Clicks,Amount Spent (USD)" className="w-full text-[12px] rounded-lg bg-surface border border-border p-2 font-mono" />
          <div className="mt-1 flex items-center gap-2 text-[11.5px] text-text-muted">
            <button onClick={() => { setMsg(null); importCsv.mutate() }} disabled={importCsv.isPending || !csv.trim() || !channel} className="px-2.5 py-1 rounded-lg font-mono bg-primary/15 text-primary-light hover:bg-primary/25 disabled:opacity-50">import</button>
            <span>Reads a Reddit Ads export, or any CSV with Date, Ad name and Spend (or Cost) columns. Each row is one day of one ad: the ad name becomes the ad tag, and every row gets the channel and campaign above. Pasting the same export twice changes nothing.</span>
          </div>
        </div>
      )}
      {rows.length > 0 && (
        <details className="mt-3 text-[12px]">
          <summary className="cursor-pointer text-text-muted">Entered spend, last 60 days ({rows.length} rows)</summary>
          <table className="w-full mt-1">
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className="border-t border-border/40">
                  <td className="py-1 pr-3 font-mono">{r.day}</td>
                  <td className="py-1 pr-3">{r.utm_source ? (CHANNEL_LABEL[r.utm_source.toLowerCase()] ?? r.utm_source) : '—'}</td>
                  <td className="py-1 pr-3 font-mono">{r.utm_campaign}</td>
                  <td className="py-1 pr-3 font-mono">{r.utm_content || '—'}</td>
                  <td className="py-1 pr-3 tabular-nums text-right">{usd(r.spend_usd)}</td>
                  <td className="py-1 pr-3 tabular-nums text-right text-text-muted">{r.impressions != null ? fmt(r.impressions) : ''}</td>
                  <td className="py-1 pr-3 tabular-nums text-right text-text-muted">{r.clicks != null ? fmt(r.clicks) : ''}</td>
                  <td className="py-1 pr-3 text-text-muted/70">{r.source}</td>
                  <td className="py-1 text-right"><button onClick={() => del.mutate(r.id)} className="text-[11px] text-text-muted hover:text-danger">remove</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </div>
  )
}
