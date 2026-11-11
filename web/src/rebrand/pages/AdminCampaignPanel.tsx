/** Paid campaign test: the per-campaign funnel (sessions → lp_view → copy_plugin_cmd by
 * utm_source / utm_campaign / utm_content), the spend Kenne enters, and cost per action.
 * Reads /analytics/attribution/campaigns (first-touch UTM tags, bots left out) and
 * /admin/ad-spend. Admin only, like the rest of the dashboard. */
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import api from '../../lib/api'

const DEFAULT_CAMPAIGN = '2026-11-test-dev'
const ALL = '__all__'
const WINDOWS = [7, 14, 28] as const

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
interface SpendRow { id: string; day: string; utm_source: string | null; utm_campaign: string; utm_content: string | null; spend_usd: number; impressions: number | null; clicks: number | null; source: string }

const fmt = (n: number | null | undefined) => (n ?? 0).toLocaleString()
const usd = (n: number | null | undefined) => (n == null ? '—' : `$${n.toFixed(2)}`)
const rate = (num: number, den: number) => (den ? `${((num / den) * 100).toFixed(1)}%` : '—')
const todayUtc = () => new Date().toISOString().slice(0, 10)
const th = 'py-1.5 pr-3 text-left font-mono text-[11px] uppercase tracking-wide text-text-muted/70'
const td = 'py-1.5 pr-3 tabular-nums'

export default function CampaignPanel() {
  const qc = useQueryClient()
  const [days, setDays] = useState<(typeof WINDOWS)[number]>(14)
  const [campaign, setCampaign] = useState<string>(DEFAULT_CAMPAIGN)
  const campaignParam = campaign === ALL ? undefined : campaign

  const funnel = useQuery<{ campaigns: CampaignRow[] }>({
    queryKey: ['admin-campaign-funnel', days],
    queryFn: async () => (await api.get('/analytics/attribution/campaigns', { params: { days } })).data,
  })
  const cost = useQuery<CostView>({
    queryKey: ['admin-campaign-cost', days, campaignParam],
    queryFn: async () => (await api.get('/admin/ad-spend/cost-per-action', { params: { days, campaign: campaignParam } })).data,
  })
  const spend = useQuery<{ rows: SpendRow[]; total_usd: number }>({
    queryKey: ['admin-ad-spend'],
    queryFn: async () => (await api.get('/admin/ad-spend', { params: { days: 60 } })).data,
  })
  const refresh = () => ['admin-campaign-cost', 'admin-ad-spend'].forEach((k) => qc.invalidateQueries({ queryKey: [k] }))

  const all = funnel.data?.campaigns || []
  const campaigns = [...new Set([DEFAULT_CAMPAIGN, ...all.map((r) => r.campaign).filter((c): c is string => !!c)])].sort()
  const rows = campaign === ALL ? all : all.filter((r) => r.campaign === campaign)
  const tot = rows.reduce((a, r) => ({ sessions: a.sessions + r.sessions, lp: a.lp + r.lp_view, copy: a.copy + r.copy_plugin_cmd }), { sessions: 0, lp: 0, copy: 0 })

  return (
    <section className="mt-10">
      <div className="flex items-baseline justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-lg font-bold">Paid campaign test</h2>
          <p className="mt-1 text-text-muted text-[13px] max-w-[72ch]">
            Sessions → landed (lp_view) → copied the plugin command, by each session's first campaign tags. A return visit counts toward the campaign that first brought the session in. Crawlers and headless browsers are left out (events from Nov 11 on carry a bot/browser class; older events all count). Plugin directory and /plugin installs can't be tied to a campaign: these are clicks and copies, not installs.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-[12px]">
          <select value={campaign} onChange={(e) => setCampaign(e.target.value)} className="bg-surface rounded-lg px-2 py-1">
            <option value={ALL}>All campaigns</option>
            {campaigns.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          {WINDOWS.map((w) => (
            <button key={w} onClick={() => setDays(w)} className={`px-2.5 py-1 rounded-lg transition-colors ${days === w ? 'bg-primary/15 text-primary-light' : 'text-text-muted hover:text-text'}`}>{w}d</button>
          ))}
        </div>
      </div>

      <div className="glass rounded-2xl p-5 mt-4 overflow-x-auto">
        <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">
          Funnel · {fmt(tot.sessions)} sessions · {fmt(tot.lp)} landed · {fmt(tot.copy)} copied ({rate(tot.copy, tot.lp)} of landed)
        </div>
        {rows.length ? (
          <table className="w-full text-[12.5px]">
            <thead><tr>
              <th className={th}>Source / medium</th>{campaign === ALL && <th className={th}>Campaign</th>}<th className={th}>Content</th><th className={th}>Term</th>
              <th className={`${th} text-right`}>Sessions</th><th className={`${th} text-right`}>Landed</th><th className={`${th} text-right`}>Checks</th>
              <th className={`${th} text-right`}>Copied cmd</th><th className={`${th} text-right`}>Copy rate</th><th className={`${th} text-right`}>Plugin dir</th>
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
        ) : <p className="text-[12.5px] text-text-muted/70">{funnel.isLoading ? 'Loading…' : `No sessions tagged ${campaign === ALL ? 'with any campaign' : campaign} in the last ${days} days.`}</p>}
      </div>

      <div className="glass rounded-2xl p-5 mt-3 overflow-x-auto">
        <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Cost per action · by utm_content</div>
        {cost.data?.rows.length ? (
          <table className="w-full text-[12.5px]">
            <thead><tr>
              <th className={th}>Content</th><th className={`${th} text-right`}>Spend</th><th className={`${th} text-right`}>Impr.</th><th className={`${th} text-right`}>Clicks</th>
              <th className={`${th} text-right`}>Landed</th><th className={`${th} text-right`}>Copied cmd</th>
              <th className={`${th} text-right`}>$ / landed</th><th className={`${th} text-right`}>$ / copy</th>
            </tr></thead>
            <tbody>
              {cost.data.rows.map((r) => (
                <tr key={r.utm_content ?? ''} className="border-t border-border/40">
                  <td className="py-1.5 pr-3 font-mono">{r.utm_content || '(no content)'}</td>
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
        ) : <p className="text-[12.5px] text-text-muted/70">No spend or sessions for this campaign in the window. Enter spend below.</p>}
        <p className="mt-2 text-[11px] text-text-muted/60">Spend is summed over the last {days} UTC days; the funnel covers sessions active in the same window. A cost shows once its action count is above zero.</p>
      </div>

      <SpendEditor key={campaign} campaign={campaignParam ?? DEFAULT_CAMPAIGN} rows={spend.data?.rows || []} onChange={refresh} />
    </section>
  )
}

function SpendEditor({ campaign, rows, onChange }: { campaign: string; rows: SpendRow[]; onChange: () => void }) {
  const [day, setDay] = useState(todayUtc())
  const [utmCampaign, setUtmCampaign] = useState(campaign)
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
      day, utm_campaign: utmCampaign.trim(), utm_content: content.trim() || null, utm_source: 'reddit',
      spend_usd: Number(amount).toFixed(2), impressions: optInt(impressions), clicks: optInt(clicks),
    })).data,
    onSuccess: () => { setAmount(''); setImpressions(''); setClicks(''); setMsg('saved'); onChange() },
    onError: () => setMsg('could not save: check the date, campaign and amount'),
  })
  const importCsv = useMutation<{ imported: number; errors: string[] }>({
    mutationFn: async () => (await api.post('/admin/ad-spend/import', { csv, utm_campaign: utmCampaign.trim() || null, utm_source: 'reddit' })).data,
    onSuccess: (d) => { setMsg(`imported ${d.imported} rows${d.errors.length ? `; skipped: ${d.errors.slice(0, 3).join(' ')}` : ''}`); if (d.imported) setCsv(''); onChange() },
    onError: () => setMsg('could not import the CSV'),
  })
  const del = useMutation({ mutationFn: (id: string) => api.delete(`/admin/ad-spend/${id}`), onSuccess: onChange })
  const input = 'bg-surface rounded-lg px-2 py-1 font-mono'

  return (
    <div className="glass rounded-2xl p-5 mt-3">
      <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Ad spend · one row per day per ad (utm_content)</div>
      <form className="flex items-center gap-2 flex-wrap text-[12px]" onSubmit={(e) => { e.preventDefault(); setMsg(null); put.mutate() }}>
        <input type="date" value={day} onChange={(e) => setDay(e.target.value)} className={input} />
        <input value={utmCampaign} onChange={(e) => setUtmCampaign(e.target.value)} placeholder="utm_campaign" className={`${input} min-w-[12rem]`} />
        <input value={content} onChange={(e) => setContent(e.target.value)} placeholder="utm_content (ad)" className={`${input} min-w-[10rem]`} />
        <input value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" placeholder="spend $" className={`${input} w-24`} />
        <input value={impressions} onChange={(e) => setImpressions(e.target.value)} inputMode="numeric" placeholder="impressions" className={`${input} w-28`} />
        <input value={clicks} onChange={(e) => setClicks(e.target.value)} inputMode="numeric" placeholder="clicks" className={`${input} w-20`} />
        <button type="submit" disabled={put.isPending || !utmCampaign.trim() || !amount.trim() || Number.isNaN(Number(amount))} className="px-2.5 py-1 rounded-lg font-mono bg-primary/15 text-primary-light hover:bg-primary/25 disabled:opacity-50">save</button>
        <button type="button" onClick={() => setShowCsv(!showCsv)} className="px-2.5 py-1 rounded-lg font-mono text-text-muted hover:text-text">{showCsv ? 'hide CSV' : 'paste Reddit Ads CSV'}</button>
        {msg && <span className="text-text-muted">{msg}</span>}
      </form>
      {showCsv && (
        <div className="mt-2">
          <textarea value={csv} onChange={(e) => setCsv(e.target.value)} rows={5} placeholder="Date,Campaign Name,Ad Group Name,Ad Name,Impressions,Clicks,Amount Spent (USD)" className="w-full text-[12px] rounded-lg bg-surface border border-border p-2 font-mono" />
          <div className="mt-1 flex items-center gap-2 text-[11.5px] text-text-muted">
            <button onClick={() => { setMsg(null); importCsv.mutate() }} disabled={importCsv.isPending || !csv.trim()} className="px-2.5 py-1 rounded-lg font-mono bg-primary/15 text-primary-light hover:bg-primary/25 disabled:opacity-50">import</button>
            <span>Each row is read as one day of one ad: the ad name becomes utm_content, and every row gets the utm_campaign above. Pasting the same export twice changes nothing.</span>
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
