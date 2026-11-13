/** The summary strip at the top of the Metrics tab: six numbers, each with its change
 *  against the period of the same length just before (▲ / ▼). Read-only, so a viewer
 *  sees it too. Reads the nightly traffic snapshot, the daily landing counts and the
 *  ad cost view (with its previous-period total). */
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'

import api from '../../lib/api'
import { Info } from './AdminGlossary'
import type { GlossaryKey } from './adminGlossaryTerms'
import { avgOf, dayLabel, fmtAvg, pctOf, previousDays, rangeLabel, sumOf, useDashWindow } from './adminMetricsUtil'

interface Row { day: string; [col: string]: number | string | null | undefined }
interface LandingDay { date: string; lp_view: number; copy_plugin_cmd: number }
interface CostTotal { spend_usd: number; lp_view: number; copy_plugin_cmd: number; cost_per_copy_plugin_cmd: number | null }

const num = (v: unknown) => (typeof v === 'number' ? v : null)
const shift = (day: string, by: number) => new Date(Date.parse(`${day}T00:00:00Z`) + by * 86_400_000).toISOString().slice(0, 10)

/** "▲ 12%" / "▼ 3%" / "no change", coloured by whether the move is good. */
function Delta({ cur, prev, better, prevText }: { cur: number | null; prev: number | null; better: 'up' | 'down'; prevText?: string }) {
  if (cur == null) return null
  const vs = prevText ? <span className="text-text-muted"> · {prevText}</span> : null
  if (prev == null) return <span className="text-text-muted/70">no earlier period on file to compare</span>
  if (prev === 0) return <span className="text-text-muted/70">{cur === 0 ? 'no change' : 'new: was 0'}{vs}</span>
  const change = (cur - prev) / prev
  if (Math.abs(change) < 0.005) return <span className="text-text-muted">no change{vs}</span>
  const up = change > 0
  const good = up === (better === 'up')
  return <span className={good ? 'text-success' : 'text-danger'}>{up ? '▲' : '▼'} {Math.abs(Math.round(change * 100)).toLocaleString()}%{vs}</span>
}

function Tile({ label, k, value, scope, children }: { label: string; k: GlossaryKey; value: string; scope: string; children?: ReactNode }) {
  return (
    <div className="glass rounded-xl p-4 min-w-0">
      <div className="text-[12px] font-semibold text-text-muted">{label}<Info k={k} /></div>
      <div className="mt-1 text-2xl font-extrabold tabular-nums">{value}</div>
      <div className="mt-0.5 font-mono text-[10.5px] text-text-muted/70">{scope}</div>
      <div className="mt-1 text-[11.5px] tabular-nums">{children}</div>
    </div>
  )
}

export default function SummaryStrip() {
  const w = useDashWindow()
  const n = w.days
  const prevDays = previousDays(n, Date.parse(`${w.today}T12:00:00Z`))
  const traffic = useQuery<{ rows?: Row[] }>({
    queryKey: ['admin-dash-claude-traffic', 2 * n + 1],
    queryFn: async () => { try { return (await api.get('/admin/metrics/traffic', { params: { days: 2 * n + 1 } })).data } catch { return {} } },
  })
  const landing = useQuery<{ landing?: LandingDay[] }>({
    queryKey: ['admin-dash-landing-daily', 2 * n + 1],
    queryFn: async () => { try { return (await api.get('/analytics/conversion/daily', { params: { days: 2 * n + 1 } })).data } catch { return {} } },
  })
  const cost = useQuery<{ total?: CostTotal; previous?: CostTotal }>({
    queryKey: ['admin-campaign-channels', n, 'previous'],
    queryFn: async () => { try { return (await api.get('/admin/ad-spend/cost-per-action', { params: { days: n, group_by: 'source', previous: true } })).data } catch { return {} } },
  })

  const byDay = Object.fromEntries((traffic.data?.rows || []).map((r) => [r.day, r]))
  const col = (days: string[], c: string) => days.map((d) => num(byDay[d]?.[c]))
  // The two 7-day machine counts: the newest snapshot in the window against the one 7
  // days before it, on the same column (cloud-excluded only when both rows have it).
  const latestDay = [...w.complete].reverse().find((d) => byDay[d])
  const weekBefore = latestDay ? shift(latestDay, -7) : undefined
  const seven = (base: string) => {
    const a = latestDay ? byDay[latestDay] : undefined
    const b = weekBefore ? byDay[weekBefore] : undefined
    const c = num(a?.[`${base}_excl_cloud`]) != null && (!b || num(b[`${base}_excl_cloud`]) != null) ? `${base}_excl_cloud` : base
    return { cur: num(a?.[c]), prev: num(b?.[c]) }
  }
  const prot = seven('checked_machines_7d')
  const conn = seven('cc_machines_7d')
  const sevenScope = latestDay ? `unique · 7 days to ${dayLabel(latestDay)}` : 'unique · 7 days'
  const sevenPrev = weekBefore ? `vs 7 days to ${dayLabel(weekBefore)}` : ''

  const prevText = `vs ${rangeLabel(prevDays)}`
  const caiCur = avgOf(col(w.complete, 'callers_claude'))
  const caiPrev = avgOf(col(prevDays, 'callers_claude'))
  const anyNew = (days: string[]) => col(days, 'new_checked_same_day').some((v) => v != null)
  const newCur = anyNew(w.complete) ? sumOf(col(w.complete, 'new_checked_same_day')) : null
  const newPrev = anyNew(prevDays) ? sumOf(col(prevDays, 'new_checked_same_day')) : null

  const lby = Object.fromEntries((landing.data?.landing || []).map((d) => [d.date, d]))
  const lsum = (days: string[], k: 'lp_view' | 'copy_plugin_cmd') => days.reduce((a, d) => a + (lby[d]?.[k] ?? 0), 0)
  const hasLanding = !!landing.data?.landing
  const landedCur = hasLanding ? lsum(w.complete, 'lp_view') : null
  const copiedCur = hasLanding ? lsum(w.complete, 'copy_plugin_cmd') : null
  const landedPrev = hasLanding ? lsum(prevDays, 'lp_view') : null
  const copiedPrev = hasLanding ? lsum(prevDays, 'copy_plugin_cmd') : null

  const cpc = cost.data?.total?.cost_per_copy_plugin_cmd ?? null
  const cpcPrev = cost.data?.previous?.cost_per_copy_plugin_cmd ?? null
  const usd = (v: number | null) => (v == null ? '—' : `$${v.toFixed(2)}`)
  const windowScope = `${rangeLabel(w.complete)} (UTC)`

  return (
    <section className="mt-6" aria-label="Summary">
      <div className="flex items-baseline justify-between gap-3 flex-wrap">
        <h2 className="text-lg font-bold">At a glance</h2>
        <span className="text-[11.5px] text-text-muted">▲ / ▼ = change against the {n} days before<Info k="change" /></span>
      </div>
      <div className="mt-3 grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        <Tile label="Machines protected" k="protected" value={prot.cur != null ? prot.cur.toLocaleString() : 'Not ready'} scope={sevenScope}>
          <Delta cur={prot.cur} prev={prot.prev} better="up" prevText={sevenPrev} />
        </Tile>
        <Tile label="Machines connecting" k="connecting" value={conn.cur != null ? conn.cur.toLocaleString() : 'Not ready'} scope={sevenScope}>
          <Delta cur={conn.cur} prev={conn.prev} better="up" prevText={sevenPrev} />
        </Tile>
        <Tile label="Claude.ai users" k="claude_ai_users" value={fmtAvg(caiCur)} scope={`average per day · ${windowScope}`}>
          <Delta cur={caiCur} prev={caiPrev} better="up" prevText={prevText} />
        </Tile>
        <Tile label="New plugin installs" k="new_installs" value={newCur != null ? newCur.toLocaleString() : 'Not ready'} scope={`first-time machines checked · ${windowScope}`}>
          <Delta cur={newCur} prev={newPrev} better="up" prevText={prevText} />
        </Tile>
        <Tile label="Landing visits → copies" k="copy" value={landedCur != null ? `${landedCur.toLocaleString()} → ${(copiedCur ?? 0).toLocaleString()}` : '—'} scope={`landed → copied the install command · ${windowScope}`}>
          {landedCur != null && <div className="text-text-muted">{pctOf(copiedCur ?? 0, landedCur)} of landed visits copied</div>}
          <div>Landed: <Delta cur={landedCur} prev={landedPrev} better="up" prevText={prevText} /></div>
          <div>Copied: <Delta cur={copiedCur} prev={copiedPrev} better="up" /></div>
        </Tile>
        <Tile label="Ad cost per copy" k="cost_per_copy" value={usd(cpc)} scope={`all channels · last ${n} days up to now`}>
          {cost.data?.total && <div className="text-text-muted">{usd(cost.data.total.spend_usd)} spent · {cost.data.total.copy_plugin_cmd.toLocaleString()} copies from ads</div>}
          <Delta cur={cpc} prev={cpcPrev} better="down" prevText={`vs the ${n} days before`} />
        </Tile>
      </div>
    </section>
  )
}
