/** Shared components for the admin Metrics tab: section frame with its time window,
 *  stat tile, sparkline, bar list and the daily trend chart. Pure SVG, no chart library.
 *  Helpers (window context, day labels, formatting) are in adminMetricsUtil.ts. */
import type { ReactNode } from 'react'

import { Reveal } from '../components/motion'
import { avgOf, dayLabel, fmt, fmtAvg, PAGE_WINDOWS, rangeLabel, sumOf, useDashWindow } from './adminMetricsUtil'
import type { PageWin } from './adminMetricsUtil'

export function Sparkline({ data }: { data?: (number | null | undefined)[] }) {
  const pts = (data ?? []).map((v, i) => [i, v] as const).filter((p): p is readonly [number, number] => typeof p[1] === 'number')
  if (!data || data.length < 2 || pts.length < 2) return null
  const max = Math.max(...pts.map((p) => p[1]), 1)
  const w = 100, h = 24
  const path = pts.map(([i, v]) => `${(i / (data.length - 1)) * w},${h - (v / max) * h}`).join(' ')
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-6 mt-2" preserveAspectRatio="none" aria-hidden="true">
      <polyline points={path} fill="none" stroke="url(#spark)" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
      <defs><linearGradient id="spark" x1="0" x2="1"><stop offset="0" stopColor="#2dd4bf" /><stop offset="1" stopColor="#818cf8" /></linearGradient></defs>
    </svg>
  )
}

export function Stat({ label, value, sub, series, tip }: { label: ReactNode; value: string | number; sub?: ReactNode; series?: (number | null | undefined)[]; tip?: string }) {
  return (
    <div className="glass rounded-2xl p-5 min-w-0" title={tip}>
      <div className="text-[24px] font-extrabold leading-none tabular-nums gradient-text">{value}</div>
      <div className="mt-1.5 text-[11.5px] font-mono uppercase tracking-wide text-text-muted">{label}</div>
      {sub && <div className="mt-0.5 text-[11px] text-text-muted/70">{sub}</div>}
      <Sparkline data={series} />
    </div>
  )
}

/** A dashboard section. `scope` is the time window its numbers cover, said in full
 *  ("Last 7 days: Nov 5–11 (UTC)", "Right now", "All time"); every section states one. */
export function Section({ title, scope, note, right, children }: { title: ReactNode; scope?: ReactNode; note?: ReactNode; right?: ReactNode; children: ReactNode }) {
  return (
    <Reveal>
      <section className="mt-10">
        <div className="flex items-baseline justify-between gap-3 flex-wrap">
          <div>
            <h2 className="text-lg font-bold">{title}</h2>
            {scope && <p className="mt-0.5 font-mono text-[11.5px] text-primary-light/90">{scope}</p>}
            {note && <p className="mt-1 text-text-muted text-[13px] max-w-[64ch]">{note}</p>}
          </div>
          {right}
        </div>
        <div className="mt-4">{children}</div>
      </section>
    </Reveal>
  )
}

export function BarList({ title, rows, labels, empty, gradient }: { title: string; rows: Record<string, number>; labels: Record<string, string>; empty: string; gradient: string }) {
  const entries = Object.entries(rows).sort((a, b) => b[1] - a[1])
  const total = entries.reduce((a, [, n]) => a + n, 0)
  const max = Math.max(...entries.map(([, n]) => n), 1)
  return (
    <div className="glass rounded-2xl p-5 min-w-0">
      <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-3">{title}</div>
      {total > 0 ? entries.map(([k, n]) => (
        <div key={k} className={`mb-2${n === 0 ? ' opacity-50' : ''}`}>
          <div className="flex justify-between text-[12.5px] mb-1"><span className="text-text-muted truncate">{labels[k] || k}</span><span className="tabular-nums text-text-muted/70 ml-3">{fmt(n)} <span className="text-[11px]">({Math.round((n / total) * 100)}%)</span></span></div>
          <div className="h-2 rounded-full bg-surface overflow-hidden"><div className="h-full rounded-full" style={{ width: `${(n / max) * 100}%`, background: gradient }} /></div>
        </div>
      )) : <p className="text-[12.5px] text-text-muted/70">{empty}</p>}
    </div>
  )
}

/** How a line's numbers add up, which decides what its legend may say:
 *  - flow: a count of events per day (calls, alerts). Days add up, so the legend shows
 *    the last day, the daily average and the window total.
 *  - distinct: distinct machines / people per day. Days do NOT add up (a machine on five
 *    days would count five times), so the legend shows the last day and the average.
 *  - stock: a level on that day (Certified tools, the answer mix): the last day only.
 *  - rolling: a rolling total (npm downloads over the last 7 days): the last day only. */
export type LineKind = 'flow' | 'distinct' | 'stock' | 'rolling'

export interface TrendLine {
  key: string; label: string; color: string
  /** One value per day in `days`; null / undefined = no data that day (drawn as a gap). */
  data?: (number | null | undefined)[]
  dashed?: boolean
  kind?: LineKind
  /** Today's partial value, drawn dashed after the last complete day when shown. */
  today?: number | null
}

/** A daily chart with labelled axes. Days with no data are gaps, never zeros. Today's
 *  partial UTC day is left out unless the page's "include today so far" is on, and is
 *  then drawn dashed and marked. Hover a point (or bar) for the exact day and value. */
export function TrendChart({ days, lines, empty, yLabel, bars }: { days?: string[]; lines: TrendLine[]; empty: string; yLabel: string; bars?: boolean }) {
  const { includeToday } = useDashWindow()
  const n0 = days?.length ?? 0
  const live = lines.map((l) => ({ ...l, data: (l.data ?? []).slice(-n0).map((v) => (typeof v === 'number' ? v : null)) }))
  const withToday = includeToday && live.some((l) => typeof l.today === 'number')
  const n = n0 + (withToday ? 1 : 0)
  const vals = (l: (typeof live)[number]) => [...l.data, ...(withToday ? [l.today ?? null] : [])]
  const allVals = live.flatMap((l) => vals(l)).filter((v): v is number => v != null)
  const stackMax = bars ? Math.max(0, ...Array.from({ length: n }, (_, i) => live.reduce((a, l) => a + (vals(l)[i] ?? 0), 0))) : 0
  const max = Math.max(1, bars ? stackMax : Math.max(0, ...allVals))
  if (!n0 || (!bars && n0 < 2) || allVals.every((v) => v === 0)) {
    return <p className="text-[12.5px] text-text-muted/70 py-6 text-center">{empty}</p>
  }
  // Nice y-axis ceiling: 1-2-5 steps so gridlines land on round numbers.
  const mag = Math.pow(10, Math.floor(Math.log10(max)))
  const step = [1, 2, 5, 10].map((m) => m * mag).find((v) => v * 4 >= max) ?? mag * 10
  const top = step * 4
  const W = 640, H = 214, L = 44, R = 12, T = 18, B = 30
  const slot = (W - L - R) / Math.max(1, bars ? n : n - 1)
  const x = (i: number) => (bars ? L + slot * (i + 0.5) : L + (i / Math.max(1, n - 1)) * (W - L - R))
  const y = (v: number) => T + (1 - v / top) * (H - T - B)
  const every = n > 14 ? Math.ceil(n / 7) : n > 7 ? 2 : 1
  const xLabel = (i: number) => (i >= n0 ? 'today*' : days![i].slice(5))
  const dayName = (i: number) => (i >= n0 ? 'today so far (partial)' : days![i])
  // Contiguous non-null runs, so a missing day breaks the line instead of dropping to 0.
  const runs = (data: (number | null)[]) => {
    const out: [number, number][][] = []
    let cur: [number, number][] = []
    data.forEach((v, i) => { if (v == null) { if (cur.length) out.push(cur); cur = [] } else cur.push([i, v]) })
    if (cur.length) out.push(cur)
    return out
  }
  const last = days![n0 - 1]
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto" role="img" aria-label={`${yLabel}, per UTC day`}>
        <text x={4} y={10} fontSize="10" fill="currentColor" fillOpacity="0.6" fontFamily="ui-monospace, monospace">{yLabel}</text>
        {[0, 1, 2, 3, 4].map((k) => (
          <g key={k}>
            <line x1={L} x2={W - R} y1={y(k * step)} y2={y(k * step)} stroke="currentColor" strokeOpacity={k === 0 ? 0.25 : 0.08} />
            <text x={L - 6} y={y(k * step) + 3.5} textAnchor="end" fontSize="10" fill="currentColor" fillOpacity="0.55" fontFamily="ui-monospace, monospace">{(k * step).toLocaleString()}</text>
          </g>
        ))}
        {Array.from({ length: n }, (_, i) => i).filter((i) => i % every === 0 || i === n - 1).map((i) => (
          <text key={i} x={x(i)} y={H - 14} textAnchor={!bars && i === 0 ? 'start' : !bars && i === n - 1 ? 'end' : 'middle'} fontSize="10" fill="currentColor" fillOpacity="0.55" fontFamily="ui-monospace, monospace">{xLabel(i)}</text>
        ))}
        <text x={W - R} y={H - 2} textAnchor="end" fontSize="9.5" fill="currentColor" fillOpacity="0.5" fontFamily="ui-monospace, monospace">day (UTC){withToday ? ' · * today so far, partial' : ''}</text>
        {withToday && <rect x={bars ? x(n0) - slot / 2 : x(n0 - 1)} y={T} width={bars ? slot : x(n0) - x(n0 - 1)} height={H - T - B} fill="currentColor" fillOpacity="0.04" />}
        {bars ? Array.from({ length: n }, (_, i) => {
          let acc = 0
          return (
            <g key={i}>
              {live.map((l) => {
                const v = vals(l)[i] ?? 0
                if (!v) return null
                const y0 = y(acc), y1 = y(acc + v)
                acc += v
                return (
                  <rect key={l.key} x={x(i) - slot * 0.35} width={slot * 0.7} y={y1} height={Math.max(1, y0 - y1)} fill={l.color} fillOpacity={i >= n0 ? 0.45 : 0.9} stroke={i >= n0 ? l.color : undefined} strokeDasharray={i >= n0 ? '3 2' : undefined}>
                    <title>{`${l.label} · ${dayName(i)} · ${v.toLocaleString()}`}</title>
                  </rect>
                )
              })}
            </g>
          )
        }) : live.map((l) => {
          const all = vals(l)
          const segs = runs(l.data)
          const lastVal = l.data[n0 - 1]
          return (
            <g key={l.key}>
              {segs.map((seg, si) => seg.length > 1 && (
                <polyline key={si} points={seg.map(([i, v]) => `${x(i)},${y(v)}`).join(' ')} fill="none" stroke={l.color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" strokeDasharray={l.dashed ? '4 4' : undefined} />
              ))}
              {withToday && lastVal != null && typeof l.today === 'number' && (
                <line x1={x(n0 - 1)} y1={y(lastVal)} x2={x(n0)} y2={y(l.today)} stroke={l.color} strokeWidth="1.5" strokeDasharray="2 3" strokeOpacity="0.7" />
              )}
              {all.map((v, i) => v != null && (
                <circle key={i} cx={x(i)} cy={y(v)} r={v > 0 ? 2.5 : 1.5} fill={i >= n0 ? 'none' : l.color} stroke={l.color} fillOpacity={v > 0 ? 1 : 0.4}>
                  <title>{`${l.label} · ${dayName(i)} · ${v.toLocaleString()}`}</title>
                </circle>
              ))}
            </g>
          )
        })}
      </svg>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11.5px]">
        {live.map((l) => {
          const kind = l.kind ?? 'flow'
          const lastV = l.data[n0 - 1]
          const avg = avgOf(l.data)
          const total = sumOf(l.data)
          const empty = l.data.every((v) => v == null || v === 0)
          const parts = [`${dayLabel(last)}: ${lastV == null ? 'no data' : lastV.toLocaleString()}`]
          if (kind === 'flow' || kind === 'distinct') parts.push(`avg ${fmtAvg(avg)}/day`)
          if (kind === 'flow') parts.push(`${total.toLocaleString()} in ${rangeLabel(days!)}`)
          if (withToday && typeof l.today === 'number') parts.push(`today so far ${l.today.toLocaleString()}`)
          return (
            <span key={l.key} className={`inline-flex items-center gap-1.5 tabular-nums${empty ? ' opacity-50' : ''}`}>
              <span className="inline-block w-3 h-0.5 rounded" style={{ background: l.color, height: bars ? 8 : undefined, width: bars ? 8 : undefined }} />
              <span className="text-text-muted">{l.label}</span>
              <span className="text-text">{parts[0]}</span>
              {parts.length > 1 && <span className="text-text-muted/60">· {parts.slice(1).join(' · ')}</span>}
            </span>
          )
        })}
      </div>
    </div>
  )
}

/** The page-level window control: 7 / 30 / 90 days, the dates they cover, and whether
 *  today's partial day is drawn on the charts. */
export function WindowBar({ days, setDays, includeToday, setIncludeToday }: { days: PageWin; setDays: (d: PageWin) => void; includeToday: boolean; setIncludeToday: (b: boolean) => void }) {
  const w = useDashWindow()
  return (
    <div className="mt-6 glass rounded-2xl px-4 py-3 flex items-center gap-x-4 gap-y-2 flex-wrap">
      <span className="text-[12.5px] font-semibold">Time window</span>
      <div className="flex gap-1 font-mono text-[12px]" role="group" aria-label="Time window">
        {PAGE_WINDOWS.map((d) => (
          <button key={d} onClick={() => setDays(d)} aria-pressed={days === d} className={`px-2.5 py-1 rounded-lg transition-colors ${days === d ? 'bg-primary/15 text-primary-light' : 'text-text-muted hover:text-text'}`}>{d} days</button>
        ))}
      </div>
      <span className="text-[13px] font-semibold tabular-nums">Last {w.days} days: {rangeLabel(w.complete)} (UTC)</span>
      <label className="ml-auto inline-flex items-center gap-2 text-[12.5px] text-text-muted cursor-pointer">
        <input type="checkbox" checked={includeToday} onChange={(e) => setIncludeToday(e.target.checked)} />
        Include today so far ({dayLabel(w.today)}, partial, drawn dashed)
      </label>
      <p className="w-full text-[11.5px] text-text-muted/70">Days are UTC days: each starts at {new Date(`${w.today}T00:00:00Z`).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', timeZoneName: 'short' })} your time. Today is left out of every total and chart unless you tick the box: a day that isn't over yet always looks like a drop.</p>
    </div>
  )
}
