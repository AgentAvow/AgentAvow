/** Shared, non-component helpers for the admin Metrics tab: the page-level time window,
 *  UTC day lists and labels, number formatting. Components live in adminMetricsKit.tsx. */
import { createContext, useContext } from 'react'

/** The one time window every windowed section on the Metrics tab uses. */
export type PageWin = 7 | 30 | 90
export const PAGE_WINDOWS: PageWin[] = [7, 30, 90]

export interface DashWindow {
  days: PageWin
  /** Draw today's partial UTC day (dashed) on the charts that can. Off by default. */
  includeToday: boolean
  /** The window's complete UTC days, oldest first (ends yesterday). */
  complete: string[]
  /** Today's UTC date, YYYY-MM-DD. */
  today: string
}

const MS_DAY = 86_400_000

/** YYYY-MM-DD for the UTC day `offset` days before today. */
export const utcDay = (offset = 0, now = Date.now()) => new Date(now - offset * MS_DAY).toISOString().slice(0, 10)

/** The `n` complete UTC days ending yesterday, oldest first. */
export const completeDays = (n: number, now = Date.now()) => Array.from({ length: n }, (_, i) => utcDay(n - i, now))

/** The `n` complete UTC days before `complete` (the previous equal period). */
export const previousDays = (n: number, now = Date.now()) => Array.from({ length: n }, (_, i) => utcDay(2 * n - i, now))

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/** "2026-11-05" -> "Nov 5". */
export const dayLabel = (d?: string | null) => {
  if (!d || d.length < 10) return '—'
  return `${MONTHS[Number(d.slice(5, 7)) - 1]} ${Number(d.slice(8, 10))}`
}

/** "Nov 5–11" or "Oct 14 – Nov 11" for a list of days (oldest first). */
export const rangeLabel = (days: string[]) => {
  if (!days.length) return '—'
  const a = days[0], b = days[days.length - 1]
  if (a === b) return dayLabel(a)
  if (a.slice(0, 7) === b.slice(0, 7)) return `${dayLabel(a)}–${Number(b.slice(8, 10))}`
  return `${dayLabel(a)} – ${dayLabel(b)}`
}

/** "Last 7 days: Nov 5–11 (UTC)" */
export const windowLabel = (w: { days: number; complete: string[] }) => `Last ${w.days} days: ${rangeLabel(w.complete)} (UTC)`

export const fmt = (n: number | undefined | null) => (n ?? 0).toLocaleString()
export const fmtOrDash = (n: number | undefined | null) => (n == null ? '—' : n.toLocaleString())
export const usd = (n: number | undefined | null) => `$${(n ?? 0).toFixed(2)}`

/** A share as a percentage that never rounds a small non-zero share to "0%". */
export const pctOf = (num: number, den: number) => {
  if (!den) return '—'
  const p = (num * 100) / den
  if (p === 0) return '0%'
  if (p < 1) return `${p.toFixed(2)}%`
  if (p < 10) return `${p.toFixed(1)}%`
  return `${Math.round(p)}%`
}

/** Average of the non-null values, or null when there are none. */
export const avgOf = (xs: (number | null | undefined)[]) => {
  const v = xs.filter((x): x is number => typeof x === 'number')
  return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null
}
export const sumOf = (xs: (number | null | undefined)[]) => xs.reduce<number>((a, b) => a + (typeof b === 'number' ? b : 0), 0)

/** Round an average for display: whole numbers from 10 up, one decimal below. */
export const fmtAvg = (n: number | null) => (n == null ? '—' : n >= 10 ? Math.round(n).toLocaleString() : n.toFixed(1).replace(/\.0$/, ''))

/** Backend windows for /admin/metrics and /admin/metrics/behavioral. Their Redis day
 *  counters are kept 45 days, so a 90-day page window falls back to 30 days there. */
export const metricsWindow = (w: PageWin): { param: '7d' | '30d'; days: 7 | 30 } => (w === 7 ? { param: '7d', days: 7 } : { param: '30d', days: 30 })

export const DashWindowContext = createContext<DashWindow>({ days: 7, includeToday: false, complete: completeDays(7), today: utcDay(0) })
export const useDashWindow = () => useContext(DashWindowContext)

/** Plain scope line for a section that uses the page window: "Last 7 days: Nov 5–11 (UTC)". */
export const useWindowLabel = () => windowLabel(useDashWindow())

/** Scope line for sections backed by /admin/metrics (30 days at most). */
export function useMetricsScope() {
  const w = useDashWindow()
  const m = metricsWindow(w.days)
  const days = w.complete.slice(-m.days)
  const base = windowLabel({ days: m.days, complete: days })
  return { ...m, days, label: w.days === 90 ? `${base} · this section keeps 30 days at most (its day counters expire after 45)` : base }
}
