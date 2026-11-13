import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { rp } from '../basePath'
import { fetchFlaggedStat } from '../catalog'
import { useSandboxStats } from '../lib/sandboxStats'
import { DNC_LIST, useAnswerMix, type AnswerMix } from '../lib/answerMix'

/**
 * How the catalog reads: the answer mix and the headline counts under it, shared by
 * Home, Browse and the Trust Index. Every figure is live (lib/answerMix.ts).
 */

const ANSWER_COLORS = { safe: '#34d399', review: '#F59E0B', dnc: '#f43f5e' } as const

const SEGMENTS = [
  { key: 'safe', short: 'Safe', phrase: 'Safe to connect', color: ANSWER_COLORS.safe },
  { key: 'review', short: 'Review', phrase: 'Review before you connect', color: ANSWER_COLORS.review },
  { key: 'dnc', short: 'Do not connect', phrase: 'Do not connect', color: ANSWER_COLORS.dnc },
] as const

/** One decimal, so three shares add up the way people expect (65.5 + 30.1 + 4.4). */
const pct = (n: number, of: number) => (of > 0 ? Math.round((n / of) * 1000) / 10 : 0)

function Stack({ mix, height }: { mix: AnswerMix | undefined; height: number }) {
  if (!mix || mix.total <= 0) {
    return <div className="rounded-full bg-surface-hover animate-pulse" style={{ height }} aria-hidden="true" />
  }
  const label = SEGMENTS.map((s) => `${pct(mix[s.key], mix.total)}% ${s.phrase}`).join(', ')
  return (
    <div className="flex rounded-full overflow-hidden bg-surface-hover" style={{ height }} role="img" aria-label={label}>
      {SEGMENTS.map((s) => (
        <i key={s.key} className="block h-full" style={{ width: `${pct(mix[s.key], mix.total)}%`, background: s.color }} />
      ))}
    </div>
  )
}

function Legend({ mix, big }: { mix: AnswerMix | undefined; big: boolean }) {
  return (
    <div className={`flex flex-wrap ${big ? 'gap-x-[18px] gap-y-1.5 text-[14px]' : 'gap-x-4 gap-y-1.5 text-[13px]'} text-text-muted`}>
      {SEGMENTS.map((s) => (
        <span key={s.key} className="inline-flex items-baseline">
          <i className={`inline-block rounded-[2px] mr-1.5 ${big ? 'w-2.5 h-2.5' : 'w-[9px] h-[9px]'}`} style={{ background: s.color }} />
          <b className={`text-text tabular-nums ${big ? 'text-[20px] mr-1' : 'mr-1'}`}>
            {mix && mix.total > 0 ? `${pct(mix[s.key], mix.total)}%` : '—'}
          </b>
          {big ? s.phrase : s.short}
        </span>
      ))}
    </div>
  )
}

/**
 * The answer-mix bar. `slim` (Browse, above search): a small kicker, an 18px bar and a
 * short legend. `big` (Home, Index): the gradient tools-checked number, the legend
 * inline at the right and a 26px bar.
 */
export function AnswerMixBar({ size }: { size: 'slim' | 'big' }) {
  const { data: mix } = useAnswerMix()
  const total = mix && mix.total > 0 ? mix.total.toLocaleString() : '—'
  if (size === 'slim') {
    return (
      <div className="glass rounded-2xl px-[18px] py-3.5">
        <div className="font-mono text-[11px] tracking-[0.12em] uppercase text-primary-light">
          How the catalog reads · <b className="text-text">{total}</b> tools checked
          {mix && mix.x402 > 0 && <> · plus {mix.x402.toLocaleString()} paid x402 endpoints</>}
        </div>
        <div className="mt-3"><Stack mix={mix} height={18} /></div>
        <div className="mt-2.5"><Legend mix={mix} big={false} /></div>
      </div>
    )
  }
  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-x-7 gap-y-2.5">
        <div>
          <b className="block gradient-text font-extrabold leading-none tracking-[-0.03em] tabular-nums text-[clamp(46px,8vw,72px)]">{total}</b>
          <span className="block mt-1.5 text-[15px] text-text-muted">tools checked, and how they read</span>
          <X402Line x402={mix?.x402} />
        </div>
        <Legend mix={mix} big />
      </div>
      <div className="mt-3"><Stack mix={mix} height={26} /></div>
    </div>
  )
}

interface Card { n: number | null | undefined; label: string; to: string; tone?: 'grad' | 'bad' }

function StatCard({ n, label, to, tone }: Card) {
  const cls = tone === 'grad' ? 'gradient-text' : tone === 'bad' ? 'text-danger' : 'text-text'
  const inner = (
    <>
      <b className={`block text-[30px] font-extrabold leading-tight tabular-nums ${cls}`}>{n != null ? n.toLocaleString() : '—'}</b>
      <span className="block mt-0.5 text-[13px] text-text-muted">{label}</span>
    </>
  )
  const box = 'glass card-hover rounded-2xl px-4 py-3.5 block min-w-0'
  return /^https?:/.test(to)
    ? <a href={to} className={box}>{inner}</a>
    : <Link to={rp(to)} className={box}>{inner}</Link>
}

/** Four linked count cards under the big bar. Two columns under 760px. */
export function StatCards({ set }: { set: 'home' | 'index' }) {
  const { data: mix } = useAnswerMix()
  const { data: stat } = useQuery({ queryKey: ['flagged-stat'], queryFn: fetchFlaggedStat, staleTime: 60_000 })
  const { data: sandbox } = useSandboxStats()
  const runs = sandbox?.totals.runs
  const cards: Card[] = set === 'home'
    ? [
        { n: stat?.by_surface?.mcp?.scanned_total, label: 'MCP servers checked', to: '/rebrand/browse' },
        { n: runs, label: 'sandbox runs', to: '/rebrand/docs/behavioral-sandbox' },
        { n: mix?.certified, label: 'Certified', to: '/rebrand/certified', tone: 'grad' },
        // The detection categories are a fixed part of the scanner, not a catalog count.
        { n: 12, label: 'detection categories', to: '/rebrand/how-it-works' },
      ]
    : [
        { n: mix?.dnc, label: 'Do not connect', to: DNC_LIST, tone: 'bad' },
        { n: mix?.certified, label: 'Certified', to: '/rebrand/certified', tone: 'grad' },
        { n: stat?.flagged, label: 'with a high or critical finding', to: '/rebrand/browse?surface=all&sev=high' },
        { n: runs, label: 'sandbox runs', to: '/rebrand/docs/behavioral-sandbox' },
      ]
  return (
    <div className="grid grid-cols-2 min-[760px]:grid-cols-4 gap-3 mt-4">
      {cards.map((c) => <StatCard key={c.label} {...c} />)}
    </div>
  )
}

/** "plus N paid x402 endpoints": checked too, but a different kind of thing, so never in the tools total. */
export function X402Line({ x402, className = '' }: { x402?: number; className?: string }) {
  if (!x402) return null
  return (
    <span className={`block mt-1 text-[13px] text-text-muted ${className}`}>
      plus <b className="text-text tabular-nums">{x402.toLocaleString()}</b> paid x402 endpoints
    </span>
  )
}
