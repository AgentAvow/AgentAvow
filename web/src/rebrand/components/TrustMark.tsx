import { useId } from 'react'
import { getTrustTier } from '../../components/trust/gradeSystem'

/**
 * The AgentAvow dual mark (0–100 pivot 2026-08).
 *   Trust    — a segmented power bar, green→red by tier. Owns the safety colour.
 *   Adoption — a McIntosh-style VU needle that fills-to-level in brand teal→magenta.
 *              NEVER a safety colour (popular ≠ safe).
 *
 * Sizes: TrustBar/AdoptionNeedle = hero (score page); TrustMini/AdoptionMini =
 * list scale (Browse rows, Home cards); TrustPill = the bare number chip.
 */

const P = (cx: number, cy: number, r: number, d: number) => {
  const a = (d * Math.PI) / 180
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)] as const
}
const ARC = (cx: number, cy: number, r: number, a0: number, a1: number) => {
  const [x0, y0] = P(cx, cy, r, a0)
  const [x1, y1] = P(cx, cy, r, a1)
  const lg = a1 - a0 > 180 ? 1 : 0
  return `M${x0.toFixed(1)} ${y0.toFixed(1)} A${r} ${r} 0 ${lg} 1 ${x1.toFixed(1)} ${y1.toFixed(1)}`
}

/** Adoption count → arc fill 0–100 (log-scaled to ~1e9 so it never pins/starves). */
export function adoptionPct(count?: number | null): number {
  const c = count || 0
  return c > 0 ? Math.min(100, Math.round((Math.log10(c + 1) / 9) * 100)) : 0
}
export function adoptionTierWord(pct: number): string {
  return pct >= 88 ? 'Load-bearing' : pct >= 65 ? 'Widely relied' : pct >= 40 ? 'Established' : pct >= 15 ? 'Rising' : 'New'
}
export function compactNum(n: number): string {
  return n >= 1e9 ? (n / 1e9).toFixed(1).replace(/\.0$/, '') + 'B'
    : n >= 1e6 ? (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M'
    : n >= 1e3 ? (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'k'
    : String(n)
}
const GRAD_TEXT = { background: 'linear-gradient(100deg,#2dd4bf,#e879f9)', WebkitBackgroundClip: 'text', backgroundClip: 'text', color: 'transparent' } as const

// ── HERO ────────────────────────────────────────────────────────────────────

/** Trust — vertical segmented power bar + number + tier word. */
export function TrustBar({ score }: { score: number }) {
  const t = getTrustTier(score)
  const total = 10
  const lv = Math.round(score / 10)
  return (
    <div className="flex flex-col items-center">
      <div className="flex flex-col-reverse gap-[3px]">
        {Array.from({ length: total }).map((_, i) => (
          <div key={i} className="w-[16px] h-[7px] rounded-[1px]" style={{ background: i < lv ? t.color : 'var(--color-border)' }} />
        ))}
      </div>
      <div className="mt-2.5 text-[34px] font-extrabold leading-none tabular-nums" style={{ color: t.color }}>
        {score}<span className="ml-1 text-[12px] font-mono text-text-muted align-baseline">/100</span>
      </div>
      <div className="mt-0.5 text-[12px] font-bold" style={{ color: t.color }}>{t.name}</div>
    </div>
  )
}

/** Adoption — VU needle that fills-to-level + compact count + tier word. */
export function AdoptionNeedle({ count, unit }: { count?: number | null; unit?: string }) {
  const gid = useId()
  const c = count || 0
  const has = c > 0
  const pct = adoptionPct(c)
  const cx = 100, cy = 88, r = 74, a0 = 180, a1 = 360
  const ang = a0 + (pct / 100) * 180
  const [nx, ny] = P(cx, cy, r - 16, ang)
  return (
    <div className="flex flex-col items-center">
      <svg width="150" viewBox="0 0 200 94" className="text-text-muted" style={{ overflow: 'visible' }}>
        <defs>
          <linearGradient id={gid} gradientUnits="userSpaceOnUse" x1="26" y1="0" x2="174" y2="0">
            <stop stopColor="#2dd4bf" /><stop offset="1" stopColor="#e879f9" />
          </linearGradient>
        </defs>
        {has && ang > a0 + 1.5 && <path d={ARC(cx, cy, r, a0, ang)} fill="none" stroke={`url(#${gid})`} strokeWidth={8} />}
        <path d={ARC(cx, cy, r, Math.max(ang, a0 + 0.5), a1)} fill="none" stroke="currentColor" strokeWidth={8} opacity={0.18} />
        {Array.from({ length: 9 }).map((_, i) => {
          const ta = a0 + 180 * ((i + 1) / 10)
          const [x0, y0] = P(cx, cy, r - 6, ta)
          const [x1, y1] = P(cx, cy, r - (i + 1 === 5 ? 14 : 10), ta)
          return <line key={i} x1={x0.toFixed(1)} y1={y0.toFixed(1)} x2={x1.toFixed(1)} y2={y1.toFixed(1)} stroke="currentColor" strokeWidth={i + 1 === 5 ? 1.6 : 1} opacity={0.35} />
        })}
        {has ? (
          <><line x1={cx} y1={cy} x2={nx.toFixed(1)} y2={ny.toFixed(1)} stroke="#2dd4bf" strokeWidth={3.4} strokeLinecap="round" /><circle cx={cx} cy={cy} r={5.5} fill="#2dd4bf" /></>
        ) : (
          <circle cx={cx} cy={cy} r={5.5} fill="currentColor" opacity={0.3} />
        )}
      </svg>
      <div className="-mt-1 text-[30px] font-extrabold leading-none tabular-nums">
        {has ? <span style={GRAD_TEXT}>{compactNum(c)}</span> : <span className="text-text-muted/70">New</span>}
        {has && unit && <span className="ml-1.5 text-[13px] font-mono text-text-muted align-baseline">{unit}</span>}
      </div>
      <div className="mt-0.5 text-[12px] font-bold">
        {has ? <span style={GRAD_TEXT}>{adoptionTierWord(pct)}</span> : <span className="text-text-muted">no adoption signal yet</span>}
      </div>
    </div>
  )
}

// ── LIST SCALE ────────────────────────────────────────────────────────────────

/** Trust — mini horizontal bar + number, for list rows. */
export function TrustMini({ score }: { score: number }) {
  const t = getTrustTier(score)
  const n = 6
  const lv = Math.round((score / 100) * n)
  return (
    <span className="inline-flex items-center gap-1.5" title={`Trust ${score}/100 — ${t.name}`}>
      <span className="inline-flex gap-[2px] items-end">
        {Array.from({ length: n }).map((_, i) => (
          <span key={i} className="w-[5px] h-[10px] rounded-[1px]" style={{ background: i < lv ? t.color : 'var(--color-border)' }} />
        ))}
      </span>
      <span className="text-[14px] font-extrabold tabular-nums leading-none" style={{ color: t.color }}>{score}</span>
    </span>
  )
}

/** Adoption — mini VU needle + compact count, for list rows. */
export function AdoptionMini({ count }: { count?: number | null }) {
  const gid = useId()
  const c = count || 0
  const has = c > 0
  const pct = adoptionPct(c)
  const cx = 50, cy = 46, r = 36, a0 = 180, a1 = 360
  const ang = a0 + (pct / 100) * 180
  const [nx, ny] = P(cx, cy, r - 8, ang)
  return (
    <span className="inline-flex items-center gap-1.5 text-text-muted" title={has ? `Adoption ${compactNum(c)} — ${adoptionTierWord(pct)}` : 'No adoption signal yet'}>
      <svg width="36" viewBox="0 0 100 52" style={{ overflow: 'visible' }}>
        <defs>
          <linearGradient id={gid} gradientUnits="userSpaceOnUse" x1="14" y1="0" x2="86" y2="0">
            <stop stopColor="#2dd4bf" /><stop offset="1" stopColor="#e879f9" />
          </linearGradient>
        </defs>
        {has && ang > a0 + 2 && <path d={ARC(cx, cy, r, a0, ang)} fill="none" stroke={`url(#${gid})`} strokeWidth={5} />}
        <path d={ARC(cx, cy, r, Math.max(ang, a0 + 0.5), a1)} fill="none" stroke="currentColor" strokeWidth={5} opacity={0.2} />
        {has ? (
          <><line x1={cx} y1={cy} x2={nx.toFixed(1)} y2={ny.toFixed(1)} stroke="#2dd4bf" strokeWidth={2.4} strokeLinecap="round" /><circle cx={cx} cy={cy} r={3.4} fill="#2dd4bf" /></>
        ) : (
          <circle cx={cx} cy={cy} r={3.4} fill="currentColor" opacity={0.3} />
        )}
      </svg>
      <span className="text-[13px] font-extrabold leading-none" style={has ? GRAD_TEXT : { color: 'var(--color-text-muted)' }}>{has ? compactNum(c) : 'New'}</span>
    </span>
  )
}

/** The bare number chip — kept for utility lists (watches, my tools). */
export function TrustPill({ score, className = '' }: { score: number; showTier?: boolean; className?: string }) {
  const t = getTrustTier(score)
  return (
    <span
      className={`inline-flex items-baseline gap-1 rounded-lg font-mono font-bold px-2 py-0.5 text-[12px] ${className}`}
      style={{ color: t.color, backgroundColor: `${t.color}1f` }}
      title={`Trust ${score}/100 — ${t.name}`}
    >
      <span className="text-[14px] font-extrabold">{score}</span>
      <span className="text-[9px] opacity-60">/100</span>
    </span>
  )
}
