import { useId, type ReactNode } from 'react'
import { getTrustTier, decisionOf, decisionPhrase, isCertified } from '../../components/trust/gradeSystem'
import { shortUnit } from '../lib/adoptionUnit'

/**
 * The AgentAvow dual mark (0–100 pivot 2026-08).
 *   Trust    — a segmented power bar, green→red by tier. Owns the safety colour.
 *   Adoption — a McIntosh-style VU needle that fills-to-level in brand teal→magenta.
 *              NEVER a safety colour (popular ≠ safe).
 *
 * Sizes: TrustBar/AdoptionNeedle = hero (score page); TrustMini/AdoptionMini =
 * list scale (Browse rows, Home cards); TrustPill = the bare number chip.
 * Certified: CertifiedBadge (lg / md / sm rosette with the score inside), shown in
 * place of the trust mark, once, only where the tool earned it.
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

/** Trust — the AgentAvow badge design (option C): the vertical segmented bar with the
 * score and tier word to its RIGHT (BELOW it on phones, ≤480px, so trust and adoption
 * can sit side by side). 10 segments, tier-tinted; the numeral is the
 * heaviest number in the pair. `scale` resizes the whole instrument uniformly (the
 * hero passes 1.5 on desktop). Same design as card.svg / the README badge / the
 * Claude & ChatGPT trust card. */
export function TrustBar({ score, scale = 1 }: { score: number; scale?: number }) {
  const t = getTrustTier(score)
  const lv = Math.round(score / 10)
  return (
    <div className="flex items-center text-left max-[480px]:flex-col max-[480px]:text-center" style={{ gap: 14 * scale }}>
      <Segments scale={scale} fill={(i) => (i < lv ? t.color : 'var(--color-border)')} />
      <PairText scale={scale}
        num={<span style={{ color: t.color }}>{score}</span>}
        unit="/100"
        word={<span style={{ color: t.color }}>{t.name}</span>} />
    </div>
  )
}

/** The 10-segment column of TrustBar. */
function Segments({ scale, fill }: { scale: number; fill: (i: number) => string }) {
  return (
    <div className="flex flex-col-reverse shrink-0" style={{ gap: 2.4 * scale }} aria-hidden="true">
      {Array.from({ length: 10 }).map((_, i) => (
        <div key={i} style={{ width: 14 * scale, height: 5.5 * scale, borderRadius: 1, background: fill(i) }} />
      ))}
    </div>
  )
}

/** The number + word block that sits to the right of a meter. `lead` = trust (the
 * larger numeral); the adoption block is a step down and shares the same baselines. */
function PairText({ scale, num, unit, word, lead = true }: {
  scale: number; num: ReactNode; unit?: ReactNode; word: ReactNode; lead?: boolean
}) {
  const size = (lead ? 30 : 21) * scale
  return (
    <div className="flex flex-col min-w-0 max-[480px]:items-center">
      <div className="font-extrabold leading-none tabular-nums whitespace-nowrap"
        style={{ fontSize: size, paddingTop: lead ? 0 : 7 * scale, paddingBottom: lead ? 0 : 2 * scale, opacity: lead ? 1 : 0.85 }}>
        {num}
        {unit && <span className="font-mono font-normal align-baseline text-text-muted" style={{ fontSize: (lead ? 10 : 9.5) * scale, marginLeft: 3 * scale }}>{unit}</span>}
      </div>
      <div className="font-bold whitespace-nowrap" style={{ fontSize: (lead ? 11 : 10.5) * scale, marginTop: 4 * scale }}>{word}</div>
    </div>
  )
}

/** Adoption — the badge card's VU dial (the heavier arc) that fills to level, with the
 * compact count + unit and the level word to its RIGHT (option C). Prefer the
 * backend's 0–100 adoption score (`scorePct`) for the fill + level so the dial agrees
 * with the adoption detail panel; fall back to a count-derived estimate. */
export function AdoptionNeedle({ count, unit, scorePct, tier, scale = 1 }: { count?: number | null; unit?: string; scorePct?: number | null; tier?: string | null; scale?: number }) {
  const gid = useId()
  const c = count || 0
  const pct = scorePct != null ? scorePct : adoptionPct(c)
  const has = pct > 0 || c > 0
  const tierWord = tier || adoptionTierWord(pct)
  const cx = 100, cy = 88, r = 72, a0 = 180, a1 = 360
  const ang = a0 + (pct / 100) * 180
  const [nx, ny] = P(cx, cy, r - 22, ang)
  return (
    <div className="flex items-center text-left max-[480px]:flex-col max-[480px]:text-center" style={{ gap: 12 * scale }} title={has && unit ? `${compactNum(c)} ${unit}` : undefined}>
      <svg width={76 * scale} viewBox="0 0 200 94" className="text-text-muted shrink-0" style={{ overflow: 'visible' }} aria-hidden="true">
        <defs>
          <linearGradient id={gid} gradientUnits="userSpaceOnUse" x1="26" y1="0" x2="174" y2="0">
            <stop stopColor="#2dd4bf" /><stop offset="1" stopColor="#e879f9" />
          </linearGradient>
        </defs>
        <path d={ARC(cx, cy, r, Math.max(ang, a0 + 0.5), a1)} fill="none" stroke="var(--color-border)" strokeWidth={16} strokeLinecap="round" />
        {has && ang > a0 + 1.5 && <path d={ARC(cx, cy, r, a0, ang)} fill="none" stroke={`url(#${gid})`} strokeWidth={16} strokeLinecap="round" />}
        {Array.from({ length: 9 }).map((_, i) => {
          const ta = a0 + 180 * ((i + 1) / 10)
          const mid = i + 1 === 5
          const [x0, y0] = P(cx, cy, r - 13, ta)
          const [x1, y1] = P(cx, cy, r - 13 - (mid ? 8 : 4), ta)
          return <line key={i} x1={x0.toFixed(1)} y1={y0.toFixed(1)} x2={x1.toFixed(1)} y2={y1.toFixed(1)} stroke="currentColor" strokeWidth={mid ? 1.6 : 1} opacity={0.4} />
        })}
        {has ? (
          <><line x1={cx} y1={cy} x2={nx.toFixed(1)} y2={ny.toFixed(1)} stroke="#2dd4bf" strokeWidth={6.5} strokeLinecap="round" /><circle cx={cx} cy={cy} r={9.5} fill="#2dd4bf" /></>
        ) : (
          <circle cx={cx} cy={cy} r={9.5} fill="currentColor" opacity={0.3} />
        )}
      </svg>
      <PairText scale={scale} lead={false}
        num={has ? <span className="text-text">{compactNum(c)}</span> : <span className="text-text-muted/70">New</span>}
        unit={has && unit ? shortUnit(unit) || undefined : undefined}
        word={has ? <span style={GRAD_TEXT}>{tierWord}</span> : <span className="text-text-muted font-semibold">no signal yet</span>} />
    </div>
  )
}

// ── CERTIFIED BADGE ─────────────────────────────────────────────────────────────

/** The rosette outline: n scalloped petals between radius r and R (the mockup's
 * `rosette(60,54,50,45,22)`), computed once. */
function rosettePath(cx: number, cy: number, R: number, r: number, n: number): string {
  const step = (Math.PI * 2) / n
  let d = ''
  for (let i = 0; i < n; i++) {
    const a0 = i * step - Math.PI / 2, a1 = a0 + step, am = a0 + step / 2
    const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0)
    const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1)
    const xm = cx + R * 1.08 * Math.cos(am), ym = cy + R * 1.08 * Math.sin(am)
    d += (i ? '' : `M${x0.toFixed(1)} ${y0.toFixed(1)}`) + `Q${xm.toFixed(1)} ${ym.toFixed(1)} ${x1.toFixed(1)} ${y1.toFixed(1)}`
  }
  return d + 'Z'
}
const ROSETTE = rosettePath(60, 54, 50, 45, 22)

/** Pixel sizes of the three badges. lg/md carry the TRUST caption and CERTIFIED ribbon;
 * sm is the list size (just the rosette and the score). */
const BADGE_SIZE = { lg: [112, 124], md: [72, 80], sm: [34, 34] } as const
export type CertifiedBadgeSize = keyof typeof BADGE_SIZE

/**
 * Certified — the earned, gated top tier: a teal→fuchsia rosette with the trust score
 * inside. Render it ONLY for a tool that carries the mark (isCertified /
 * certified_mark: all six checks pass and the answer is Safe to connect at 81+), and
 * never with a second "Certified" tag beside it. A 3-digit score (100) gets a smaller
 * numeral so it fits.
 */
export function CertifiedBadge({ score, size = 'md', className = '' }: { score: number; size?: CertifiedBadgeSize; className?: string }) {
  const gid = useId()
  const [w, h] = BADGE_SIZE[size]
  const long = String(score).length > 2
  const body = (
    <>
      <defs>
        <linearGradient id={gid} x1="10" y1="4" x2="110" y2="104" gradientUnits="userSpaceOnUse">
          <stop stopColor="#2DD4BF" /><stop offset="1" stopColor="#E879F9" />
        </linearGradient>
      </defs>
      <path d={ROSETTE} fill={`url(#${gid})`} />
      <circle cx="60" cy="54" r="38" style={{ fill: 'var(--color-surface)' }} />
      <circle cx="60" cy="54" r="33.5" fill="none" stroke={`url(#${gid})`} strokeWidth="1.3" opacity=".55" />
    </>
  )
  if (size === 'sm') {
    return (
      <svg viewBox="4 0 112 110" width={w} height={h} role="img" aria-label={`Certified, trust score ${score}`} className={`block shrink-0 overflow-visible ${className}`}>
        {body}
        <text x="60" y="69" textAnchor="middle" fontFamily="Geist,system-ui,sans-serif" fontSize={long ? 32 : 44} fontWeight={900} fill={`url(#${gid})`}>{score}</text>
      </svg>
    )
  }
  return (
    <svg viewBox="0 0 120 128" width={w} height={h} role="img" aria-label={`Certified, trust score ${score} out of 100`} className={`block shrink-0 overflow-visible ${className}`}>
      {body}
      <text x="60" y="37" textAnchor="middle" fontFamily="ui-monospace,Menlo,monospace" fontSize="7.5" fontWeight={700} letterSpacing="1.6" style={{ fill: 'var(--color-text-muted)' }}>TRUST</text>
      <text x="60" y="70" textAnchor="middle" fontFamily="Geist,system-ui,sans-serif" fontSize={long ? 25 : 34} fontWeight={900} fill={`url(#${gid})`}>{score}</text>
      <path d="M2 96H118L111 107L118 118H2L9 107Z" fill={`url(#${gid})`} />
      <text x="60" y="111" textAnchor="middle" fontFamily="ui-monospace,Menlo,monospace" fontSize="10.5" fontWeight={800} letterSpacing="2.4" fill="#06231f">CERTIFIED</text>
    </svg>
  )
}

/** The large/medium Certified mark (the score-card slot on Home, Preflight and the
 * Certified page). Kept under its old name so existing imports keep working; it now
 * draws the rosette badge. `scale` < 1 picks the medium badge. */
export function CertifiedMark({ score = 98, scale = 1, size }: { score?: number; scale?: number; size?: 'lg' | 'md' }) {
  return <CertifiedBadge score={score} size={size ?? (scale >= 1.2 ? 'lg' : 'md')} />
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

/** Certified at list scale: the small rosette with the score inside, shown in place of
 * TrustMini on a row that carries `certified_mark`. `caption` adds the CERTIFIED /
 * "trust 92" label beside it (Browse cards); pills and tight rows leave it off. */
export function CertifiedMini({ score, caption = false }: { score: number; caption?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2" title={`Certified · trust ${score}/100`}>
      <CertifiedBadge score={score} size="sm" />
      {caption && (
        <span className="font-mono text-[9px] font-extrabold tracking-[0.16em] leading-[1.1]">
          <span style={GRAD_TEXT}>CERTIFIED</span>
          <small className="block text-[9px] font-medium tracking-[0.04em] text-text-muted mt-0.5">trust {score}</small>
        </span>
      )}
    </span>
  )
}

/** Trust at list scale: CertifiedMini when the row carries the Certified mark (only ever
 * beside Safe to connect), else TrustMini. */
export function TrustOrCertifiedMini({ row, caption = false }: { row: { trust_score?: number | null } & Record<string, unknown>; caption?: boolean }) {
  if (row.trust_score == null) return null
  return rowIsCertified(row)
    ? <CertifiedMini score={row.trust_score} caption={caption} />
    : <TrustMini score={row.trust_score} />
}

/** True when a list row carries the Certified mark: the answer is Safe to connect and
 * isCertified (certified_mark from the API; never inferred from a letter grade). */
function rowIsCertified(row: { trust_score?: number | null } & Record<string, unknown>): boolean {
  if (row.trust_score == null) return false
  const d = decisionOf({ ...row, findings: { critical: (row.critical as number) ?? 0, high: (row.high as number) ?? 0 } })
  return d.decision === 'safe' && isCertified(row)
}

/** The list-row score pair, in the Browse order: the trust or Certified mark, then the
 * adoption half-gauge. With no adoption signal the gauge shows muted, reading "New".
 * `stack` puts them in a column (Browse cards); otherwise side by side. */
export function ScorePairMini({ row, stack = false, caption = false }: {
  row: { trust_score?: number | null; adoption_count?: number | null; adoption_unit?: string | null } & Record<string, unknown>
  stack?: boolean; caption?: boolean
}) {
  if (row.trust_score == null) return null
  return (
    <span className={`inline-flex shrink-0 ${stack ? 'flex-col items-end gap-1.5' : 'items-center gap-3'}`}>
      <TrustOrCertifiedMini row={row} caption={caption} />
      <AdoptionMini count={row.adoption_count} unit={row.adoption_unit} />
    </span>
  )
}

/** The three-phrase headline for a list row / card, in the phrase colour, with the
 * reason (when known) muted beside it. Reads the row's own `decision` (catalog / API)
 * or decides from what the row carries. Certified is shown ONCE, as the badge in the
 * score slot, so the line carries no "· Certified" unless `certifiedSuffix` is set (for
 * a surface that shows no badge). */
export function DecisionLine({ row, className = '', certifiedSuffix = false }: {
  row: { trust_score?: number | null; decision?: string | null; decision_reason?: string | null
    critical?: number | null; high?: number | null; grade?: string | null
    certified?: { eligible?: boolean } | null; certified_mark?: boolean | null }
  className?: string
  certifiedSuffix?: boolean
}) {
  const d = decisionOf({ ...row, findings: { critical: row.critical ?? 0, high: row.high ?? 0 } })
  const p = decisionPhrase(d.decision)
  // The mark only ever sits beside Safe to connect; catalog rows and API results both
  // carry it as certified_mark (never inferred from a stored letter grade).
  const cert = certifiedSuffix && d.decision === 'safe' && isCertified(row)
  return (
    <div className={`text-[12.5px] font-semibold ${className}`} style={{ color: p.color }} data-decision={p.value}>
      {p.phrase}{cert && <span className="ml-1" style={GRAD_TEXT}>· Certified</span>}
      {row.decision_reason && <span className="ml-1.5 font-normal text-text-muted">— {row.decision_reason}</span>}
    </div>
  )
}

/** Adoption — mini VU needle + compact count, for list rows. */
export function AdoptionMini({ count, unit }: { count?: number | null; unit?: string | null }) {
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
      {has && unit && shortUnit(unit) ? <span className="text-[11px] leading-none text-text-muted" title={unit}>{shortUnit(unit)}</span> : null}
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

