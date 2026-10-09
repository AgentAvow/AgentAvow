import { useId, type ReactNode } from 'react'
import { getTrustTier, decisionOf, decisionPhrase, isCertified } from '../../components/trust/gradeSystem'

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

/** Trust — the AgentAvow badge design (option C): the vertical segmented bar with the
 * score and tier word to its RIGHT. 10 segments, tier-tinted; the numeral is the
 * heaviest number in the pair. `scale` resizes the whole instrument uniformly (the
 * hero passes 1.5 on desktop). Same design as card.svg / the README badge / the
 * Claude & ChatGPT trust card. */
export function TrustBar({ score, scale = 1 }: { score: number; scale?: number }) {
  const t = getTrustTier(score)
  const lv = Math.round(score / 10)
  return (
    <div className="flex items-center text-left" style={{ gap: 14 * scale }}>
      <Segments scale={scale} fill={(i) => (i < lv ? t.color : 'var(--color-border)')} />
      <PairText scale={scale}
        num={<span style={{ color: t.color }}>{score}</span>}
        unit="/100"
        word={<span style={{ color: t.color }}>{t.name}</span>} />
    </div>
  )
}

/** The 10-segment column shared by TrustBar and CertifiedMark. */
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
    <div className="flex flex-col min-w-0">
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
    <div className="flex items-center text-left" style={{ gap: 12 * scale }}>
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
        unit={has && unit ? unit : undefined}
        word={has ? <span style={GRAD_TEXT}>{tierWord}</span> : <span className="text-text-muted font-semibold">no signal yet</span>} />
    </div>
  )
}

/** Certified — the earned, gated top tier, in the option C layout: the full
 * teal→magenta bar with the gradient pill (branded ring-check + number) to its right
 * and CERTIFIED beneath. Only rendered for a tool that carries the Certified mark. */
export function CertifiedMark({ score = 98, scale = 1 }: { score?: number; scale?: number }) {
  return (
    <div className="flex items-center text-left" style={{ gap: 14 * scale }}>
      <Segments scale={scale} fill={() => 'linear-gradient(90deg,#2dd4bf,#e879f9)'} />
      <div className="flex flex-col items-start min-w-0">
        <div className="inline-flex items-center rounded-full shadow-lg" style={{ gap: 6 * scale, paddingLeft: 13 * scale, paddingRight: 15 * scale, paddingTop: 5 * scale, paddingBottom: 5 * scale, background: 'linear-gradient(120deg,#2dd4bf,#e879f9)', boxShadow: '0 6px 20px -6px rgba(45,212,191,0.5)' }}>
          <svg width={17 * scale} height={17 * scale} viewBox="0 0 40 40" fill="none" aria-hidden="true"><circle cx="20" cy="20" r="16.5" stroke="#06231f" strokeWidth="3.2" /><path d="M12 21l6 6 12-13" stroke="#06231f" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" /></svg>
          <span className="font-extrabold leading-none tabular-nums" style={{ fontSize: 24 * scale, color: '#06231f' }}>{score}</span>
        </div>
        <div className="font-mono font-extrabold tracking-[0.18em]" style={{ ...GRAD_TEXT, fontSize: 10.5 * scale, marginTop: 7 * scale }}>CERTIFIED</div>
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

/** The three-phrase headline for a list row / card: "Safe to connect · Certified" in the
 * phrase colour, with the reason (when known) muted beside it. Reads the row's own
 * `decision` (catalog / API) or decides from what the row carries. */
export function DecisionLine({ row, className = '' }: {
  row: { trust_score?: number | null; decision?: string | null; decision_reason?: string | null
    critical?: number | null; high?: number | null; grade?: string | null
    certified?: { eligible?: boolean } | null; certified_mark?: boolean | null }
  className?: string
}) {
  const d = decisionOf({ ...row, findings: { critical: row.critical ?? 0, high: row.high ?? 0 } })
  const p = decisionPhrase(d.decision)
  // The mark only ever sits beside Safe to connect; a catalog row carries it as the
  // stored A+ (which follows the Certified mark), an API result as certified_mark.
  const cert = d.decision === 'safe' && (isCertified(row) || row.grade === 'A+')
  return (
    <div className={`text-[12.5px] font-semibold ${className}`} style={{ color: p.color }} data-decision={p.value}>
      {p.phrase}{cert && <span className="ml-1" style={GRAD_TEXT}>· Certified</span>}
      {row.decision_reason && <span className="ml-1.5 font-normal text-text-muted">— {row.decision_reason}</span>}
    </div>
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

/**
 * Binary verdict banner (Shawn #4) — the plain decision above the number.
 * Derived from the already-signed scan; never a rescore. Safe = A/A+ (>=81) AND
 * no blocking critical/high (the server's certified.checks.no_critical_or_high
 * gate). Verb is surface-aware (connect / install / use).
 */
export function VerdictBadge(
  { scan, className = '' }: {
    scan: {
      trust_score?: number | null
      decision?: string | null
      decision_final?: boolean | null
      decision_reason?: string | null
      certified?: { eligible?: boolean; checks?: { no_critical_or_high?: boolean } }
      findings?: unknown
      critical?: number | null
      high?: number | null
      metadata?: { files_scanned?: number | null } | null
      deprecation?: string | null
      behavioral?: {
        ran?: boolean; pending?: boolean; plan?: string; state?: string
        canary_exfil?: unknown[]
        findings?: Array<{ severity?: string; name?: string; rule?: string }>
        exercise?: { launch_ok?: boolean; calls?: unknown[] } | null
        grade_summary?: { start_reason?: string } | null
        unexpected_egress?: string[]
      } | null
      behavioral_score_effect?: { applied?: boolean; delta?: number } | null
    }
    /** Kept for call-site compatibility; the three phrases are fixed wording. */
    verb?: 'connect' | 'install' | 'use'
    className?: string
  },
) {
  // The headline is ONE of three phrases plus the one reason that triggered it —
  // the API's own `decision` when present, else the same rule here (gradeSystem.decide).
  // Certified rides beside the phrase; the score and tier sit underneath elsewhere.
  const d = decisionOf(scan)
  const p = decisionPhrase(d.decision)
  const certified = isCertified(scan)
  const b = scan.behavioral
  const bFindings = (b?.ran && !b.pending ? b.findings : []) ?? []
  // One line about the sandbox for the card, whatever the decision.
  const calls = b?.exercise?.calls?.length ?? 0
  const reason = (b?.grade_summary?.start_reason ?? '').replace(/_/g, ' ')
  const delta = scan.behavioral_score_effect?.applied ? scan.behavioral_score_effect.delta ?? 0 : 0
  const deltaTxt = delta ? ` · score ${delta > 0 ? '+' : ''}${delta}` : ''
  const severe = bFindings.filter((f) => f.severity === 'critical' || f.severity === 'high')
  const leaked = !!(b?.ran && (b.canary_exfil?.length ?? 0) > 0)
  const sandboxLine = !b ? null
    : b.pending && b.state === 'queued' ? 'Sandbox: waiting for a free slot — this answer may move to Review when it lands'
    : b.pending ? 'Sandbox: still running — this answer may move to Review when it lands'
    : !b.ran ? null
    : leaked ? `Sandbox: caught — a planted credential left the sandbox${deltaTxt}`
    : severe.length ? `Sandbox: caught — ${severe[0].name ?? 'a behavioral finding'}${deltaTxt}`
    : bFindings.length ? `Sandbox: ran, ${bFindings.length} minor finding${bFindings.length === 1 ? '' : 's'}${deltaTxt}`
    : b.exercise?.launch_ok ? `Sandbox: called ${calls} tool${calls === 1 ? '' : 's'}, clean${deltaTxt}`
    : reason === 'install failed' ? 'Sandbox: the install failed, so nothing ran — not a finding'
    : reason && reason !== 'not applicable' && reason !== 'started' ? `Sandbox: installed; server not started (${reason}) — not a finding`
    : 'Sandbox: installed and imported, clean'
  const cfg = {
    safe: { box: 'bg-success/10 border-success/30', fg: 'text-success', icon: '✓' },
    review: { box: 'bg-warning/10 border-warning/30', fg: 'text-warning', icon: '⚠' },
    do_not_connect: { box: 'bg-danger/10 border-danger/30', fg: 'text-danger', icon: '✕' },
  }[d.decision]
  const why = d.reason ? d.reason[0].toUpperCase() + d.reason.slice(1) + '.' : ''
  return (
    <div className={`rounded-xl px-4 py-3 flex items-center gap-3 border ${cfg.box} ${className}`} data-decision={d.decision}>
      <span className={`text-lg leading-none ${cfg.fg}`} aria-hidden="true">{cfg.icon}</span>
      <div className="min-w-0">
        <div className={`font-bold text-[15px] ${cfg.fg}`}>
          {p.phrase}
          {certified && <span className="ml-1.5 font-semibold" style={GRAD_TEXT}>· Certified</span>}
          {!d.final && <span className="ml-2 align-middle font-mono text-[10px] uppercase tracking-wide text-text-muted">provisional</span>}
        </div>
        <div className="text-[12.5px] text-text-muted">{why}</div>
        {sandboxLine && <div className="text-[12px] text-text-muted mt-0.5"><span className="font-mono text-[10px] uppercase tracking-wide mr-1.5">gVisor</span>{sandboxLine}</div>}
      </div>
      <span className="ml-auto font-mono text-[10px] text-text-muted/60 shrink-0 hidden sm:block">from the signed findings</span>
    </div>
  )
}
