import { getTrustTier } from '../../components/trust/gradeSystem'

/**
 * The compact Trust mark — a 0–100 number pill coloured green→red by tier
 * (dual-mark system). Replaces the A–F letter badge everywhere a small, inline
 * trust indicator is needed (catalog rows, cards, teasers). For the full paired
 * mark (trust + adoption) use DualScore; for the hero use ScoreRing.
 *
 * Trust owns the semantic scale — this is the ONLY axis allowed a good/bad colour.
 */
export function TrustPill({
  score,
  showTier = false,
  size = 'md',
  className = '',
}: {
  score: number
  showTier?: boolean
  size?: 'sm' | 'md'
  className?: string
}) {
  const t = getTrustTier(score)
  const pad = size === 'sm' ? 'px-1.5 py-0.5 text-[11px]' : 'px-2 py-0.5 text-[12px]'
  const num = size === 'sm' ? 'text-[12px]' : 'text-[14px]'
  return (
    <span
      className={`inline-flex items-baseline gap-1 rounded-lg font-mono font-bold ${pad} ${className}`}
      style={{ color: t.color, backgroundColor: `${t.color}1f` }}
      title={`Trust ${score}/100 — ${t.name}`}
    >
      <span className={`${num} font-extrabold`}>{score}</span>
      <span className="text-[9px] opacity-60">/100</span>
      {showTier && <span className="ml-0.5 text-[10px] font-semibold">{t.name}</span>}
    </span>
  )
}
