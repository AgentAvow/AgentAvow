import { getTrustTier } from '../../components/trust/gradeSystem'
import { CountUp } from './motion'

/**
 * The two-axis "Rotten Tomatoes for agent trust" score:
 *  - Attestation Trust — the signed, verifiable safety score (REAL, live now).
 *  - Adoption — how much the ecosystem actually uses it (usage signal). Not yet
 *    wired end-to-end, so it's shown honestly as "coming soon" rather than faked.
 *    Pass `adoption` once real usage data exists to light it up.
 */
export function DualScore({
  score,
  adoption,
  compact = false,
}: {
  score: number
  adoption?: { label: string; sub: string } | null
  compact?: boolean
}) {
  const t = getTrustTier(score)
  return (
    <div className={`grid ${compact ? 'grid-cols-2' : 'sm:grid-cols-2'} gap-2.5`}>
      {/* Trust — the number is primary (0–100), tier word beneath. Green→red. */}
      <div className="bg-surface border border-border rounded-xl px-4 py-3">
        <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted">Attestation Trust</div>
        <div className="mt-1 flex items-baseline gap-1.5">
          <span className="text-2xl font-extrabold" style={{ color: t.color }}>
            <CountUp value={score} />
          </span>
          <span className="text-[11px] font-mono text-text-muted">/100</span>
          <span className="ml-1 text-[13px] font-bold" style={{ color: t.color }}>{t.name}</span>
        </div>
        <div className="text-[11px] text-text-muted mt-0.5">signed scanner score · verifiable now</div>
      </div>
      {/* Adoption — brand teal, NEVER a trust/safety colour (popular ≠ safe). */}
      <div className="bg-surface border border-border rounded-xl px-4 py-3 relative overflow-hidden">
        <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted">Adoption</div>
        {adoption ? (
          <>
            <div className="mt-1 text-lg font-bold text-teal-400">{adoption.label}</div>
            <div className="text-[11px] text-text-muted mt-0.5">{adoption.sub}</div>
          </>
        ) : (
          <>
            <div className="mt-1 text-lg font-bold text-text-muted/70">Just launched</div>
            <div className="text-[11px] text-text-muted mt-0.5">stars · checks · watchers — real usage, not opinions</div>
          </>
        )}
      </div>
    </div>
  )
}
