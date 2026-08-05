import { getGradeInfo } from '../../components/trust/gradeSystem'
import { CountUp } from './motion'

/**
 * The two-axis "Rotten Tomatoes for agent trust" score:
 *  - Attestation Trust — the signed, verifiable safety grade (REAL, live now).
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
  const g = getGradeInfo(score)
  return (
    <div className={`grid ${compact ? 'grid-cols-2' : 'sm:grid-cols-2'} gap-2.5`}>
      <div className="bg-surface border border-border rounded-xl px-4 py-3">
        <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted">Attestation Trust</div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className={`text-xl font-extrabold ${g.textClass}`}>{g.grade}</span>
          <CountUp value={score} suffix="/100" className={`text-lg font-bold ${g.textClass}`} />
        </div>
        <div className="text-[11px] text-text-muted mt-0.5">signed scanner grade · verifiable now</div>
      </div>
      <div className="bg-surface border border-border rounded-xl px-4 py-3 relative overflow-hidden">
        <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted">Adoption</div>
        {adoption ? (
          <>
            <div className="mt-1 text-lg font-bold text-gold">{adoption.label}</div>
            <div className="text-[11px] text-text-muted mt-0.5">{adoption.sub}</div>
          </>
        ) : (
          <>
            <div className="mt-1 text-lg font-bold text-text-muted/60">Coming soon</div>
            <div className="text-[11px] text-text-muted mt-0.5">downloads · stars · checks — real usage, not opinions</div>
          </>
        )}
      </div>
    </div>
  )
}
