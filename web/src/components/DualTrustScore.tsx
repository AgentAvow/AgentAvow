import { Link } from 'react-router-dom'

// ─── Trust Split Logic ───
// Splits existing 5-component trust into dual numbers:
//   Attestation Trust = verification (35%) + age (10%)  → institutional/credential signals
//   Community Trust   = activity (20%) + peer_reviews (15%) + community (20%) → peer/interaction signals

export interface TrustComponents {
  verification?: number
  age?: number
  activity?: number
  reputation?: number
  community?: number
  scan_score?: number
}

export interface DualTrust {
  attestation: number  // 0-100
  community: number    // 0-100
  overall: number      // 0-100 — weighted combo matching backend formula
  divergent: boolean   // >30pt gap
}

const ATTESTATION_WEIGHTS = { verification: 0.25, age: 0.08, scan_score: 0.05 }
const COMMUNITY_WEIGHTS = { activity: 0.18, reputation: 0.14, community: 0.18 }
// external_reputation (0.12) is excluded from dual display — it feeds into overall only

// eslint-disable-next-line react-refresh/only-export-components -- pure helper co-located with the component it serves; HMR falls back to a full reload here
export function computeDualTrust(components: TrustComponents | null | undefined): DualTrust | null {
  if (!components) return null

  const v = components.verification ?? 0
  const a = components.age ?? 0
  const sc = components.scan_score ?? 0
  const act = components.activity ?? 0
  const rep = components.reputation ?? 0
  const com = components.community ?? 0

  const attTotal = ATTESTATION_WEIGHTS.verification + ATTESTATION_WEIGHTS.age + ATTESTATION_WEIGHTS.scan_score
  const comTotal = COMMUNITY_WEIGHTS.activity + COMMUNITY_WEIGHTS.reputation + COMMUNITY_WEIGHTS.community

  const attestation = Math.round(
    ((v * ATTESTATION_WEIGHTS.verification + a * ATTESTATION_WEIGHTS.age + sc * ATTESTATION_WEIGHTS.scan_score) / attTotal) * 100
  )
  const community = Math.round(
    ((act * COMMUNITY_WEIGHTS.activity + rep * COMMUNITY_WEIGHTS.reputation + com * COMMUNITY_WEIGHTS.community) / comTotal) * 100
  )

  // Overall: sum all weighted components (matches backend formula, *100)
  const overall = Math.round(
    (v * 0.25 + a * 0.08 + act * 0.18 + rep * 0.14 + com * 0.18 + sc * 0.05) * 100
  )

  return {
    attestation: Math.min(attestation, 100),
    community: Math.min(community, 100),
    overall: Math.min(overall, 100),
    divergent: Math.abs(attestation - community) > 30,
  }
}

// Fallback: estimate from single overall score when components unavailable
// eslint-disable-next-line react-refresh/only-export-components -- pure helper co-located with the component it serves; HMR falls back to a full reload here
export function estimateFromOverall(score: number | null | undefined): DualTrust | null {
  if (score == null) return null
  const pct = Math.round(score * 100)
  return { attestation: pct, community: pct, overall: pct, divergent: false }
}

// ─── Shield Icon (Attestation) ───
function ShieldIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
        d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  )
}

// ─── People Icon (Community) ───
function PeopleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
        d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
    </svg>
  )
}

// ─── Color helpers (axis-specific) ───
// Attestation = pink/fuchsia spectrum (matches accent), Community = warm green spectrum
function scoreColor(pct: number, axis: 'attestation' | 'community' = 'attestation'): string {
  if (pct < 50) return 'text-danger'
  if (pct < 80) return axis === 'attestation' ? 'text-fuchsia-400' : 'text-emerald-400'
  return axis === 'attestation' ? 'text-accent' : 'text-green-400'
}

function barColor(pct: number, axis: 'attestation' | 'community' = 'attestation'): string {
  if (pct < 50) return 'bg-danger'
  if (pct < 80) return axis === 'attestation' ? 'bg-fuchsia-500' : 'bg-emerald-500'
  return axis === 'attestation' ? 'bg-accent' : 'bg-green-400'
}

// ─── Compact Mode (feed cards, search results, discover) ───
// Two small inline badges: [🛡 72] [👥 85]

interface CompactProps {
  components?: TrustComponents | null
  score?: number | null
  entityId?: string
  className?: string
}

export function TrustScoreCompact({ components, score, entityId, className = '' }: CompactProps) {
  const dual = computeDualTrust(components) ?? estimateFromOverall(score)
  if (!dual) return <span className="text-[10px] text-text-muted">--</span>

  const content = (
    <span className={`inline-flex items-center gap-1.5 ${className}`}>
      <span className={`text-[11px] font-bold ${scoreColor(dual.overall, 'attestation')}`} title={`Overall Trust: ${dual.overall}`}>
        {dual.overall}
      </span>
      <span className="text-border text-[9px]">(</span>
      <span className="inline-flex items-center gap-0.5" title="Attestation Trust — verified credentials">
        <ShieldIcon className="w-3 h-3 text-accent" />
        <span className={`text-[11px] font-semibold ${scoreColor(dual.attestation, 'attestation')}`}>
          {dual.attestation}
        </span>
      </span>
      <span className="text-border">|</span>
      <span className="inline-flex items-center gap-0.5" title="Community Trust — peer interactions">
        <PeopleIcon className="w-3 h-3 text-emerald-400" />
        <span className={`text-[11px] font-semibold ${scoreColor(dual.community, 'community')}`}>
          {dual.community}
        </span>
      </span>
      <span className="text-border text-[9px]">)</span>
      {dual.divergent && (
        <span className="w-1.5 h-1.5 rounded-full bg-warning animate-pulse" title="Trust scores diverge significantly" />
      )}
    </span>
  )

  if (entityId) {
    return (
      <Link to={`/trust/${entityId}`} className="hover:opacity-80 transition-opacity">
        {content}
      </Link>
    )
  }
  return content
}

// ─── Standard Mode (profile headers, dashboard) ───
// Two labeled numbers with mini bars and divergence indicator

interface StandardProps {
  components?: TrustComponents | null
  score?: number | null
  entityId?: string
  className?: string
}

export function TrustScoreStandard({ components, score, entityId, className = '' }: StandardProps) {
  const dual = computeDualTrust(components) ?? estimateFromOverall(score)
  if (!dual) {
    return (
      <div className={`text-sm text-text-muted ${className}`}>
        No trust data yet
      </div>
    )
  }

  const inner = (
    <div className={className}>
      {/* Overall Trust Score */}
      <div className="flex items-center gap-2 mb-2">
        <span className="text-[10px] text-text-muted uppercase tracking-wider">Overall Trust</span>
        <span className={`text-sm font-bold ${scoreColor(dual.overall, 'attestation')}`}>
          {dual.overall}
        </span>
        <div className="flex-1 bg-background rounded-full h-1 overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${barColor(dual.overall, 'attestation')}`}
            style={{ width: `${dual.overall}%` }}
          />
        </div>
      </div>
      <div className="flex items-stretch gap-3">
      {/* Attestation Trust */}
      <div className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 min-w-0">
        <div className="flex items-center gap-1.5 mb-1">
          <ShieldIcon className="w-3.5 h-3.5 text-accent shrink-0" />
          <span className="text-[10px] text-text-muted uppercase tracking-wider truncate">Attestation</span>
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-lg font-bold ${scoreColor(dual.attestation, 'attestation')}`}>
            {dual.attestation}
          </span>
          <div className="flex-1 bg-background rounded-full h-1.5 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${barColor(dual.attestation, 'attestation')}`}
              style={{ width: `${dual.attestation}%` }}
            />
          </div>
        </div>
      </div>

      {/* Divergence indicator */}
      {dual.divergent && (
        <div className="flex items-center" title="Attestation and Community trust scores diverge significantly — investigate before trusting">
          <div className="w-6 h-6 rounded-full bg-warning/15 border border-warning/30 flex items-center justify-center">
            <span className="text-warning text-xs font-bold">!</span>
          </div>
        </div>
      )}

      {/* Community Trust */}
      <div className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 min-w-0">
        <div className="flex items-center gap-1.5 mb-1">
          <PeopleIcon className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
          <span className="text-[10px] text-text-muted uppercase tracking-wider truncate">Community</span>
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-lg font-bold ${scoreColor(dual.community, 'community')}`}>
            {dual.community}
          </span>
          <div className="flex-1 bg-background rounded-full h-1.5 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${barColor(dual.community, 'community')}`}
              style={{ width: `${dual.community}%` }}
            />
          </div>
        </div>
      </div>
    </div>
    </div>
  )

  if (entityId) {
    return (
      <Link to={`/trust/${entityId}`} className="block hover:opacity-90 transition-opacity">
        {inner}
      </Link>
    )
  }
  return inner
}

// ─── Overall Trust Hero (profile page) ───
// Full-width card with large score, progress bar, and explainer text

interface OverallTrustHeroProps {
  components?: TrustComponents | null
  score?: number | null
  className?: string
}

function overallScoreColor(pct: number): string {
  if (pct < 50) return 'text-danger'
  if (pct < 80) return 'text-fuchsia-400'
  return 'text-accent'
}

function overallBarColor(pct: number): string {
  if (pct < 50) return 'bg-danger'
  if (pct < 80) return 'bg-fuchsia-500'
  return 'bg-accent'
}

export function OverallTrustHero({ components, score, className = '' }: OverallTrustHeroProps) {
  const dual = computeDualTrust(components) ?? estimateFromOverall(score)
  if (!dual) return null

  return (
    <div className={`bg-surface border border-border rounded-lg px-4 py-3 ${className}`}>
      <div className="flex items-center gap-3 mb-2">
        <ShieldIcon className="w-6 h-6 text-accent shrink-0" />
        <span className={`text-3xl font-bold ${overallScoreColor(dual.overall)}`}>
          {dual.overall}
        </span>
        <span className="text-xs text-text-muted uppercase tracking-wider font-semibold">
          Overall Trust
        </span>
      </div>
      <div className="bg-background rounded-full h-2 overflow-hidden mb-2">
        <div
          className={`h-full rounded-full transition-all ${overallBarColor(dual.overall)}`}
          style={{ width: `${dual.overall}%` }}
        />
      </div>
      <p className="text-xs text-text-muted leading-relaxed">
        Combines verified credentials, community endorsements, and platform activity.
        This is the score shown in your GitHub badge.
      </p>
    </div>
  )
}

// ─── Badge Mode (single inline pill for tight spaces) ───
// Shows overall score with dual tooltip

interface BadgeProps {
  components?: TrustComponents | null
  score?: number | null
  className?: string
}

export function TrustScoreBadge({ components, score, className = '' }: BadgeProps) {
  const dual = computeDualTrust(components) ?? estimateFromOverall(score)
  if (!dual) return <span className="text-xs text-text-muted">--</span>

  const overall = Math.round((dual.attestation + dual.community) / 2)

  return (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-surface border border-border text-[10px] ${className}`}
      title={`Attestation: ${dual.attestation}% | Community: ${dual.community}%`}
    >
      <ShieldIcon className="w-2.5 h-2.5 text-accent" />
      <span className={`font-semibold ${scoreColor(overall, 'attestation')}`}>{overall}</span>
      {dual.divergent && (
        <span className="w-1 h-1 rounded-full bg-warning" />
      )}
    </span>
  )
}
