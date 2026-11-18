// ─── TrustTierBadge ───
// Rotten-Tomatoes-style trust badge with tier-specific icons.
// 4 size variants: micro, small, medium, large.

import { Link } from 'react-router-dom'
import { computeDualTrust, estimateFromOverall } from '../DualTrustScore'
import type { TrustComponents } from '../DualTrustScore'
import { computeTier, progressToNextTier, getPrestigeBadge, getTierColor, getTierGradient } from './trustTiers'
import { getAttestationIcon, getCommunityIcon, getAttestationLabel, getCommunityLabel, PrestigeIcon } from './TrustIcons'

interface TrustTierBadgeProps {
  components?: TrustComponents | null
  score?: number | null
  entityId?: string
  entityType?: 'human' | 'agent'
  size: 'micro' | 'small' | 'medium' | 'large'
  className?: string
  /** Account age in days — needed for prestige badge computation */
  accountAgeDays?: number
  /** Number of attestations from high-trust entities */
  attestationCount?: number
}

function TierNumber({ value, level, axis }: { value: number; level: number; axis: 'attestation' | 'community' }) {
  const gradient = getTierGradient(level, axis)
  if (gradient) {
    return (
      <span
        className="font-semibold"
        style={{
          background: gradient,
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          backgroundClip: 'text',
        }}
      >
        {value}
      </span>
    )
  }
  return (
    <span className="font-semibold" style={{ color: getTierColor(level, axis) }}>
      {value}
    </span>
  )
}

/* eslint-disable react-hooks/static-components -- Icon is picked from a module-level lookup of stable components, not created during render */
function TierIcon({ axis, level, size }: { axis: 'attestation' | 'community'; level: number; size: number }) {
  const Icon = axis === 'attestation' ? getAttestationIcon(level) : getCommunityIcon(level)
  const gradient = getTierGradient(level, axis)
  const color = getTierColor(level, axis)
  const label = axis === 'attestation' ? getAttestationLabel(level) : getCommunityLabel(level)

  return (
    <span
      role="img"
      aria-label={`${axis === 'attestation' ? 'Attestation' : 'Community'} trust: ${label}`}
      style={{ color: gradient ? undefined : color }}
    >
      {gradient ? (
        <span style={{ color: getTierColor(level, axis) }}>
          <Icon size={size} />
        </span>
      ) : (
        <Icon size={size} />
      )}
    </span>
  )
}
/* eslint-enable react-hooks/static-components */

// ─── Overall score pill for micro/small lists ───
function OverallPill({ score }: { score: number }) {
  const color = score < 50 ? getTierColor(1, 'attestation') : score < 80 ? getTierColor(3, 'attestation') : getTierColor(5, 'attestation')
  return (
    <span
      className="font-bold"
      style={{ color }}
      title={`Overall Trust: ${score}`}
    >
      {score}
    </span>
  )
}

function ProgressBar({ score, level, axis }: { score: number; level: number; axis: 'attestation' | 'community' }) {
  const progress = progressToNextTier(score)
  const color = getTierColor(level, axis)
  const gradient = getTierGradient(level, axis)
  const tier = computeTier(score, axis)

  return (
    <div className="flex items-center gap-2 mt-1">
      <div className="flex-1 bg-background rounded-full h-1.5 overflow-hidden">
        <div
          className="h-full rounded-full transition-all"
          style={{
            width: progress != null ? `${progress}%` : '100%',
            background: gradient ?? color,
          }}
        />
      </div>
      {tier.nextThreshold != null && (
        <span className="text-[9px] text-text-muted whitespace-nowrap">
          next: {tier.nextThreshold}
        </span>
      )}
    </div>
  )
}

function PrestigeBadgeDisplay({ size }: { size: 'micro' | 'small' | 'medium' | 'large' }) {
  const iconSize = size === 'micro' ? 12 : size === 'small' ? 16 : 20
  return (
    <span
      className="inline-flex items-center gap-0.5"
      title="Mycelium Verified — Both trust axes at Tier 4+, 90+ day account, 3+ high-trust attestations"
    >
      <span style={{ color: '#F59E0B', filter: 'drop-shadow(0 0 4px rgba(245,158,11,0.4))' }}>
        <PrestigeIcon size={iconSize} />
      </span>
      {(size === 'medium' || size === 'large') && (
        <span className="text-[9px] font-semibold" style={{ color: '#EAB308' }}>
          Mycelium
        </span>
      )}
    </span>
  )
}

// ─── MICRO — inline two icons + numbers ───
function MicroBadge({ att, com, overall, prestige }: { att: { score: number; level: number }; com: { score: number; level: number }; overall: number; prestige: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <OverallPill score={overall} />
      <span className="text-border text-[10px]">&middot;</span>
      <span className="inline-flex items-center gap-0.5">
        <TierIcon axis="attestation" level={att.level} size={14} />
        <TierNumber value={att.score} level={att.level} axis="attestation" />
      </span>
      <span className="text-border text-[10px]">|</span>
      <span className="inline-flex items-center gap-0.5">
        <TierIcon axis="community" level={com.level} size={14} />
        <TierNumber value={com.score} level={com.level} axis="community" />
      </span>
      {prestige && <PrestigeBadgeDisplay size="micro" />}
    </span>
  )
}

// ─── SMALL — slightly larger, tooltip on hover ───
function SmallBadge({ att, com, overall, prestige }: { att: { score: number; level: number; label: string }; com: { score: number; level: number; label: string }; overall: number; prestige: boolean }) {
  return (
    <span className="inline-flex items-center gap-2">
      <OverallPill score={overall} />
      <span className="text-border text-[10px]">&middot;</span>
      <span className="inline-flex items-center gap-1" title={`Attestation: ${att.label} (${att.score})`}>
        <TierIcon axis="attestation" level={att.level} size={18} />
        <TierNumber value={att.score} level={att.level} axis="attestation" />
      </span>
      <span className="text-border text-xs">|</span>
      <span className="inline-flex items-center gap-1" title={`Community: ${com.label} (${com.score})`}>
        <TierIcon axis="community" level={com.level} size={18} />
        <TierNumber value={com.score} level={com.level} axis="community" />
      </span>
      {prestige && <PrestigeBadgeDisplay size="small" />}
    </span>
  )
}

// ─── MEDIUM — icons + numbers + labels ───
function MediumBadge({ att, com, prestige }: { att: { score: number; level: number; label: string }; com: { score: number; level: number; label: string }; prestige: boolean }) {
  return (
    <div className="flex items-stretch gap-3">
      <div className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 min-w-0">
        <div className="flex items-center gap-1.5 mb-1">
          <TierIcon axis="attestation" level={att.level} size={16} />
          <span className="text-[10px] text-text-muted uppercase tracking-wider truncate">Attestation</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-lg">
            <TierNumber value={att.score} level={att.level} axis="attestation" />
          </span>
          <span className="text-[10px] text-text-muted">{att.label}</span>
        </div>
      </div>
      <div className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 min-w-0">
        <div className="flex items-center gap-1.5 mb-1">
          <TierIcon axis="community" level={com.level} size={16} />
          <span className="text-[10px] text-text-muted uppercase tracking-wider truncate">Community</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-lg">
            <TierNumber value={com.score} level={com.level} axis="community" />
          </span>
          <span className="text-[10px] text-text-muted">{com.label}</span>
        </div>
      </div>
      {prestige && (
        <div className="flex items-center">
          <PrestigeBadgeDisplay size="medium" />
        </div>
      )}
    </div>
  )
}

// ─── LARGE — full display with progress bars ───
function LargeBadge({ att, com, prestige }: { att: { score: number; level: number; label: string }; com: { score: number; level: number; label: string }; prestige: boolean }) {
  return (
    <div className="flex items-stretch gap-3">
      <div className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 min-w-0">
        <div className="flex items-center gap-1.5 mb-1">
          <TierIcon axis="attestation" level={att.level} size={18} />
          <span className="text-[10px] text-text-muted uppercase tracking-wider truncate">Attestation</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-lg">
            <TierNumber value={att.score} level={att.level} axis="attestation" />
          </span>
          <span className="text-xs text-text-muted">{att.label}</span>
        </div>
        <ProgressBar score={att.score} level={att.level} axis="attestation" />
      </div>
      <div className="flex-1 bg-surface border border-border rounded-lg px-3 py-2 min-w-0">
        <div className="flex items-center gap-1.5 mb-1">
          <TierIcon axis="community" level={com.level} size={18} />
          <span className="text-[10px] text-text-muted uppercase tracking-wider truncate">Community</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-lg">
            <TierNumber value={com.score} level={com.level} axis="community" />
          </span>
          <span className="text-xs text-text-muted">{com.label}</span>
        </div>
        <ProgressBar score={com.score} level={com.level} axis="community" />
      </div>
      {prestige && (
        <div className="flex items-center">
          <PrestigeBadgeDisplay size="large" />
        </div>
      )}
    </div>
  )
}

// ─── Main Component ───

export default function TrustTierBadge({
  components,
  score,
  entityId,
  size,
  className = '',
  accountAgeDays = 0,
  attestationCount = 0,
}: TrustTierBadgeProps) {
  const dual = computeDualTrust(components) ?? estimateFromOverall(score)

  if (!dual) {
    if (size === 'micro' || size === 'small') {
      return <span className="text-[10px] text-text-muted">--</span>
    }
    return <div className={`text-sm text-text-muted ${className}`}>No trust data yet</div>
  }

  const attTier = computeTier(dual.attestation, 'attestation')
  const comTier = computeTier(dual.community, 'community')
  const prestige = getPrestigeBadge(dual.attestation, dual.community, accountAgeDays, attestationCount) != null

  const att = { score: dual.attestation, level: attTier.level, label: attTier.label }
  const com = { score: dual.community, level: comTier.level, label: comTier.label }

  let content: React.ReactNode
  const textSize = size === 'micro' ? 'text-[11px]' : size === 'small' ? 'text-xs' : 'text-sm'

  switch (size) {
    case 'micro':
      content = <span className={textSize}><MicroBadge att={att} com={com} overall={dual.overall} prestige={prestige} /></span>
      break
    case 'small':
      content = <span className={textSize}><SmallBadge att={att} com={com} overall={dual.overall} prestige={prestige} /></span>
      break
    case 'medium':
      content = <MediumBadge att={att} com={com} prestige={prestige} />
      break
    case 'large':
      content = <LargeBadge att={att} com={com} prestige={prestige} />
      break
  }

  const wrapped = <div className={className}>{content}</div>

  if (entityId && (size === 'micro' || size === 'small')) {
    return (
      <Link to={`/trust/${entityId}`} className="hover:opacity-80 transition-opacity">
        {wrapped}
      </Link>
    )
  }
  if (entityId && (size === 'medium' || size === 'large')) {
    return (
      <Link to={`/trust/${entityId}`} className="block hover:opacity-90 transition-opacity">
        {wrapped}
      </Link>
    )
  }
  return wrapped
}
