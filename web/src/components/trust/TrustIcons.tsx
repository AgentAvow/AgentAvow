// ─── Trust Tier Icons ───
// 12 SVG components: 6 attestation shield tiers + 6 community network tiers.
// Each icon's SHAPE changes at each tier level (Rotten Tomatoes-style).

interface IconProps {
  size?: number
  className?: string
}

// ═══════════════════════════════════════════════════════
// ATTESTATION ICONS (Shield axis — credential/verification)
// ═══════════════════════════════════════════════════════

/** Tier 0 — Dashed shield outline (broken, unverified) */
function ShieldDashed({ size = 20, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      <path d="M12 3L4 7v4c0 5.25 3.4 10.15 8 11.25" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeDasharray="3 3" />
      <path d="M12 3l8 4v4c0 5.25-3.4 10.15-8 11.25" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeDasharray="3 3" />
    </svg>
  )
}

/** Tier 1 — Solid shield outline (empty) */
function ShieldOutline({ size = 20, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      <path d="M12 3L4 7v4c0 5.25 3.4 10.15 8 11.25 4.6-1.1 8-6 8-11.25V7l-8-4z" stroke="currentColor" strokeWidth={1.8} strokeLinejoin="round" />
    </svg>
  )
}

/** Tier 2 — Shield + small checkmark */
function ShieldCheck({ size = 20, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      <path d="M12 3L4 7v4c0 5.25 3.4 10.15 8 11.25 4.6-1.1 8-6 8-11.25V7l-8-4z" stroke="currentColor" strokeWidth={1.8} strokeLinejoin="round" />
      <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

/** Tier 3 — Filled shield + checkmark */
function ShieldFilled({ size = 20, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} aria-hidden="true">
      <path d="M12 3L4 7v4c0 5.25 3.4 10.15 8 11.25 4.6-1.1 8-6 8-11.25V7l-8-4z" fill="currentColor" opacity={0.2} stroke="currentColor" strokeWidth={1.8} strokeLinejoin="round" />
      <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

/** Tier 4 — Shield + star inside */
function ShieldStar({ size = 20, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} aria-hidden="true">
      <path d="M12 3L4 7v4c0 5.25 3.4 10.15 8 11.25 4.6-1.1 8-6 8-11.25V7l-8-4z" fill="currentColor" opacity={0.15} stroke="currentColor" strokeWidth={1.8} strokeLinejoin="round" />
      <path d="M12 8l1.12 2.27 2.5.36-1.81 1.77.43 2.5L12 13.77l-2.24 1.13.43-2.5-1.81-1.77 2.5-.36L12 8z" fill="currentColor" stroke="currentColor" strokeWidth={0.5} strokeLinejoin="round" />
    </svg>
  )
}

/** Tier 5 — Shield + wreath/laurel border */
function ShieldWreath({ size = 20, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} aria-hidden="true">
      {/* Laurel left */}
      <path d="M5 18c0-3 1-5.5 2.5-7.5M4.5 16c.5-2 1.5-3.5 3-5M5.5 19c-.5-1.5 0-3.5 1-5" stroke="currentColor" strokeWidth={1.2} strokeLinecap="round" opacity={0.6} />
      {/* Laurel right */}
      <path d="M19 18c0-3-1-5.5-2.5-7.5M19.5 16c-.5-2-1.5-3.5-3-5M18.5 19c.5-1.5 0-3.5-1-5" stroke="currentColor" strokeWidth={1.2} strokeLinecap="round" opacity={0.6} />
      {/* Shield */}
      <path d="M12 3L6 6.5v3.5c0 4.4 2.6 8.5 6 9.5 3.4-1 6-5.1 6-9.5V6.5L12 3z" fill="currentColor" opacity={0.2} stroke="currentColor" strokeWidth={1.8} strokeLinejoin="round" />
      {/* Star */}
      <path d="M12 8l1.12 2.27 2.5.36-1.81 1.77.43 2.5L12 13.77l-2.24 1.13.43-2.5-1.81-1.77 2.5-.36L12 8z" fill="currentColor" stroke="currentColor" strokeWidth={0.5} strokeLinejoin="round" />
    </svg>
  )
}

// ═══════════════════════════════════════════════════════
// COMMUNITY ICONS (Network axis — peer/interaction)
// ═══════════════════════════════════════════════════════

/** Tier 0 — Single dot (isolated) */
function NodeSingle({ size = 20, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      <circle cx={12} cy={12} r={3} fill="currentColor" opacity={0.5} />
      <circle cx={12} cy={12} r={3} stroke="currentColor" strokeWidth={1.5} />
    </svg>
  )
}

/** Tier 1 — Two connected dots */
function NodePair({ size = 20, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      <line x1={8} y1={12} x2={16} y2={12} stroke="currentColor" strokeWidth={1.5} />
      <circle cx={8} cy={12} r={2.5} fill="currentColor" opacity={0.3} stroke="currentColor" strokeWidth={1.5} />
      <circle cx={16} cy={12} r={2.5} fill="currentColor" opacity={0.3} stroke="currentColor" strokeWidth={1.5} />
    </svg>
  )
}

/** Tier 2 — Triangle of 3 nodes */
function NodeTriangle({ size = 20, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      <line x1={12} y1={6} x2={6} y2={17} stroke="currentColor" strokeWidth={1.3} />
      <line x1={12} y1={6} x2={18} y2={17} stroke="currentColor" strokeWidth={1.3} />
      <line x1={6} y1={17} x2={18} y2={17} stroke="currentColor" strokeWidth={1.3} />
      <circle cx={12} cy={6} r={2.2} fill="currentColor" opacity={0.3} stroke="currentColor" strokeWidth={1.3} />
      <circle cx={6} cy={17} r={2.2} fill="currentColor" opacity={0.3} stroke="currentColor" strokeWidth={1.3} />
      <circle cx={18} cy={17} r={2.2} fill="currentColor" opacity={0.3} stroke="currentColor" strokeWidth={1.3} />
    </svg>
  )
}

/** Tier 3 — 4-node cluster with edges */
function NodeCluster({ size = 20, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      {/* Edges */}
      <line x1={8} y1={7} x2={16} y2={7} stroke="currentColor" strokeWidth={1.2} />
      <line x1={8} y1={7} x2={6} y2={16} stroke="currentColor" strokeWidth={1.2} />
      <line x1={16} y1={7} x2={18} y2={16} stroke="currentColor" strokeWidth={1.2} />
      <line x1={6} y1={16} x2={18} y2={16} stroke="currentColor" strokeWidth={1.2} />
      <line x1={8} y1={7} x2={18} y2={16} stroke="currentColor" strokeWidth={1.2} opacity={0.5} />
      <line x1={16} y1={7} x2={6} y2={16} stroke="currentColor" strokeWidth={1.2} opacity={0.5} />
      {/* Nodes */}
      <circle cx={8} cy={7} r={2} fill="currentColor" opacity={0.35} stroke="currentColor" strokeWidth={1.3} />
      <circle cx={16} cy={7} r={2} fill="currentColor" opacity={0.35} stroke="currentColor" strokeWidth={1.3} />
      <circle cx={6} cy={16} r={2} fill="currentColor" opacity={0.35} stroke="currentColor" strokeWidth={1.3} />
      <circle cx={18} cy={16} r={2} fill="currentColor" opacity={0.35} stroke="currentColor" strokeWidth={1.3} />
    </svg>
  )
}

/** Tier 4 — Hexagonal node cluster */
function NodeHex({ size = 20, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      {/* Hex edges */}
      <polygon points="12,4 18.5,8 18.5,16 12,20 5.5,16 5.5,8" fill="currentColor" opacity={0.08} stroke="currentColor" strokeWidth={1} />
      {/* Internal edges */}
      <line x1={12} y1={4} x2={12} y2={20} stroke="currentColor" strokeWidth={0.8} opacity={0.4} />
      <line x1={5.5} y1={8} x2={18.5} y2={16} stroke="currentColor" strokeWidth={0.8} opacity={0.4} />
      <line x1={18.5} y1={8} x2={5.5} y2={16} stroke="currentColor" strokeWidth={0.8} opacity={0.4} />
      {/* Nodes */}
      <circle cx={12} cy={4} r={1.8} fill="currentColor" opacity={0.4} stroke="currentColor" strokeWidth={1.2} />
      <circle cx={18.5} cy={8} r={1.8} fill="currentColor" opacity={0.4} stroke="currentColor" strokeWidth={1.2} />
      <circle cx={18.5} cy={16} r={1.8} fill="currentColor" opacity={0.4} stroke="currentColor" strokeWidth={1.2} />
      <circle cx={12} cy={20} r={1.8} fill="currentColor" opacity={0.4} stroke="currentColor" strokeWidth={1.2} />
      <circle cx={5.5} cy={16} r={1.8} fill="currentColor" opacity={0.4} stroke="currentColor" strokeWidth={1.2} />
      <circle cx={5.5} cy={8} r={1.8} fill="currentColor" opacity={0.4} stroke="currentColor" strokeWidth={1.2} />
      {/* Center node */}
      <circle cx={12} cy={12} r={2} fill="currentColor" opacity={0.5} stroke="currentColor" strokeWidth={1.3} />
    </svg>
  )
}

/** Tier 5 — Dense graph cluster (glowing hub) */
function NodeDense({ size = 20, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      {/* Outer ring edges */}
      <polygon points="12,3 17.5,5.5 20,11 18,17 13,20 7,18.5 4,13 5,6.5" fill="currentColor" opacity={0.06} stroke="currentColor" strokeWidth={0.8} />
      {/* Spokes to center */}
      <line x1={12} y1={3} x2={12} y2={12} stroke="currentColor" strokeWidth={0.8} opacity={0.5} />
      <line x1={17.5} y1={5.5} x2={12} y2={12} stroke="currentColor" strokeWidth={0.8} opacity={0.5} />
      <line x1={20} y1={11} x2={12} y2={12} stroke="currentColor" strokeWidth={0.8} opacity={0.5} />
      <line x1={18} y1={17} x2={12} y2={12} stroke="currentColor" strokeWidth={0.8} opacity={0.5} />
      <line x1={13} y1={20} x2={12} y2={12} stroke="currentColor" strokeWidth={0.8} opacity={0.5} />
      <line x1={7} y1={18.5} x2={12} y2={12} stroke="currentColor" strokeWidth={0.8} opacity={0.5} />
      <line x1={4} y1={13} x2={12} y2={12} stroke="currentColor" strokeWidth={0.8} opacity={0.5} />
      <line x1={5} y1={6.5} x2={12} y2={12} stroke="currentColor" strokeWidth={0.8} opacity={0.5} />
      {/* Outer nodes */}
      <circle cx={12} cy={3} r={1.5} fill="currentColor" opacity={0.4} stroke="currentColor" strokeWidth={1} />
      <circle cx={17.5} cy={5.5} r={1.5} fill="currentColor" opacity={0.4} stroke="currentColor" strokeWidth={1} />
      <circle cx={20} cy={11} r={1.5} fill="currentColor" opacity={0.4} stroke="currentColor" strokeWidth={1} />
      <circle cx={18} cy={17} r={1.5} fill="currentColor" opacity={0.4} stroke="currentColor" strokeWidth={1} />
      <circle cx={13} cy={20} r={1.5} fill="currentColor" opacity={0.4} stroke="currentColor" strokeWidth={1} />
      <circle cx={7} cy={18.5} r={1.5} fill="currentColor" opacity={0.4} stroke="currentColor" strokeWidth={1} />
      <circle cx={4} cy={13} r={1.5} fill="currentColor" opacity={0.4} stroke="currentColor" strokeWidth={1} />
      <circle cx={5} cy={6.5} r={1.5} fill="currentColor" opacity={0.4} stroke="currentColor" strokeWidth={1} />
      {/* Glowing center hub */}
      <circle cx={12} cy={12} r={3} fill="currentColor" opacity={0.3} />
      <circle cx={12} cy={12} r={2.2} fill="currentColor" opacity={0.6} stroke="currentColor" strokeWidth={1.3} />
    </svg>
  )
}

// ═══════════════════════════════════════════════════════
// PRESTIGE ICON — Mycelium Verified
// ═══════════════════════════════════════════════════════

/** Combined shield + network nodes with glow effect */
export function PrestigeIcon({ size = 20, className }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className} aria-hidden="true">
      {/* Shield base */}
      <path d="M12 2L5 5.5v4c0 4.8 3 9.2 7 10.5 4-1.3 7-5.7 7-10.5v-4L12 2z" fill="currentColor" opacity={0.15} stroke="currentColor" strokeWidth={1.5} strokeLinejoin="round" />
      {/* Network nodes on shield */}
      <circle cx={12} cy={8} r={1.3} fill="currentColor" />
      <circle cx={9} cy={13} r={1.3} fill="currentColor" />
      <circle cx={15} cy={13} r={1.3} fill="currentColor" />
      <line x1={12} y1={8} x2={9} y2={13} stroke="currentColor" strokeWidth={1.2} />
      <line x1={12} y1={8} x2={15} y2={13} stroke="currentColor" strokeWidth={1.2} />
      <line x1={9} y1={13} x2={15} y2={13} stroke="currentColor" strokeWidth={1.2} />
    </svg>
  )
}

// ═══════════════════════════════════════════════════════
// ICON ACCESSORS
// ═══════════════════════════════════════════════════════

const ATTESTATION_ICONS = [ShieldDashed, ShieldOutline, ShieldCheck, ShieldFilled, ShieldStar, ShieldWreath] as const
const COMMUNITY_ICONS = [NodeSingle, NodePair, NodeTriangle, NodeCluster, NodeHex, NodeDense] as const

// eslint-disable-next-line react-refresh/only-export-components -- pure helper co-located with the component it serves; HMR falls back to a full reload here
export function getAttestationIcon(tier: number): React.FC<IconProps> {
  return ATTESTATION_ICONS[Math.max(0, Math.min(5, tier))]
}

// eslint-disable-next-line react-refresh/only-export-components -- pure helper co-located with the component it serves; HMR falls back to a full reload here
export function getCommunityIcon(tier: number): React.FC<IconProps> {
  return COMMUNITY_ICONS[Math.max(0, Math.min(5, tier))]
}

/** Get aria-label text for a tier icon */
// eslint-disable-next-line react-refresh/only-export-components -- pure helper co-located with the component it serves; HMR falls back to a full reload here
export function getAttestationLabel(tier: number): string {
  const labels = ['Unverified', 'Basic', 'Confirmed', 'Validated', 'Verified', 'Certified']
  return labels[Math.max(0, Math.min(5, tier))]
}

// eslint-disable-next-line react-refresh/only-export-components -- pure helper co-located with the component it serves; HMR falls back to a full reload here
export function getCommunityLabel(tier: number): string {
  const labels = ['Unknown', 'Emerging', 'Connected', 'Established', 'Trusted', 'Pillar']
  return labels[Math.max(0, Math.min(5, tier))]
}
