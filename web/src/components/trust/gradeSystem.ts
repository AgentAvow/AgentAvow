/**
 * Unified Trust Grade System
 *
 * One grade system used across ALL surfaces: badges, profile, API, SVG.
 * Replaces the 4 separate tier systems (attestation 6-tier, community 6-tier,
 * badge 4-tier, scan 6-tier) with a single A-F letter grade.
 *
 * Each entity has 3 dimensions + 1 overall:
 *   - Identity:       verification, age, profile completeness
 *   - Code Security:  scanner score + 4 sub-categories
 *   - Community Trust: attestation count + attester quality
 *   - Overall:        weighted composite
 */

// ─── Grade Definitions ───

export type LetterGrade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F'

export interface GradeInfo {
  grade: LetterGrade
  label: string
  color: string        // hex color, same everywhere
  bgColor: string      // subtle background for cards
  textClass: string    // Tailwind class
  bgClass: string      // Tailwind bg class
}

const GRADE_MAP: Record<LetterGrade, Omit<GradeInfo, 'grade'>> = {
  'A+': {
    label: 'Exceptional',
    color: '#14B8A6',      // teal-500
    bgColor: '#0D1F1F',
    textClass: 'text-teal-400',
    bgClass: 'bg-teal-500/10',
  },
  'A': {
    label: 'Trusted',
    color: '#2DD4BF',      // teal-400
    bgColor: '#0D1F1F',
    textClass: 'text-teal-400',
    bgClass: 'bg-teal-400/10',
  },
  'B': {
    label: 'Good',
    color: '#22C55E',      // green-500
    bgColor: '#0D1F0D',
    textClass: 'text-green-500',
    bgClass: 'bg-green-500/10',
  },
  'C': {
    label: 'Fair',
    color: '#F59E0B',      // amber-500
    bgColor: '#1F1A0D',
    textClass: 'text-amber-500',
    bgClass: 'bg-amber-500/10',
  },
  'D': {
    label: 'Caution',
    color: '#F97316',      // orange-500
    bgColor: '#1F150D',
    textClass: 'text-orange-500',
    bgClass: 'bg-orange-500/10',
  },
  'F': {
    label: 'Fail',
    color: '#EF4444',      // red-500
    bgColor: '#1F0D0D',
    textClass: 'text-red-500',
    bgClass: 'bg-red-500/10',
  },
}

// ─── Score → Grade Conversion ───

/** Convert a 0-100 score to a letter grade. */
export function scoreToGrade(score: number): LetterGrade {
  if (score >= 96) return 'A+'
  if (score >= 81) return 'A'
  if (score >= 61) return 'B'
  if (score >= 41) return 'C'
  if (score >= 21) return 'D'
  return 'F'
}

/** Get full grade info for a score. */
export function getGradeInfo(score: number): GradeInfo {
  const grade = scoreToGrade(score)
  return { grade, ...GRADE_MAP[grade] }
}

/** Get grade info by letter. */
export function gradeInfo(grade: LetterGrade): GradeInfo {
  return { grade, ...GRADE_MAP[grade] }
}

// ─── 0–100 Trust mark (dual-mark pivot 2026-08) ─────────────────────────────
// The product now displays a 0–100 number + tier word, not an A–F letter.
// Trust owns the semantic green→red scale; thresholds 80/60/40/20 per the locked
// mark spec. The A–F helpers above are retained for legacy logic (e.g. verdict
// keying, SEO strings) during the flip — display surfaces use getTrustTier().

export type TrustTierName = 'Trusted' | 'Standard' | 'Caution' | 'Restricted' | 'Blocked'

export interface TrustTier {
  name: TrustTierName
  min: number
  color: string       // vivid — for bars/rings/needles on dark
  colorText: string   // darkened — for the number/word on light surfaces
  posture: string     // recommended execution posture
}

const TRUST_TIERS: TrustTier[] = [
  { name: 'Trusted',    min: 80, color: '#22C55E', colorText: '#15803D', posture: 'Auto-approve within budget' },
  { name: 'Standard',   min: 60, color: '#5BBF3A', colorText: '#3F7D1F', posture: 'Standard rate + token limits' },
  { name: 'Caution',    min: 40, color: '#F59E0B', colorText: '#B45309', posture: 'Confirm on sensitive calls' },
  { name: 'Restricted', min: 20, color: '#F97316', colorText: '#C2410C', posture: 'Gated · manual approval' },
  { name: 'Blocked',    min: 0,  color: '#EF4444', colorText: '#B91C1C', posture: 'Do not connect' },
]

/** Map a 0–100 score to its Trust tier (word, colour, posture). */
export function getTrustTier(score: number): TrustTier {
  return TRUST_TIERS.find((t) => score >= t.min) ?? TRUST_TIERS[TRUST_TIERS.length - 1]
}

// ─── Dimension Scores ───

export interface DimensionScores {
  identity: number        // 0-100
  codeSecurity: number    // 0-100
  communityTrust: number  // 0-100
  overall: number         // 0-100
}

export interface DimensionGrades {
  identity: GradeInfo
  codeSecurity: GradeInfo
  communityTrust: GradeInfo
  overall: GradeInfo
}

export interface TrustComponents {
  verification?: number
  age?: number
  activity?: number
  reputation?: number
  community?: number
  external_reputation?: number
  scan_score?: number
}

/**
 * Compute the 3 dimension scores from the 7-component trust data.
 *
 * Identity = verification (weighted heavily) + age + external signals
 * Code Security = scan_score (if available, else neutral 50)
 * Community Trust = community attestations + reputation + activity
 * Overall = weighted composite matching backend formula
 */
export function computeDimensions(
  components: TrustComponents | null | undefined,
  overallScore?: number | null,
): DimensionScores {
  if (!components && overallScore != null) {
    // Estimate from overall when components aren't available
    return {
      identity: Math.round(overallScore * 100),
      codeSecurity: 50, // unknown
      communityTrust: Math.round(overallScore * 100),
      overall: Math.round(overallScore * 100),
    }
  }

  const c = components ?? {}
  const v = c.verification ?? 0
  const a = c.age ?? 0
  const act = c.activity ?? 0
  const rep = c.reputation ?? 0
  const com = c.community ?? 0
  const ext = c.external_reputation ?? 0
  const scan = c.scan_score ?? 0

  // Identity: how verified is this entity?
  // Heavily weights verification + external proof, age adds tenure
  const identity = Math.round(
    Math.min(100, (v * 45 + ext * 30 + a * 25))
  )

  // Code Security: scan results (if scanned)
  // If no scan exists (scan_score = 0 and no scan data), show as "Not Scanned"
  const codeSecurity = Math.round(scan * 100)

  // Community Trust: do other verified people vouch for them?
  // Combines attestations, peer reviews, and activity level
  const communityTrust = Math.round(
    Math.min(100, (com * 40 + rep * 35 + act * 25))
  )

  // Use backend's authoritative score when available (prevents mismatch
  // when backend weights change but frontend hasn't been redeployed)
  const overall = overallScore != null
    ? Math.round((overallScore <= 1.0 && overallScore > 0 ? overallScore * 100 : overallScore))
    : Math.round(
        (v * 0.35 + a * 0.10 + act * 0.0 + rep * 0.0 + com * 0.0 + ext * 0.35 + scan * 0.20) * 100
      )

  return { identity, codeSecurity, communityTrust, overall }
}

/** Convert dimension scores to letter grades. */
export function computeDimensionGrades(dims: DimensionScores): DimensionGrades {
  return {
    identity: getGradeInfo(dims.identity),
    codeSecurity: getGradeInfo(dims.codeSecurity),
    communityTrust: getGradeInfo(dims.communityTrust),
    overall: getGradeInfo(dims.overall),
  }
}

// ─── Security Sub-Scores (from scanner) ───

export interface SecuritySubScores {
  secret_hygiene: number
  code_safety: number
  data_handling: number
  filesystem_access: number
  dependency_health?: number
}

export function getSecuritySubGrades(scores: SecuritySubScores): Record<string, GradeInfo> {
  const grades: Record<string, GradeInfo> = {
    'Secret Hygiene': getGradeInfo(scores.secret_hygiene),
    'Code Safety': getGradeInfo(scores.code_safety),
    'Data Handling': getGradeInfo(scores.data_handling),
    'Filesystem Access': getGradeInfo(scores.filesystem_access),
  }
  if (scores.dependency_health != null) {
    grades['Dependency Health'] = getGradeInfo(scores.dependency_health)
  }
  return grades
}

// ─── Dimension Reasons (one-line explanations) ───

export function identityReason(components: TrustComponents): string {
  const parts: string[] = []
  if ((components.verification ?? 0) >= 0.3) parts.push('Email verified')
  if ((components.verification ?? 0) >= 0.5) parts.push('Profile complete')
  if ((components.verification ?? 0) >= 0.7) parts.push('Operator linked')
  if ((components.external_reputation ?? 0) > 0) parts.push('External accounts linked')
  if ((components.age ?? 0) >= 0.5) parts.push('180+ day account')
  else if ((components.age ?? 0) >= 0.25) parts.push('90+ day account')
  if (parts.length === 0) parts.push('No verification yet')
  return parts.join(' · ')
}

export function communityReason(components: TrustComponents): string {
  const parts: string[] = []
  if ((components.community ?? 0) >= 0.5) parts.push('Strong attestations')
  else if ((components.community ?? 0) > 0) parts.push('Some attestations')
  if ((components.reputation ?? 0) >= 0.5) parts.push('Good peer reviews')
  else if ((components.reputation ?? 0) > 0) parts.push('Some peer reviews')
  if ((components.activity ?? 0) >= 0.5) parts.push('Active participant')
  if (parts.length === 0) parts.push('New to the community')
  return parts.join(' · ')
}
