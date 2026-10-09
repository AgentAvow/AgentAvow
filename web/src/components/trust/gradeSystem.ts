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

/**
 * Binary decision layer over the signed score (Shawn feedback #4). A VIEW, not a
 * rescore: 'safe' iff the score is A/A+ (>=81) AND there are no blocking critical
 * or high findings (the server's `certified.checks.no_critical_or_high` gate,
 * which already excludes test/benchmark-only findings). Anything else is
 * 'needs_review'. The signed 0-100 and attestation are unchanged.
 */
export function binaryVerdict(score: number, noBlockingCritHigh: boolean): 'safe' | 'needs_review' {
  return score >= 81 && noBlockingCritHigh ? 'safe' : 'needs_review'
}

// ─── 0–100 Trust mark (dual-mark pivot 2026-08) ─────────────────────────────
// The product displays a 0–100 number + tier word, not an A–F letter. The tiers
// are the API's six (`trust_tier`: verified / trusted / standard / minimal /
// restricted / blocked, floors 96/81/51/31/11/0) — ONE table, byte-identical to
// `src/trust_tiers.py`; do not fork it. Trust owns the semantic green→red scale.
// The A–F helpers above are retained for legacy logic (verdict keying, SEO
// strings, the catalog's letter filter) — display surfaces use getTrustTier().

export type TrustTierValue = 'verified' | 'trusted' | 'standard' | 'minimal' | 'restricted' | 'blocked'
export type TrustTierName = 'Verified' | 'Trusted' | 'Standard' | 'Minimal' | 'Restricted' | 'Blocked'

export interface TrustTier {
  value: TrustTierValue  // the API's `trust_tier` value (lowercase)
  name: TrustTierName    // the display word
  min: number            // score floor
  color: string          // vivid — for bars/rings/needles on dark
  colorText: string      // darkened — for the number/word on light surfaces
  posture: string        // recommended execution posture
  requestsPerMinute: number | null   // null = unlimited
  maxTokensPerCall: number | null    // null = unlimited
  requireConfirmation: boolean
}

// No tier carries a phrase: the headline comes from DECISIONS / decide() below.
export const TRUST_TIERS: readonly TrustTier[] = [
  { value: 'verified',   name: 'Verified',   min: 96, color: '#16A34A', colorText: '#166534', posture: 'Connect normally · no limits',  requestsPerMinute: null, maxTokensPerCall: null, requireConfirmation: false },
  { value: 'trusted',    name: 'Trusted',    min: 81, color: '#22C55E', colorText: '#15803D', posture: 'Auto-approve within budget',    requestsPerMinute: 60,   maxTokensPerCall: 8192, requireConfirmation: false },
  { value: 'standard',   name: 'Standard',   min: 51, color: '#5BBF3A', colorText: '#3F7D1F', posture: 'Standard rate + token limits',  requestsPerMinute: 30,   maxTokensPerCall: 4096, requireConfirmation: false },
  { value: 'minimal',    name: 'Minimal',    min: 31, color: '#F59E0B', colorText: '#B45309', posture: 'Confirm on sensitive calls',    requestsPerMinute: 15,   maxTokensPerCall: 2048, requireConfirmation: true },
  { value: 'restricted', name: 'Restricted', min: 11, color: '#F97316', colorText: '#C2410C', posture: 'Gated · manual approval',       requestsPerMinute: 5,    maxTokensPerCall: 1024, requireConfirmation: true },
  { value: 'blocked',    name: 'Blocked',    min: 0,  color: '#EF4444', colorText: '#B91C1C', posture: 'Do not connect',                requestsPerMinute: 0,    maxTokensPerCall: 0,    requireConfirmation: true },
]

/** Map a 0–100 score to its Trust tier (API value, word, colour, posture, limits). */
export function getTrustTier(score: number): TrustTier {
  return TRUST_TIERS.find((t) => score >= t.min) ?? TRUST_TIERS[TRUST_TIERS.length - 1]
}

// ─── The three-phrase decision (LOCKED 2026-10-07) ──────────────────────────
// Every surface leads with one of three phrases plus the one reason that triggered
// it; the 0–100 score, the adoption score and the tier sit underneath as evidence.
// Certified is a separate axis that rides beside the phrase ("Safe to connect ·
// Certified"). Twin of DECISIONS / decide() in src/trust_tiers.py and
// src/scanner/verdict.py — tests/test_decision.py runs both on one table and requires
// byte-identical output. Prefer the API's own `decision` fields when present.

export type DecisionValue = 'safe' | 'review' | 'do_not_connect'

export interface DecisionPhrase {
  value: DecisionValue
  phrase: string     // the headline
  label: string      // the short label (badges, chips)
  color: string      // vivid — on dark grounds
  colorText: string  // darkened — on light grounds
}

export const DECISIONS: readonly DecisionPhrase[] = [
  { value: 'safe', phrase: 'Safe to connect', label: 'Safe', color: '#22C55E', colorText: '#15803D' },
  { value: 'review', phrase: 'Review before you connect', label: 'Review', color: '#F59E0B', colorText: '#B45309' },
  { value: 'do_not_connect', phrase: 'Do not connect', label: 'Blocked', color: '#EF4444', colorText: '#B91C1C' },
]

export const REVIEW_PHRASE = 'Review before you connect'
export const CERTIFIED_SUFFIX = ' · Certified'

export interface Decision {
  decision: DecisionValue
  final: boolean
  reason: string
}

export const REVIEW_SCORE_FLOOR = 51
export const THIN_COVERAGE_FILES = 8
export const PENDING_SUFFIX = '; sandbox still running'
/** Pending because every sandbox slot is busy (`behavioral.state === 'queued'`). */
export const QUEUED_SUFFIX = '; waiting for a sandbox slot'
export const THIN_REASON = 'nothing found; little code to inspect'
// A live MCP server scan reads the served tool definitions only (files = tools).
export const THIN_REASON_REMOTE_MCP = 'tool definitions clean; server code not inspected'

const BEHAVIORAL_LABELS: Record<string, string> = {
  behavioral_undeclared_egress: 'undeclared network call',
  ssrf_internal_fetch: 'fetched an internal network address',
  annotation_readonly_violated: 'a read-only tool wrote files',
  credential_canary_exfiltrated: 'a planted credential left the sandbox',
}

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)
const asObj = (v: unknown): Obj => (isObj(v) ? v : {})
const asList = (v: unknown): Obj[] => (Array.isArray(v) ? v.filter(isObj) : [])
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v)

function toInt(v: unknown): number {
  if (typeof v === 'boolean') return v ? 1 : 0
  if (typeof v === 'number') return Number.isFinite(v) ? Math.trunc(v) : 0
  if (typeof v === 'string') {
    const n = Number(v.trim())
    return v.trim() !== '' && Number.isFinite(n) ? Math.trunc(n) : 0
  }
  return 0
}

const isUpper = (c: string) => c !== c.toLowerCase()

function findingLabel(name: unknown): string {
  let s = String(name ?? '').split(/\s+/).filter(Boolean).join(' ')
  if (!s) return 'unnamed finding'
  if (s.length > 70) s = s.slice(0, 69).trimEnd() + '…'
  if (s.length > 1 && isUpper(s[0]) && !isUpper(s[1])) s = s[0].toLowerCase() + s.slice(1)
  return s
}

function stripMalPrefix(name: unknown): string {
  let s = String(name ?? '')
  if (s.toLowerCase().startsWith('known-malicious package:')) s = s.slice(s.indexOf(':') + 1)
  return s
}

// A live MCP server scan (coverage.surface or surface_detail.surface === 'mcp'): only the
// served tool definitions were read. A stdio MCP package from npm/PyPI is not this.
const isRemoteMcp = (data: Obj): boolean =>
  asObj(data.coverage).surface === 'mcp' || asObj(data.surface_detail).surface === 'mcp'

const isMaliciousItem = (i: Obj) => i.kind !== 'capability' && String(i.name ?? '').toLowerCase().includes('malicious')

function isBlockingItem(i: Obj): boolean {
  if (isMaliciousItem(i)) return true
  if (i.kind === 'capability' || i.installed === false) return false
  if (i.category === 'install_hook') return true
  if (i.category === 'dependency') return false
  return i.shipped !== false
}

function countPhrase(n: number, severity: string, label: string | null, where = ''): string {
  if (n === 1) return `one ${severity} finding${where}` + (label ? `: ${label}` : '')
  return `${n} ${severity} findings${where}` + (label ? `, including ${label}` : '')
}

// A vulnerable-dependency finding: counted in the totals, never a decision input (a
// known-malicious one is).
const isDependencyAdvisory = (i: Obj) =>
  i.category === 'dependency' && i.kind !== 'capability' && !isMaliciousItem(i)

/** [critical, high] dependency advisories as the totals count them: the larger of the
 * listed items and the scored supply-chain counts (the item list is capped). */
function dependencyCounts(data: Obj, items: Obj[]): [number, number] {
  const sevOf = (i: Obj) => String(i.severity ?? '').toLowerCase()
  let crit = items.filter((i) => isDependencyAdvisory(i) && sevOf(i) === 'critical').length
  let high = items.filter((i) => isDependencyAdvisory(i) && sevOf(i) === 'high').length
  const sc = asObj(data.supply_chain)
  if (sc.scored === true && isObj(sc.counts)) {
    crit = Math.max(crit, toInt(sc.counts.critical))
    high = Math.max(high, toInt(sc.counts.high))
  }
  return [crit, high]
}

function dependencyPhrase(crit: number, high: number): string {
  const parts: string[] = []
  if (crit > 0) parts.push(`${crit} critical`)
  if (high > 0) parts.push(`${high} high`)
  return parts.join(' and ')
}

/** The three-phrase decision for a scan result (API response JSON). Byte-identical twin
 * of `decide()` in src/scanner/verdict.py. Never throws. */
export function decide(input: unknown): Decision {
  const data = asObj(input)
  const score = toInt(data.trust_score)
  const findings = asObj(data.findings)
  const items = asList(findings.items)
  const meta = asObj(data.metadata)
  const files = isInt(meta.files_scanned) ? meta.files_scanned : 0

  const b = isObj(data.behavioral) ? data.behavioral : null
  const pending = !!(b && b.pending)
  const bLive = !!(b && b.ran && !b.pending && !(b.plan === 'live-probe' || b.advisory === true))
  const bFindings = bLive && b ? asList(b.findings) : []

  const suffix = !pending ? '' : (b && b.state === 'queued' ? QUEUED_SUFFIX : PENDING_SUFFIX)
  const done = (decision: DecisionValue, reason: string): Decision =>
    ({ decision, final: !pending, reason: reason + suffix })
  const sev = (i: Obj) => String(i.severity ?? '').toLowerCase()

  // Dependency advisories never decide, but the totals count them: a reason that counts
  // findings names them too. Wording only; nothing here changes the decision.
  const [depC, depH] = dependencyCounts(data, items)
  const deps = dependencyPhrase(depC, depH)
  const inCode = deps ? ' in its code' : ''
  const inSandbox = deps ? ' in the sandbox' : ''
  const plusDeps = deps ? `; plus ${deps} in dependencies` : ''

  // do_not_connect
  const canaryList = b ? b.canary_exfil : undefined
  const canary = bLive && ((Array.isArray(canaryList) ? canaryList.length > 0 : !!canaryList)
    || bFindings.some((f) => f.rule === 'credential_canary_exfiltrated'))
  if (canary) return done('do_not_connect', 'a planted credential left the sandbox')
  const inc = asObj(data.incident_history)
  if (inc.current_version_affected === true) {
    return done('do_not_connect', 'this version is listed as malicious (OpenSSF MAL advisory)')
  }
  const mal = items.find(isMaliciousItem)
  const scMal = asObj(data.supply_chain).malicious
  if (mal || (Array.isArray(scMal) && scMal.length > 0)) {
    const what = mal ? findingLabel(stripMalPrefix(mal.name)) : String((scMal as unknown[])[0])
    return done('do_not_connect', `a known-malicious dependency: ${what}`)
  }

  const isAdvisory = (i: Obj) => i.category === 'known_vulnerability' && i.kind !== 'capability'
  const defect = (severity: string): [number, Obj | undefined] => {
    let hits = items.filter((i) => sev(i) === severity && isBlockingItem(i) && !isAdvisory(i))
    const headline = findings[severity]
    let n: number
    if (isInt(headline)) {
      const adv = items.filter((i) => sev(i) === severity && isAdvisory(i)).length
      n = Math.max(headline - adv, 0)
    } else {
      n = hits.length
    }
    if (n && !hits.length) {
      hits = items.filter((i) => sev(i) === severity && i.kind !== 'capability'
        && i.installed !== false && !isAdvisory(i))
    }
    return [n, hits[0]]
  }

  const [nCrit, crit] = defect('critical')
  if (nCrit) return done('do_not_connect', countPhrase(nCrit, 'critical', crit ? findingLabel(crit.name) : null, inCode) + plusDeps)
  const bCrit = bFindings.filter((f) => sev(f) === 'critical')
  if (bCrit.length) {
    const f = bCrit[0]
    const label = BEHAVIORAL_LABELS[String(f.rule ?? '')] || findingLabel(f.name)
    return done('do_not_connect', `the sandbox caught a critical behavior: ${label}` + plusDeps)
  }

  // review
  const [nHigh, high] = defect('high')
  if (nHigh) return done('review', countPhrase(nHigh, 'high', high ? findingLabel(high.name) : null, inCode) + plusDeps)
  const bHigh = bFindings.filter((f) => sev(f) === 'high')
  if (bHigh.length) {
    const f = bHigh[0]
    const label = BEHAVIORAL_LABELS[String(f.rule ?? '')] || findingLabel(f.name)
    return done('review', countPhrase(bHigh.length, 'high', label, inSandbox) + plusDeps)
  }

  const rawAdv = Array.isArray(data.advisories) && data.advisories.length ? data.advisories : inc.advisories
  const advisories = asList(rawAdv).filter((a) => a.affects_scanned_version === true)
  if (Array.isArray(data.advisories_affecting_version)) advisories.push(...asList(data.advisories_affecting_version))
  const advItem = items.find(isAdvisory)
  if (advisories.length || advItem) {
    const aid = String((advisories.length ? advisories[0].id : '') || '')
    return done('review', 'a published advisory affects this version' + (aid ? ` (${aid})` : ''))
  }
  const dep = data.deprecation
  if (typeof dep === 'string' && dep.trim()) return done('review', 'the maintainer has deprecated this package')
  if (score < REVIEW_SCORE_FLOOR) return done('review', `trust score ${score}/100 is under ${REVIEW_SCORE_FLOOR}`)

  const found = items.some((i) => ['critical', 'high', 'medium'].includes(sev(i))
    && i.kind !== 'capability' && i.installed !== false)

  // safe — thin coverage (0 < files < 8, nothing found) reads Safe and says so in the
  // reason (decided 2026-10-08, #19); the 74 / 82 score cap still shows it.
  if (deps) {
    const noun = depC + depH === 1 ? 'advisory' : 'advisories'
    return done('safe', `no critical or high findings in its code (dependencies: ${deps} ${noun})`)
  }
  if (files > 0 && files < THIN_COVERAGE_FILES && !found) {
    return done('safe', isRemoteMcp(data) ? THIN_REASON_REMOTE_MCP : THIN_REASON)
  }
  let reason: string
  if (files > 0) {
    const n = files.toLocaleString('en-US')
    const unit = files === 1 ? 'file' : 'files'
    reason = found ? `no critical or high findings in ${n} ${unit}` : `nothing found in ${n} ${unit}`
  } else {
    reason = found ? 'no critical or high findings' : 'nothing found'
  }
  return done('safe', reason)
}

const DECISION_BY_VALUE = (v: unknown): DecisionPhrase | undefined => DECISIONS.find((d) => d.value === v)

/** The API's decision when the result carries one, else decided here (same rule). */
export function decisionOf(scan: unknown): Decision {
  const o = asObj(scan)
  if (DECISION_BY_VALUE(o.decision) && typeof o.decision_reason === 'string') {
    return { decision: o.decision as DecisionValue, final: o.decision_final !== false, reason: o.decision_reason }
  }
  return decide(o)
}

/** The phrase row (headline, short label, colours) for a decision value. */
export function decisionPhrase(value: DecisionValue | string | null | undefined): DecisionPhrase {
  return DECISION_BY_VALUE(value) ?? DECISIONS[1]
}

/** The one headline phrase for a scan (twin of `verdict_phrase` in src/trust_tiers.py).
 * Pass the scan result, or a decision value. A bare score decides from the score alone. */
export function verdictPhrase(scanOrDecision: unknown): string {
  if (typeof scanOrDecision === 'string' && DECISION_BY_VALUE(scanOrDecision)) return decisionPhrase(scanOrDecision).phrase
  if (typeof scanOrDecision === 'number') return decisionPhrase(decide({ trust_score: scanOrDecision }).decision).phrase
  return decisionPhrase(decisionOf(scanOrDecision).decision).phrase
}

/** Whether a scan carries the Certified mark (the full conjunctive gate). */
export function isCertified(scan: unknown): boolean {
  return asObj(asObj(scan).certified).eligible === true
}

/** "Safe to connect · Certified" — the phrase with the Certified mark when earned. */
export function headline(scan: unknown): string {
  return verdictPhrase(scan) + (isCertified(scan) ? CERTIFIED_SUFFIX : '')
}

/** Look a tier up by the API's `trust_tier` value; an unknown value falls back to the score. */
export function trustTierByValue(value: string | null | undefined, score: number): TrustTier {
  return TRUST_TIERS.find((t) => t.value === value) ?? getTrustTier(score)
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
