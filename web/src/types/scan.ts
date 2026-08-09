/**
 * Shared types for the public scan API (GET /public/scan/{owner}/{repo}).
 * Mirrors PublicScanResponse in src/api/public_scan_router.py. Every consumer
 * should import these instead of re-declaring partial local interfaces.
 */

export interface ScanFindingItem {
  category: string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | string
  file_path: string
  line_number: number
  remediation?: string
}

export interface FindingsSummary {
  critical: number
  high: number
  medium: number
  total: number
  categories: Record<string, number>
  suppressed_lines: number
  items: ScanFindingItem[]
}

export interface RecommendedLimits {
  requests_per_minute: number | null
  max_tokens_per_call: number | null
  require_user_confirmation: boolean
}

export interface ScanMetadata {
  files_scanned: number
  primary_language: string
  has_readme: boolean
  has_license: boolean
  has_tests: boolean
  is_mcp_server: boolean
}

export interface CategoryScores {
  secret_hygiene: number
  code_safety: number
  data_handling: number
  filesystem_access: number
  dependency_health: number
}

/** #8 tool-definition drift diff vs the previous scan (rug-pull signal). */
export interface ToolDrift {
  drift_detected: boolean
  changed: string[]
  added: string[]
  removed: string[]
  previous_manifest_digest?: string | null
  previous_scanned_at?: string | null
}

export interface PublicScanResponse {
  repo: string
  trust_score: number
  security_score: number
  trust_tier: string
  recommended_limits: RecommendedLimits
  scan_result: string
  findings: FindingsSummary
  positive_signals: string[]
  // Letter grade with the A+ "Certified" gate applied (roadmap §7). May be absent
  // on older cached responses — fall back to deriving from trust_score.
  grade?: string
  // A+ certified-tier eligibility: { eligible, checks: {check_name: bool} }.
  certified?: { eligible?: boolean; checks?: Record<string, boolean> }
  // Recompute-discipline coverage: scan_depth / provenance_binding / db_snapshots.
  coverage?: { scan_depth?: string; provenance_binding?: string; [k: string]: unknown }
  provenance?: { verified?: boolean; source_matches_claim?: boolean; [k: string]: unknown }
  category_scores: Partial<CategoryScores>
  metadata: ScanMetadata
  scanned_at: string
  cached: boolean
  // #8 tool-definition pinning — signed into the JWS `scan` block
  tool_manifest_digest?: string | null
  tool_digests?: Record<string, string>
  tool_drift?: ToolDrift | null
  jws: string
  algorithm: string
  key_id: string
  jwks_url: string
  entity_trust?: Record<string, unknown> | null
  trust_envelope?: unknown
}

export interface WalletScanResponse {
  found: boolean
  wallet: string
  chain: string
  entity_id?: string | null
  reason?: string
  scan?: PublicScanResponse
}
