import { publicApi } from '../lib/scanApi'

/**
 * Minimal typed access to the public scan catalog for the /rebrand pages.
 * (Scans.tsx keeps its own private CatalogResponse interface; we define our own
 * slim shape here so the rebrand sandbox stays self-contained.)
 */

export interface CatalogSummary {
  total_scans: number
  by_surface: Record<string, number>
  by_category?: Record<string, number>
  by_surface_critical?: Record<string, number>
  by_surface_high?: Record<string, number>
  repo_scans_total?: number
  x402_endpoints_total?: number
  x402_compliant?: number
}

export interface CatalogRow {
  surface: string
  name: string
  full_name: string | null
  repository_url: string | null
  endpoint_url?: string | null
  trust_score: number | null
  grade?: string | null  // letter grade WITH the A+ certified gate (roadmap §7)
  critical: number | null
  high: number | null
  findings_count: number | null
  is_mcp_server?: boolean | null
  primary_language?: string | null
  category?: string | null
  adoption_score?: number | null
  adoption_count?: number | null
  adoption_unit?: string | null
  scan_error?: string | null
  skipped?: string | null
  has_x402_header?: boolean | null
  http_status?: number | null
}

export interface CatalogResponse {
  summary: CatalogSummary
  rows: CatalogRow[]
  total?: number
  offset?: number
  limit?: number
}

export async function fetchCatalog(
  params: Record<string, string | number> = {},
): Promise<CatalogResponse> {
  // Prune empty/undefined values — the API 422s on an empty `severity=` (not a
  // valid enum) and treats empty `q=` as a no-match filter. Only send real ones.
  const clean: Record<string, string | number> = {}
  for (const [k, v] of Object.entries(params)) {
    if (v === '' || v == null) continue
    clean[k] = v
  }
  const { data } = await publicApi.get<CatalogResponse>('/public/scan-catalog', { params: clean })
  return data
}

/** surface value → human label used in the UI. */
export const SURFACE_LABEL: Record<string, string> = {
  mcp: 'MCP servers',
  npm: 'npm packages',
  pypi: 'Python packages',
  crates: 'Rust crates',
  huggingface: 'Hugging Face models',
  docker: 'Container images',
  openclaw: 'Agent skills',
  x402: 'x402 endpoints',
}

/** A display name + a repo path (owner/repo) if this row is a scannable repo. */
export function rowIdentity(row: CatalogRow): { display: string; repoPath: string | null } {
  const display = row.full_name || row.name || row.endpoint_url || 'unknown'
  const repoPath = row.full_name && row.full_name.includes('/') ? row.full_name : null
  return { display, repoPath }
}
