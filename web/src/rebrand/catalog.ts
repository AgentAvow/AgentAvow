import { publicApi } from '../lib/scanApi'

/**
 * Minimal typed access to the public scan catalog for the /rebrand pages.
 * (Scans.tsx keeps its own private CatalogResponse interface; we define our own
 * slim shape here so the rebrand sandbox stays self-contained.)
 */

export interface CatalogSummary {
  total_scans: number
  by_surface: Record<string, number>
  by_surface_critical?: Record<string, number>
  by_surface_high?: Record<string, number>
  repo_scans_total?: number
}

export interface CatalogRow {
  surface: string
  name: string
  full_name: string | null
  repository_url: string | null
  endpoint_url?: string | null
  trust_score: number | null
  critical: number | null
  high: number | null
  findings_count: number | null
  is_mcp_server?: boolean | null
}

export interface CatalogResponse {
  summary: CatalogSummary
  rows: CatalogRow[]
}

export async function fetchCatalog(
  params: Record<string, string | number> = {},
): Promise<CatalogResponse> {
  const { data } = await publicApi.get<CatalogResponse>('/public/scan-catalog', { params })
  return data
}

/** surface value → human label used in the UI. */
export const SURFACE_LABEL: Record<string, string> = {
  mcp: 'MCP servers',
  npm: 'npm packages',
  pypi: 'Python packages',
  openclaw: 'Agent skills',
  x402: 'x402 endpoints',
}

/** A display name + a repo path (owner/repo) if this row is a scannable repo. */
export function rowIdentity(row: CatalogRow): { display: string; repoPath: string | null } {
  const display = row.full_name || row.name || row.endpoint_url || 'unknown'
  const repoPath = row.full_name && row.full_name.includes('/') ? row.full_name : null
  return { display, repoPath }
}
