/**
 * Typed client for the public (no-auth) scan API. One place that knows every
 * scan endpoint + response shape, replacing the ad-hoc `publicApi` instances that
 * were re-declared in Check / Scans / ScanHistoryPanel (which is how new response
 * fields kept getting missed).
 */
import axios from 'axios'
import type { PublicScanResponse, WalletScanResponse } from '../types/scan'

export const publicApi = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api/v1',
  headers: { 'Content-Type': 'application/json' },
  timeout: 30_000, // scans can take a while
})

const apiBase = import.meta.env.VITE_API_BASE_URL || '/api/v1'

export async function fetchPublicScan(
  owner: string,
  repo: string,
  force = false,
): Promise<PublicScanResponse> {
  const { data } = await publicApi.get<PublicScanResponse>(
    `/public/scan/${owner}/${repo}${force ? '?force=true' : ''}`,
  )
  return data
}

/** Deep scan: also run the behavioral sandbox tier (~45s). Returns the same
 * response with a `behavioral` block attached (egress/fs/exit observed by
 * running the tool's package in isolation). Never affects the signed score. */
export async function fetchBehavioralScan(
  owner: string,
  repo: string,
): Promise<PublicScanResponse> {
  const { data } = await publicApi.get<PublicScanResponse>(
    `/public/scan/${owner}/${repo}?behavioral=true`,
    { timeout: 150_000 },
  )
  return data
}

/** Scan a PUBLISHED npm/PyPI package by coordinate (no GitHub repo). `name` may
 * be a scoped package (@scope/pkg) — the slash is preserved in the path. */
export async function fetchPackageScan(
  surface: string,
  name: string,
  force = false,
): Promise<PublicScanResponse> {
  const { data } = await publicApi.get<PublicScanResponse>(
    `/public/scan/package/${surface}/${name}${force ? '?force=true' : ''}`,
  )
  return data
}

/** Grade an OpenClaw / Agent Skill in a GitHub repo. */
export async function fetchSkillScan(owner: string, repo: string, force = false): Promise<PublicScanResponse> {
  const { data } = await publicApi.get<PublicScanResponse>(
    `/public/scan/skill/${owner}/${repo}${force ? '?force=true' : ''}`,
  )
  return data
}

/** Grade a LIVE MCP server by its Streamable-HTTP endpoint URL. */
export async function fetchMcpScan(endpoint: string, force = false): Promise<PublicScanResponse> {
  const { data } = await publicApi.get<PublicScanResponse>(
    `/public/scan/mcp?endpoint=${encodeURIComponent(endpoint)}${force ? '&force=true' : ''}`,
  )
  return data
}

export async function fetchWalletScan(
  wallet: string,
  chain = 'ethereum',
): Promise<WalletScanResponse> {
  const { data } = await publicApi.get<WalletScanResponse>(
    `/public/scan/wallet/${wallet}?chain=${chain}`,
  )
  return data
}

export interface ScanHistoryResponse {
  repo: string
  entity_id: string | null
  score_timeline: { recorded_at: string; score: number }[]
  framework_scans: {
    framework: string
    scan_result: string
    scanned_at: string
    vulnerabilities_count: number
  }[]
  jws?: string | null
}

export async function fetchScanHistory(
  owner: string,
  repo: string,
): Promise<ScanHistoryResponse> {
  const { data } = await publicApi.get<ScanHistoryResponse>(
    `/public/scan/${owner}/${repo}/history`,
  )
  return data
}

/** Absolute URL to the trust badge SVG (for README embeds / img src). */
export function badgeUrl(owner: string, repo: string): string {
  return `${window.location.origin}${apiBase}/public/scan/${owner}/${repo}/badge`
}
