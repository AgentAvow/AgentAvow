/**
 * Public behavioral-sandbox stats (GET /public/sandbox-stats): aggregate counts only,
 * never a package name. Shared by Home, How it works and the Index so all three read
 * the same cached query. `null` means "hide the block": the request failed or the
 * sandbox has not run anything yet.
 */
import { useQuery } from '@tanstack/react-query'
import { publicApi } from '../../lib/scanApi'

export interface SandboxStats {
  generated_at?: string
  totals: { runs: number; exercised: number; tools_called: number; findings: number; canary_leaks: number }
  last_30_days: {
    runs: number
    exercised: number
    runs_with_findings: number
    findings: number
    findings_by_rule: Record<string, number>
  }
}

export const SANDBOX_RULE_LABEL: Record<string, string> = {
  behavioral_undeclared_egress: 'Contacted an undeclared host',
  annotation_readonly_violated: 'Read-only tool wrote files',
  annotation_open_world_violated: 'Closed-world server reached the network',
  credential_canary_exfiltrated: 'Canary credential sent off the machine',
  canary_echoed_in_result: 'Tool returned a secret in its output',
  tool_call_crashed_server: 'Tool call crashed the server',
}

async function fetchSandboxStats(): Promise<SandboxStats | null> {
  try {
    const { data } = await publicApi.get<SandboxStats>('/public/sandbox-stats')
    if (!data?.totals || !(data.totals.runs > 0)) return null
    return data
  } catch {
    return null
  }
}

export function useSandboxStats() {
  return useQuery({ queryKey: ['sandbox-stats'], queryFn: fetchSandboxStats, staleTime: 5 * 60_000 })
}
