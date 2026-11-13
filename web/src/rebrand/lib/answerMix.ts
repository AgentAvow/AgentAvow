/**
 * How the catalog reads, live from the public API:
 *
 *   tools checked  = the sum of the three /public/scan-catalog?decision=… totals
 *   Certified      = /public/scan-catalog?grade=certified total
 *   x402           = summary.x402_scored (paid x402 endpoints, counted apart from tools)
 *
 * Numbers only (no rows), so the prerender ships it as is. Cached for an hour.
 */
import { useQuery } from '@tanstack/react-query'
import { fetchCatalog } from '../catalog'

export interface AnswerMix {
  safe: number
  review: number
  dnc: number
  certified: number
  /** tools checked: safe + review + dnc */
  total: number
  /** paid x402 endpoints checked: shown apart, never added to total */
  x402: number
}

async function fetchAnswerMix(): Promise<AnswerMix> {
  let x402 = 0
  const total = async (params: Record<string, string | number>) => {
    const data = await fetchCatalog({ ...params, limit: 1 })
    if (typeof data.total !== 'number') throw new Error('catalog total missing')
    const s = data.summary
    x402 = Math.max(x402, s?.x402_scored || s?.x402_endpoints_total || 0)
    return data.total
  }
  const [safe, review, dnc, certified] = await Promise.all([
    total({ decision: 'safe' }),
    total({ decision: 'review' }),
    total({ decision: 'do_not_connect' }),
    total({ grade: 'certified' }),
  ])
  return { safe, review, dnc, certified, total: safe + review + dnc, x402 }
}

export function useAnswerMix() {
  return useQuery({ queryKey: ['answer-mix'], queryFn: fetchAnswerMix, staleTime: 60 * 60_000 })
}

/** Every tool that reads Do not connect, across every surface. */
export const DNC_LIST = '/rebrand/browse?surface=all&dec=do_not_connect'
