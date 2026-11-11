/** ERC-8004 agents on the check page: `erc8004:base:1234` → its chain + agent id.
 *
 * The chains are the ones GET /api/v1/public/scan/erc8004/{chain}/{agent_id} reads
 * (src/scanner/erc8004_agent.py CHAINS). A few common aliases map onto them. */

export const ERC8004_CHAINS: Record<string, string> = {
  ethereum: 'Ethereum',
  base: 'Base',
  bnb: 'BNB Chain',
}

const ALIASES: Record<string, string> = {
  ethereum: 'ethereum', eth: 'ethereum', mainnet: 'ethereum',
  base: 'base',
  bnb: 'bnb', bsc: 'bnb', bnbchain: 'bnb',
}

/** `erc8004:<chain>:<id>` (also `erc-8004`, spaces or `/` between parts) → the API's
 * chain key and agent id; null when it isn't one, or names a chain we don't read. */
export function parseErc8004(input: string): { chain: string; agentId: string } | null {
  const m = input.trim().match(/^erc-?8004\s*[:/\s]\s*([a-z-]+)\s*[:/\s]\s*#?(\d{1,20})$/i)
  if (!m) return null
  const chain = ALIASES[m[1].toLowerCase().replace(/-/g, '')]
  if (!chain) return null
  return { chain, agentId: m[2].replace(/^0+(?=\d)/, '') }
}

/** True for `erc8004:…` input, so a wrong chain gets a notice instead of a repo scan. */
export function looksLikeErc8004(input: string): boolean {
  return /^erc-?8004\b/i.test(input.trim())
}
