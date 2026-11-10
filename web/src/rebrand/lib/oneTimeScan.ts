/**
 * Hand-off for a one-time private scan (My Tools → the score page).
 *
 * The result is held in this module's memory only, keyed by a random id. The router
 * state carries just that id, never the scan itself and never the GitHub token. So
 * nothing about a one-time scan lands in history.state, the URL, localStorage or
 * logs, and a reload drops it: "Nothing is stored" holds in the browser too.
 */
const held = new Map<string, unknown>()
const MAX_HELD = 5

export interface OneTimeScanState { oneTimeScan: string }

/** Keep a one-time result in memory and return the router state that points to it. */
export function holdOneTimeScan(result: unknown): OneTimeScanState {
  const id = typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).slice(2)}`
  held.set(id, result)
  // Keep only the last few, so back/forward between recent scans works without growing.
  while (held.size > MAX_HELD) held.delete(held.keys().next().value as string)
  return { oneTimeScan: id }
}

/** The held result for this router state, if this tab still has it in memory. */
export function oneTimeScanFor<T>(state: unknown): T | undefined {
  const id = (state as Partial<OneTimeScanState> | null)?.oneTimeScan
  return typeof id === 'string' ? (held.get(id) as T | undefined) : undefined
}
