/** Text helpers for watch-alert notifications: the score change and the three-phrase
 * answer an alert's body carries, and the tool it is about. */
import { DECISIONS, type DecisionPhrase } from '../../components/trust/gradeSystem'
import type { RowArt } from '../components/AccountBits'
import { referenceLink } from './toolLinks'

export interface Notif {
  id: string; kind: string; title: string; body: string
  reference_id: string | null; is_read: boolean; created_at: string
  /** Watch alerts: the tool's current answer, scores and adoption (additive, 11-11). */
  tool?: (RowArt & { surface: string }) | null
}

export function parseScores(body: string): { from: number; to: number } | null {
  const m = body.match(/(\d{1,3})\s*(?:->|→|to)\s*(\d{1,3})/)
  if (!m) return null
  const from = +m[1], to = +m[2]
  if (from > 100 || to > 100) return null
  return { from, to }
}

/** Drop the "(94 -> 63)" parenthetical from the sentence when we also render the
 * score chip — so the numbers show once, in the chip. */
export function stripScores(body: string): string {
  return body
    .replace(/\s*\(\s*\d{1,3}\s*(?:->|→|to)\s*\d{1,3}(?:\s*\/\s*100)?\s*\)/g, '')
    .replace(/\s+([.,])/g, '$1')
    .replace(/\s{2,}/g, ' ')
    .trim()
}

export const ago = (iso: string) => {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 3600) return `${Math.max(1, Math.floor(s / 60))} min`
  if (s < 86400) return `${Math.floor(s / 3600)} h`
  return `${Math.floor(s / 86400)} d`
}

/** The three-phrase headline a watch alert carries ("Now: Review before you connect
 * (one high finding: …)."), so the row can lead with it in its colour. */
export function parsePhrase(body: string): { phrase: DecisionPhrase; reason: string } | null {
  for (const p of DECISIONS) {
    const i = body.indexOf(p.phrase)
    if (i >= 0) {
      const m = body.slice(i + p.phrase.length).match(/^(?: · Certified)?\s*\(([^)]*)\)/)
      return { phrase: p, reason: m ? m[1] : '' }
    }
  }
  return null
}

/** Drop the "Now: <phrase> (<reason>)." clause from the sentence when the row shows it. */
export function stripPhrase(body: string): string {
  return body.replace(/\s*Now: [^.]*\)\.?/, '').trim()
}

/** The tool an alert is about: label, chip and report route. */
export function notifTool(n: Notif) {
  return n.reference_id ? referenceLink(n.reference_id, n.tool?.surface) : null
}

