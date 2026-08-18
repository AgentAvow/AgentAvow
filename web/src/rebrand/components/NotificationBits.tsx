/** Shared notification UI — used by the header bell dropdown AND the full page.
 * Filters to tool-safety kinds (not the old social-era firehose) and gives watch
 * alerts a compact before→after score visual, echoing the score-page trend UX. */
import { Link } from 'react-router-dom'

import { getTrustTier } from '../../components/trust/gradeSystem'
import { rp } from '../basePath'

export interface Notif {
  id: string; kind: string; title: string; body: string
  reference_id: string | null; is_read: boolean; created_at: string
}

// Only tool-safety notifications belong in the rebrand — the account also holds the
// user's old social-era notifications (follow/reply/vote/…), which are the "thousands".
export const RELEVANT_KINDS = new Set(['watch_alert', 'watch_good_news'])

export const isRelevant = (n: Notif) => RELEVANT_KINDS.has(n.kind)

export function parseScores(body: string): { from: number; to: number } | null {
  const m = body.match(/(\d{1,3})\s*(?:->|→|to)\s*(\d{1,3})/)
  if (!m) return null
  const from = +m[1], to = +m[2]
  if (from > 100 || to > 100) return null
  return { from, to }
}

/** Drop the "(94 -> 63)" parenthetical from the sentence when we also render the
 * score chip — so the numbers show once, in the chip, and the sentence keeps the
 * context ("…score dropped. Review it before your agents keep using it."). */
export function stripScores(body: string): string {
  return body
    .replace(/\s*\(\s*\d{1,3}\s*(?:->|→|to)\s*\d{1,3}(?:\s*\/\s*100)?\s*\)/g, '')
    .replace(/\s+([.,])/g, '$1')
    .replace(/\s{2,}/g, ' ')
    .trim()
}

export const ago = (iso: string) => {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 3600) return `${Math.max(1, Math.floor(s / 60))}m`
  if (s < 86400) return `${Math.floor(s / 3600)}h`
  return `${Math.floor(s / 86400)}d`
}

/** Compact before→after score, colored by tier — the score-page trend UX, notification-sized. */
export function ScoreChange({ from, to }: { from: number; to: number }) {
  const down = to < from
  const cTo = getTrustTier(to).color
  const cFrom = getTrustTier(from).color
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-[13px] tabular-nums rounded-lg bg-surface/70 border border-border/60 px-2 py-1">
      <span style={{ color: cFrom }}>{from}</span>
      <span className={down ? 'text-danger' : 'text-success'} aria-hidden>{down ? '▼' : '▲'}</span>
      <span className="font-bold text-[14px]" style={{ color: cTo }}>{to}</span>
      <span className={`text-[11px] font-semibold ${down ? 'text-danger' : 'text-success'}`}>{down ? '' : '+'}{to - from}</span>
    </span>
  )
}

/** One notification row (used in the dropdown and the full page). */
export function NotifRow({ n, compact, onRead, onDelete, onNavigate }: {
  n: Notif; compact?: boolean
  onRead: (id: string) => void; onDelete: (id: string) => void; onNavigate?: () => void
}) {
  const scores = parseScores(n.body)
  const good = n.kind === 'watch_good_news'
  return (
    <div className={`glass rounded-xl px-3.5 py-3 border-l-4 ${n.is_read ? 'border-border/50' : good ? 'border-success' : 'border-warning'}`}>
      <div className="flex items-center gap-2 flex-wrap">
        {!n.is_read && <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${good ? 'bg-success' : 'bg-warning'}`} />}
        <span className="text-[13.5px] font-semibold min-w-0 truncate">{n.title}</span>
        <span className="text-[11px] text-text-muted/70 ml-auto shrink-0">{ago(n.created_at)} ago</span>
      </div>
      <div className="mt-1.5 flex flex-col gap-1.5">
        {scores && <ScoreChange from={scores.from} to={scores.to} />}
        <p className={`text-[12.5px] leading-snug text-text-muted ${compact ? 'line-clamp-2' : ''}`}>
          {scores ? stripScores(n.body) : n.body}
        </p>
      </div>
      <div className="mt-2 flex gap-3 text-[12px] font-semibold">
        {n.reference_id && <Link to={rp(`/rebrand/check/${n.reference_id}`)} onClick={onNavigate} className="text-primary-light hover:text-primary">Re-check →</Link>}
        {!n.is_read && <button onClick={() => onRead(n.id)} className="text-text-muted hover:text-text">Mark read</button>}
        <button onClick={() => onDelete(n.id)} className="text-text-muted hover:text-danger">Delete</button>
      </div>
    </div>
  )
}
