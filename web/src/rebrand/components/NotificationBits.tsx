/** Shared notification UI, used by the header bell dropdown and the Notifications tab.
 * Shows tool-safety kinds only (not the old social-era firehose). Each alert is an
 * account row: the tool, what changed, and the same artwork as a Browse row (trust or
 * Certified mini + adoption gauge), from the API's `tool` field. */
import { Link } from 'react-router-dom'

import { getTrustTier } from '../../components/trust/gradeSystem'
import { ago, notifTool, parsePhrase, parseScores, stripPhrase, stripScores, type Notif } from '../lib/notifText'
import { AccRow, ToolArt, rowAct } from './AccountBits'

export type { Notif }


/** Compact before→after score, coloured by tier. */
export function ScoreChange({ from, to }: { from: number; to: number }) {
  const down = to < from
  const cTo = getTrustTier(to).color
  const cFrom = getTrustTier(from).color
  return (
    <span className="inline-flex items-center gap-1 font-mono text-[12px] tabular-nums rounded-md bg-surface/70 border border-border/60 px-1.5 py-px align-middle">
      <span style={{ color: cFrom }}>{from}</span>
      <span className={down ? 'text-danger' : 'text-success'} aria-hidden>{down ? '▼' : '▲'}</span>
      <span className="font-bold" style={{ color: cTo }}>{to}</span>
    </span>
  )
}

/** What changed, in one line: the phrase in its colour, the score change, the sentence. */
function Summary({ n, clamp }: { n: Notif; clamp?: boolean }) {
  const scores = parseScores(n.body)
  const phrase = parsePhrase(n.body)
  const sentence = (() => { const b = phrase ? stripPhrase(n.body) : n.body; return scores ? stripScores(b) : b })()
  return (
    <span className={clamp ? 'line-clamp-2' : ''}>
      {phrase && <b className="font-semibold" style={{ color: phrase.phrase.color }} data-decision={phrase.phrase.value}>{phrase.phrase.phrase}</b>}
      {phrase && (scores || sentence) && ' · '}
      {scores && <><ScoreChange from={scores.from} to={scores.to} />{' '}</>}
      {sentence}
      {' · '}{ago(n.created_at)} ago
    </span>
  )
}

const tone = (n: Notif) => {
  const kind = n.kind === 'watch_good_news' ? 'good' : 'alert'
  return (n.is_read ? kind : `${kind}-unread`) as 'alert' | 'good' | 'alert-unread' | 'good-unread'
}

/** One alert on the Notifications tab and in Watches & alerts' recent alerts. */
export function NotifRow({ n, onRead, onDelete, onNavigate }: {
  n: Notif
  onRead: (id: string) => void; onDelete: (id: string) => void; onNavigate?: () => void
}) {
  const t = notifTool(n)
  return (
    <AccRow
      name={t?.label ?? n.title}
      chip={t?.badge}
      tone={tone(n)}
      sub={<Summary n={n} />}
      art={n.tool ? <ToolArt row={n.tool} /> : undefined}
      actions={<>
        {t && <Link to={t.href} onClick={() => { if (!n.is_read) onRead(n.id); onNavigate?.() }} className={rowAct}>Re-check</Link>}
        {!n.is_read && <button type="button" onClick={() => onRead(n.id)} className={rowAct}>Mark read</button>}
        <button type="button" onClick={() => onDelete(n.id)} className={`${rowAct} hover:!text-danger hover:!border-danger/50`}>Delete</button>
      </>}
    />
  )
}

/** The bell's compact row: the whole row opens the tool's report and marks it read. */
export function BellRow({ n, onOpen }: { n: Notif; onOpen: (n: Notif) => void }) {
  const t = notifTool(n)
  const body = (
    <AccRow name={t?.label ?? n.title} tone={tone(n)} sub={<Summary n={n} clamp />}
      art={n.tool ? <ToolArt row={n.tool} /> : undefined} />
  )
  return t
    ? <Link to={t.href} onClick={() => onOpen(n)} className="block hover:bg-surface-hover/50 transition-colors">{body}</Link>
    : <div>{body}</div>
}
