/** Small shared pieces for the signed-in pages (My Tools, My watches, Settings,
 * Notifications): the loading skeleton, a load-error card, and an
 * in-page confirm for destructive actions. */
import { useState, type ReactNode } from 'react'

/** What an account page shows while we find out who is signed in (instead of a blank page). */
export function AccountSkeleton({ width = 'max-w-[860px]' }: { width?: string }) {
  return (
    <div className={`${width} mx-auto px-6 py-14`} aria-busy="true" aria-label="Loading">
      <div className="h-3 w-24 rounded bg-surface-hover animate-pulse" />
      <div className="mt-3 h-8 w-64 max-w-full rounded bg-surface-hover animate-pulse" />
      <div className="mt-3 h-4 w-full max-w-[520px] rounded bg-surface-hover animate-pulse" />
      <div className="mt-10 flex flex-col gap-2.5">
        {[0, 1, 2].map((i) => <div key={i} className="glass rounded-xl h-[64px] animate-pulse" />)}
      </div>
    </div>
  )
}

/** A list that failed to load says so, so an outage never reads as "nothing here". */
export function LoadError({ what, onRetry, retrying = false }: { what: string; onRetry: () => void; retrying?: boolean }) {
  return (
    <div className="glass rounded-xl p-4 flex items-center justify-between gap-3 flex-wrap border border-danger/30" role="alert">
      <span className="text-[13px] text-text-muted">Couldn&apos;t load {what}. Check your connection and try again.</span>
      <button type="button" onClick={onRetry} disabled={retrying}
        className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg border border-border text-text hover:border-primary-light hover:text-primary-light disabled:opacity-60">
        {retrying ? 'Retrying…' : 'Try again'}
      </button>
    </div>
  )
}

/**
 * A destructive action that asks first, in place: the button turns into
 * "<question> [confirm] [Cancel]". No window.confirm.
 */
export function ConfirmAction({ label, question, confirmLabel, onConfirm, pending = false, pendingLabel, className }: {
  label: ReactNode
  question: string
  confirmLabel: string
  onConfirm: () => void
  pending?: boolean
  pendingLabel?: string
  className?: string
}) {
  const [asking, setAsking] = useState(false)
  if (pending) return <span className="text-[12px] text-text-muted">{pendingLabel ?? '…'}</span>
  if (!asking) {
    return (
      <button type="button" onClick={() => setAsking(true)} className={className ?? 'text-[12px] text-text-muted hover:text-danger transition-colors'}>
        {label}
      </button>
    )
  }
  return (
    <span className="inline-flex items-center gap-2 flex-wrap text-[12px]" role="group" aria-label={question}>
      <span className="text-text-muted">{question}</span>
      <button type="button" autoFocus onClick={() => { setAsking(false); onConfirm() }}
        className="font-semibold px-2.5 py-1 rounded-lg text-danger border border-danger/40 hover:bg-danger/10">
        {confirmLabel}
      </button>
      <button type="button" onClick={() => setAsking(false)} className="text-text-muted hover:text-text">Cancel</button>
    </span>
  )
}
