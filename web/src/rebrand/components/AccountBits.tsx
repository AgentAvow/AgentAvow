/** Shared pieces for the signed-in pages (My Tools, Watches & alerts, Notifications,
 * Settings): the one account shell (header + tabs at 720px, approved mock "Account
 * v2", 2026-11-10), list sections with their loading, empty and error states, the
 * Browse-style row artwork, and an in-page confirm for destructive actions. */
import { Suspense, useEffect, useState, type ReactNode } from 'react'
import { Link, Outlet, useLocation } from 'react-router-dom'
import { rp } from '../basePath'
import SEOHead from '../../components/SEOHead'
import { useAuth } from '../../hooks/useAuth'
import { decisionOf, decisionPhrase } from '../../components/trust/gradeSystem'
import { useRequireUser } from '../lib/useRequireUser'
import { AdoptionMini, TrustOrCertifiedMini } from './TrustMark'
import { useUnreadAlertCount } from '../lib/useUnreadAlerts'
import { ACCOUNT_TABS, accountTabFor, type AccountTab } from '../lib/accountRoutes'

/** What an account page shows while we find out who is signed in (instead of a blank page). */
export function AccountSkeleton({ width = 'max-w-[720px]' }: { width?: string }) {
  return (
    <div className={`${width} mx-auto px-6 pt-9 pb-16`} aria-busy="true" aria-label="Loading">
      <div className="h-3 w-24 rounded bg-surface-hover animate-pulse" />
      <div className="mt-3 h-8 w-64 max-w-full rounded bg-surface-hover animate-pulse" />
      <div className="mt-3 h-4 w-full max-w-[520px] rounded bg-surface-hover animate-pulse" />
      <div className="mt-6 h-9 w-full rounded bg-surface-hover/60 animate-pulse" />
      <div className="mt-6"><SkeletonRows n={3} /></div>
    </div>
  )
}

/** Loading state for a list: a few grey rows in the list frame. */
export function SkeletonRows({ n = 3 }: { n?: number }) {
  return (
    <div className="rounded-[14px] border border-border/60 overflow-hidden" aria-busy="true" aria-label="Loading">
      {Array.from({ length: n }).map((_, i) => (
        <div key={i} className={`h-[58px] bg-surface-hover/60 animate-pulse ${i ? 'border-t border-border/60' : ''}`} />
      ))}
    </div>
  )
}

/** A list that failed to load says so, so an outage never reads as "nothing here". */
export function LoadError({ what, note, onRetry, retrying = false }: {
  what: string; note?: string; onRetry: () => void; retrying?: boolean
}) {
  return (
    <div className="rounded-[14px] px-[18px] py-4 flex items-center justify-between gap-3 flex-wrap border-[1.5px] border-danger/45 bg-danger/[.07] text-[14px]" role="alert">
      <span><b>Couldn&apos;t load {what}.</b> <span className="text-text-muted">{note ?? 'Check your connection and try again.'}</span></span>
      <button type="button" onClick={onRetry} disabled={retrying}
        className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg border border-border text-text hover:border-primary-light hover:text-primary-light disabled:opacity-60">
        {retrying ? 'Retrying…' : 'Try again'}
      </button>
    </div>
  )
}

/** An empty list: one glass card, one sentence, one action. */
export function EmptyCard({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  return (
    <div className="glass rounded-[14px] border border-border/60 px-5 py-[26px] text-center">
      <b className="text-[15px]">{title}</b>
      <p className="text-text-muted text-[14px] mt-1.5 mb-3.5 mx-auto max-w-[44ch]">{children}</p>
      {action}
    </div>
  )
}

export const btnSm = 'inline-flex items-center text-[13px] font-semibold px-3.5 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60'
export const btnGhostSm = 'inline-flex items-center text-[13px] font-semibold px-3.5 py-1.5 rounded-lg border border-border text-text hover:border-primary-light hover:text-primary-light disabled:opacity-60'
/** Small row action (link or button) in the mock's outlined style. */
export const rowAct = 'text-[12.5px] border border-border rounded-lg px-2.5 py-1 bg-surface text-text hover:border-primary-light hover:text-primary-light disabled:opacity-60'

/** One section of an account page: the mono uppercase label, then its content. */
export function AccSection({ title, right, id, children }: { title: ReactNode; right?: ReactNode; id?: string; children: ReactNode }) {
  return (
    <section className="mt-[22px] scroll-mt-24" id={id}>
      <div className="flex items-baseline justify-between gap-3 mb-2.5">
        <h2 className="font-mono text-[13px] uppercase tracking-[.05em] text-text-muted font-semibold">{title}</h2>
        {right}
      </div>
      {children}
    </section>
  )
}

/** The list frame rows sit in. */
export function AccList({ children }: { children: ReactNode }) {
  return <div className="rounded-[14px] border border-border/60 overflow-hidden glass divide-y divide-border/60">{children}</div>
}

/** One account row: who (name + one small line), optional chip, the artwork, actions. */
export function AccRow({ name, sub, chip, art, actions, tone, children }: {
  name: ReactNode; sub?: ReactNode; chip?: string; art?: ReactNode; actions?: ReactNode
  tone?: 'alert' | 'good' | 'alert-unread' | 'good-unread'; children?: ReactNode
}) {
  const border = tone?.startsWith('alert') ? 'border-l-[3px] border-l-danger' : tone?.startsWith('good') ? 'border-l-[3px] border-l-success' : ''
  const unread = tone?.endsWith('unread') ? 'bg-primary/[.05]' : ''
  return (
    <div className={`px-4 py-3 ${border} ${unread}`}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <div className="flex-[1_1_220px] min-w-0 flex flex-col gap-0.5">
          <b className="font-mono text-[13.5px] font-semibold [overflow-wrap:anywhere]">{name}</b>
          {sub && <small className="text-text-muted text-[12.5px]">{sub}</small>}
        </div>
        {chip && <span className="self-start font-mono text-[9.5px] font-bold uppercase px-1.5 py-px rounded bg-primary/12 text-primary-light">{chip}</span>}
        {art}
        {actions && <div className="flex gap-1.5 flex-wrap items-center">{actions}</div>}
      </div>
      {children}
    </div>
  )
}

/** The fields an account row carries for its artwork (additive API fields, 2026-11-11). */
export interface RowArt {
  trust_score?: number | null
  decision?: string | null
  decision_reason?: string | null
  certified_mark?: boolean | null
  adoption_count?: number | null
  adoption_unit?: string | null
}

/** The Browse-row artwork: the trust or Certified mini over the adoption gauge, which
 * shows "New" when there's no adoption signal. */
export function ToolArt({ row, status }: { row: RowArt; status?: ReactNode }) {
  return (
    <span className="flex flex-col items-end gap-1.5 shrink-0">
      {row.trust_score != null
        ? <TrustOrCertifiedMini row={row as Record<string, unknown> & { trust_score: number }} />
        : status ?? <span className="font-mono text-[10px] text-text-muted">not checked yet</span>}
      <AdoptionMini count={row.adoption_count} unit={row.adoption_unit} />
    </span>
  )
}

/** The answer as coloured text ("Review before you connect"), or null before a check. */
export function PhraseText({ row }: { row: RowArt }) {
  if (row.trust_score == null) return null
  const p = decisionPhrase(decisionOf({ ...row, findings: {} }).decision)
  return <span style={{ color: p.color }} data-decision={p.value}>{p.phrase}</span>
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

export type { AccountTab } from '../lib/accountRoutes'

/** The row of account tabs. They are links to the four routes, so URLs don't change. */
function AccountTabs({ tab, unread }: { tab: AccountTab; unread: number }) {
  return (
    <nav aria-label="Account" className="mt-5 flex gap-1 border-b border-border/60 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
      {ACCOUNT_TABS.map(([k, label, to]) => (
        <Link key={k} to={rp(to)} aria-current={tab === k ? 'page' : undefined}
          className={`shrink-0 whitespace-nowrap px-3 py-[9px] text-[14px] border-b-2 -mb-px transition-colors ${tab === k ? 'text-text border-primary-light font-semibold' : 'text-text-muted border-transparent hover:text-text'}`}>
          {label}
          {k === 'notif' && unread > 0 && (
            <span className="ml-[5px] font-mono text-[10.5px] font-bold bg-danger text-white rounded-full px-1.5">{unread > 99 ? '99+' : unread}</span>
          )}
        </Link>
      ))}
    </nav>
  )
}

/** Warm the other tabs' chunks once the shell is up, so a tab switch never waits on a download. */
function preloadAccountTabs() {
  void import('../pages/MyTools')
  void import('../pages/Account')
  void import('../pages/Notifications')
  void import('../pages/Settings')
}

/**
 * The account shell: one 720px column, one header, one row of tabs, for My Tools,
 * Watches & alerts, Notifications and Settings. It is the parent route of all four
 * (App.tsx), so it stays mounted while you switch tabs and only the <Outlet/> swaps.
 * The signed-in user lives in AuthProvider for the whole session, so the skeleton
 * shows only on a true first load. Signed out it shows the skeleton and sends you to
 * /login?returnTo=… (no blank flash). The tab pages render only signed in.
 */
export function AccountLayout() {
  const { user, isLoading } = useAuth()
  useRequireUser(user, isLoading)
  const unread = useUnreadAlertCount(!!user)
  const { pathname, hash } = useLocation()
  const tab = accountTabFor(pathname) ?? 'watch'
  const signedIn = !!user
  useEffect(() => { if (signedIn) preloadAccountTabs() }, [signedIn])
  // A link to a section (/settings#developer) scrolls there once the page has rendered.
  useEffect(() => {
    if (!hash || !signedIn) return
    const t = setTimeout(() => document.getElementById(hash.slice(1))?.scrollIntoView({ block: 'start' }), 250)
    return () => clearTimeout(t)
  }, [hash, signedIn, pathname])
  const [, label, route] = ACCOUNT_TABS.find(([k]) => k === tab)!
  // Private pages: titled, never indexed.
  const head = <SEOHead title={label} path={route.replace('/rebrand', '')} noindex />
  if (!user) return <>{head}<AccountSkeleton /></>
  return (
    <div className="max-w-[720px] mx-auto px-6 pt-9 pb-16">
      {head}
      <div className="font-mono text-[12px] tracking-[.16em] uppercase text-primary-light font-semibold">Account</div>
      <h1 className="mt-2.5 text-[clamp(26px,3.6vw,32px)] font-extrabold tracking-tight">Your tools and alerts</h1>
      <p className="mt-1.5 text-text-muted text-[15px]">Claim tools you maintain, watch the ones you depend on, and choose how alerts reach you.</p>
      <AccountTabs tab={tab} unread={unread} />
      {/* Only the tab content swaps. A tab whose chunk is still loading shows rows, not a page skeleton. */}
      <Suspense fallback={<div className="mt-[22px]"><SkeletonRows n={3} /></div>}>
        <Outlet />
      </Suspense>
    </div>
  )
}
