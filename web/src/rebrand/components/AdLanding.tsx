import { useId, useState } from 'react'
import { Link } from 'react-router-dom'

import api from '../../lib/api'
import { trackCta } from '../../lib/analytics'
import { rp } from '../basePath'
import { adTags, setupUrl } from '../lib/adLanding'
import { CHATGPT_LISTING, trackListing } from '../lib/listings'
import { BTN_CLASS, BTN_GHOST_CLASS } from './PageBits'

/**
 * The pieces the ad landings share (approved 2026-11-16, "Landing page concept v2"):
 * the phone path on /claude-code (email me the setup, copy or share the link, add to
 * ChatGPT) and the X wallet-key ad's homepage hero (real example results).
 */

async function writeClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

/** "Copy link", or "Share link" where the phone has a share sheet (Web Share API). */
export function ShareSetupLink({ search, className = '' }: { search: string; className?: string }) {
  // No share sheet (most computers, the prerender): copy instead.
  const [canShare] = useState(() => typeof navigator !== 'undefined' && typeof navigator.share === 'function')
  const [state, setState] = useState<'idle' | 'copied' | 'manual'>('idle')
  const url = setupUrl(search)
  const onClick = async () => {
    if (canShare) {
      try {
        await navigator.share({ title: 'AgentAvow for Claude Code', text: 'Set up AgentAvow in Claude Code on my computer', url })
        trackCta('share_link')
        return
      } catch (e) {
        // Closed the sheet: nothing to do. Any other failure falls back to copying.
        if ((e as { name?: string })?.name === 'AbortError') return
      }
    }
    if (await writeClipboard(url)) {
      trackCta('share_link')
      setState('copied')
      window.setTimeout(() => setState('idle'), 2000)
    } else {
      setState('manual')
    }
  }
  return (
    <div className={className}>
      <button type="button" onClick={onClick} className={`${BTN_GHOST_CLASS} w-full`}>
        {state === 'copied' ? 'Link copied' : canShare ? 'Share the link instead' : 'Copy the link instead'}
      </button>
      {state === 'manual' && (
        <p role="status" className="mt-1.5 text-[12.5px] text-text-muted [overflow-wrap:anywhere]">
          This browser blocked copying. The link: <span className="font-mono text-text select-all">{url}</span>
        </p>
      )}
    </div>
  )
}

/**
 * "Email me the setup": one fixed email with the two install commands and a link back
 * to /claude-code that keeps the ad's tags. The address isn't kept (see
 * src/api/send_setup_router.py). The no-email option sits right under the button.
 */
export function EmailSetup({ search, label = 'Email me the setup' }: { search: string; label?: string }) {
  const inputId = useId()
  const [email, setEmail] = useState('')
  const [state, setState] = useState<'idle' | 'sending' | 'sent' | 'error'>('idle')
  const [error, setError] = useState('')
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (state === 'sending') return
    setState('sending')
    setError('')
    try {
      await api.post('/public/send-setup', { email: email.trim(), utm: adTags(search) })
      trackCta('email_setup')
      setState('sent')
    } catch (err) {
      const status = (err as { response?: { status?: number } })?.response?.status
      setError(status === 422 ? 'That email address doesn\'t look right.'
        : status === 429 ? 'Too many requests for now. Copy the link instead.'
          : 'We couldn\'t send it just now. Copy the link instead.')
      setState('error')
    }
  }
  return (
    <div>
      {state === 'sent' ? (
        <p role="status" className="rounded-xl border border-success/40 bg-success/[0.08] px-4 py-3 text-[14.5px] text-text">
          <b className="text-success">Sent.</b> Open it on your computer and paste the two lines into Claude Code.
        </p>
      ) : (
        <form onSubmit={submit} className="grid gap-2">
          <label htmlFor={inputId} className="sr-only">Your email</label>
          <input
            id={inputId}
            type="email"
            inputMode="email"
            autoComplete="email"
            required
            maxLength={254}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            className="w-full rounded-xl border border-border bg-background px-4 py-[11px] text-[15.5px] text-text placeholder:text-text-muted outline-none focus:border-primary-light"
          />
          <button type="submit" disabled={state === 'sending'} className={`${BTN_CLASS} w-full disabled:opacity-70`}>
            {state === 'sending' ? 'Sending…' : label}
          </button>
          {error && <p role="alert" className="text-[13px] text-warning">{error}</p>}
        </form>
      )}
      <p className="mt-1.5 text-[12.5px] leading-snug text-text-muted">We send one email with the setup. We don&apos;t keep your address or add you to a list.</p>
      <ShareSetupLink search={search} className="mt-2.5" />
    </div>
  )
}

/** Add to ChatGPT: the ChatGPT app works on a phone today. Counted as add_chatgpt. */
export function ChatGptLink({ className = '' }: { className?: string }) {
  return (
    <a href={CHATGPT_LISTING} target="_blank" rel="noopener noreferrer" onClick={() => trackListing(CHATGPT_LISTING)}
      className={`${BTN_GHOST_CLASS} ${className}`}>
      Add to ChatGPT ↗
    </a>
  )
}

type Answer = 'safe' | 'review' | 'dnc'
const TONE: Record<Answer, { text: string; icon: string; phrase: string }> = {
  safe: { text: 'text-success', icon: '✓', phrase: 'Safe to connect' },
  review: { text: 'text-warning', icon: '!', phrase: 'Review before you connect' },
  dnc: { text: 'text-danger', icon: '✕', phrase: 'Do not connect' },
}

/**
 * Real results, each read from the live API (GET /public/scan/package/...) on
 * 2026-11-17 UTC before it went in here (context7 re-read that evening: 83 → 80, 31
 * files). Each row links to its report, which always shows today's result. Re-check
 * before changing a row. `short` is the name the compact card shows.
 */
const EXAMPLE_ROWS: { name: string; short?: string; answer: Answer; score: number; why: string; report: string }[] = [
  { name: 'context7', answer: 'safe', score: 80, why: 'No critical or high findings in 31 files.', report: '/rebrand/check/pkg/npm/@upstash/context7-mcp' },
  { name: 'mcp-server-git', answer: 'safe', score: 77, why: 'Nothing found. Latest version, 2026.11.11.', report: '/rebrand/check/pkg/pypi/mcp-server-git' },
  { name: '@modelcontextprotocol/server-puppeteer', short: 'server-puppeteer', answer: 'review', score: 64, why: 'One high finding: an undeclared network call. Archived by its maintainer, so nobody patches it.', report: '/rebrand/check/pkg/npm/@modelcontextprotocol/server-puppeteer' },
]

/**
 * A report link. On /claude-code (`full`) it's a full page load, like that page's other
 * links, so the Meta Pixel loaded there never rides along into the app (see the Meta Pixel loader).
 */
function ReportLink({ to, full, className, children }: { to: string; full: boolean; className: string; children: React.ReactNode }) {
  return full
    ? <a href={rp(to)} className={className}>{children}</a>
    : <Link to={rp(to)} className={className}>{children}</Link>
}

function Row({ name, answer, score, children, report, compact }: { name: string; answer: Answer; score: number; children: React.ReactNode; report: string; compact?: boolean }) {
  const t = TONE[answer]
  // Compact (/claude-code): Safe and Review rows are one line; each name links to its report.
  const brief = compact && answer !== 'dnc'
  return (
    <li className={`grid grid-cols-[22px_1fr] gap-x-2.5 gap-y-1 px-4 ${compact ? 'py-2.5' : 'py-3.5'} ${answer === 'dnc' ? 'bg-danger/[0.07]' : ''}`}>
      <span className={`mt-[1px] w-[22px] h-[22px] rounded-full inline-grid place-items-center text-[12px] font-extrabold ${t.text} ${answer === 'safe' ? 'bg-success/15' : answer === 'review' ? 'bg-warning/15' : 'bg-danger/15'}`} aria-hidden="true">{t.icon}</span>
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          {compact
            ? <ReportLink to={report} full className="font-mono text-[13.5px] text-text [overflow-wrap:anywhere] underline decoration-border underline-offset-2 hover:text-primary-light">{name}</ReportLink>
            : <span className="font-mono text-[13.5px] text-text [overflow-wrap:anywhere]">{name}</span>}
          <span className={`text-[14.5px] font-bold ${t.text}`}>{t.phrase}</span>
          <span className="text-[12.5px] text-text-muted">· {compact ? '' : 'trust score '}{score}</span>
        </div>
        {!brief && <div className={`${compact ? 'mt-0.5' : 'mt-1'} text-[13.5px] text-text-muted`}>{children}</div>}
        {!compact && <Link to={rp(report)} className="mt-1 inline-block text-[13px] font-semibold text-primary-light hover:text-primary">See the report →</Link>}
      </div>
    </li>
  )
}

/**
 * "What a check looks like": mostly Safe, one Review, and the ad's Do not connect with
 * the fix beside it. `compact` (the /claude-code hero) keeps one line per Safe or Review
 * row and a shorter finding, so the phone actions stay on the first screen. Its links
 * are full page loads (see ReportLink).
 */
export function WalletAdExamples({ compact = false }: { compact?: boolean }) {
  const latest = (
    <ReportLink to="/rebrand/check/pkg/npm/gadgethumans-mcp" full={compact} className="font-semibold text-primary-light hover:text-primary">See 1.2.4 →</ReportLink>
  )
  return (
    <div className="glass rounded-2xl border border-border/60 overflow-hidden text-left">
      <div className="px-4 py-2.5 border-b border-border/60 text-[12.5px] font-semibold text-text-muted">
        {compact ? 'Real results and trust scores, November 2026' : <>Real results, November 2026. Each report shows today&apos;s result.</>}
      </div>
      <ul className="divide-y divide-border/60">
        {EXAMPLE_ROWS.map((r) => (
          <Row key={r.name} name={compact ? r.short ?? r.name : r.name} answer={r.answer} score={r.score} report={r.report} compact={compact}>{r.why}</Row>
        ))}
        <Row name="gadgethumans-mcp 1.0.15" answer="dnc" score={45} report="/rebrand/check/pkg/npm/gadgethumans-mcp?version=1.0.15" compact={compact}>
          {compact
            ? <p>Sends your wallet private key over the network (index.js:215).</p>
            : <p>Reads the wallet private key from your environment and sends it over the network (index.js, line 215).</p>}
          <p className={`${compact ? 'mt-1.5' : 'mt-2'} rounded-lg bg-danger/[0.10] px-2.5 py-1.5 text-[13px] text-text`}>AgentAvow asks before you install it, and stops calls to a server that&apos;s already connected.</p>
          {compact
            ? <p className="mt-1.5">Latest <ReportLink to="/rebrand/check/pkg/npm/gadgethumans-mcp" full className="font-semibold text-primary-light hover:text-primary underline underline-offset-2">1.2.4</ReportLink>: <b className="text-success font-semibold">Safe to connect</b> (82).</p>
            : <p className="mt-2">The latest version, 1.2.4, reads <b className="text-success font-semibold">Safe to connect</b> (82). {latest}</p>}
        </Row>
      </ul>
    </div>
  )
}
