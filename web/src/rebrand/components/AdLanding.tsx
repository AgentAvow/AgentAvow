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
 * 2026-11-17 UTC before it went in here. Each row links to its report, which always
 * shows today's result. Re-check before changing a row.
 */
const EXAMPLE_ROWS: { name: string; answer: Answer; score: number; why: string; report: string }[] = [
  { name: 'context7', answer: 'safe', score: 83, why: 'No critical or high findings in 30 files.', report: '/rebrand/check/pkg/npm/@upstash/context7-mcp' },
  { name: 'mcp-server-git', answer: 'safe', score: 77, why: 'Nothing found. Latest version, 2026.11.11.', report: '/rebrand/check/pkg/pypi/mcp-server-git' },
  { name: '@modelcontextprotocol/server-puppeteer', answer: 'review', score: 64, why: 'One high finding: an undeclared network call. Archived by its maintainer, so nobody patches it.', report: '/rebrand/check/pkg/npm/@modelcontextprotocol/server-puppeteer' },
]

function Row({ name, answer, score, children, report }: { name: string; answer: Answer; score: number; children: React.ReactNode; report: string }) {
  const t = TONE[answer]
  return (
    <li className={`grid grid-cols-[22px_1fr] gap-x-2.5 gap-y-1 px-4 py-3.5 ${answer === 'dnc' ? 'bg-danger/[0.07]' : ''}`}>
      <span className={`mt-[1px] w-[22px] h-[22px] rounded-full inline-grid place-items-center text-[12px] font-extrabold ${t.text} ${answer === 'safe' ? 'bg-success/15' : answer === 'review' ? 'bg-warning/15' : 'bg-danger/15'}`} aria-hidden="true">{t.icon}</span>
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span className="font-mono text-[13.5px] text-text [overflow-wrap:anywhere]">{name}</span>
          <span className={`text-[14.5px] font-bold ${t.text}`}>{t.phrase}</span>
          <span className="text-[12.5px] text-text-muted">· trust score {score}</span>
        </div>
        <div className="mt-1 text-[13.5px] text-text-muted">{children}</div>
        <Link to={rp(report)} className="mt-1 inline-block text-[13px] font-semibold text-primary-light hover:text-primary">See the report →</Link>
      </div>
    </li>
  )
}

/** "What a check looks like": mostly Safe, one Review, and the ad's Do not connect with the fix beside it. */
export function WalletAdExamples() {
  return (
    <div className="glass rounded-2xl border border-border/60 overflow-hidden text-left">
      <div className="px-4 py-2.5 border-b border-border/60 text-[12.5px] font-semibold text-text-muted">Real results, November 2026. Each report shows today&apos;s result.</div>
      <ul className="divide-y divide-border/60">
        {EXAMPLE_ROWS.map((r) => (
          <Row key={r.name} name={r.name} answer={r.answer} score={r.score} report={r.report}>{r.why}</Row>
        ))}
        <Row name="gadgethumans-mcp 1.0.15" answer="dnc" score={45} report="/rebrand/check/pkg/npm/gadgethumans-mcp?version=1.0.15">
          <p>Reads the wallet private key from your environment and sends it over the network (index.js, line 215).</p>
          <p className="mt-2 rounded-lg bg-danger/[0.10] px-2.5 py-1.5 text-[13px] text-text">AgentAvow asks before you install it, and stops calls to a server that&apos;s already connected.</p>
          <p className="mt-2">The latest version, 1.2.4, reads <b className="text-success font-semibold">Safe to connect</b> (82). <Link to={rp('/rebrand/check/pkg/npm/gadgethumans-mcp')} className="font-semibold text-primary-light hover:text-primary">See 1.2.4 →</Link></p>
        </Row>
      </ul>
    </div>
  )
}
