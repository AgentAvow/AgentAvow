import { useState, useSyncExternalStore } from 'react'
import { Link } from 'react-router-dom'
import { rp } from '../basePath'
import { trackListing } from '../lib/listings'
import { AGENTAVOW_PATHS, readPathPick, savePathPick, type PathLink } from '../lib/agentavowPaths'

/**
 * The score page's "Check tools like this automatically" chooser: every AgentAvow
 * install path from /get as one row of pills, with the picked one's line, command and
 * link below. The pick is remembered on this device (localStorage, wrapped so private
 * mode just forgets). The first render is always Claude Code, so the prerendered HTML
 * and the first client render agree; a remembered pick applies after mount.
 */

const PILL = 'shrink-0 text-[13px] rounded-full border px-3 py-1.5 whitespace-nowrap transition-colors'
const LINK = 'text-[13.5px] font-semibold text-primary-light hover:text-primary whitespace-nowrap'
const BTN = 'inline-flex items-center justify-center text-[13.5px] font-bold px-3.5 py-2 rounded-[10px] whitespace-nowrap'

function PathAction({ link }: { link: PathLink }) {
  const onClick = () => { if (link.href.startsWith('https://claude.ai/') || link.href.startsWith('https://chatgpt.com/')) trackListing(link.href) }
  const cls = link.style === 'primary' ? `${BTN} text-white bg-gradient-to-r from-primary to-primary-dark`
    : link.style === 'claude' ? `${BTN} text-[#06231f]`
      : link.style === 'chatgpt' ? `${BTN} text-[#06231f]` : LINK
  const style = link.style === 'claude' ? { background: 'linear-gradient(90deg,#2DD4BF,#5eead4)' }
    : link.style === 'chatgpt' ? { background: 'linear-gradient(90deg,#f0abfc,#E879F9)' } : undefined
  // /claude-code has its own CSP, so it loads as a full page; other site pages route in place.
  if (link.href === '/rebrand/claude-code' || link.href.startsWith('/api/')) {
    return <a href={link.href.startsWith('/api/') ? link.href : rp(link.href)} className={cls} style={style}>{link.label}</a>
  }
  if (link.href.startsWith('/rebrand/')) return <Link to={rp(link.href)} className={cls} style={style}>{link.label}</Link>
  const external = /^https?:/.test(link.href)
  return (
    <a href={link.href} onClick={onClick} className={cls} style={style}
      {...(external ? { target: '_blank', rel: 'noopener noreferrer' } : {})}>{link.label}</a>
  )
}

// The remembered pick, read as an external store: null on the server and in the
// prerendered HTML, the saved key once the page runs in a browser.
const PICK_EVENT = 'agentavow-path-pick'
function subscribePick(cb: () => void): () => void {
  window.addEventListener('storage', cb)
  window.addEventListener(PICK_EVENT, cb)
  return () => { window.removeEventListener('storage', cb); window.removeEventListener(PICK_EVENT, cb) }
}

export function AgentAvowChooser({ dnc = false }: { dnc?: boolean }) {
  const saved = useSyncExternalStore(subscribePick, readPathPick, () => null)
  const [chosen, setChosen] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const pick = chosen ?? saved ?? AGENTAVOW_PATHS[0].key
  const remembered = !!(chosen ?? saved)
  const choose = (key: string) => {
    setChosen(key); setCopied(false); savePathPick(key)
    try { window.dispatchEvent(new Event(PICK_EVENT)) } catch { /* old browser */ }
  }
  const p = AGENTAVOW_PATHS.find((x) => x.key === pick) ?? AGENTAVOW_PATHS[0]
  const copy = () => {
    if (!p.snippet) return
    try { void navigator.clipboard?.writeText(p.snippet) } catch { /* no clipboard */ }
    setCopied(true); setTimeout(() => setCopied(false), 1400)
  }
  return (
    <div className="mt-3 min-w-0" data-testid="agentavow-chooser">
      <div className="flex gap-1.5 overflow-x-auto pb-1 min-w-0 [scrollbar-width:thin]" role="group" aria-label="Where you work">
        {AGENTAVOW_PATHS.map((x) => (
          <button key={x.key} type="button" aria-pressed={x.key === p.key} onClick={() => choose(x.key)}
            className={`${PILL} ${x.key === p.key ? 'border-primary-light text-primary-light bg-primary/10 font-semibold' : 'border-border bg-surface text-text-muted hover:text-text'}`}>
            {x.label}
          </button>
        ))}
      </div>
      <div className="mt-2.5 rounded-xl bg-surface border border-border/60 px-4 py-3 flex flex-col gap-2 min-w-0">
        <span className="font-mono text-[10.5px] tracking-[.08em] uppercase text-primary-light">{p.label} · {p.tag}</span>
        <p className="text-[14px] text-text">{dnc && p.dncText ? p.dncText : p.text}</p>
        {p.snippet && (
          <div className="flex items-start gap-2 min-w-0">
            <pre className="flex-1 min-w-0 font-mono text-[12px] text-text whitespace-pre-wrap [overflow-wrap:anywhere]">{p.snippet}</pre>
            <button type="button" onClick={copy} className="shrink-0 text-[11px] font-semibold px-2 py-1 rounded-md border border-border text-text-muted hover:text-primary-light hover:border-primary-light">{copied ? 'Copied ✓' : 'Copy'}</button>
          </div>
        )}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          {p.links.map((l) => <PathAction key={l.label} link={l} />)}
        </div>
      </div>
      <p className="mt-2 text-[12px] text-text-muted">
        {remembered && <>Remembered on this device: {p.label}. </>}
        Every option is on <Link to={rp('/rebrand/get')} className="text-primary-light hover:text-primary">Get AgentAvow</Link>.
      </p>
    </div>
  )
}
