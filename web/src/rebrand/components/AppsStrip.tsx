import { CHATGPT_LISTING, CLAUDE_LISTING, trackListing } from '../lib/listings'

/**
 * "Available in Claude and ChatGPT": the two assistant listings. Product names in
 * plain text only, no Anthropic or OpenAI logos. A gradient border and a soft glow,
 * no blur. Used on Home under the check box, on /get and the score page's next steps;
 * the footer carries the one-line version (AppsLine).
 */

const BTN = 'inline-flex items-center justify-center gap-[7px] font-bold text-[14px] px-4 py-[9px] rounded-[11px] whitespace-nowrap text-[#06231f] transition-transform hover:-translate-y-px'

/** The two buttons on their own, for places that already have a heading. */
export function AppsButtons({ className = '' }: { className?: string }) {
  return (
    <div className={`flex gap-2.5 flex-wrap ${className}`}>
      <a href={CLAUDE_LISTING} target="_blank" rel="noopener noreferrer" onClick={() => trackListing(CLAUDE_LISTING)}
        className={`${BTN} max-[520px]:flex-1`} style={{ background: 'linear-gradient(90deg,#2DD4BF,#5eead4)' }}>
        <span className="w-2 h-2 rounded-full bg-[#06231f] opacity-55" aria-hidden="true" />Add to Claude ↗
      </a>
      <a href={CHATGPT_LISTING} target="_blank" rel="noopener noreferrer" onClick={() => trackListing(CHATGPT_LISTING)}
        className={`${BTN} max-[520px]:flex-1`} style={{ background: 'linear-gradient(90deg,#f0abfc,#E879F9)' }}>
        <span className="w-2 h-2 rounded-full bg-[#06231f] opacity-55" aria-hidden="true" />Add to ChatGPT ↗
      </a>
    </div>
  )
}

export function AppsStrip({ align = 'center', className = '' }: { align?: 'center' | 'start'; className?: string }) {
  return (
    <div
      className={`flex flex-wrap items-center gap-x-3.5 gap-y-3 max-w-[640px] px-[18px] py-3.5 rounded-2xl max-[520px]:flex-col max-[520px]:items-stretch ${align === 'center' ? 'mx-auto justify-center max-[520px]:text-center' : 'justify-start'} ${className}`}
      style={{
        border: '1.5px solid transparent',
        background: 'linear-gradient(var(--color-surface),var(--color-surface)) padding-box, linear-gradient(90deg,#2DD4BF,#E879F9) border-box',
        boxShadow: '0 0 0 1px rgba(45,212,191,.08), 0 10px 28px -14px rgba(232,121,249,.45)',
      }}
    >
      {/* "start" (inside a left-aligned page) stays left on small screens too */}
      <div className={`text-[15px] font-semibold text-text text-left ${align === 'center' ? 'max-[520px]:text-center' : ''}`}>
        Available in Claude and ChatGPT
        <small className="block text-[12.5px] font-normal text-text-muted mt-px">Ask before you connect anything, right in the chat.</small>
      </div>
      <AppsButtons className={align === 'center' ? 'max-[520px]:justify-center' : ''} />
    </div>
  )
}

/** The footer's one-line version. */
export function AppsLine({ className = '' }: { className?: string }) {
  const link = 'font-semibold text-primary-light hover:text-primary'
  return (
    <p className={`text-[13px] text-text-muted ${className}`}>
      Available in{' '}
      <a href={CLAUDE_LISTING} target="_blank" rel="noopener noreferrer" onClick={() => trackListing(CLAUDE_LISTING)} className={link}>Claude</a>
      {' '}and{' '}
      <a href={CHATGPT_LISTING} target="_blank" rel="noopener noreferrer" onClick={() => trackListing(CHATGPT_LISTING)} className={link}>ChatGPT</a>
    </p>
  )
}
