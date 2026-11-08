import { CHATGPT_LISTING, CLAUDE_LISTING, trackListingClick } from '../lib/listings'

/**
 * "Available in Claude and ChatGPT": the colored strip with both listings. Gradient
 * border and a soft shadow, no blur. Product names in plain text, no logos.
 */
export function AppsStrip({ align = 'center' }: { align?: 'center' | 'left' }) {
  const button = 'inline-flex flex-1 sm:flex-none items-center justify-center gap-2 whitespace-nowrap font-bold text-[14px] px-4 py-2.5 rounded-[11px] text-[#06231f]'
  return (
    <div
      className={`flex flex-col sm:flex-row sm:flex-wrap items-stretch sm:items-center gap-3 sm:gap-x-4 mt-5 max-w-[640px] px-[18px] py-3.5 rounded-2xl border-[1.5px] border-transparent text-center sm:text-left ${align === 'center' ? 'mx-auto sm:justify-center' : 'sm:justify-start'}`}
      style={{
        background: 'linear-gradient(var(--color-surface), var(--color-surface)) padding-box, linear-gradient(90deg, #2DD4BF, #E879F9) border-box',
        boxShadow: '0 0 0 1px rgba(45,212,191,.08), 0 10px 28px -14px rgba(232,121,249,.45)',
      }}
    >
      <div className="text-[15px] font-semibold text-text">
        Available in Claude and ChatGPT
        <small className="block text-[12.5px] font-normal text-text-muted mt-px">Ask before you connect anything, right in the chat.</small>
      </div>
      <div className="flex gap-2.5 flex-wrap justify-center">
        <a href={CLAUDE_LISTING} target="_blank" rel="noopener noreferrer" onClick={() => trackListingClick(CLAUDE_LISTING)}
          className={button} style={{ background: 'linear-gradient(90deg, #2DD4BF, #5eead4)' }}>
          <span className="w-2 h-2 rounded-full bg-[#06231f] opacity-55" aria-hidden="true" />Add to Claude ↗
        </a>
        <a href={CHATGPT_LISTING} target="_blank" rel="noopener noreferrer" onClick={() => trackListingClick(CHATGPT_LISTING)}
          className={button} style={{ background: 'linear-gradient(90deg, #f0abfc, #E879F9)' }}>
          <span className="w-2 h-2 rounded-full bg-[#06231f] opacity-55" aria-hidden="true" />Add to ChatGPT ↗
        </a>
      </div>
    </div>
  )
}
