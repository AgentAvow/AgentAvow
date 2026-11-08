/**
 * "Built in the open": what others can check about the method, each item linked to its
 * source. One quiet line of text on Home, no logos. Worded so nothing implies an
 * endorsement: "participant in", "individual Internet-Draft".
 */

import { OPEN_ITEMS } from '../lib/openItems'

export function BuiltInTheOpenLine({ className = '' }: { className?: string }) {
  return (
    <div className={`flex flex-wrap justify-center items-baseline gap-x-4 gap-y-1.5 text-[13px] text-text-muted text-center ${className}`}>
      <span className="font-mono text-[11px] tracking-[0.12em] uppercase text-primary-light">Built in the open</span>
      {OPEN_ITEMS.map((it) => (
        <a key={it.href} href={it.href} target="_blank" rel="noopener noreferrer" className="hover:text-text underline decoration-border underline-offset-[3px] hover:decoration-primary-light">
          {it.text}
        </a>
      ))}
    </div>
  )
}
