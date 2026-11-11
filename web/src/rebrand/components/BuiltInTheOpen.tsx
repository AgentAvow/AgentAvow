/**
 * "Built in the open": what others can check about the method, each tile linked to its
 * source. No logos.
 */

import { OPEN_ITEMS } from '../lib/openItems'

export function BuiltInTheOpen({ className = '' }: { className?: string }) {
  return (
    <div className={className}>
      <div className="font-mono text-[12px] tracking-[.06em] uppercase text-text-muted font-semibold">Built in the open</div>
      <div className="grid gap-2.5 mt-4 grid-cols-[repeat(auto-fit,minmax(200px,1fr))]">
        {OPEN_ITEMS.map((it) => (
          <a key={it.href} href={it.href} target="_blank" rel="noopener noreferrer"
            className="block px-3.5 py-3 rounded-xl border border-border bg-surface text-text text-[13.5px] hover:border-primary-light transition-colors">
            <b className="block font-mono text-[10.5px] tracking-[.08em] uppercase text-primary-light mb-[3px]">{it.label}</b>
            {it.text}
          </a>
        ))}
      </div>
    </div>
  )
}
