import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'

/**
 * The page type scale shared by /get, /teams, /claude-code and the pages built to the
 * 2026-11-10 mockups (design audit M1): an eyebrow, a clamp() H1 at 30-46px with an
 * 18px light lede, a clamp() section H2 at 25-33px, a 21px sub-section H2, 60px
 * sections, and one closing CTA band.
 */

export const H1_CLASS = 'text-[clamp(30px,4.6vw,46px)] font-extrabold leading-[1.1] tracking-[-.025em] [text-wrap:balance]'
export const H2_CLASS = 'text-[clamp(25px,3.4vw,33px)] font-bold tracking-tight leading-tight'
export const H2S_CLASS = 'text-[21px] font-bold tracking-tight leading-snug'
export const LEDE_CLASS = 'text-[18px] font-light text-text-muted max-w-[58ch]'
export const SECTION_CLASS = 'relative z-[2] py-[60px] max-sm:py-11 border-t border-border/60'
export const BTN_CLASS = 'inline-flex items-center justify-center font-semibold text-[15px] px-5 py-[11px] rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow'
export const BTN_GHOST_CLASS = 'inline-flex items-center justify-center font-semibold text-[15px] px-5 py-[11px] rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors'

export function Eyebrow({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`font-mono text-[12px] tracking-[.16em] uppercase text-primary-light font-semibold ${className}`}>{children}</div>
}

/** The page hero: eyebrow, H1, lede, then anything else (a badge, buttons). */
export function PageHeader({ eyebrow, title, lede, width = 1080, children }: {
  eyebrow?: ReactNode; title: ReactNode; lede?: ReactNode; width?: 860 | 1080; children?: ReactNode
}) {
  return (
    <div className="relative pt-14 pb-[34px]">
      <div className={`relative z-[2] mx-auto px-6 ${width === 860 ? 'max-w-[860px]' : 'max-w-[1080px]'}`}>
        {eyebrow && <Eyebrow>{eyebrow}</Eyebrow>}
        <h1 className={`${eyebrow ? 'mt-3' : ''} ${H1_CLASS}`}>{title}</h1>
        {lede && <p className={`mt-[18px] ${LEDE_CLASS}`}>{lede}</p>}
        {children}
      </div>
    </div>
  )
}

/** A section H2: `size="sub"` is the 21px heading for a run of short sections. */
export function SectionH2({ children, size = 'main', className = '', id }: { children: ReactNode; size?: 'main' | 'sub'; className?: string; id?: string }) {
  return <h2 id={id} className={`${size === 'sub' ? H2S_CLASS : H2_CLASS} ${className}`}>{children}</h2>
}

type Action = { label: string; to: string }

/** One app link or plain URL as a button. */
function ActionLink({ a, cls }: { a: Action; cls: string }) {
  return /^(https?:|mailto:|#)/.test(a.to)
    ? <a href={a.to} className={cls}>{a.label}</a>
    : <Link to={a.to} className={cls}>{a.label}</Link>
}

/** The closing band: a centred H2, one line, a primary and a ghost button. */
export function CtaBand({ title, line, primary, secondary, className = '' }: {
  title: ReactNode; line?: ReactNode; primary: Action; secondary?: Action; className?: string
}) {
  return (
    <div className={`text-center rounded-[18px] border border-border px-[22px] py-10 ${className}`}
      style={{ background: 'linear-gradient(120deg,rgba(45,212,191,.10),rgba(232,121,249,.08)), var(--color-surface)' }}>
      <h2 className={H2_CLASS}>{title}</h2>
      {line && <p className="mt-2.5 mx-auto max-w-[52ch] text-text-muted">{line}</p>}
      <div className="mt-5 flex gap-3 justify-center flex-wrap">
        <ActionLink a={primary} cls={BTN_CLASS} />
        {secondary && <ActionLink a={secondary} cls={BTN_GHOST_CLASS} />}
      </div>
    </div>
  )
}
