/** The (i) tooltip for a term, and the collapsible "What these numbers mean" list. Both
 *  read the same definitions (adminGlossaryTerms.ts), so a term means one thing. */
import { GLOSSARY } from './adminGlossaryTerms'
import type { GlossaryKey } from './adminGlossaryTerms'

/** A small (i) after a label: hover (or focus) shows the term's definition. */
export function Info({ k }: { k: GlossaryKey }) {
  const g = GLOSSARY[k]
  return (
    <span
      tabIndex={0}
      title={`${g.term}: ${g.def}`}
      aria-label={`${g.term}: ${g.def}`}
      className="ml-1 inline-flex items-center justify-center w-3.5 h-3.5 rounded-full border border-current text-[9px] leading-none font-sans normal-case not-italic cursor-help opacity-60 hover:opacity-100 focus:opacity-100 align-middle"
    >
      i
    </span>
  )
}

export function GlossarySection() {
  return (
    <details className="mt-6 glass rounded-2xl px-5 py-3 group">
      <summary className="cursor-pointer text-[13px] font-semibold select-none">What these numbers mean <span className="font-normal text-text-muted">· one definition per term</span></summary>
      <dl className="mt-3 grid md:grid-cols-2 gap-x-8 gap-y-2 text-[12.5px]">
        {Object.entries(GLOSSARY).map(([key, g]) => (
          <div key={key} id={`glossary-${key}`}>
            <dt className="font-semibold">{g.term}</dt>
            <dd className="text-text-muted">{g.def}</dd>
          </div>
        ))}
      </dl>
    </details>
  )
}
