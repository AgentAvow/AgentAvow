import { useEffect, useState } from 'react'
import { useReducedMotion } from 'framer-motion'

/**
 * Rotating placeholder for the "check" inputs — cycles through the kinds of things
 * you can check (repo, MCP server, npm/PyPI, skill) while the field is empty and
 * unfocused. Returns the current placeholder string. Reduced-motion → first item only.
 */
export function useRotatingPlaceholder(items: string[], intervalMs = 2400): string {
  const reduce = useReducedMotion()
  const [i, setI] = useState(0)
  useEffect(() => {
    if (reduce || items.length < 2) return
    const id = setInterval(() => setI((n) => (n + 1) % items.length), intervalMs)
    return () => clearInterval(id)
  }, [items.length, intervalMs, reduce])
  return items[i]
}

/** True on desktop-width viewports (>= md). Client-only; false during first paint on
 * narrow screens. Used to scale the score-page marks up on desktop while mobile stays
 * at spec size. */
export function useIsDesktop(minWidth = 768): boolean {
  const [isDesktop, setIsDesktop] = useState(() =>
    typeof window !== 'undefined' ? window.matchMedia(`(min-width:${minWidth}px)`).matches : false)
  useEffect(() => {
    const mq = window.matchMedia(`(min-width:${minWidth}px)`)
    const on = () => setIsDesktop(mq.matches)
    on()
    mq.addEventListener('change', on)
    return () => mq.removeEventListener('change', on)
  }, [minWidth])
  return isDesktop
}
