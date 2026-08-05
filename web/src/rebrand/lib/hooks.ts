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
