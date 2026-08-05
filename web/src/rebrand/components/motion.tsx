import { useEffect, useRef, useState } from 'react'
import { motion, useInView, useReducedMotion } from 'framer-motion'

/**
 * Shared rebrand motion primitives. Everything respects prefers-reduced-motion
 * (framer's useReducedMotion) so the site stays accessible.
 */

/** Fade + rise into view once. The workhorse scroll reveal, used site-wide. */
export function Reveal({
  children,
  className,
  delay = 0,
  y = 16,
}: {
  children: React.ReactNode
  className?: string
  delay?: number
  y?: number
}) {
  const reduce = useReducedMotion()
  return (
    <motion.div
      className={className}
      initial={reduce ? false : { opacity: 0, y }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-70px' }}
      transition={{ duration: 0.55, ease: 'easeOut', delay }}
    >
      {children}
    </motion.div>
  )
}

/**
 * Reveal a list of children with a stagger — cards, table rows, chips animate in
 * one after another. Pass an array of nodes as children.
 */
export function RevealStagger({
  children,
  className,
  stagger = 0.05,
  y = 14,
}: {
  children: React.ReactNode[]
  className?: string
  stagger?: number
  y?: number
}) {
  const reduce = useReducedMotion()
  return (
    <motion.div
      className={className}
      initial={reduce ? undefined : 'hidden'}
      whileInView="show"
      viewport={{ once: true, margin: '-60px' }}
      variants={{ show: { transition: { staggerChildren: stagger } } }}
    >
      {children.map((child, i) => (
        <motion.div
          key={i}
          variants={{ hidden: { opacity: 0, y }, show: { opacity: 1, y: 0 } }}
          transition={{ duration: 0.45, ease: 'easeOut' }}
        >
          {child}
        </motion.div>
      ))}
    </motion.div>
  )
}

/**
 * Count a number up from 0 → value when it scrolls into view. Formats with
 * thousands separators. `suffix`/`prefix` for units. Falls back to the final
 * value immediately under reduced-motion.
 */
export function CountUp({
  value,
  duration = 1100,
  className,
  prefix = '',
  suffix = '',
}: {
  value: number
  duration?: number
  className?: string
  prefix?: string
  suffix?: string
}) {
  const ref = useRef<HTMLSpanElement>(null)
  const inView = useInView(ref, { once: true, margin: '-40px' })
  const reduce = useReducedMotion()
  const [display, setDisplay] = useState(0)

  useEffect(() => {
    if (!inView) return
    if (reduce || value === 0) {
      const id = requestAnimationFrame(() => setDisplay(value))
      return () => cancelAnimationFrame(id)
    }
    let raf = 0
    let start: number | null = null
    const tick = (t: number) => {
      if (start === null) start = t
      const p = Math.min((t - start) / duration, 1)
      // easeOutCubic
      const eased = 1 - Math.pow(1 - p, 3)
      setDisplay(Math.round(value * eased))
      if (p < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [inView, value, duration, reduce])

  return (
    <span ref={ref} className={className}>
      {prefix}{display.toLocaleString()}{suffix}
    </span>
  )
}
