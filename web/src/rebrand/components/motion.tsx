import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { animate, inView, motion, useInView, useReducedMotion } from 'framer-motion'
import { inSnapshot } from '../lib/snapshot'

/**
 * Shared rebrand motion primitives. Everything respects prefers-reduced-motion
 * (framer's useReducedMotion) so the site stays accessible.
 */

/** Below the fold at the moment the app takes over from a prerendered snapshot? */
function offscreen(el: HTMLElement): boolean {
  return el.getBoundingClientRect().top >= window.innerHeight
}

/**
 * Reveal for the page a visitor lands on through a prerendered snapshot. It renders
 * visible, so the snapshot has real text and nothing already on screen blinks out.
 * Whatever is still below the fold is hidden before paint and gets the normal reveal.
 */
function SnapshotReveal({
  children,
  className,
  delay = 0,
  y,
  duration,
  margin,
}: {
  children: React.ReactNode
  className?: string
  delay?: number
  y: number
  duration: number
  margin: `${number}px`
}) {
  const ref = useRef<HTMLDivElement>(null)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el || !offscreen(el)) return
    animate(el, { opacity: 0, y }, { duration: 0 })
    return inView(el, () => {
      animate(el, { opacity: 1, y: 0 }, { duration, ease: 'easeOut', delay })
    }, { margin: `0px 0px ${margin} 0px` })
  }, [y, duration, margin, delay])
  return <div ref={ref} className={className}>{children}</div>
}

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
  const [snapshot] = useState(inSnapshot)
  // Under reduced-motion, bypass the scroll reveal entirely so content is always
  // visible (never a blank section waiting on an IntersectionObserver that won't fire).
  if (reduce) return <div className={className}>{children}</div>
  if (snapshot) {
    return <SnapshotReveal className={className} delay={delay} y={y} duration={0.55} margin="-70px">{children}</SnapshotReveal>
  }
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y }}
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
  // A `whileInView` with `once` fires a single time, so children mounted after the
  // reveal (a filter that returns more rows than before) never got the "show"
  // variant and stayed at opacity 0 until a full page reload. Once the first reveal
  // has finished, every child animates to "show" on its own, new ones included.
  const [revealed, setRevealed] = useState(false)
  const [snapshot] = useState(inSnapshot)
  if (reduce) return <div className={className}>{children}</div>
  if (snapshot) {
    return (
      <div className={className}>
        {children.map((child, i) => (
          <SnapshotReveal key={i} delay={i * stagger} y={y} duration={0.45} margin="-60px">{child}</SnapshotReveal>
        ))}
      </div>
    )
  }
  return (
    <motion.div
      className={className}
      initial="hidden"
      whileInView="show"
      onAnimationComplete={() => setRevealed(true)}
      viewport={{ once: true, margin: '-60px' }}
      variants={{ show: { transition: { staggerChildren: stagger } } }}
    >
      {children.map((child, i) => (
        <motion.div
          key={i}
          animate={revealed ? 'show' : undefined}
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
  // A prerendered snapshot needs the real number. Below the fold it can still count up.
  const [snapshot] = useState(inSnapshot)
  const landed = useRef(snapshot)
  const [display, setDisplay] = useState(snapshot ? value : 0)

  useLayoutEffect(() => {
    if (ref.current && offscreen(ref.current)) landed.current = false
  }, [])

  useEffect(() => {
    if (!inView) return
    if (reduce || value === 0 || landed.current) {
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
