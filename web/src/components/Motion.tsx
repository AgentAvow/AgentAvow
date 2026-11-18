/**
 * Reusable animation primitives built on framer-motion.
 * Import these in any page for scroll-triggered reveals,
 * staggered lists, counters, and ambient effects.
 */
import { memo, useEffect, useRef } from 'react'
import {
  motion,
  useInView,
  useScroll,
  useTransform,
  type Variant,
} from 'framer-motion'
import { useTheme } from '../hooks/useTheme'

// ─── Spring configs ───

// eslint-disable-next-line react-refresh/only-export-components -- shared motion presets live next to the components that use them
export const spring = {
  gentle: { type: 'spring' as const, stiffness: 120, damping: 20 },
  snappy: { type: 'spring' as const, stiffness: 300, damping: 30 },
  bouncy: { type: 'spring' as const, stiffness: 400, damping: 25, mass: 0.8 },
}

// ─── Fade In (scroll-triggered) ───

interface FadeInProps {
  children: React.ReactNode
  className?: string
  delay?: number
  direction?: 'up' | 'down' | 'left' | 'right' | 'none'
  duration?: number
  once?: boolean
}

const directionOffset = {
  up: { y: 40 },
  down: { y: -40 },
  left: { x: 40 },
  right: { x: -40 },
  none: {},
}

export function FadeIn({
  children,
  className = '',
  delay = 0,
  direction = 'up',
  duration = 0.6,
  once = true,
}: FadeInProps) {
  const ref = useRef<HTMLDivElement>(null)
  const isInView = useInView(ref, { once, margin: '-50px' })

  return (
    <motion.div
      ref={ref}
      className={className}
      initial={{ opacity: 0, ...directionOffset[direction] }}
      animate={isInView ? { opacity: 1, x: 0, y: 0 } : undefined}
      transition={{ duration, delay, ease: [0.25, 0.46, 0.45, 0.94] }}
    >
      {children}
    </motion.div>
  )
}

// ─── Stagger Children ───

interface StaggerProps {
  children: React.ReactNode
  className?: string
  staggerDelay?: number
  once?: boolean
}

export function Stagger({
  children,
  className = '',
  staggerDelay = 0.08,
  once = true,
}: StaggerProps) {
  const ref = useRef<HTMLDivElement>(null)
  const isInView = useInView(ref, { once, margin: '-30px' })

  return (
    <motion.div
      ref={ref}
      className={className}
      initial="hidden"
      animate={isInView ? 'visible' : 'hidden'}
      variants={{
        hidden: {},
        visible: { transition: { staggerChildren: staggerDelay } },
      }}
    >
      {children}
    </motion.div>
  )
}

// Item inside a Stagger container
interface StaggerItemProps {
  children: React.ReactNode
  className?: string
}

const staggerItemVariants: Record<string, Variant> = {
  hidden: { opacity: 0, y: 20, scale: 0.97 },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: { duration: 0.5, ease: [0.25, 0.46, 0.45, 0.94] },
  },
}

export function StaggerItem({ children, className = '' }: StaggerItemProps) {
  return (
    <motion.div className={className} variants={staggerItemVariants}>
      {children}
    </motion.div>
  )
}

// ─── Animated Counter ───

interface CounterProps {
  value: number
  className?: string
  duration?: number
}

export function Counter({ value, className = '', duration = 1.5 }: CounterProps) {
  const ref = useRef<HTMLSpanElement>(null)
  const isInView = useInView(ref, { once: true })

  return (
    <motion.span
      ref={ref}
      className={className}
      initial={{ opacity: 0 }}
      animate={isInView ? { opacity: 1 } : undefined}
    >
      {isInView ? (
        <motion.span
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3 }}
        >
          <AnimatedNumber value={value} duration={duration} />
        </motion.span>
      ) : (
        '0'
      )}
    </motion.span>
  )
}

function AnimatedNumber({ value, duration }: { value: number; duration: number }) {
  return (
    <motion.span
      initial="from"
      animate="to"
      variants={{
        from: { '--num': 0 } as Record<string, number>,
        to: { '--num': value } as Record<string, number>,
      }}
      transition={{ duration, ease: [0.25, 0.46, 0.45, 0.94] }}
      style={{ counterSet: 'num var(--num)' }}
    >
      <CounterDisplay target={value} duration={duration} />
    </motion.span>
  )
}

function CounterDisplay({ target, duration }: { target: number; duration: number }) {
  const ref = useRef<HTMLSpanElement>(null)
  const startRef = useRef(0)
  const frameRef = useRef(0)

  useEffect(() => {
    const animate = () => {
      const elapsed = (performance.now() - startRef.current) / 1000
      const progress = Math.min(elapsed / duration, 1)
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3)
      const current = Math.round(eased * target)
      if (ref.current) {
        ref.current.textContent = current.toLocaleString()
      }
      if (progress < 1) {
        frameRef.current = requestAnimationFrame(animate)
      }
    }

    startRef.current = performance.now()
    frameRef.current = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(frameRef.current)
  }, [target, duration])

  return <span ref={ref}>0</span>
}

// ─── Magnetic Hover Effect ───

interface MagneticProps {
  children: React.ReactNode
  className?: string
  strength?: number
}

export function Magnetic({ children, className = '' }: MagneticProps) {
  return (
    <motion.div
      className={className}
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      transition={spring.snappy}
    >
      {children}
    </motion.div>
  )
}

// ─── Page Transition Wrapper ───

interface PageTransitionProps {
  children: React.ReactNode
  className?: string
}

export function PageTransition({ children, className = '' }: PageTransitionProps) {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: [0.25, 0.46, 0.45, 0.94] }}
    >
      {children}
    </motion.div>
  )
}

// ─── Particle Field (canvas-based floating data points) ───

// Module-level color constants — stable references prevent re-render loops
const PARTICLE_COLORS_DARK = ['#2DD4BF', '#E879F9', '#F59E0B']
const PARTICLE_COLORS_LIGHT = ['#0D9488', '#A21CAF', '#D97706']

interface ParticleFieldProps {
  className?: string
  count?: number
  colors?: string[]
  speed?: number
}

export const ParticleField = memo(function ParticleField({
  className = '',
  count = 50,
  colors,
  speed = 0.5,
}: ParticleFieldProps) {
  const { theme } = useTheme()
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const resolvedColors = colors ?? (theme === 'light' ? PARTICLE_COLORS_LIGHT : PARTICLE_COLORS_DARK)
  const connectionColor = theme === 'light' ? '#0D9488' : '#2DD4BF'
  const connectionAlpha = theme === 'light' ? 0.15 : 0.08

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const resize = () => {
      const dpr = window.devicePixelRatio || 1
      canvas.width = canvas.offsetWidth * dpr
      canvas.height = canvas.offsetHeight * dpr
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }
    resize()
    window.addEventListener('resize', resize)

    const particles = Array.from({ length: count }, () => ({
      x: Math.random() * canvas.offsetWidth,
      y: Math.random() * canvas.offsetHeight,
      vx: (Math.random() - 0.5) * speed,
      vy: (Math.random() - 0.5) * speed,
      r: Math.random() * 2 + 0.5,
      color: resolvedColors[Math.floor(Math.random() * resolvedColors.length)],
      alpha: Math.random() * 0.6 + 0.2,
    }))

    let raf = 0
    let lastFrame = 0
    let paused = document.hidden
    const FRAME_INTERVAL = 50 // ~20fps — lower CPU with negligible visual difference

    const onVisibility = () => { paused = document.hidden }
    document.addEventListener('visibilitychange', onVisibility)

    const animate = (now: number) => {
      raf = requestAnimationFrame(animate)
      if (paused) return
      if (now - lastFrame < FRAME_INTERVAL) return
      lastFrame = now

      const w = canvas.offsetWidth
      const h = canvas.offsetHeight
      ctx.clearRect(0, 0, w, h)

      for (const p of particles) {
        p.x += p.vx
        p.y += p.vy
        if (p.x < 0) p.x = w
        if (p.x > w) p.x = 0
        if (p.y < 0) p.y = h
        if (p.y > h) p.y = 0

        ctx.beginPath()
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
        ctx.fillStyle = p.color
        ctx.globalAlpha = p.alpha
        ctx.fill()
      }

      // Draw connections — use squared distance to avoid sqrt per pair
      const CONN_DIST_SQ = 120 * 120
      ctx.globalAlpha = connectionAlpha
      ctx.strokeStyle = connectionColor
      ctx.lineWidth = 0.5
      ctx.beginPath() // Single path for all lines — much fewer draw calls
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x
          const dy = particles[i].y - particles[j].y
          if (dx * dx + dy * dy < CONN_DIST_SQ) {
            ctx.moveTo(particles[i].x, particles[i].y)
            ctx.lineTo(particles[j].x, particles[j].y)
          }
        }
      }
      ctx.stroke() // Single stroke call for all connections
      ctx.globalAlpha = 1
    }
    raf = requestAnimationFrame(animate)

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [count, resolvedColors, speed, connectionColor, connectionAlpha])

  return (
    <canvas
      ref={canvasRef}
      className={`absolute inset-0 pointer-events-none ${className}`}
      style={{ width: '100%', height: '100%' }}
    />
  )
})

// ─── Gradient Breath (slow-pulsing gradient) ───

const GRADIENT_COLORS_DARK: [string, string, string] = ['#0D9488', '#E879F9', '#F59E0B']
const GRADIENT_COLORS_LIGHT: [string, string, string] = ['#0D9488', '#A21CAF', '#D97706']

interface GradientBreathProps {
  className?: string
  colors?: [string, string, string]
  duration?: number
}

export function GradientBreath({
  className = '',
  colors,
  duration = 8,
}: GradientBreathProps) {
  const { theme } = useTheme()
  const resolvedColors = colors ?? (theme === 'light' ? GRADIENT_COLORS_LIGHT : GRADIENT_COLORS_DARK)
  // Light mode needs higher alpha so gradients are visible on bright backgrounds
  const [a1, a2, a3] = theme === 'light' ? ['40', '35', '28'] : ['15', '10', '08']
  // Wider gradient spread in light mode so background isn't flat white
  const spread = theme === 'light' ? '65%' : '50%'

  // Use pure CSS animation instead of framer-motion to reduce JS overhead
  return (
    <div
      className={`absolute inset-0 pointer-events-none animate-gradient-breathe ${className}`}
      style={{
        background: `radial-gradient(ellipse at 30% 50%, ${resolvedColors[0]}${a1} 0%, transparent ${spread}),
                     radial-gradient(ellipse at 70% 30%, ${resolvedColors[1]}${a2} 0%, transparent ${spread}),
                     radial-gradient(ellipse at 50% 80%, ${resolvedColors[2]}${a3} 0%, transparent ${spread})`,
        animationDuration: `${duration}s`,
      }}
    />
  )
}

// ─── Bioluminescent Glow (color-shifting orb variant) ───

interface BioluminescentGlowProps {
  className?: string
  size?: number
  delay?: number
}

export function BioluminescentGlow({
  className = '',
  size = 400,
  delay = 0,
}: BioluminescentGlowProps) {
  const { theme } = useTheme()

  // Use pure CSS animation instead of framer-motion to avoid JS overhead.
  // The float-slow keyframe handles x/y/scale; we just set the gradient as static background.
  const bg = theme === 'light'
    ? 'radial-gradient(circle, rgba(13,148,136,0.22) 0%, rgba(162,28,175,0.12) 50%, transparent 75%)'
    : 'radial-gradient(circle, rgba(13,148,136,0.2) 0%, rgba(232,121,249,0.1) 50%, transparent 70%)'

  return (
    <div
      className={`absolute rounded-full pointer-events-none blur-2xl animate-float-slow ${className}`}
      style={{
        width: size,
        height: size,
        background: bg,
        animationDelay: `${delay}s`,
        animationDuration: '16s',
      }}
    />
  )
}

// Re-export motion for use in other components
// eslint-disable-next-line react-refresh/only-export-components -- re-exports framer-motion primitives so callers import from one module
export { motion, useInView, useScroll, useTransform }
