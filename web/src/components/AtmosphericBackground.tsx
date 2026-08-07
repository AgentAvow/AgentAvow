import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { useLocation } from 'react-router-dom'
import { motion, useScroll, useTransform } from 'framer-motion'
import { GradientBreath } from './Motion'
import { useTheme } from '../hooks/useTheme'
import heroArt from '../assets/hero-art.png'

// ─── Types ───

type Intensity = 'none' | 'subtle' | 'medium' | 'full'

// ─── Reduced Motion Hook ───

function getReducedMotion() {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

function subscribeReducedMotion(cb: () => void) {
  const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
  mq.addEventListener('change', cb)
  return () => mq.removeEventListener('change', cb)
}

function useReducedMotion() {
  return useSyncExternalStore(subscribeReducedMotion, getReducedMotion, () => false)
}

// ─── Tab Visibility Hook ───
// Pauses animations when the browser tab is hidden to save CPU/GPU.

function useTabVisible() {
  const [visible, setVisible] = useState(!document.hidden)
  useEffect(() => {
    const handler = () => setVisible(!document.hidden)
    document.addEventListener('visibilitychange', handler)
    return () => document.removeEventListener('visibilitychange', handler)
  }, [])
  return visible
}

// ─── Route → Intensity Mapping ───

const exactRoutes: Record<string, Intensity> = {
  '/': 'none',            // Home.tsx handles its own
  '/login': 'medium',
  '/register': 'medium',
  '/verify-email': 'none',
  '/forgot-password': 'medium',
  '/reset-password': 'medium',
  '/dashboard': 'full',
  '/feed': 'medium',
  '/search': 'medium',
  '/graph': 'medium',
  '/discover': 'medium',
  '/communities': 'medium',
  '/marketplace': 'medium',
  '/leaderboard': 'medium',
  '/notifications': 'medium',
  '/messages': 'medium',
  '/settings': 'subtle',
  '/agents': 'subtle',
  '/webhooks': 'subtle',
  '/bookmarks': 'subtle',
  '/transactions': 'subtle',
  '/disputes': 'subtle',
  '/marketplace/create': 'subtle',
  '/my-listings': 'subtle',
  '/tools': 'subtle',
  '/bot-onboarding': 'medium',
  '/developers': 'medium',
  '/docs': 'medium',
  '/faq': 'medium',
  '/sandbox': 'medium',
  '/badges': 'medium',
  '/check': 'medium',
  '/x402': 'medium',
  '/state-of-agent-security-2026': 'medium',
  '/scans': 'medium',
  '/admin': 'none',
}

const prefixRoutes: Array<[string, Intensity]> = [
  ['/rebrand', 'medium'],
  ['/profile/', 'medium'],
  ['/post/', 'medium'],
  ['/m/', 'medium'],
  ['/trust/', 'medium'],
  ['/evolution/', 'medium'],
  ['/marketplace/', 'medium'],
  ['/agent/', 'medium'],
  ['/legal/', 'medium'],
  ['/docs/', 'medium'],
  ['/check/', 'medium'],
]

function getIntensity(pathname: string): Intensity {
  const exact = exactRoutes[pathname]
  if (exact !== undefined) return exact
  for (const [prefix, intensity] of prefixRoutes) {
    if (pathname.startsWith(prefix)) return intensity
  }
  return 'none'
}

// ─── Parallax Hero Face ───
// Shows on medium + full intensity pages in both themes.
// Parallax: moves slower than scroll giving depth.
// Over content areas it's very subtle; more visible at page top.

function ParallaxHeroFace({ intensity, reducedMotion }: { intensity: Intensity; reducedMotion: boolean }) {
  const { theme } = useTheme()
  const ref = useRef<HTMLDivElement>(null)
  const { scrollY } = useScroll()

  // Parallax: face moves at 30% of scroll speed
  const y = useTransform(scrollY, [0, 1000], [0, -300])
  // Fade out as user scrolls into content
  const scrollOpacity = useTransform(scrollY, [0, 400], [1, 0.3])

  // Base opacity varies by intensity and theme
  const baseOpacity = theme === 'light'
    ? (intensity === 'full' ? 0.20 : 0.14)
    : (intensity === 'full' ? 0.22 : 0.12)

  return (
    <motion.div
      ref={ref}
      className="absolute inset-0 flex items-center justify-center pointer-events-none overflow-hidden"
      style={reducedMotion ? { opacity: 0.7 } : { y, opacity: scrollOpacity }}
    >
      <img
        src={heroArt}
        alt=""
        aria-hidden="true"
        className={`w-full h-full object-cover ${reducedMotion ? '' : 'animate-hero-breathe'}`}
        style={{
          opacity: baseOpacity,
          mixBlendMode: theme === 'light' ? 'multiply' : 'screen',
          filter: theme === 'light' ? 'contrast(1.2) brightness(0.9)' : 'none',
          // The bottom fade is now baked into hero-art.png's alpha channel (fades
          // with the image content regardless of object-cover crop), so no CSS mask.
        }}
      />
      {/* Vignette — fades edges into the background color */}
      <div
        className="absolute inset-0"
        style={{
          background: 'radial-gradient(ellipse at center, transparent 20%, var(--color-background) 70%)',
        }}
      />
      {/* Bottom fade is now handled by the image mask above (fades to transparent,
          so the atmosphere shows through instead of an opaque band). */}
    </motion.div>
  )
}

// ─── Hero-confined face ───
// Instead of a fixed full-viewport background, the head lives only in the top
// hero (one viewport tall) and scrolls away with the page, so lower sections and
// the footer sit on clean dark. Used by the rebrand (confineFaceToHero).

function HeroFace({ reducedMotion }: { reducedMotion: boolean }) {
  const { theme } = useTheme()
  return (
    <div className="absolute top-0 inset-x-0 h-screen z-0 pointer-events-none overflow-hidden">
      <img
        src={heroArt}
        alt=""
        aria-hidden="true"
        className={`w-full h-full object-cover ${reducedMotion ? '' : 'animate-hero-breathe'}`}
        style={{
          opacity: theme === 'light' ? 0.16 : 0.15,
          mixBlendMode: theme === 'light' ? 'multiply' : 'screen',
          filter: theme === 'light' ? 'contrast(1.2) brightness(0.9)' : 'none',
          // Fade the head out toward the bottom of the hero so it dissolves before
          // the first section — no hard edge where the hero ends.
          maskImage: 'linear-gradient(to bottom, #000 30%, transparent 82%)',
          WebkitMaskImage: 'linear-gradient(to bottom, #000 30%, transparent 82%)',
        }}
      />
    </div>
  )
}

// ─── Network Pulse — Canvas-based animated mycelium lines ───
// Renders 18 flowing connection paths + 11 pulsing junction nodes in a single
// canvas pass instead of 29 separate CSS-animated SVG elements.
// - Same visual as previous SVG: quadratic bezier paths with stroke-dash flow
// - Throttled to ~24fps to minimize CPU/GPU overhead
// - Pauses automatically when tab is hidden
// - Draws static frame for prefers-reduced-motion

// Ease-in-out quadratic — matches CSS ease-in-out timing
function easeInOut(t: number): number {
  return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2
}

// Path data extracted 1:1 from the previous SVG paths.
// Each entry: [startX, startY, controlX, controlY, endX, endY, color, delaySeconds]
const PATHS: [number, number, number, number, number, number, string, number][] = [
  // Central web
  [600,400, 520,350, 420,380, '#2DD4BF', 0],
  [600,400, 680,340, 780,360, '#E879F9', 3],
  [600,400, 560,480, 480,520, '#F59E0B', 6],
  [600,400, 660,490, 760,510, '#2DD4BF', 9],
  [600,400, 580,310, 560,240, '#E879F9', 2],
  [600,400, 640,310, 680,230, '#F59E0B', 5],
  // Left tendrils
  [420,380, 350,340, 280,360, '#2DD4BF', 1],
  [280,360, 220,310, 160,340, '#F59E0B', 4],
  [420,380, 380,440, 340,480, '#E879F9', 7],
  [160,340, 110,290, 80,250,  '#2DD4BF', 10],
  // Right tendrils
  [780,360, 850,320, 920,350, '#E879F9', 2.5],
  [920,350, 980,310, 1040,330,'#2DD4BF', 5.5],
  [780,360, 820,420, 880,450, '#F59E0B', 8],
  [1040,330,1090,290,1140,310,'#F59E0B', 11],
  // Top branches
  [560,240, 500,190, 440,200, '#2DD4BF', 3.5],
  [680,230, 730,180, 780,190, '#F59E0B', 6.5],
  // Bottom branches
  [480,520, 430,570, 380,580, '#2DD4BF', 4.5],
  [760,510, 810,560, 860,570, '#E879F9', 7.5],
]

// Node data extracted 1:1 from the previous SVG circles.
// Each entry: [cx, cy, radius, fillColor, delaySeconds]
const NODES: [number, number, number, string, number][] = [
  [600, 400, 3,   '#2DD4BF', 0],
  [420, 380, 2,   '#2DD4BF', 1],
  [780, 360, 2.5, '#E879F9', 2],
  [480, 520, 2,   '#F59E0B', 3],
  [760, 510, 1.5, '#2DD4BF', 4],
  [560, 240, 2,   '#E879F9', 5],
  [680, 230, 1.5, '#F59E0B', 6],
  [280, 360, 1.5, '#E879F9', 1.5],
  [920, 350, 2,   '#F59E0B', 3.5],
  [160, 340, 1.5, '#2DD4BF', 5.5],
  [1040,330, 1.5, '#E879F9', 7.5],
]

// Viewbox dimensions matching the previous SVG
const VW = 1200
const VH = 800
const CYCLE = 12   // path flow cycle in seconds
const PULSE_CYCLE = 4 // node pulse cycle in seconds
const FRAME_INTERVAL = 42 // ~24fps

function drawFrame(ctx: CanvasRenderingContext2D, w: number, h: number, t: number) {
  // Cover scaling — matches SVG preserveAspectRatio="xMidYMid slice"
  const scale = Math.max(w / VW, h / VH)
  const ox = (w - VW * scale) / 2
  const oy = (h - VH * scale) / 2

  ctx.clearRect(0, 0, w, h)

  // ── Draw flowing paths ──
  ctx.lineWidth = 0.8 * scale
  for (const [sx, sy, cpx, cpy, ex, ey, color, delay] of PATHS) {
    const elapsed = ((t - delay) % CYCLE + CYCLE) % CYCLE
    const progress = elapsed / CYCLE
    let dashOffset: number, alpha: number
    if (progress < 0.5) {
      const e = easeInOut(progress * 2)
      dashOffset = 400 * (1 - e)
      alpha = 0.2 + 0.6 * e
    } else {
      const e = easeInOut((progress - 0.5) * 2)
      dashOffset = -400 * e
      alpha = 0.8 - 0.6 * e
    }
    ctx.setLineDash([80 * scale, 320 * scale])
    ctx.lineDashOffset = dashOffset * scale
    ctx.globalAlpha = alpha
    ctx.strokeStyle = color
    ctx.beginPath()
    ctx.moveTo(sx * scale + ox, sy * scale + oy)
    ctx.quadraticCurveTo(cpx * scale + ox, cpy * scale + oy, ex * scale + ox, ey * scale + oy)
    ctx.stroke()
  }

  // ── Draw pulsing nodes ──
  ctx.setLineDash([])
  for (const [cx, cy, r, fill, delay] of NODES) {
    const elapsed = ((t - delay) % PULSE_CYCLE + PULSE_CYCLE) % PULSE_CYCLE
    const progress = elapsed / PULSE_CYCLE
    let a: number, s: number
    if (progress < 0.5) {
      const e = easeInOut(progress * 2)
      a = 0.4 + 0.3 * e
      s = 1 + 0.05 * e
    } else {
      const e = easeInOut((progress - 0.5) * 2)
      a = 0.7 - 0.3 * e
      s = 1.05 - 0.05 * e
    }
    ctx.globalAlpha = a
    ctx.fillStyle = fill
    ctx.beginPath()
    ctx.arc(cx * scale + ox, cy * scale + oy, r * s * scale, 0, Math.PI * 2)
    ctx.fill()
  }

  ctx.globalAlpha = 1
}

function NetworkPulseCanvas({ opacity = 0.12, reducedMotion = false }: { opacity?: number; reducedMotion?: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let w = 0, h = 0
    const resize = () => {
      const dpr = window.devicePixelRatio || 1
      w = canvas.offsetWidth
      h = canvas.offsetHeight
      canvas.width = w * dpr
      canvas.height = h * dpr
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }
    resize()
    window.addEventListener('resize', resize)

    // Reduced motion: draw one static frame and stop
    if (reducedMotion) {
      drawFrame(ctx, w, h, 6) // t=6s gives a natural mid-cycle snapshot
      return () => window.removeEventListener('resize', resize)
    }

    let raf = 0
    let lastFrame = 0
    let paused = document.hidden

    const onVisibility = () => { paused = document.hidden }
    document.addEventListener('visibilitychange', onVisibility)

    const animate = (now: number) => {
      raf = requestAnimationFrame(animate)
      if (paused) return
      if (now - lastFrame < FRAME_INTERVAL) return
      lastFrame = now
      drawFrame(ctx, w, h, now / 1000)
    }
    raf = requestAnimationFrame(animate)

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [reducedMotion])

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 w-full h-full pointer-events-none"
      style={{ opacity }}
    />
  )
}

// ─── Subtle Layer (pure CSS, no JS animations) ───

function SubtleLayer({ reducedMotion }: { reducedMotion: boolean }) {
  const { theme } = useTheme()
  // Light mode needs stronger gradients to be visible
  const alpha = theme === 'light' ? 1 : 0.3

  return (
    <div
      className={`absolute inset-0 pointer-events-none ${reducedMotion ? '' : 'animate-gradient-breathe'}`}
      style={{
        opacity: alpha,
        background: theme === 'light'
          ? `
            radial-gradient(ellipse at 20% 50%, rgba(13,148,136,0.08) 0%, transparent 50%),
            radial-gradient(ellipse at 80% 30%, rgba(162,28,175,0.06) 0%, transparent 50%),
            radial-gradient(ellipse at 50% 80%, rgba(217,119,6,0.05) 0%, transparent 50%)
          `
          : `
            radial-gradient(ellipse at 20% 50%, rgba(13,148,136,0.12) 0%, transparent 50%),
            radial-gradient(ellipse at 80% 30%, rgba(232,121,249,0.08) 0%, transparent 50%),
            radial-gradient(ellipse at 50% 80%, rgba(245,158,11,0.06) 0%, transparent 50%)
          `,
      }}
    />
  )
}

// ─── Medium Layer ───
// GradientBreath + parallax face + canvas network pulse.

function MediumLayer({ reducedMotion, showFace = true }: { reducedMotion: boolean; showFace?: boolean }) {
  return (
    <>
      <GradientBreath className={reducedMotion ? '' : 'opacity-50'} />
      {showFace && <ParallaxHeroFace intensity="medium" reducedMotion={reducedMotion} />}
      <NetworkPulseCanvas opacity={0.08} reducedMotion={reducedMotion} />
    </>
  )
}

// ─── Full Layer (Dashboard) ───
// Richer gradients + parallax face + canvas network pulse.

function FullLayer({ reducedMotion, showFace = true }: { reducedMotion: boolean; showFace?: boolean }) {
  return (
    <>
      <GradientBreath className={reducedMotion ? '' : ''} />
      {showFace && <ParallaxHeroFace intensity="full" reducedMotion={reducedMotion} />}
      <NetworkPulseCanvas opacity={0.14} reducedMotion={reducedMotion} />
    </>
  )
}

// ─── Auth routes get full-bleed background (no header offset) ───

const authRoutes = new Set(['/login', '/register', '/forgot-password', '/reset-password'])

// ─── Main Component ───

export function AtmosphericBackground({ children, intensity: intensityProp, confineFaceToHero = false }: { children: React.ReactNode; intensity?: Intensity; confineFaceToHero?: boolean }) {
  const location = useLocation()
  const reducedMotion = useReducedMotion()
  const tabVisible = useTabVisible()
  // Explicit override (e.g. the rebrand shell forces 'medium' now that it's at
  // the root and no longer matches the /rebrand prefix). Falls back to route-based.
  const intensity = intensityProp ?? getIntensity(location.pathname)

  if (intensity === 'none') {
    return <>{children}</>
  }

  const isAuth = authRoutes.has(location.pathname)

  return (
    <div className="relative flex-1 flex flex-col">
      {/* Background layers — full viewport width, pinned behind content.
          data-paused pauses remaining CSS animations (hero-breathe, gradient-breathe)
          when the tab is hidden, saving CPU/GPU. */}
      <div
        className="fixed inset-0 pointer-events-none z-0 overflow-hidden"
        style={{ top: isAuth ? 0 : '3.5rem' }}
        data-paused={!tabVisible || undefined}
      >
        {intensity === 'subtle' && <SubtleLayer reducedMotion={reducedMotion} />}
        {intensity === 'medium' && <MediumLayer reducedMotion={reducedMotion} showFace={!confineFaceToHero} />}
        {intensity === 'full' && <FullLayer reducedMotion={reducedMotion} showFace={!confineFaceToHero} />}
      </div>
      {/* Hero-confined head: scrolls away with the page, so only the top hero shows
          it and lower sections + footer stay clean. */}
      {confineFaceToHero && (intensity === 'medium' || intensity === 'full') && <HeroFace reducedMotion={reducedMotion} />}
      <div className="relative z-10 flex-1 flex flex-col">
        {children}
      </div>
    </div>
  )
}

export { getIntensity }
export type { Intensity }
