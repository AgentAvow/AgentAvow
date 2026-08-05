import { useEffect, useRef, useState } from 'react'
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { motion, useReducedMotion } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import { AtmosphericBackground } from '../components/AtmosphericBackground'
import { useAuth } from '../hooks/useAuth'
import api from '../lib/api'

/**
 * Signed-in account controls: a notifications bell (unread count from the real
 * /notifications API) + an avatar dropdown (My watches, Settings, Admin, Sign out).
 * Signed-out: a plain "Sign in" link. Settings/Admin reuse the existing app.
 */
function AccountMenu() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  const { data: unread } = useQuery({
    queryKey: ['rebrand-unread'],
    queryFn: async () => (await api.get<{ unread_count: number }>('/notifications/unread-count')).data,
    enabled: !!user,
    refetchInterval: 60_000,
  })

  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [open])

  if (!user) {
    return <Link to="/rebrand/login" className="text-[14px] text-text-muted hover:text-text transition-colors">Sign in</Link>
  }

  const count = unread?.unread_count ?? 0
  const initial = user.display_name?.charAt(0).toUpperCase() || '?'

  return (
    <div className="flex items-center gap-3" ref={ref}>
      <Link to="/rebrand/account" className="relative p-1 text-text-muted hover:text-text transition-colors" aria-label={`Notifications${count ? `, ${count} unread` : ''}`}>
        <svg viewBox="0 0 24 24" fill="none" className="w-[19px] h-[19px]"><path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /><path d="M13.7 21a2 2 0 0 1-3.4 0" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" /></svg>
        {count > 0 && <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-[16px] px-1 grid place-items-center rounded-full bg-accent text-white text-[10px] font-bold tabular-nums">{count > 9 ? '9+' : count}</span>}
      </Link>
      <div className="relative">
        <button onClick={() => setOpen(!open)} className="flex items-center gap-2 group" aria-label="Account menu">
          <span className="w-8 h-8 rounded-full grid place-items-center text-[13px] font-bold text-white bg-gradient-to-br from-primary to-accent">{initial}</span>
        </button>
        {open && (
          <div className="absolute right-0 mt-2 w-52 glass rounded-xl border border-border/60 shadow-xl py-1.5 z-30">
            <div className="px-3.5 py-2 border-b border-border/60">
              <div className="text-[13.5px] font-semibold truncate">{user.display_name}</div>
              <div className="text-[11.5px] text-text-muted truncate">{user.email}</div>
            </div>
            <Link to="/rebrand/account" onClick={() => setOpen(false)} className="block px-3.5 py-2 text-[13.5px] text-text-muted hover:text-text hover:bg-surface">My watches</Link>
            <a href="/settings" className="block px-3.5 py-2 text-[13.5px] text-text-muted hover:text-text hover:bg-surface">Settings</a>
            {user.is_admin && <a href="/admin" className="block px-3.5 py-2 text-[13.5px] text-text-muted hover:text-text hover:bg-surface">Admin</a>}
            <button onClick={() => { setOpen(false); logout(); navigate('/rebrand') }} className="block w-full text-left px-3.5 py-2 text-[13.5px] text-text-muted hover:text-danger hover:bg-surface border-t border-border/60 mt-1">Sign out</button>
          </div>
        )}
      </div>
    </div>
  )
}

/**
 * Isolated shell for the AgentAvow rebrand sandbox (/rebrand/*).
 *
 * Deliberately does NOT import the old Layout — this keeps the live site's
 * header/footer/nav untouched. Uses the existing design system (index.css
 * utility classes + Tailwind color tokens), so it looks native without
 * depending on the social-era components.
 */

/**
 * Animated wordmark — on hover the outer ring sweeps and the checkmark redraws.
 * `id` keeps the gradient/def ids unique between the header and footer instances.
 */
function Wordmark({ id = 'hdr' }: { id?: string }) {
  const reduce = useReducedMotion()
  return (
    <motion.span
      className="group flex items-center gap-2 font-bold text-[17px] tracking-tight cursor-pointer"
      initial="rest"
      whileHover="hover"
      animate="rest"
    >
      <svg viewBox="0 0 24 24" fill="none" className="w-6 h-6" aria-hidden="true">
        {/* outer gradient ring — rotates on hover */}
        <motion.circle
          cx="12" cy="12" r="9.3" stroke={`url(#av-g-${id})`} strokeWidth="1.7"
          style={{ transformBox: 'fill-box', transformOrigin: 'center' }}
          variants={reduce ? {} : { rest: { scale: 1 }, hover: { scale: [1, 1.09, 1] } }}
          transition={{ duration: 0.5, ease: 'easeInOut' }}
        />
        <circle cx="12" cy="12" r="5.2" stroke="var(--color-primary-light)" strokeWidth="1.2" opacity="0.5" />
        {/* checkmark — redraws on hover via dash offset */}
        <motion.path
          d="M8.6 12.2l2.3 2.3 4.6-4.9" stroke="var(--color-primary-light)" strokeWidth="2"
          strokeLinecap="round" strokeLinejoin="round" pathLength={1}
          variants={reduce ? {} : { rest: { pathLength: 1, opacity: 1 }, hover: { pathLength: [0, 1], opacity: 1 } }}
          transition={{ duration: 0.5, ease: 'easeOut', delay: 0.15 }}
        />
        <defs>
          <linearGradient id={`av-g-${id}`} x1="0" y1="0" x2="24" y2="24">
            <stop stopColor="#2DD4BF" />
            <stop offset="1" stopColor="#E879F9" />
          </linearGradient>
        </defs>
      </svg>
      AgentAvow<span className="text-text-muted font-medium">™</span>
    </motion.span>
  )
}

export default function RebrandLayout() {
  const { pathname } = useLocation()

  // Rebrand-only favicon + title swap — restored on unmount so the live site
  // (which shares index.html) keeps its own identity until the real cutover.
  useEffect(() => {
    const iconEl = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
    const prevIcon = iconEl?.getAttribute('href') ?? null
    const prevTitle = document.title
    if (iconEl) iconEl.setAttribute('href', '/favicon-avow.svg')
    document.title = 'AgentAvow — Trust for the tools your agents connect to'
    return () => {
      if (iconEl && prevIcon) iconEl.setAttribute('href', prevIcon)
      document.title = prevTitle
    }
  }, [])
  const link = (to: string, label: string) => (
    <Link
      to={to}
      className={`text-[14.5px] transition-colors ${
        pathname === to ? 'text-text' : 'text-text-muted hover:text-text'
      }`}
    >
      {label}
    </Link>
  )

  return (
    <div className="min-h-screen bg-background text-text">
      {/* prototype ribbon so reviewers know this is the sandbox */}
      <div className="w-full text-center text-[11px] tracking-wide py-1 bg-primary/10 text-primary-light font-mono">
        AgentAvow rebrand preview · sandbox at /rebrand · not the live site
      </div>

      <header className="sticky top-0 z-20 glass border-b border-border/60">
        <div className="max-w-[1080px] mx-auto px-6 h-[62px] flex items-center gap-7">
          <Link to="/rebrand" aria-label="AgentAvow home">
            <Wordmark />
          </Link>
          <nav className="hidden md:flex items-center gap-6 ml-2">
            {link('/rebrand/browse', 'Browse')}
            {link('/rebrand/badge', 'For developers')}
            {link('/rebrand/docs', 'Docs')}
          </nav>
          <div className="ml-auto flex items-center gap-4">
            <AccountMenu />
            <Link
              to="/rebrand/check"
              className="text-[13.5px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow"
            >
              Check a tool
            </Link>
          </div>
        </div>
      </header>

      <main>
        <AtmosphericBackground>
          {/* per-route entrance — a gentle fade+rise on every navigation.
              Keyed on pathname; no exit anim (plays nice with lazy/Suspense). */}
          <motion.div
            key={pathname}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.32, ease: 'easeOut' }}
          >
            <Outlet />
          </motion.div>
        </AtmosphericBackground>
      </main>

      <footer className="relative z-10 bg-background border-t border-border/60 mt-8">
        <div className="max-w-[1080px] mx-auto px-6 py-10">
          <div className="flex flex-wrap items-center justify-between gap-5">
            <Wordmark id="ftr" />
            <div className="flex flex-wrap gap-5 text-[14px] text-text-muted">
              <Link to="/rebrand/docs" className="hover:text-text">Docs</Link>
              <a href="/api/v1/redoc" target="_blank" rel="noopener noreferrer" className="hover:text-text">API</a>
              <a href="/.well-known/jwks.json" target="_blank" rel="noopener noreferrer" className="hover:text-text">Verify keys</a>
              <Link to="/rebrand/legal/terms" className="hover:text-text">Terms</Link>
              <Link to="/rebrand/legal/privacy" className="hover:text-text">Privacy</Link>
              <a href="/" className="hover:text-text">Community ↗</a>
            </div>
          </div>
          <div className="mt-6 flex items-center justify-between gap-4 flex-wrap">
            <div className="font-mono text-[12px] text-text-muted/70">
              A trust score you can verify. · © {new Date().getFullYear()} AgentAvow
            </div>
            <div className="flex items-center gap-5">
              <a href="https://github.com/agentgraph-co/agentgraph" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text transition-colors" aria-label="GitHub">
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>
              </a>
              <a href="https://bsky.app/profile/agentavow.bsky.social" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text transition-colors" aria-label="Bluesky">
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M12 10.8c-1.087-2.114-4.046-6.053-6.798-7.995C2.566.944 1.561 1.266.902 1.565.139 1.908 0 3.08 0 3.768c0 .69.378 5.65.624 6.479.785 2.627 3.6 3.476 6.18 3.232-4.165.712-8.232 2.625-4.412 8.51C5.777 26.373 11.268 21.248 12 17.04c.732 4.208 6.13 9.282 9.608 4.95 3.82-5.886-.247-7.799-4.412-8.511 2.58.244 5.395-.605 6.18-3.232.246-.828.624-5.79.624-6.479 0-.688-.139-1.86-.902-2.203-.659-.299-1.664-.621-4.3 1.24C16.046 4.748 13.087 8.687 12 10.8z"/></svg>
              </a>
              <a href="https://x.com/agentavow" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text transition-colors" aria-label="X">
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
              </a>
              <a href="https://huggingface.co/agentavow" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text transition-colors" aria-label="Hugging Face">
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M10.7 2.08C8.26 2.5 6.2 4.14 5.36 6.42c-.3.8-.4 1.26-.45 2.15-.04.6-.1 1-.18 1.16a3.03 3.03 0 0 0-.2.73c-.02.3.03.6.16.93.08.2.1.3.06.42a2.7 2.7 0 0 0-.04 1.35c.13.5.4.93.83 1.3.15.13.17.18.2.42.12 1.22.7 2.3 1.66 3.1.26.2.82.55.97.6.07.01.05.06-.1.3-.36.52-.56 1.02-.65 1.59l-.04.32-1.17.08c-1.12.06-1.2.07-1.5.18-.67.26-1.06.68-1.3 1.42-.1.28-.1.3-.07.45.02.14.05.17.18.24.24.11.44.1.6-.03.08-.07.13-.18.22-.5.14-.46.28-.68.54-.83.23-.14.34-.16 1.16-.22l.7-.04.03.2c.06.45.27 1 .5 1.3l.12.16-.17.1c-.56.37-.85.58-1.13.84-.65.63-.9 1.24-.77 1.86.04.17.06.2.18.26.1.06.17.07.27.04.17-.04.28-.17.34-.4.1-.33.26-.56.61-.87.3-.26.64-.5 1.17-.8l.27-.15.2.14c.3.2.73.4 1.12.52l.24.06v.37c0 .7.1 1.12.36 1.56.12.2.16.24.28.27.23.05.4-.04.47-.24.04-.15.01-.3-.13-.56-.16-.28-.22-.54-.22-1.01v-.38l.23-.01c.3-.02.82-.14 1.13-.25a3.85 3.85 0 0 0 1.17-.7l.18-.17.12.13c.3.33.5.48.84.66.22.12.27.13.48.13s.27-.01.5-.13c.33-.18.54-.33.83-.66l.12-.13.18.17c.3.28.72.53 1.17.7.3.11.82.23 1.12.25l.24.01v.38c0 .47-.06.73-.22 1.01-.14.26-.17.41-.13.56.07.2.24.29.47.24.12-.03.16-.06.28-.27.27-.44.37-.86.36-1.56v-.37l.24-.07c.4-.11.82-.3 1.12-.51l.2-.14.27.16c.53.3.87.53 1.17.79.35.31.52.54.6.87.07.23.18.36.35.4.1.03.17.02.27-.04.12-.06.14-.09.18-.26.13-.62-.12-1.23-.77-1.86-.28-.27-.57-.47-1.13-.83l-.17-.1.12-.17c.23-.3.44-.85.5-1.3l.03-.2.7.05c.82.06.93.08 1.16.22.26.15.4.37.54.83.1.32.14.43.22.5.16.13.36.14.6.03.13-.07.16-.1.18-.24.03-.15.02-.17-.07-.45-.24-.74-.63-1.16-1.3-1.42-.3-.11-.38-.12-1.5-.18l-1.17-.08-.04-.32a3.12 3.12 0 0 0-.65-1.6c-.15-.23-.17-.28-.1-.29.15-.05.71-.4.97-.6a4.22 4.22 0 0 0 1.66-3.1c.03-.24.05-.3.2-.42.42-.37.7-.8.83-1.3a2.7 2.7 0 0 0-.04-1.35c-.04-.13-.02-.22.06-.42.13-.33.18-.62.16-.93a3.03 3.03 0 0 0-.2-.73c-.08-.16-.14-.55-.18-1.16-.05-.89-.16-1.35-.44-2.15C17.8 4.14 15.74 2.5 13.3 2.08a6.66 6.66 0 0 0-2.6 0zm-.33 6.35c.4.17.6.4.73.82.07.22.07.66 0 .88-.12.4-.36.66-.72.81-.22.09-.27.1-.55.1-.28 0-.33-.01-.54-.1a1.08 1.08 0 0 1-.57-.55c-.1-.23-.12-.31-.12-.62 0-.3.02-.39.11-.6.17-.37.46-.6.86-.72.18-.05.6.01.8.1zm4.33-.1c.4.11.7.35.86.72.1.21.11.3.11.6 0 .31-.02.39-.12.62-.11.25-.3.44-.57.55-.21.09-.26.1-.54.1-.28 0-.33-.01-.55-.1a1.11 1.11 0 0 1-.72-.81c-.07-.22-.07-.66 0-.88.12-.42.34-.65.73-.82.2-.09.62-.06.8.01zm-5.62 4.3c.13.08.16.18.14.41-.08.7.19 1.49.72 2.1.43.5 1.13.93 1.8 1.1.34.1 1.02.1 1.36 0 .67-.17 1.37-.6 1.8-1.1.53-.61.8-1.4.72-2.1-.02-.23 0-.33.14-.41.12-.07.31-.06.41.03.12.12.14.23.1.69-.06.75-.32 1.38-.82 2.01-.7.88-1.74 1.4-2.86 1.4-1.12.01-2.17-.51-2.86-1.4-.5-.63-.76-1.26-.82-2.01-.03-.46 0-.57.1-.69.1-.09.3-.1.41-.03z"/></svg>
              </a>
              <a href="https://dev.to/agentavow" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text transition-colors" aria-label="dev.to">
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M7.42 10.05c-.18-.16-.46-.23-.84-.23H6v4.36h.58c.37 0 .67-.08.84-.23.2-.18.3-.46.3-.94v-2.02c0-.48-.1-.76-.3-.94zM0 4.94v14.12h24V4.94H0zM8.56 15.3c-.44.58-1.06.77-1.94.77H4.84V8.1h1.86c.84 0 1.44.2 1.86.62.46.46.62 1.12.62 2.12v2.36c0 1-.2 1.66-.62 2.1zm5.02-5.36H11.3v1.98h1.5v1.28H11.3v1.98h2.28v1.28H10.5c-.46 0-.84-.34-.84-.78V8.92c0-.44.38-.78.84-.78h3.08v1.28zm4.22 5.9c-.6 1.46-1.38 1.1-1.78 0L14.1 8.12h1.5l1.38 6.64 1.38-6.64h1.5l-2.06 7.68z"/></svg>
              </a>
              {/* TODO(cutover): update LinkedIn URL once the AgentAvow company page exists — Kenne to supply post-cutover */}
              <a href="https://www.linkedin.com/company/agentavow" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text transition-colors" aria-label="LinkedIn">
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M20.45 20.45h-3.56v-5.57c0-1.33-.02-3.04-1.85-3.04-1.85 0-2.13 1.45-2.13 2.94v5.67H9.35V9h3.41v1.56h.05c.48-.9 1.63-1.85 3.36-1.85 3.6 0 4.27 2.37 4.27 5.45v6.29zM5.34 7.43a2.06 2.06 0 1 1 0-4.13 2.06 2.06 0 0 1 0 4.13zm1.78 13.02H3.56V9h3.56v11.45zM22.22 0H1.77C.79 0 0 .77 0 1.72v20.56C0 23.23.79 24 1.77 24h20.45c.98 0 1.78-.77 1.78-1.72V1.72C24 .77 23.2 0 22.22 0z"/></svg>
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
