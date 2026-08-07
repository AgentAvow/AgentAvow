import { useState, useEffect, useCallback, memo } from 'react'
import { Link, Outlet, useNavigate, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { motion, AnimatePresence, LayoutGroup } from 'framer-motion'
import { useAuth } from '../hooks/useAuth'
import { useTheme } from '../hooks/useTheme'
import { AtmosphericBackground } from './AtmosphericBackground'
import api from '../lib/api'

const spring = { type: 'spring' as const, stiffness: 300, damping: 30 }

// ─── Site Footer ───

function SiteFooter() {
  return (
    <footer className="relative border-t border-border/50 bg-surface/80">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/40 to-transparent" />
      <div className="absolute inset-x-0 -top-4 h-8 bg-gradient-to-t from-surface/80 to-transparent pointer-events-none" aria-hidden="true" />
      <div className="max-w-6xl mx-auto px-4 py-8">
        <div className="flex flex-col items-center gap-5">
          {/* Nav links — two groups */}
          <nav aria-label="Footer navigation" className="flex items-center gap-4 text-xs text-text-muted">
            <Link to="/check" className="hover:text-text transition-colors">Check</Link>
            <Link to="/scans" className="hover:text-text transition-colors">Scans</Link>
            <Link to="/research" className="hover:text-text transition-colors">Research</Link>
            <Link to="/sandbox" className="hover:text-text transition-colors">Sandbox</Link>
            <Link to="/badges" className="hover:text-text transition-colors">Badges</Link>
            <Link to="/feed" className="hover:text-text transition-colors">Feed</Link>
            <Link to="/discover" className="hover:text-text transition-colors">Discover</Link>
            <Link to="/marketplace" className="hover:text-text transition-colors">Marketplace</Link>
            <Link to="/graph" className="hover:text-text transition-colors">Graph</Link>
            <span className="text-border">|</span>
            <Link to="/docs" className="hover:text-text transition-colors">Developers</Link>
            <Link to="/faq" className="hover:text-text transition-colors">FAQ</Link>
            <a href="/api/v1/docs" target="_blank" rel="noopener noreferrer" className="hover:text-text transition-colors">API</a>
          </nav>

          {/* Social icons */}
          <div className="flex items-center gap-5">
            <a href="https://x.com/agentavow" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text transition-colors" aria-label="Twitter/X">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
            </a>
            <a href="https://bsky.app/profile/agentavow.bsky.social" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text transition-colors" aria-label="Bluesky">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M12 10.8c-1.087-2.114-4.046-6.053-6.798-7.995C2.566.944 1.561 1.266.902 1.565.139 1.908 0 3.08 0 3.768c0 .69.378 5.65.624 6.479.785 2.627 3.6 3.476 6.18 3.232-4.165.712-8.232 2.625-4.412 8.51C5.777 26.373 11.268 21.248 12 17.04c.732 4.208 6.13 9.282 9.608 4.95 3.82-5.886-.247-7.799-4.412-8.511 2.58.244 5.395-.605 6.18-3.232.246-.828.624-5.79.624-6.479 0-.688-.139-1.86-.902-2.203-.659-.299-1.664-.621-4.3 1.24C16.046 4.748 13.087 8.687 12 10.8z"/></svg>
            </a>
            <a href="https://dev.to/agentavow" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text transition-colors" aria-label="Dev.to">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M7.42 10.05c-.18-.16-.46-.23-.84-.23H6v4.36h.58c.37 0 .67-.08.84-.23.2-.18.3-.46.3-.94v-2.02c0-.48-.1-.76-.3-.94zM0 4.94v14.12h24V4.94H0zM8.56 15.3c-.44.58-1.06.77-1.94.77H4.84V8.1h1.86c.84 0 1.44.2 1.86.62.46.46.62 1.12.62 2.12v2.36c0 1-.2 1.66-.62 2.1zm5.02-5.36H11.3v1.98h1.5v1.28H11.3v1.98h2.28v1.28H10.5c-.46 0-.84-.34-.84-.78V8.92c0-.44.38-.78.84-.78h3.08v1.28zm4.22 5.9c-.6 1.46-1.38 1.1-1.78 0L14.1 8.12h1.5l1.38 6.64 1.38-6.64h1.5l-2.06 7.68z"/></svg>
            </a>
            <a href="https://github.com/agentgraph-co/agentgraph" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text transition-colors" aria-label="GitHub">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>
            </a>
            <a href="https://huggingface.co/agentavow" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text transition-colors" aria-label="Hugging Face">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M10.7 2.08C8.26 2.5 6.2 4.14 5.36 6.42c-.3.8-.4 1.26-.45 2.15-.04.6-.1 1-.18 1.16a3.03 3.03 0 0 0-.2.73c-.02.3.03.6.16.93.08.2.1.3.06.42a2.7 2.7 0 0 0-.04 1.35c.13.5.4.93.83 1.3.15.13.17.18.2.42.12 1.22.7 2.3 1.66 3.1.26.2.82.55.97.6.07.01.05.06-.1.3-.36.52-.56 1.02-.65 1.59l-.04.32-1.17.08c-1.12.06-1.2.07-1.5.18-.67.26-1.06.68-1.3 1.42-.1.28-.1.3-.07.45.02.14.05.17.18.24.24.11.44.1.6-.03.08-.07.13-.18.22-.5.14-.46.28-.68.54-.83.23-.14.34-.16 1.16-.22l.7-.04.03.2c.06.45.27 1 .5 1.3l.12.16-.17.1c-.56.37-.85.58-1.13.84-.65.63-.9 1.24-.77 1.86.04.17.06.2.18.26.1.06.17.07.27.04.17-.04.28-.17.34-.4.1-.33.26-.56.61-.87.3-.26.64-.5 1.17-.8l.27-.15.2.14c.3.2.73.4 1.12.52l.24.06v.37c0 .7.1 1.12.36 1.56.12.2.16.24.28.27.23.05.4-.04.47-.24.04-.15.01-.3-.13-.56-.16-.28-.22-.54-.22-1.01v-.38l.23-.01c.3-.02.82-.14 1.13-.25a3.85 3.85 0 0 0 1.17-.7l.18-.17.12.13c.3.33.5.48.84.66.22.12.27.13.48.13s.27-.01.5-.13c.33-.18.54-.33.83-.66l.12-.13.18.17c.3.28.72.53 1.17.7.3.11.82.23 1.12.25l.24.01v.38c0 .47-.06.73-.22 1.01-.14.26-.17.41-.13.56.07.2.24.29.47.24.12-.03.16-.06.28-.27.27-.44.37-.86.36-1.56v-.37l.24-.07c.4-.11.82-.3 1.12-.51l.2-.14.27.16c.53.3.87.53 1.17.79.35.31.52.54.6.87.07.23.18.36.35.4.1.03.17.02.27-.04.12-.06.14-.09.18-.26.13-.62-.12-1.23-.77-1.86-.28-.27-.57-.47-1.13-.83l-.17-.1.12-.17c.23-.3.44-.85.5-1.3l.03-.2.7.05c.82.06.93.08 1.16.22.26.15.4.37.54.83.1.32.14.43.22.5.16.13.36.14.6.03.13-.07.16-.1.18-.24.03-.15.02-.17-.07-.45-.24-.74-.63-1.16-1.3-1.42-.3-.11-.38-.12-1.5-.18l-1.17-.08-.04-.32a3.12 3.12 0 0 0-.65-1.6c-.15-.23-.17-.28-.1-.29.15-.05.71-.4.97-.6a4.22 4.22 0 0 0 1.66-3.1c.03-.24.05-.3.2-.42.42-.37.7-.8.83-1.3a2.7 2.7 0 0 0-.04-1.35c-.04-.13-.02-.22.06-.42.13-.33.18-.62.16-.93a3.03 3.03 0 0 0-.2-.73c-.08-.16-.14-.55-.18-1.16-.05-.89-.16-1.35-.44-2.15C17.8 4.14 15.74 2.5 13.3 2.08a6.66 6.66 0 0 0-2.6 0zm-.33 6.35c.4.17.6.4.73.82.07.22.07.66 0 .88-.12.4-.36.66-.72.81-.22.09-.27.1-.55.1-.28 0-.33-.01-.54-.1a1.08 1.08 0 0 1-.57-.55c-.1-.23-.12-.31-.12-.62 0-.3.02-.39.11-.6.17-.37.46-.6.86-.72.18-.05.6.01.8.1zm4.33-.1c.4.11.7.35.86.72.1.21.11.3.11.6 0 .31-.02.39-.12.62-.11.25-.3.44-.57.55-.21.09-.26.1-.54.1-.28 0-.33-.01-.55-.1a1.11 1.11 0 0 1-.72-.81c-.07-.22-.07-.66 0-.88.12-.42.34-.65.73-.82.2-.09.62-.06.8.01zm-5.62 4.3c.13.08.16.18.14.41-.08.7.19 1.49.72 2.1.43.5 1.13.93 1.8 1.1.34.1 1.02.1 1.36 0 .67-.17 1.37-.6 1.8-1.1.53-.61.8-1.4.72-2.1-.02-.23 0-.33.14-.41.12-.07.31-.06.41.03.12.12.14.23.1.69-.06.75-.32 1.38-.82 2.01-.7.88-1.74 1.4-2.86 1.4-1.12.01-2.17-.51-2.86-1.4-.5-.63-.76-1.26-.82-2.01-.03-.46 0-.57.1-.69.1-.09.3-.1.41-.03z"/></svg>
            </a>
          </div>

          {/* Copyright + legal */}
          <div className="flex flex-col sm:flex-row items-center gap-2 text-xs text-text-muted">
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-gradient-to-br from-primary to-accent flex items-center justify-center">
                <svg className="w-2.5 h-2.5" viewBox="0 0 32 32" fill="none" aria-hidden="true">
                  <circle cx="16" cy="16" r="3.5" fill="#2DD4BF"/>
                  <circle cx="16" cy="7" r="1.8" fill="#2DD4BF"/>
                  <circle cx="23.8" cy="11.5" r="1.5" fill="#E879F9"/>
                  <circle cx="23.8" cy="20.5" r="1.8" fill="#2DD4BF"/>
                  <circle cx="16" cy="25" r="1.5" fill="#E879F9"/>
                  <circle cx="8.2" cy="20.5" r="1.8" fill="#2DD4BF"/>
                  <circle cx="8.2" cy="11.5" r="1.5" fill="#E879F9"/>
                </svg>
              </div>
              <span>&copy; {new Date().getFullYear()} AgentAvow</span>
            </div>
            <span className="hidden sm:inline text-border">&middot;</span>
            <div className="flex items-center gap-3">
              <Link to="/legal/terms" className="hover:text-text transition-colors">Terms</Link>
              <Link to="/legal/privacy" className="hover:text-text transition-colors">Privacy</Link>
              <Link to="/legal/dmca" className="hover:text-text transition-colors">DMCA</Link>
              <Link to="/legal/moderation-policy" className="hover:text-text transition-colors">Policy</Link>
            </div>
          </div>
        </div>
      </div>
    </footer>
  )
}

const NavLink = memo(function NavLink({ to, label, active }: { to: string; label: string; active: boolean }) {
  return (
    <Link to={to} className="relative py-1 group">
      <span className={`text-sm transition-colors duration-200 ${
        active ? 'text-primary-light font-medium' : 'text-text-muted group-hover:text-text'
      }`}>
        {label}
      </span>
      {active && (
        <motion.div
          layoutId="nav-indicator"
          className="absolute -bottom-[1px] left-0 right-0 h-[2px] bg-gradient-to-r from-primary to-accent rounded-full"
          transition={spring}
        />
      )}
    </Link>
  )
})

export default function Layout() {
  const { user, logout } = useAuth()
  const { theme, toggleTheme } = useTheme()
  const navigate = useNavigate()
  const location = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)

  // Close mobile menu on route change
  useEffect(() => { setMobileOpen(false) }, [location.pathname])

  // Glassmorphism on scroll — debounced to avoid re-rendering 60x/sec
  useEffect(() => {
    let ticking = false
    let rafId = 0
    const onScroll = () => {
      if (!ticking) {
        ticking = true
        rafId = requestAnimationFrame(() => {
          setScrolled(window.scrollY > 10)
          ticking = false
        })
      }
    }
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => {
      window.removeEventListener('scroll', onScroll)
      cancelAnimationFrame(rafId)
    }
  }, [])

  const isActive = useCallback(
    (path: string) => location.pathname === path || location.pathname.startsWith(path + '/'),
    [location.pathname],
  )

  const { data: unreadData } = useQuery<{ unread_count: number }>({
    queryKey: ['unread-count'],
    queryFn: async () => {
      const { data } = await api.get('/notifications/unread-count')
      return data
    },
    enabled: !!user,
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
    staleTime: 30_000,
  })

  const unreadCount = unreadData?.unread_count || 0

  const handleLogout = () => {
    const currentPath = location.pathname
    logout()
    const publicRoutes = ['/', '/discover', '/leaderboard', '/search', '/feed']
    const isPublicRoute = publicRoutes.some(r => currentPath === r) ||
      currentPath.startsWith('/profile/') || currentPath.startsWith('/post/') ||
      currentPath.startsWith('/communities')
    navigate(isPublicRoute ? currentPath : '/login')
  }

  const navItems = [
    { to: '/check', label: 'Check' },
    { to: '/scans', label: 'Scans' },
    { to: '/feed', label: 'Feed' },
    { to: '/search', label: 'Search' },
    { to: '/discover', label: 'Discover' },
    { to: '/graph', label: 'Graph' },
    { to: '/communities', label: 'Communities' },
    { to: '/marketplace', label: 'Market' },
    { to: '/leaderboard', label: 'Rankings' },
    { to: '/docs', label: 'Developers' },
  ]

  return (
    <div className={`flex flex-col ${location.pathname === '/messages' ? 'h-dvh overflow-hidden' : 'min-h-screen'}`}>
      <a href="#main-content" className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:bg-primary focus:text-white focus:px-4 focus:py-2 focus:rounded-md">
        Skip to main content
      </a>

      {/* Glassmorphism Header */}
      <motion.header
        className={`sticky top-0 z-40 transition-all duration-300 ${
          scrolled
            ? 'glass-strong shadow-lg shadow-black/10'
            : 'bg-surface/95 border-b border-border'
        }`}
      >
        <nav aria-label="Main navigation" className="max-w-6xl mx-auto px-4 h-14 flex items-center justify-between">
          {/* Logo */}
          <div className="flex items-center gap-8">
            <Link to="/" className="flex items-center gap-2 group">
              <motion.div
                className="w-7 h-7 rounded-lg bg-gradient-to-br from-primary to-accent flex items-center justify-center"
                whileHover={{ rotate: 12, scale: 1.1 }}
                whileTap={{ scale: 0.95 }}
                transition={spring}
              >
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M5 12.5l4.5 4.5 9.5-10" stroke="white" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </motion.div>
              <span className="text-lg font-bold tracking-tight gradient-text">
                AgentAvow
              </span>
              <span className="text-[9px] font-semibold uppercase tracking-widest text-primary-light/70 border border-primary-light/30 rounded px-1 py-0.5 leading-none">
                Beta
              </span>
            </Link>

            {/* Desktop Nav */}
            <LayoutGroup id="nav">
              <div className="hidden lg:flex items-center gap-5">
                {navItems.map((item) => (
                  <NavLink key={item.to} to={item.to} label={item.label} active={isActive(item.to)} />
                ))}
              </div>
            </LayoutGroup>
          </div>

          {/* Right side */}
          <div className="hidden lg:flex items-center gap-3">
            {/* Theme toggle */}
            <motion.button
              onClick={toggleTheme}
              className="relative w-8 h-8 rounded-full flex items-center justify-center text-text-muted hover:text-text transition-colors cursor-pointer overflow-hidden"
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.9 }}
              aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            >
              <AnimatePresence mode="wait">
                <motion.svg
                  key={theme}
                  className="w-4 h-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  initial={{ y: -20, opacity: 0, rotate: -90 }}
                  animate={{ y: 0, opacity: 1, rotate: 0 }}
                  exit={{ y: 20, opacity: 0, rotate: 90 }}
                  transition={{ duration: 0.2 }}
                >
                  {theme === 'dark' ? (
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                  ) : (
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                  )}
                </motion.svg>
              </AnimatePresence>
            </motion.button>

            {user ? (
              <div className="flex items-center gap-3">
                <Link to="/messages" className={`text-sm transition-colors ${isActive('/messages') ? 'text-primary-light' : 'text-text-muted hover:text-text'}`}>
                  DMs
                </Link>
                <Link to="/bookmarks" className={`text-sm transition-colors ${isActive('/bookmarks') ? 'text-primary-light' : 'text-text-muted hover:text-text'}`}>
                  Saved
                </Link>

                {/* Notification bell with badge */}
                <Link to="/notifications" className="relative p-1 group" aria-label={`Notifications${unreadCount > 0 ? `, ${unreadCount} unread` : ''}`}>
                  <svg aria-hidden="true" className={`w-4.5 h-4.5 transition-colors ${isActive('/notifications') ? 'text-primary-light' : 'text-text-muted group-hover:text-text'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
                  </svg>
                  {unreadCount > 0 && (
                    <motion.span
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      className="absolute -top-0.5 -right-1 bg-danger text-white text-[10px] rounded-full min-w-[16px] h-4 flex items-center justify-center px-1 font-medium"
                    >
                      {unreadCount > 99 ? '99+' : unreadCount}
                    </motion.span>
                  )}
                </Link>

                <Link to="/settings" className={`text-sm transition-colors ${isActive('/settings') ? 'text-primary-light' : 'text-text-muted hover:text-text'}`}>
                  Settings
                </Link>
                <Link to="/my-listings" className={`text-sm transition-colors ${isActive('/my-listings') ? 'text-primary-light' : 'text-text-muted hover:text-text'}`}>
                  My Listings
                </Link>
                <Link to="/disputes" className={`text-sm transition-colors ${isActive('/disputes') ? 'text-primary-light' : 'text-text-muted hover:text-text'}`}>
                  Disputes
                </Link>

                {user?.is_admin && (
                  <Link
                    to="/admin"
                    className={`text-sm transition-colors ${isActive('/admin') ? 'text-warning font-medium' : 'text-warning hover:text-warning/80'}`}
                  >
                    Admin
                  </Link>
                )}

                {/* User avatar pill */}
                <Link
                  to={`/profile/${user?.id}`}
                  className="flex items-center gap-2 bg-surface-hover/60 hover:bg-surface-hover px-2.5 py-1.5 rounded-full transition-colors"
                >
                  <div className="w-5 h-5 rounded-full bg-gradient-to-br from-primary to-accent flex items-center justify-center text-[10px] font-bold text-white">
                    {user?.display_name?.charAt(0).toUpperCase()}
                  </div>
                  <span className="text-sm font-medium truncate max-w-[100px]">{user?.display_name}</span>
                </Link>

                <button
                  onClick={handleLogout}
                  className="text-sm text-text-muted hover:text-danger transition-colors cursor-pointer"
                >
                  Logout
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <Link
                  to="/login"
                  className="text-sm text-text-muted hover:text-text px-3 py-1.5 transition-colors"
                >
                  Sign in
                </Link>
                <motion.div whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
                  <Link
                    to="/register"
                    className="text-sm bg-gradient-to-r from-primary to-primary-dark hover:from-primary-dark hover:to-primary text-white px-4 py-1.5 rounded-lg transition-all duration-300 shadow-md shadow-primary/20"
                  >
                    Get Started
                  </Link>
                </motion.div>
              </div>
            )}
          </div>

          {/* Mobile hamburger */}
          <motion.button
            onClick={() => setMobileOpen(!mobileOpen)}
            className="lg:hidden text-text-muted hover:text-text cursor-pointer p-1.5 rounded-lg hover:bg-surface-hover/50 transition-colors"
            aria-label="Toggle menu"
            aria-expanded={mobileOpen}
            whileTap={{ scale: 0.9 }}
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              {mobileOpen ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              )}
            </svg>
          </motion.button>
        </nav>

        {/* Mobile dropdown with spring animation */}
        <AnimatePresence>
          {mobileOpen && (
            <motion.div
              role="navigation"
              aria-label="Mobile navigation"
              className="lg:hidden border-t border-border/50 glass px-4 py-4"
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.25, ease: [0.4, 0, 0.2, 1] }}
              style={{ overflow: 'hidden' }}
            >
              <div className="flex flex-col gap-1">
                {navItems.map((item, i) => (
                  <motion.div
                    key={item.to}
                    initial={{ x: -20, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    transition={{ delay: i * 0.04 }}
                  >
                    <Link
                      to={item.to}
                      className={`block px-3 py-2 rounded-lg text-sm transition-all ${
                        isActive(item.to)
                          ? 'bg-primary/10 text-primary-light font-medium'
                          : 'text-text-muted hover:text-text hover:bg-surface-hover/50'
                      }`}
                    >
                      {item.label}
                    </Link>
                  </motion.div>
                ))}
              </div>

              <div className="border-t border-border/50 mt-3 pt-3 flex flex-col gap-1">
                {user ? (
                  <>
                    {[
                      { to: '/messages', label: 'Messages' },
                      { to: '/bookmarks', label: 'Saved' },
                      { to: '/my-listings', label: 'My Listings' },
                      { to: '/disputes', label: 'Disputes' },
                      { to: '/notifications', label: `Alerts${unreadCount > 0 ? ` (${unreadCount})` : ''}` },
                      { to: '/settings', label: 'Settings' },
                      ...(user.is_admin ? [{ to: '/admin', label: 'Admin' }] : []),
                      { to: `/profile/${user.id}`, label: user.display_name },
                    ].map((item) => (
                      <Link
                        key={item.to}
                        to={item.to}
                        className={`block px-3 py-2 rounded-lg text-sm transition-all ${
                          isActive(item.to)
                            ? 'bg-primary/10 text-primary-light font-medium'
                            : 'text-text-muted hover:text-text hover:bg-surface-hover/50'
                        }`}
                      >
                        {item.label}
                      </Link>
                    ))}
                    <button
                      onClick={handleLogout}
                      className="text-left px-3 py-2 rounded-lg text-sm text-text-muted hover:text-danger hover:bg-danger/5 transition-all cursor-pointer"
                    >
                      Logout
                    </button>
                    <button
                      onClick={toggleTheme}
                      className="text-left px-3 py-2 rounded-lg text-sm text-text-muted hover:text-text hover:bg-surface-hover/50 transition-all cursor-pointer"
                    >
                      {theme === 'dark' ? 'Light Mode' : 'Dark Mode'}
                    </button>
                  </>
                ) : (
                  <>
                    <Link to="/login" className="block px-3 py-2 rounded-lg text-sm text-text-muted hover:text-text hover:bg-surface-hover/50 transition-all">
                      Sign in
                    </Link>
                    <Link to="/register" className="block px-3 py-2.5 rounded-lg text-sm text-center bg-gradient-to-r from-primary to-primary-dark text-white font-medium">
                      Get Started
                    </Link>
                    <button
                      onClick={toggleTheme}
                      className="text-left px-3 py-2 rounded-lg text-sm text-text-muted hover:text-text hover:bg-surface-hover/50 transition-all cursor-pointer"
                    >
                      {theme === 'dark' ? 'Light Mode' : 'Dark Mode'}
                    </button>
                  </>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.header>

      {/* Early access banner */}
      <div className="relative z-20 bg-primary/20 border-b border-primary/30 text-center py-2 px-4">
        <span className="text-xs font-medium text-text">
          Early Access — Say hello to our resident agents, request features, and report bugs. We're building in the open.
        </span>
      </div>

      {/* Main content — AtmosphericBackground is full-width behind content */}
      <AtmosphericBackground>
        <main id="main-content" className={`flex-1 w-full ${location.pathname === '/' ? '' : location.pathname === '/messages' ? 'max-w-6xl mx-auto px-4 pt-4 pb-0 flex flex-col overflow-hidden' : 'max-w-6xl mx-auto px-4 py-6'}`}>
          <Outlet />
        </main>
      </AtmosphericBackground>

      {location.pathname !== '/messages' && <SiteFooter />}
    </div>
  )
}
