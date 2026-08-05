import { Link, Outlet, useLocation } from 'react-router-dom'
import { AtmosphericBackground } from '../components/AtmosphericBackground'

/**
 * Isolated shell for the AgentAvow rebrand sandbox (/rebrand/*).
 *
 * Deliberately does NOT import the old Layout — this keeps the live site's
 * header/footer/nav untouched. Uses the existing design system (index.css
 * utility classes + Tailwind color tokens), so it looks native without
 * depending on the social-era components. Static prototype content; live data
 * gets wired in a later pass.
 */

function Wordmark() {
  return (
    <span className="flex items-center gap-2 font-bold text-[17px] tracking-tight">
      <svg viewBox="0 0 24 24" fill="none" className="w-6 h-6" aria-hidden="true">
        <circle cx="12" cy="12" r="9.3" stroke="url(#av-g)" strokeWidth="1.7" />
        <circle cx="12" cy="12" r="5.2" stroke="var(--color-primary-light)" strokeWidth="1.2" opacity="0.5" />
        <path d="M8.6 12.2l2.3 2.3 4.6-4.9" stroke="var(--color-primary-light)" strokeWidth="2"
          strokeLinecap="round" strokeLinejoin="round" />
        <defs>
          <linearGradient id="av-g" x1="0" y1="0" x2="24" y2="24">
            <stop stopColor="#2DD4BF" />
            <stop offset="1" stopColor="#E879F9" />
          </linearGradient>
        </defs>
      </svg>
      AgentAvow<span className="text-text-muted font-medium">™</span>
    </span>
  )
}

export default function RebrandLayout() {
  const { pathname } = useLocation()
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
            <Link to="/rebrand/login" className="text-[14px] text-text-muted hover:text-text transition-colors">Sign in</Link>
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
          <Outlet />
        </AtmosphericBackground>
      </main>

      <footer className="relative z-10 bg-background border-t border-border/60 mt-8">
        <div className="max-w-[1080px] mx-auto px-6 py-10">
          <div className="flex flex-wrap items-center justify-between gap-5">
            <Wordmark />
            <div className="flex flex-wrap gap-5 text-[14px] text-text-muted">
              <Link to="/rebrand/docs" className="hover:text-text">Docs</Link>
              <a href="/api/v1/redoc" className="hover:text-text">API</a>
              <a href="/.well-known/jwks.json" className="hover:text-text">Verify (JWKS)</a>
              <a href="https://github.com/agentgraph-co/agentgraph" className="hover:text-text">GitHub</a>
              <Link to="/rebrand/legal/terms" className="hover:text-text">Terms</Link>
              <Link to="/rebrand/legal/privacy" className="hover:text-text">Privacy</Link>
              <a href="/" className="hover:text-text">Community ↗</a>
            </div>
          </div>
          <div className="mt-6 flex items-center justify-between gap-4 flex-wrap">
            <div className="font-mono text-[12px] text-text-muted/70">
              A trust score you can verify. · © {new Date().getFullYear()} AgentAvow
            </div>
            <div className="flex gap-4 text-[13px]">
              <a href="https://github.com/agentgraph-co/agentgraph" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text" aria-label="GitHub">GitHub</a>
              <a href="https://bsky.app/profile/agentavow.bsky.social" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text" aria-label="Bluesky">Bluesky</a>
              <a href="https://x.com/agentavow" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text" aria-label="X">X</a>
              <a href="https://huggingface.co/agentavow" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text" aria-label="Hugging Face">HuggingFace</a>
              <a href="https://dev.to/agentavow" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text" aria-label="dev.to">dev.to</a>
              {/* TODO(cutover): update LinkedIn URL once the AgentAvow company page exists — Kenne to supply post-cutover */}
              <a href="https://www.linkedin.com/company/agentavow" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-text" aria-label="LinkedIn">LinkedIn</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
