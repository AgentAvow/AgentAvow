import { useState, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth'
import api from '../lib/api'
import { Helmet } from 'react-helmet-async'
import { Link } from 'react-router-dom'

type BadgeStyle = 'compact' | 'detailed' | 'minimal' | 'flat-square'
type BadgeTheme = 'light' | 'dark'
type BadgeScale = '1' | '1.5' | '2'
type SnippetFormat = 'markdown' | 'html' | 'rst'

interface Agent {
  id: string
  display_name: string
  type: string
}

const PROD_BASE = 'https://agentavow.com'
const GITHUB_REPO = 'https://github.com/AgentAvow/AgentAvow'

const STYLE_INFO: Record<BadgeStyle, { label: string; desc: string }> = {
  compact: { label: 'Compact', desc: 'Best for GitHub READMEs' },
  detailed: { label: 'Detailed', desc: 'Shows agent name + score' },
  minimal: { label: 'Minimal', desc: 'Score only, tight spaces' },
  'flat-square': { label: 'Flat Square', desc: 'No rounded corners' },
}

function badgeSvgUrl(entityId: string, style: BadgeStyle, theme: BadgeTheme, scale: BadgeScale): string {
  return `/api/v1/badges/trust/${entityId}.svg?style=${style}&theme=${theme}&scale=${scale}`
}

function badgeProdUrl(entityId: string, style: BadgeStyle, theme: BadgeTheme, scale: BadgeScale): string {
  return `${PROD_BASE}/api/v1/badges/trust/${entityId}.svg?style=${style}&theme=${theme}&scale=${scale}`
}

function profileUrl(entityId: string): string {
  return `${PROD_BASE}/profile/${entityId}`
}

function generateSnippet(
  entityId: string,
  style: BadgeStyle,
  theme: BadgeTheme,
  scale: BadgeScale,
  format: SnippetFormat,
): string {
  const imgUrl = badgeProdUrl(entityId, style, theme, scale)
  const link = profileUrl(entityId)

  switch (format) {
    case 'markdown':
      return `<a href="${link}">\n  <img src="${imgUrl}" alt="AgentAvow Trust Score" height="30" />\n</a>\n\n<sub>Verified on <a href="https://agentavow.com">AgentAvow</a> — trust infrastructure for AI agents. <a href="${link}">View profile</a></sub>`
    case 'html':
      return `<a href="${link}"><img src="${imgUrl}" alt="AgentAvow Trust Score" height="30" /></a>`
    case 'rst':
      return `.. image:: ${imgUrl}\n   :target: ${link}\n   :alt: AgentAvow Trust Score\n   :height: 28`
  }
}

export default function Badges() {
  const { user } = useAuth()
  const [agents, setAgents] = useState<Agent[]>([])
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null)
  const [style, setStyle] = useState<BadgeStyle>('compact')
  const [theme, setTheme] = useState<BadgeTheme>('light')
  const [badgeScale, setBadgeScale] = useState<BadgeScale>('1.5')
  const [snippetFormat, setSnippetFormat] = useState<SnippetFormat>('markdown')
  const [copied, setCopied] = useState(false)
  const [loadingAgents, setLoadingAgents] = useState(false)

  useEffect(() => {
    if (!user) return
    setLoadingAgents(true)
    api
      .get('/agents')
      .then(({ data }) => {
        const list = Array.isArray(data) ? data : data.agents ?? data.items ?? []
        setAgents(list)
        if (list.length > 0) setSelectedAgent(list[0])
      })
      .catch(() => {
        setAgents([])
      })
      .finally(() => setLoadingAgents(false))
  }, [user])

  const entityId = selectedAgent?.id ?? ''
  const isDemo = !selectedAgent

  const snippet = entityId ? generateSnippet(entityId, style, theme, badgeScale, snippetFormat) : ''

  async function copySnippet() {
    if (!snippet) return
    try {
      await navigator.clipboard.writeText(snippet)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      const textarea = document.createElement('textarea')
      textarea.value = snippet
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const tweetText = encodeURIComponent(
    `Just added trust verification to my AI agent with @agentavow ${profileUrl(entityId)}`,
  )
  const tweetUrl = `https://twitter.com/intent/tweet?text=${tweetText}`

  const activeBtn = 'bg-primary text-white'
  const inactiveBtn = 'bg-surface border border-border text-text-muted hover:text-text'

  // Force a unique key to bust browser image cache when style/theme changes
  const badgeKey = `${entityId}-${style}-${theme}-${badgeScale}`

  return (
    <>
      <Helmet>
        <title>Trust Badges - AgentAvow</title>
        <meta
          name="description"
          content="Add a verified trust badge to your GitHub README, docs, or website in seconds."
        />
      </Helmet>

      <div className="max-w-3xl mx-auto px-4 py-12 space-y-8">
        {/* Hero */}
        <div className="text-center space-y-3">
          <h1 className="text-3xl font-bold text-text">Trust Badges</h1>
          <p className="text-text-muted text-lg max-w-xl mx-auto">
            Show your agent's trust score in your GitHub README, documentation, or website.
            Badges update automatically as your trust score changes.
          </p>
        </div>

        {/* Entity selector */}
        {user ? (
          <div className="bg-surface border border-border rounded-lg p-5 space-y-3">
            <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wide">
              Select Agent
            </h2>
            {loadingAgents ? (
              <div className="flex items-center gap-2 text-text-muted text-sm">
                <div className="w-4 h-4 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
                Loading agents...
              </div>
            ) : agents.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {agents.map((agent) => (
                  <button
                    key={agent.id}
                    onClick={() => setSelectedAgent(agent)}
                    className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                      selectedAgent?.id === agent.id ? activeBtn : inactiveBtn
                    }`}
                  >
                    {agent.display_name}
                  </button>
                ))}
              </div>
            ) : (
              <div className="text-text-muted text-sm">
                No agents yet.{' '}
                <Link to="/bot-onboarding" className="text-primary hover:underline">
                  Register an agent
                </Link>{' '}
                to get your badge.
              </div>
            )}
          </div>
        ) : (
          <div className="bg-surface border border-border rounded-lg p-5 text-center">
            <p className="text-text-muted text-sm">
              <Link to="/login" className="text-primary hover:underline">
                Log in
              </Link>{' '}
              to generate badges for your agents.
            </p>
          </div>
        )}

        {/* Style + Theme controls */}
        <div className="bg-surface border border-border rounded-lg p-5 space-y-4">
          <div className="space-y-3">
            <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wide">
              Style
            </h2>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {(Object.keys(STYLE_INFO) as BadgeStyle[]).map((s) => (
                <button
                  key={s}
                  onClick={() => setStyle(s)}
                  className={`px-3 py-2.5 rounded-md text-sm font-medium transition-colors text-left ${
                    style === s ? activeBtn : inactiveBtn
                  }`}
                >
                  <div>{STYLE_INFO[s].label}</div>
                  <div
                    className={`text-xs mt-0.5 ${
                      style === s ? 'text-white/70' : 'text-text-muted'
                    }`}
                  >
                    {STYLE_INFO[s].desc}
                  </div>
                </button>
              ))}
            </div>
          </div>

          <div className="flex gap-6">
            <div className="space-y-3">
              <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wide">
                Theme
              </h2>
              <div className="flex gap-2">
                {(['light', 'dark'] as const).map((t) => (
                  <button
                    key={t}
                    onClick={() => setTheme(t)}
                    className={`px-4 py-2 rounded-md text-sm font-medium capitalize transition-colors ${
                      theme === t ? activeBtn : inactiveBtn
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-3">
              <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wide">
                Size
              </h2>
              <div className="flex gap-2">
                {(['1', '1.5', '2'] as BadgeScale[]).map((s) => (
                  <button
                    key={s}
                    onClick={() => setBadgeScale(s)}
                    className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                      badgeScale === s ? activeBtn : inactiveBtn
                    }`}
                  >
                    {s}x
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Live preview */}
        <div className="bg-surface border border-border rounded-lg p-5 space-y-4">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wide">
            Preview
          </h2>
          {isDemo ? (
            <p className="text-xs text-text-muted">
              Select an agent above to see your live badge.
            </p>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Light background preview */}
              <div className="rounded-lg p-8 flex flex-col items-center justify-center gap-3 bg-white border border-gray-200">
                <img
                  key={`light-${badgeKey}`}
                  src={badgeSvgUrl(entityId, style, theme, badgeScale)}
                  alt="Badge on light background"
                  className="max-w-full"
                />
                <span className="text-[10px] text-gray-400 uppercase tracking-wider">
                  Light background
                </span>
              </div>
              {/* Dark background preview */}
              <div className="rounded-lg p-8 flex flex-col items-center justify-center gap-3 bg-[#0d1117] border border-gray-700">
                <img
                  key={`dark-${badgeKey}`}
                  src={badgeSvgUrl(entityId, style, theme, badgeScale)}
                  alt="Badge on dark background"
                  className="max-w-full"
                />
                <span className="text-[10px] text-gray-500 uppercase tracking-wider">
                  Dark background
                </span>
              </div>
            </div>
          )}
          {!isDemo && (
            <p className="text-xs text-text-muted">
              Tip: Use <strong>light</strong> theme for dark READMEs and{' '}
              <strong>dark</strong> theme for light READMEs.
            </p>
          )}
        </div>

        {/* Copy snippet */}
        {!isDemo && (
          <div className="bg-surface border border-border rounded-lg p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wide">
                Embed Code
              </h2>
              <div className="flex gap-1">
                {(['markdown', 'html', 'rst'] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => setSnippetFormat(f)}
                    className={`px-3 py-1 rounded text-xs font-medium uppercase transition-colors ${
                      snippetFormat === f ? activeBtn : inactiveBtn
                    }`}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>
            <div className="relative">
              <pre className="bg-background border border-border rounded-md p-4 text-sm text-text overflow-x-auto whitespace-pre-wrap break-all font-mono">
                {snippet}
              </pre>
              <button
                onClick={copySnippet}
                className="absolute top-2 right-2 px-3 py-1 rounded text-xs font-medium bg-primary text-white hover:bg-primary/90 transition-colors"
              >
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </div>
        )}

        {/* Share + GitHub CTA */}
        {!isDemo && (
          <div className="flex flex-col sm:flex-row gap-4 items-center justify-center py-4">
            <a
              href={tweetUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-md bg-[#1DA1F2] text-white text-sm font-medium hover:bg-[#1a8cd8] transition-colors"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z" />
              </svg>
              Share on Twitter
            </a>
            <a
              href={GITHUB_REPO}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-md bg-surface border border-border text-text text-sm font-medium hover:bg-surface-hover transition-colors"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
              </svg>
              Star on GitHub
            </a>
          </div>
        )}
      </div>
    </>
  )
}
