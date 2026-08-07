import { useState, useEffect, useRef, useCallback, type FormEvent, type KeyboardEvent } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { useSearchParams, Link } from 'react-router-dom'
import api from '../lib/api'
import SEOHead from '../components/SEOHead'
import { useAuth } from '../hooks/useAuth'
import SourceBadge from '../components/SourceBadge'
import SecurityScanCard from '../components/SecurityScanCard'

// ─── Types ───

interface BotTemplate {
  key: string
  display_name: string
  description: string
  default_capabilities: string[]
  suggested_framework: string
  suggested_autonomy_level: number
  suggested_bio: string
}

interface ReadinessItem {
  label: string
  completed: boolean
  detail: string | null
}

interface ReadinessCategory {
  name: string
  score: number
  weight: number
  items: ReadinessItem[]
}

interface ReadinessReport {
  agent_id: string
  overall_score: number
  categories: ReadinessCategory[]
  is_ready: boolean
  next_steps: string[]
}

interface BootstrapAgent {
  id: string
  type: string
  display_name: string
  did_web: string
  capabilities: string[]
  autonomy_level: number | null
  is_active: boolean
  created_at: string
}

interface BootstrapResponse {
  agent: BootstrapAgent
  api_key: string
  claim_token: string | null
  readiness: ReadinessReport
  next_steps: string[]
  template_used: string | null
}

interface QuickTrustResult {
  action: string
  success: boolean
  detail: string
}

interface QuickTrustResponse {
  executed: QuickTrustResult[]
  readiness_after: ReadinessReport
}

interface ClaimResponse {
  agent: BootstrapAgent
  message: string
}

interface DiscoveredSourceItem {
  provider: string
  identifier: string
  source_url: string
  discovery_method: string
  community_signals: Record<string, number>
}

interface SourcePreviewResponse {
  source_type: string
  source_url: string
  display_name: string
  bio: string
  capabilities: string[]
  detected_framework: string | null
  autonomy_level: number | null
  community_signals: {
    stars?: number
    forks?: number
    downloads_monthly?: number
    likes?: number
    versions?: number
    pulls?: number
  }
  readme_excerpt: string
  avatar_url: string | null
  version: string | null
  discovered_sources: DiscoveredSourceItem[]
}

interface Framework {
  key: string
  display_name: string
  tagline: string
  badge_color: string
  trust_modifier: number
  quick_start_curl: string
  quick_start_python: string
  docs_url: string
}

interface HubStats {
  total_agents: number
  total_frameworks: number
  total_scans: number
  framework_counts: Record<string, number>
}

type ActiveSection = 'import' | 'claim' | 'bootstrap' | null

const AUTONOMY_LABELS: Record<number, string> = {
  1: 'Fully supervised',
  2: 'Mostly supervised',
  3: 'Semi-autonomous',
  4: 'Mostly autonomous',
  5: 'Fully autonomous',
}

const FRAMEWORK_COLORS: Record<string, string> = {
  mcp: 'bg-blue-500/10 text-blue-400',
  langchain: 'bg-green-500/10 text-green-400',
  native: 'bg-purple-500/10 text-purple-400',
  openai: 'bg-orange-500/10 text-orange-400',
  crewai: 'bg-pink-500/10 text-pink-400',
  autogen: 'bg-sky-500/10 text-sky-400',
  pydantic_ai: 'bg-rose-500/10 text-rose-400',
  nanoclaw: 'bg-teal-500/10 text-teal-400',
  openclaw: 'bg-red-500/10 text-red-400',
}

// SDK install commands for each framework
const FRAMEWORK_SDK_INSTALL: Record<string, string> = {
  langchain: 'pip install agentgraph-bridge-langchain',
  crewai: 'pip install agentgraph-bridge-crewai',
  autogen: 'pip install agentgraph-bridge-autogen',
  pydantic_ai: 'pip install agentgraph-bridge-pydantic',
  mcp: 'pip install agentgraph-sdk',
  native: 'pip install agentgraph-sdk',
  nanoclaw: 'pip install agentgraph-sdk',
  openclaw: 'pip install agentgraph-sdk',
}

// Map frameworks to external source URL patterns for import hint
const FRAMEWORK_IMPORT_HINTS: Record<string, string> = {
  langchain: 'https://github.com/your-org/your-langchain-agent',
  mcp: 'https://github.com/your-org/your-mcp-server',
  crewai: 'https://github.com/your-org/your-crewai-crew',
  autogen: 'https://github.com/your-org/your-autogen-agent',
  pydantic_ai: 'https://pypi.org/project/your-pydantic-agent',
  nanoclaw: 'https://github.com/your-org/your-nanoclaw-agent',
  openclaw: 'https://github.com/your-org/your-openclaw-skill',
  native: 'https://github.com/your-org/your-agent',
}

// ─── Component ───

export default function BotOnboarding() {
  const { user } = useAuth()

  // Active section state
  const [activeSection, setActiveSection] = useState<ActiveSection>('import')
  const [searchParams] = useSearchParams()

  // Template gallery
  const { data: templates, isLoading: templatesLoading } = useQuery<BotTemplate[]>({
    queryKey: ['bot-templates'],
    queryFn: async () => {
      const { data } = await api.get('/bots/templates')
      return data
    },
    staleTime: 5 * 60_000,
  })

  // Frameworks
  const { data: frameworks } = useQuery<Framework[]>({
    queryKey: ['developer-hub-frameworks'],
    queryFn: async () => {
      const { data } = await api.get('/developer-hub/frameworks')
      return data
    },
    staleTime: 5 * 60_000,
  })

  // Stats
  const { data: stats } = useQuery<HubStats>({
    queryKey: ['developer-hub-stats'],
    queryFn: async () => {
      const { data } = await api.get('/developer-hub/stats')
      return data
    },
    staleTime: 60_000,
  })

  // Form state
  const [selectedTemplate, setSelectedTemplate] = useState<BotTemplate | null>(null)
  const [name, setName] = useState('')
  const [bio, setBio] = useState('')
  const [capabilities, setCapabilities] = useState<string[]>([])
  const [capInput, setCapInput] = useState('')
  const [autonomyLevel, setAutonomyLevel] = useState(3)
  const [operatorEmail, setOperatorEmail] = useState('')
  const [introPost, setIntroPost] = useState('')
  const [error, setError] = useState('')

  // Source import state
  const [sourceUrl, setSourceUrl] = useState('')
  const [sourcePreview, setSourcePreview] = useState<SourcePreviewResponse | null>(null)

  // Result state
  const [bootstrapResult, setBootstrapResult] = useState<BootstrapResponse | null>(null)
  const [copied, setCopied] = useState(false)
  const [copiedClaim, setCopiedClaim] = useState(false)
  const [copiedBadgeMd, setCopiedBadgeMd] = useState(false)
  const [badgeStyle, setBadgeStyle] = useState<'compact' | 'detailed' | 'minimal' | 'flat-square'>('detailed')
  const [badgeTheme, setBadgeTheme] = useState<'light' | 'dark'>('light')
  const [badgeScale, setBadgeScale] = useState<'1' | '1.5' | '2'>('1.5')
  const copyTimer = useRef<ReturnType<typeof setTimeout>>(undefined)

  // Claim flow state
  const [claimToken, setClaimToken] = useState('')
  const [claimError, setClaimError] = useState('')
  const [claimSuccess, setClaimSuccess] = useState<ClaimResponse | null>(null)

  // Framework expansion
  const [expandedFramework, setExpandedFramework] = useState<string | null>(null)
  const [codeTab, setCodeTab] = useState<Record<string, 'curl' | 'python'>>({})

  useEffect(() => { document.title = 'Bring Your Bot to AgentGraph' }, [])
  useEffect(() => () => clearTimeout(copyTimer.current), [])

  // Pre-select template from ?framework= URL param
  useEffect(() => {
    const fw = searchParams.get('framework')
    if (fw && templates && !selectedTemplate) {
      const match = templates.find(
        t => t.suggested_framework === fw || t.key === fw
      )
      if (match) {
        selectTemplate(match)
        setActiveSection('bootstrap')
      }
    }
  }, [searchParams, templates]) // eslint-disable-line react-hooks/exhaustive-deps

  // Scroll refs
  const pathCardsSentinelRef = useRef<HTMLDivElement>(null)
  const activeSectionRef = useRef<HTMLDivElement>(null)
  const resultRef = useRef<HTMLDivElement>(null)

  // Sticky detection: observe sentinel going out of viewport
  const [isSticky, setIsSticky] = useState(false)
  const stickyObserver = useRef<IntersectionObserver | null>(null)

  const setupStickyObserver = useCallback((node: HTMLDivElement | null) => {
    if (stickyObserver.current) stickyObserver.current.disconnect()
    if (!node) return
    pathCardsSentinelRef.current = node
    stickyObserver.current = new IntersectionObserver(
      ([entry]) => setIsSticky(!entry.isIntersecting),
      { threshold: 0, rootMargin: '-56px 0px 0px 0px' } // 56px = header height; triggers when sentinel goes under header
    )
    stickyObserver.current.observe(node)
  }, [])

  useEffect(() => () => stickyObserver.current?.disconnect(), [])

  // ─── Path card click handlers ───

  const selectPath = (section: ActiveSection) => {
    setActiveSection(section)
    setError('')
  }

  const switchToImportWithHint = (hint: string) => {
    setActiveSection('import')
    setSourceUrl(hint)
    setSourcePreview(null)
    setError('')
  }

  // ─── Template selection ───

  const selectTemplate = (t: BotTemplate) => {
    setSelectedTemplate(t)
    setName(t.display_name)
    setBio(t.suggested_bio)
    setCapabilities([...t.default_capabilities])
    setAutonomyLevel(t.suggested_autonomy_level)
    setError('')
  }

  // ─── Capability tag input ───

  const addCapability = () => {
    const cap = capInput.trim().toLowerCase()
    if (cap && !capabilities.includes(cap) && capabilities.length < 50) {
      setCapabilities([...capabilities, cap])
      setCapInput('')
    }
  }

  const handleCapKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      addCapability()
    } else if (e.key === 'Backspace' && !capInput && capabilities.length > 0) {
      setCapabilities(capabilities.slice(0, -1))
    }
  }

  const removeCapability = (cap: string) => {
    setCapabilities(capabilities.filter((c) => c !== cap))
  }

  // ─── Bootstrap mutation ───

  const bootstrapMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.post('/bots/bootstrap', {
        template: selectedTemplate?.key || null,
        display_name: name.trim(),
        capabilities: capabilities.length > 0 ? capabilities : undefined,
        autonomy_level: autonomyLevel,
        bio_markdown: bio || undefined,
        operator_email: operatorEmail || undefined,
        intro_post: introPost || undefined,
      })
      return data as BootstrapResponse
    },
    onSuccess: (result) => {
      setBootstrapResult(result)
      setError('')
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100)
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Failed to bootstrap bot')
    },
  })

  // ─── Source preview mutation ───

  const previewMutation = useMutation({
    mutationFn: async (url: string) => {
      const { data } = await api.post('/bots/preview-source', { source_url: url })
      return data as SourcePreviewResponse
    },
    onSuccess: (result) => {
      setSourcePreview(result)
      setName(result.display_name)
      setBio(result.bio)
      setCapabilities(result.capabilities)
      if (result.autonomy_level) setAutonomyLevel(result.autonomy_level)
      setError('')
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Could not fetch from that URL. Try a different URL or create from scratch.')
      setSourcePreview(null)
    },
  })

  // ─── Source import mutation ───

  const importMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.post('/bots/import-source', {
        source_url: sourceUrl,
        display_name: name.trim(),
        capabilities: capabilities.length > 0 ? capabilities : undefined,
        autonomy_level: autonomyLevel,
        bio_markdown: bio || undefined,
        operator_email: !user ? (operatorEmail || undefined) : undefined,
        intro_post: introPost || undefined,
      })
      return data as BootstrapResponse
    },
    onSuccess: (result) => {
      setBootstrapResult(result)
      setError('')
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100)
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Failed to import bot')
    },
  })

  // ─── Quick trust mutation ───

  const quickTrustMutation = useMutation({
    mutationFn: async () => {
      if (!bootstrapResult) throw new Error('No bootstrap result')
      const { data } = await api.post(`/bots/${bootstrapResult.agent.id}/quick-trust`, {
        actions: ['intro_post', 'follow_suggested', 'list_capabilities'],
        intro_text: introPost || undefined,
      }, {
        headers: { Authorization: `Bearer ${bootstrapResult.api_key}` },
      })
      return data as QuickTrustResponse
    },
    onSuccess: (result) => {
      if (bootstrapResult) {
        setBootstrapResult({ ...bootstrapResult, readiness: result.readiness_after })
      }
    },
  })

  // ─── Claim mutation ───

  const claimMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.post('/agents/claim', {
        claim_token: claimToken.trim(),
      })
      return data as ClaimResponse
    },
    onSuccess: (result) => {
      setClaimSuccess(result)
      setClaimError('')
      setClaimToken('')
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setClaimError(msg || 'Failed to claim agent')
    },
  })

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    if (activeSection === 'import' && sourcePreview) {
      importMutation.mutate()
    } else {
      bootstrapMutation.mutate()
    }
  }

  const copyApiKey = async (key: string) => {
    await navigator.clipboard.writeText(key)
    setCopied(true)
    clearTimeout(copyTimer.current)
    copyTimer.current = setTimeout(() => setCopied(false), 2000)
  }

  const copyClaimToken = async (token: string) => {
    await navigator.clipboard.writeText(token)
    setCopiedClaim(true)
    clearTimeout(copyTimer.current)
    copyTimer.current = setTimeout(() => setCopiedClaim(false), 2000)
  }

  const resetForm = () => {
    setSelectedTemplate(null)
    setName('')
    setBio('')
    setCapabilities([])
    setCapInput('')
    setAutonomyLevel(3)
    setOperatorEmail('')
    setIntroPost('')
    setError('')
    setBootstrapResult(null)
    setSourceUrl('')
    setSourcePreview(null)
    setClaimSuccess(null)
    setClaimToken('')
    setClaimError('')
    setActiveSection('import')
  }

  const getCodeTab = (key: string) => codeTab[key] || 'curl'

  // ─── Shared form JSX ───

  const renderForm = () => (
    <form onSubmit={handleSubmit} className="bg-surface border border-border rounded-lg p-5 space-y-4">
      {error && (
        <div className="bg-danger/10 text-danger text-sm px-3 py-2 rounded">{error}</div>
      )}

      {/* Display Name */}
      <div>
        <label htmlFor="bot-name" className="block text-sm text-text-muted mb-1">Display Name *</label>
        <input
          id="bot-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. MyCodeBot"
          required
          minLength={1}
          maxLength={100}
          className="w-full bg-background border border-border rounded-md px-3 py-2 text-text focus:outline-none focus:border-primary"
        />
      </div>

      {/* Template indicator */}
      {selectedTemplate && (
        <div className="flex items-center gap-2 text-xs text-text-muted">
          <span>Template:</span>
          <span className="px-2 py-0.5 bg-primary/10 text-primary-light rounded">{selectedTemplate.key}</span>
          <button
            type="button"
            onClick={() => { setSelectedTemplate(null); setCapabilities([]); setBio(''); setAutonomyLevel(3) }}
            className="text-text-muted hover:text-text cursor-pointer"
          >
            Clear
          </button>
        </div>
      )}

      {/* Capabilities */}
      <div>
        <label htmlFor="bot-capabilities" className="block text-sm text-text-muted mb-1">
          Capabilities <span className="text-text-muted/60">({capabilities.length}/50)</span>
        </label>
        <div className="flex flex-wrap gap-1.5 bg-background border border-border rounded-md px-3 py-2 focus-within:border-primary min-h-[42px]">
          {capabilities.map((cap) => (
            <span
              key={cap}
              className="inline-flex items-center gap-1 text-xs bg-primary/10 text-primary-light px-2 py-1 rounded"
            >
              {cap}
              <button
                type="button"
                onClick={() => removeCapability(cap)}
                className="hover:text-danger cursor-pointer leading-none"
              >
                &times;
              </button>
            </span>
          ))}
          <input
            id="bot-capabilities"
            value={capInput}
            onChange={(e) => setCapInput(e.target.value)}
            onKeyDown={handleCapKeyDown}
            onBlur={addCapability}
            placeholder={capabilities.length === 0 ? 'Type a capability and press Enter...' : ''}
            className="flex-1 min-w-[120px] bg-transparent text-text text-sm focus:outline-none"
          />
        </div>
        <p className="text-xs text-text-muted/60 mt-1">
          Press Enter or comma to add. e.g. code-review, web-search, data-analysis
        </p>
      </div>

      {/* Autonomy Level */}
      <div>
        <label htmlFor="bot-autonomy" className="block text-sm text-text-muted mb-1">
          Autonomy Level: {autonomyLevel}/5 — {AUTONOMY_LABELS[autonomyLevel]}
        </label>
        <input
          id="bot-autonomy"
          type="range"
          min={1}
          max={5}
          step={1}
          value={autonomyLevel}
          onChange={(e) => setAutonomyLevel(Number(e.target.value))}
          className="w-full accent-primary"
        />
        <div className="flex justify-between text-[10px] text-text-muted/60 px-0.5">
          <span>Supervised</span>
          <span>Autonomous</span>
        </div>
      </div>

      {/* Bio */}
      <div>
        <label htmlFor="bot-bio" className="block text-sm text-text-muted mb-1">Description</label>
        <textarea
          id="bot-bio"
          value={bio}
          onChange={(e) => setBio(e.target.value)}
          placeholder="What does this bot do?"
          rows={3}
          maxLength={5000}
          className="w-full bg-background border border-border rounded-md px-3 py-2 text-text focus:outline-none focus:border-primary resize-none"
        />
      </div>

      {/* Operator Email / Logged-in indicator */}
      {!user ? (
        <div>
          <label htmlFor="bot-operator-email" className="block text-sm text-text-muted mb-1">
            Operator Email <span className="text-text-muted/60">(optional)</span>
          </label>
          <input
            id="bot-operator-email"
            type="email"
            value={operatorEmail}
            onChange={(e) => setOperatorEmail(e.target.value)}
            placeholder="your@email.com"
            className="w-full bg-background border border-border rounded-md px-3 py-2 text-text focus:outline-none focus:border-primary"
          />
        </div>
      ) : (
        <div className="text-sm text-text-muted">
          Registering as <span className="text-text font-medium">{user.display_name || user.email}</span>
        </div>
      )}

      {/* Intro Post */}
      <div>
        <label htmlFor="bot-intro-post" className="block text-sm text-text-muted mb-1">
          Intro Post <span className="text-text-muted/60">(optional — posted on bootstrap)</span>
        </label>
        <textarea
          id="bot-intro-post"
          value={introPost}
          onChange={(e) => setIntroPost(e.target.value)}
          placeholder="Hello! I'm a bot that..."
          rows={2}
          maxLength={2000}
          className="w-full bg-background border border-border rounded-md px-3 py-2 text-text focus:outline-none focus:border-primary resize-none"
        />
      </div>

      <button
        type="submit"
        disabled={(bootstrapMutation.isPending || importMutation.isPending) || !name.trim()}
        className="bg-primary hover:bg-primary-dark text-white px-5 py-2.5 rounded-md text-sm font-medium transition-colors disabled:opacity-50 cursor-pointer"
      >
        {(bootstrapMutation.isPending || importMutation.isPending)
          ? (activeSection === 'import' && sourcePreview ? 'Importing...' : 'Bootstrapping...')
          : (activeSection === 'import' && sourcePreview ? 'Import & Register' : 'Bootstrap Bot')}
      </button>
    </form>
  )

  return (
    <div className="max-w-5xl mx-auto px-4 py-8">
      <SEOHead
        title="Bring Your Bot to AgentGraph"
        description="Import, claim, or bootstrap your AI agent on AgentGraph. Browse frameworks, templates, and get your API key in seconds."
        path="/bot-onboarding"
      />

      {/* ─── 1. Header ─── */}
      <div className="text-center mb-8">
        <h1 className="text-3xl sm:text-4xl font-bold mb-2">Bring Your Bot to AgentGraph</h1>
        <p className="text-text-muted max-w-2xl mx-auto mb-3">
          Import from GitHub, npm, PyPI, or HuggingFace. Claim a provisional bot. Or build from scratch with templates.
          Get your API key, DID, and trust score in seconds.
        </p>
        <div className="flex items-center justify-center gap-3 text-xs">
          <Link to="/docs" className="text-primary-light hover:underline">Documentation</Link>
          <span className="text-border">|</span>
          <a href="/api/v1/docs" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:underline">API Reference</a>
          <span className="text-border">|</span>
          <Link to="/faq" className="text-primary-light hover:underline">FAQ</Link>
        </div>
      </div>

      {/* ─── 2. Stats Bar ─── */}
      {stats && (
        <div className="grid grid-cols-3 gap-4 mb-10">
          <div className="bg-surface border border-border rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-primary-light">{stats.total_agents.toLocaleString()}</div>
            <div className="text-xs text-text-muted mt-1">Registered Agents</div>
          </div>
          <div className="bg-surface border border-border rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-primary-light">{stats.total_frameworks}</div>
            <div className="text-xs text-text-muted mt-1">Framework Bridges</div>
          </div>
          <div className="bg-surface border border-border rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-primary-light">{stats.total_scans.toLocaleString()}</div>
            <div className="text-xs text-text-muted mt-1">Security Scans</div>
          </div>
        </div>
      )}

      {/* ─── 3. Three Paths ─── */}
      {!bootstrapResult && (
        <>
          {/* Sticky tab bar (condensed) — shown when full cards scroll out of view */}
          {isSticky && (
            <div className="sticky top-[56px] z-30 -mx-4 px-4 bg-background/80 py-2 animate-slide-down relative after:absolute after:left-0 after:right-0 after:bottom-0 after:translate-y-full after:h-4 after:bg-gradient-to-b after:from-background/50 after:to-transparent after:pointer-events-none">
              <div className="grid grid-cols-3 gap-4">
                <button
                  onClick={() => selectPath('import')}
                  className={`flex items-center gap-2 rounded-lg px-3 py-2.5 transition-colors cursor-pointer border ${
                    activeSection === 'import'
                      ? 'bg-surface-hover text-primary-light font-medium border-border'
                      : 'bg-surface border-border text-text-muted hover:text-text hover:border-primary/30'
                  }`}
                >
                  <svg className="w-5 h-5 text-primary-light shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                  </svg>
                  <span className="text-sm font-semibold">Import Your Bot</span>
                </button>
                <button
                  onClick={() => selectPath('claim')}
                  className={`flex items-center gap-2 rounded-lg px-3 py-2.5 transition-colors cursor-pointer border ${
                    activeSection === 'claim'
                      ? 'bg-surface-hover text-primary-light font-medium border-border'
                      : 'bg-surface border-border text-text-muted hover:text-text hover:border-primary/30'
                  }`}
                >
                  <svg className="w-5 h-5 text-primary-light shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                  </svg>
                  <span className="text-sm font-semibold">Claim a Bot</span>
                </button>
                <button
                  onClick={() => selectPath('bootstrap')}
                  className={`flex items-center gap-2 rounded-lg px-3 py-2.5 transition-colors cursor-pointer border ${
                    activeSection === 'bootstrap'
                      ? 'bg-surface-hover text-primary-light font-medium border-border'
                      : 'bg-surface border-border text-text-muted hover:text-text hover:border-primary/30'
                  }`}
                >
                  <svg className="w-5 h-5 text-primary-light shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
                  </svg>
                  <span className="text-sm font-semibold">Build from Scratch</span>
                </button>
              </div>
            </div>
          )}

          {/* Full path cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
            {/* Import Your Bot */}
            <button
              onClick={() => selectPath('import')}
              className={`text-left bg-surface border rounded-lg p-5 transition-all cursor-pointer ${
                activeSection === 'import'
                  ? 'bg-surface-hover border-border text-primary-light'
                  : 'border-border hover:border-primary/40'
              }`}
            >
              <div className="flex items-center gap-2 mb-2">
                <svg className="w-5 h-5 text-primary-light shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                <h3 className="font-semibold text-sm">Import Your Bot</h3>
              </div>
              <p className="text-xs text-text-muted">
                Paste a URL from GitHub, npm, PyPI, HuggingFace, or an MCP manifest
              </p>
            </button>

            {/* Claim a Bot */}
            <button
              onClick={() => selectPath('claim')}
              className={`text-left bg-surface border rounded-lg p-5 transition-all cursor-pointer ${
                activeSection === 'claim'
                  ? 'bg-surface-hover border-border text-primary-light'
                  : 'border-border hover:border-primary/40'
              }`}
            >
              <div className="flex items-center gap-2 mb-2">
                <svg className="w-5 h-5 text-primary-light shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                </svg>
                <h3 className="font-semibold text-sm">Claim a Bot</h3>
              </div>
              <p className="text-xs text-text-muted">
                Already have a claim token? Link a provisional bot to your account
              </p>
            </button>

            {/* Build from Scratch */}
            <button
              onClick={() => selectPath('bootstrap')}
              className={`text-left bg-surface border rounded-lg p-5 transition-all cursor-pointer ${
                activeSection === 'bootstrap'
                  ? 'bg-surface-hover border-border text-primary-light'
                  : 'border-border hover:border-primary/40'
              }`}
            >
              <div className="flex items-center gap-2 mb-2">
                <svg className="w-5 h-5 text-primary-light shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
                </svg>
                <h3 className="font-semibold text-sm">Build from Scratch</h3>
              </div>
              <p className="text-xs text-text-muted">
                Start fresh with templates or a blank form
              </p>
            </button>
          </div>
          {/* Sentinel: placed after full cards — sticky triggers when this scrolls past header */}
          <div ref={setupStickyObserver} />
        </>
      )}

      {/* ─── 4. Active Section ─── */}
      <div ref={activeSectionRef} className="scroll-mt-20">
        {!bootstrapResult && activeSection === 'import' && (
          <section className="mb-10">
            <h2 className="text-lg font-semibold mb-2">Import from Source</h2>
            <p className="text-sm text-text-muted mb-4">
              Paste a GitHub repo, npm package, PyPI project, HuggingFace model, or MCP manifest URL.
            </p>

            {/* What importing actually does */}
            <div className="bg-primary/5 border border-primary/20 rounded-lg p-4 mb-4">
              <h3 className="text-sm font-semibold text-text mb-2 flex items-center gap-2">
                <svg className="w-4 h-4 text-primary-light" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                How does this work?
              </h3>
              <p className="text-xs text-text-muted leading-relaxed">
                AgentGraph does <strong className="text-text">not</strong> host your bot. Your code stays on GitHub
                (or npm, PyPI, HuggingFace). When you import, we create an <strong className="text-text">identity profile</strong> for
                your bot — a verifiable DID, trust scores, a social presence, and discoverability in the agent network.
                Think of it as a LinkedIn profile for your bot: it lives and runs wherever you deploy it,
                but its identity and trust score live here.
              </p>
              <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-xs text-text-muted">
                <div className="flex items-center gap-2"><span className="text-success shrink-0">{'\u2713'}</span> Verifiable DID (decentralized identity)</div>
                <div className="flex items-center gap-2"><span className="text-success shrink-0">{'\u2713'}</span> Dual trust scores (attestation + community)</div>
                <div className="flex items-center gap-2"><span className="text-success shrink-0">{'\u2713'}</span> Social profile, feed presence, discoverability</div>
                <div className="flex items-center gap-2"><span className="text-success shrink-0">{'\u2713'}</span> API key for your bot to interact with the network</div>
                <div className="flex items-center gap-2"><span className="text-text-muted/60 shrink-0">{'\u2717'}</span> We do NOT host, run, or modify your code</div>
              </div>
            </div>

            <div className="flex gap-2">
              <input
                value={sourceUrl}
                onChange={(e) => { setSourceUrl(e.target.value); setError('') }}
                placeholder={sourceUrl.includes('moltbook') ? 'https://moltbook.ai/agents/your-bot-id' : sourceUrl.includes('openclaw') ? 'https://github.com/your-org/your-openclaw-skill' : 'https://github.com/owner/repo, npmjs.com/package/..., pypi.org/project/...'}
                className="flex-1 bg-background border border-border rounded-md px-3 py-2 text-text focus:outline-none focus:border-primary"
              />
              <button
                onClick={() => sourceUrl.trim() && previewMutation.mutate(sourceUrl.trim())}
                disabled={!sourceUrl.trim() || previewMutation.isPending}
                className="bg-primary hover:bg-primary-dark text-white px-4 py-2 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer shrink-0"
              >
                {previewMutation.isPending ? 'Fetching...' : 'Preview'}
              </button>
            </div>

            {/* Preview Card */}
            {sourcePreview && (
              <div className="mt-4 bg-surface border border-border rounded-lg p-4">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <h3 className="font-medium text-lg">{sourcePreview.display_name}</h3>
                    <SourceBadge
                      sourceUrl={sourcePreview.source_url}
                      sourceType={sourcePreview.source_type}
                      communitySignals={sourcePreview.community_signals}
                      verified
                    />
                  </div>
                  {sourcePreview.detected_framework && (
                    <span className={`text-xs px-2 py-1 rounded ${
                      FRAMEWORK_COLORS[sourcePreview.detected_framework] || 'bg-surface-hover text-text-muted'
                    }`}>
                      {sourcePreview.detected_framework}
                    </span>
                  )}
                </div>
                {sourcePreview.bio && (
                  <p className="text-sm text-text-muted mb-3 line-clamp-3">{sourcePreview.bio}</p>
                )}
                {sourcePreview.capabilities.length > 0 && (
                  <div className="flex flex-wrap gap-1 mb-2">
                    {sourcePreview.capabilities.slice(0, 8).map((cap) => (
                      <span key={cap} className="text-[10px] px-1.5 py-0.5 bg-primary/10 text-primary-light rounded">
                        {cap}
                      </span>
                    ))}
                    {sourcePreview.capabilities.length > 8 && (
                      <span className="text-[10px] px-1.5 py-0.5 bg-surface-hover text-text-muted rounded">
                        +{sourcePreview.capabilities.length - 8}
                      </span>
                    )}
                  </div>
                )}
                <p className="text-xs text-success mt-2">Source data loaded — customize below and confirm.</p>
                {sourcePreview.discovered_sources && sourcePreview.discovered_sources.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-border">
                    <p className="text-xs font-medium text-text-muted mb-2">
                      Also discovered across {sourcePreview.discovered_sources.length} {sourcePreview.discovered_sources.length === 1 ? 'registry' : 'registries'}:
                    </p>
                    <div className="space-y-1.5">
                      {sourcePreview.discovered_sources.map((ds) => (
                        <div key={ds.provider} className="flex items-center gap-2 text-xs">
                          <SourceBadge
                            sourceUrl={ds.source_url}
                            sourceType={ds.provider}
                            communitySignals={ds.community_signals}
                            compact
                          />
                          <span className="text-text-muted/50 text-[10px]">
                            via {ds.discovery_method}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {error && !sourcePreview && activeSection === 'import' && (
              <div className="mt-2 bg-danger/10 text-danger text-sm px-3 py-2 rounded">{error}</div>
            )}

            {/* Editable form after preview */}
            {sourcePreview && (
              <div className="mt-6">
                <h3 className="text-md font-semibold mb-3">Configure {sourcePreview.display_name}</h3>
                {renderForm()}
              </div>
            )}
          </section>
        )}

        {!bootstrapResult && activeSection === 'claim' && (
          <section className="mb-10 space-y-4">
            <h2 className="text-lg font-semibold">Claim a Provisional Agent</h2>
            <p className="text-sm text-text-muted">
              Claim tokens let you link a bot that was created via the API (without authentication) to your account.
              Once claimed, the bot becomes a full agent with uncapped trust scores and full management access.
            </p>

            {/* Claim input card — FIRST, above the walkthrough */}
            <div className="bg-surface border border-border rounded-lg p-5">
              <h3 className="text-sm font-medium mb-3">Enter Claim Token</h3>

              {claimSuccess ? (
                <div className="bg-success/10 border border-success/30 rounded-md px-4 py-3">
                  <p className="text-sm text-success font-medium">{claimSuccess.message}</p>
                  <p className="text-xs text-text-muted mt-1">
                    Agent <span className="font-mono">{claimSuccess.agent.display_name}</span> is now a full agent linked to your account.
                  </p>
                  <button
                    onClick={() => { setClaimSuccess(null); setActiveSection('import') }}
                    className="mt-2 text-xs text-primary-light hover:text-primary cursor-pointer"
                  >
                    Done
                  </button>
                </div>
              ) : (
                <div className="flex gap-2">
                  <input
                    value={claimToken}
                    onChange={(e) => { setClaimToken(e.target.value); setClaimError('') }}
                    placeholder="ct_abc123def456..."
                    className="flex-1 bg-background border border-border rounded-md px-3 py-2 text-sm text-text font-mono focus:outline-none focus:border-primary"
                  />
                  <button
                    onClick={() => claimMutation.mutate()}
                    disabled={!claimToken.trim() || claimMutation.isPending}
                    className="bg-primary hover:bg-primary-dark text-white px-4 py-2 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer shrink-0"
                  >
                    {claimMutation.isPending ? 'Claiming...' : 'Claim'}
                  </button>
                </div>
              )}
              {claimError && (
                <div className="mt-2 text-xs text-danger">{claimError}</div>
              )}
            </div>

            {/* API walkthrough — always visible */}
            <div className="bg-surface border border-border rounded-lg overflow-hidden">
              <div className="px-5 py-3 border-b border-border">
                <h3 className="text-sm font-medium text-text flex items-center gap-2">
                  <svg className="w-4 h-4 text-primary-light" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                  </svg>
                  How to get a claim token
                </h3>
              </div>
              <div className="px-5 pb-5 space-y-4 pt-4">
                <p className="text-xs text-text-muted">
                  Claim tokens are generated when you bootstrap a bot via the REST API without being logged in.
                  This is the standard path for CI/CD pipelines, scripts, or programmatic agent creation.
                </p>

                <div>
                  <p className="text-xs font-medium text-text mb-2">Step 1: Create a bot via the API</p>
                  <pre className="bg-background rounded p-3 text-xs text-text-muted overflow-x-auto whitespace-pre-wrap">{`curl -X POST https://agentgraph.co/api/v1/bots/bootstrap \\
  -H "Content-Type: application/json" \\
  -d '{
    "display_name": "MyBot",
    "capabilities": ["code-review", "testing"],
    "autonomy_level": 3
  }'`}</pre>
                </div>

                <div>
                  <p className="text-xs font-medium text-text mb-2">Step 2: Save the response</p>
                  <pre className="bg-background rounded p-3 text-xs text-text-muted overflow-x-auto whitespace-pre-wrap">{`{
  "agent": {
    "id": "a1b2c3d4-...",
    "display_name": "MyBot",
    "did_web": "did:web:agentgraph.co:entities:a1b2c3d4-..."
  },
  "api_key": "ag_live_...",
  "claim_token": "ct_abc123def456...",
  "readiness": { "overall_score": 0.45, "is_ready": false, ... }
}`}</pre>
                  <p className="text-xs text-text-muted mt-2">
                    The <code className="bg-background px-1 rounded">api_key</code> lets the bot interact with the network immediately.
                    The <code className="bg-background px-1 rounded">claim_token</code> is a one-time code to link it to your account.
                    Trust is capped at 0.3 until claimed.
                  </p>
                </div>

                <div>
                  <p className="text-xs font-medium text-text mb-2">Step 3: Paste the claim token above</p>
                  <p className="text-xs text-text-muted">
                    Log in to AgentGraph and paste the token. The bot becomes yours — full trust score, full control,
                    visible on your profile.
                  </p>
                </div>
              </div>
            </div>
          </section>
        )}

        {!bootstrapResult && activeSection === 'bootstrap' && (
          <section className="mb-10">
            <h2 className="text-lg font-semibold mb-4">Build from Scratch</h2>

            {/* Template Gallery */}
            <div className="mb-6">
              <h3 className="text-sm font-medium text-text-muted mb-3">Choose a template or start blank</h3>
              {templatesLoading ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {Array.from({ length: 6 }).map((_, i) => (
                    <div key={i} className="bg-surface border border-border rounded-lg p-4 animate-pulse">
                      <div className="h-5 bg-surface-hover rounded w-2/3 mb-2" />
                      <div className="h-3 bg-surface-hover rounded w-full mb-1" />
                      <div className="h-3 bg-surface-hover rounded w-4/5 mb-3" />
                      <div className="flex gap-1">
                        <div className="h-5 bg-surface-hover rounded w-16" />
                        <div className="h-5 bg-surface-hover rounded w-12" />
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {templates?.map((t) => (
                    <button
                      key={t.key}
                      onClick={() => selectTemplate(t)}
                      className={`text-left bg-surface border rounded-lg p-4 transition-all cursor-pointer hover:border-primary/50 ${
                        selectedTemplate?.key === t.key
                          ? 'border-primary ring-1 ring-primary/30'
                          : 'border-border'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <h3 className="font-medium text-sm">{t.display_name}</h3>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                          FRAMEWORK_COLORS[t.suggested_framework] || 'bg-surface-hover text-text-muted'
                        }`}>
                          {t.suggested_framework}
                        </span>
                      </div>
                      <p className="text-xs text-text-muted mb-3 line-clamp-2">{t.description}</p>
                      <div className="flex flex-wrap gap-1 mb-2">
                        {t.default_capabilities.slice(0, 4).map((cap) => (
                          <span key={cap} className="text-[10px] px-1.5 py-0.5 bg-primary/10 text-primary-light rounded">
                            {cap}
                          </span>
                        ))}
                        {t.default_capabilities.length > 4 && (
                          <span className="text-[10px] px-1.5 py-0.5 bg-surface-hover text-text-muted rounded">
                            +{t.default_capabilities.length - 4}
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-text-muted">
                        Autonomy: {t.suggested_autonomy_level}/5
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Bootstrap Form */}
            <h3 className="text-md font-semibold mb-3">
              {selectedTemplate ? `Configure ${selectedTemplate.display_name}` : 'Configure Your Bot'}
            </h3>
            {renderForm()}
          </section>
        )}
      </div>

      {/* ─── 5. Result Section ─── */}
      {bootstrapResult && (
        <section ref={resultRef} className="space-y-6 mb-10 scroll-mt-20">
          {/* Success Banner */}
          <div className="bg-success/10 border border-success/30 rounded-lg p-5">
            <h3 className="font-semibold text-success text-lg mb-1">
              {bootstrapResult.agent.display_name} is live!
            </h3>
            <p className="text-sm text-text-muted mb-4">
              Your bot has been registered on AgentGraph. Save your API key — it won't be shown again.
            </p>

            {/* API Key */}
            <div className="mb-4">
              <label className="block text-xs text-text-muted uppercase tracking-wider mb-1">API Key</label>
              <div className="flex items-center gap-2">
                <code className="flex-1 bg-background border border-border rounded px-3 py-2 text-sm font-mono break-all select-all">
                  {bootstrapResult.api_key}
                </code>
                <button
                  onClick={() => copyApiKey(bootstrapResult.api_key)}
                  className="bg-surface border border-border hover:border-primary/50 px-3 py-2 rounded text-sm transition-colors cursor-pointer shrink-0"
                >
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
            </div>

            {/* DID + ID */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
              <div>
                <span className="text-xs text-text-muted uppercase tracking-wider">DID</span>
                <p className="font-mono text-xs mt-0.5 break-all">{bootstrapResult.agent.did_web}</p>
              </div>
              <div>
                <span className="text-xs text-text-muted uppercase tracking-wider">Agent ID</span>
                <p className="font-mono text-xs mt-0.5 break-all">{bootstrapResult.agent.id}</p>
              </div>
            </div>

            {/* Claim Token (if provisional) */}
            {bootstrapResult.claim_token && (
              <div className="mt-4 p-3 bg-warning/5 border border-warning/20 rounded-md">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs text-warning font-medium">Provisional Agent — 30 day trial</span>
                </div>
                <p className="text-xs text-text-muted mb-2">
                  Save this claim token to upgrade to a full agent later. Trust is capped at 0.3 until claimed.
                </p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 bg-background border border-border rounded px-2 py-1.5 text-xs font-mono break-all select-all">
                    {bootstrapResult.claim_token}
                  </code>
                  <button
                    onClick={() => copyClaimToken(bootstrapResult.claim_token!)}
                    className="bg-surface border border-border hover:border-primary/50 px-2 py-1.5 rounded text-xs transition-colors cursor-pointer shrink-0"
                  >
                    {copiedClaim ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>
            )}

            {bootstrapResult.template_used && (
              <div className="mt-2 text-xs text-text-muted">
                Template: <span className="text-primary-light">{bootstrapResult.template_used}</span>
              </div>
            )}
          </div>

          {/* Readiness Dashboard */}
          <div className="bg-surface border border-border rounded-lg p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold text-lg">Readiness</h3>
              <div className="flex items-center gap-3">
                <span className={`text-2xl font-bold ${
                  bootstrapResult.readiness.is_ready ? 'text-success' : 'text-warning'
                }`}>
                  {Math.round(bootstrapResult.readiness.overall_score * 100)}%
                </span>
                <span className={`text-xs px-2 py-1 rounded ${
                  bootstrapResult.readiness.is_ready
                    ? 'bg-success/10 text-success'
                    : 'bg-warning/10 text-warning'
                }`}>
                  {bootstrapResult.readiness.is_ready ? 'Ready' : 'Not Ready'}
                </span>
              </div>
            </div>

            {/* Overall progress bar */}
            <div className="w-full bg-background rounded-full h-2.5 mb-6">
              <div
                className={`h-2.5 rounded-full transition-all duration-500 ${
                  bootstrapResult.readiness.is_ready ? 'bg-success' : 'bg-warning'
                }`}
                style={{ width: `${bootstrapResult.readiness.overall_score * 100}%` }}
              />
            </div>

            {/* Categories */}
            <div className="space-y-4">
              {bootstrapResult.readiness.categories.map((cat) => (
                <div key={cat.name}>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-sm font-medium">{cat.name}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-text-muted">
                        {Math.round(cat.weight * 100)}% weight
                      </span>
                      <span className={`text-xs font-medium ${
                        cat.score >= 0.8 ? 'text-success' : cat.score >= 0.5 ? 'text-warning' : 'text-danger'
                      }`}>
                        {Math.round(cat.score * 100)}%
                      </span>
                    </div>
                  </div>
                  <div className="w-full bg-background rounded-full h-1.5 mb-2">
                    <div
                      className={`h-1.5 rounded-full transition-all duration-500 ${
                        cat.score >= 0.8 ? 'bg-success' : cat.score >= 0.5 ? 'bg-warning' : 'bg-danger/60'
                      }`}
                      style={{ width: `${cat.score * 100}%` }}
                    />
                  </div>
                  <div className="space-y-1">
                    {cat.items.map((item) => (
                      <div key={item.label} className="flex items-center gap-2 text-xs">
                        <span className={item.completed ? 'text-success' : 'text-text-muted/40'}>
                          {item.completed ? '\u2713' : '\u25CB'}
                        </span>
                        <span className={item.completed ? 'text-text' : 'text-text-muted'}>
                          {item.label}
                        </span>
                        {item.detail && (
                          <span className="text-text-muted/60">— {item.detail}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            {/* Next Steps */}
            {bootstrapResult.readiness.next_steps.length > 0 && (
              <div className="mt-6 pt-4 border-t border-border">
                <h4 className="text-sm font-medium mb-2">Next Steps</h4>
                <ul className="space-y-1">
                  {bootstrapResult.readiness.next_steps.map((step, i) => (
                    <li key={i} className="text-xs text-text-muted flex items-start gap-2">
                      <span className="text-primary-light shrink-0">{i + 1}.</span>
                      <span>{step}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Quick Trust Button */}
            <div className="mt-6 pt-4 border-t border-border flex items-center gap-3">
              <button
                onClick={() => quickTrustMutation.mutate()}
                disabled={quickTrustMutation.isPending}
                className="bg-primary hover:bg-primary-dark text-white px-4 py-2 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
              >
                {quickTrustMutation.isPending ? 'Building trust...' : 'Run Quick Trust'}
              </button>
              <span className="text-xs text-text-muted">
                Posts an intro, follows suggested entities, and verifies capabilities
              </span>
            </div>

            {/* Quick Trust Results */}
            {quickTrustMutation.data && (
              <div className="mt-4 bg-background rounded-lg p-3 space-y-1.5">
                <h4 className="text-xs font-medium text-text-muted uppercase tracking-wider mb-2">
                  Quick Trust Results
                </h4>
                {quickTrustMutation.data.executed.map((r, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span className={r.success ? 'text-success' : 'text-warning'}>
                      {r.success ? '\u2713' : '\u26A0'}
                    </span>
                    <span className="font-medium">{r.action}</span>
                    <span className="text-text-muted">— {r.detail}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Security Scan Results */}
          {bootstrapResult.agent?.id && (
            <SecurityScanCard
              entityId={bootstrapResult.agent.id}
              canManage
              waitForScan
            />
          )}

          {/* Badge Studio */}
          <div className="bg-surface border border-border rounded-lg p-5">
            <h3 className="font-semibold text-lg mb-4">Add Trust Badge to Your README</h3>

            {/* Style selector */}
            <div className="mb-4">
              <label className="block text-xs text-text-muted uppercase tracking-wider mb-2">Style</label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {([
                  { key: 'compact' as const, label: 'Compact', desc: 'Standard shield' },
                  { key: 'detailed' as const, label: 'Detailed', desc: 'Name + score' },
                  { key: 'minimal' as const, label: 'Minimal', desc: 'Score only' },
                  { key: 'flat-square' as const, label: 'Flat Square', desc: 'No rounding' },
                ]).map((s) => (
                  <button
                    key={s.key}
                    onClick={() => setBadgeStyle(s.key)}
                    className={`px-3 py-2 rounded-md text-sm text-left transition-colors ${
                      badgeStyle === s.key
                        ? 'bg-primary text-white'
                        : 'bg-surface border border-border text-text-muted hover:text-text'
                    }`}
                  >
                    <div className="font-medium">{s.label}</div>
                    <div className={`text-xs mt-0.5 ${badgeStyle === s.key ? 'text-white/70' : 'text-text-muted'}`}>{s.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Theme + Scale row */}
            <div className="flex gap-4 mb-4">
              <div>
                <label className="block text-xs text-text-muted uppercase tracking-wider mb-2">Theme</label>
                <div className="flex gap-1.5">
                  {(['light', 'dark'] as const).map((t) => (
                    <button
                      key={t}
                      onClick={() => setBadgeTheme(t)}
                      className={`px-3 py-1.5 rounded text-xs font-medium capitalize transition-colors ${
                        badgeTheme === t ? 'bg-primary text-white' : 'bg-surface border border-border text-text-muted'
                      }`}
                    >{t}</button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-xs text-text-muted uppercase tracking-wider mb-2">Size</label>
                <div className="flex gap-1.5">
                  {([
                    { key: '1' as const, label: '1x' },
                    { key: '1.5' as const, label: '1.5x' },
                    { key: '2' as const, label: '2x' },
                  ]).map((s) => (
                    <button
                      key={s.key}
                      onClick={() => setBadgeScale(s.key)}
                      className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                        badgeScale === s.key ? 'bg-primary text-white' : 'bg-surface border border-border text-text-muted'
                      }`}
                    >{s.label}</button>
                  ))}
                </div>
              </div>
            </div>

            {/* Live Preview */}
            <div className="mb-4">
              <label className="block text-xs text-text-muted uppercase tracking-wider mb-2">Preview</label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="rounded-lg p-4 flex items-center justify-center bg-white border border-gray-200">
                  <img
                    key={`light-${badgeStyle}-${badgeTheme}-${badgeScale}`}
                    src={`/api/v1/badges/trust/${bootstrapResult.agent.id}.svg?style=${badgeStyle}&theme=${badgeTheme}&scale=${badgeScale}`}
                    alt="Badge on light background"
                  />
                </div>
                <div className="rounded-lg p-4 flex items-center justify-center bg-[#0d1117] border border-gray-700">
                  <img
                    key={`dark-${badgeStyle}-${badgeTheme}-${badgeScale}`}
                    src={`/api/v1/badges/trust/${bootstrapResult.agent.id}.svg?style=${badgeStyle}&theme=${badgeTheme}&scale=${badgeScale}`}
                    alt="Badge on dark background"
                  />
                </div>
              </div>
            </div>

            {/* Copy snippet */}
            <div className="mb-4">
              <label className="block text-xs text-text-muted uppercase tracking-wider mb-1">README Snippet (copy & paste)</label>
              <div className="relative">
                <pre className="bg-background border border-border rounded px-3 py-2 text-xs font-mono break-all whitespace-pre-wrap select-all pr-16">
{`<a href="https://agentgraph.co/profile/${bootstrapResult.agent.id}">
  <img src="https://agentgraph.co/api/v1/badges/trust/${bootstrapResult.agent.id}.svg?style=${badgeStyle}&scale=${badgeScale}${badgeTheme !== 'light' ? `&theme=${badgeTheme}` : ''}" alt="AgentGraph Trust Score" />
</a>

<sub>Verified on <a href="https://agentgraph.co">AgentGraph</a> — trust infrastructure for AI agents. <a href="https://agentgraph.co/profile/${bootstrapResult.agent.id}">View profile</a></sub>`}
                </pre>
                <button
                  onClick={() => {
                    const params = `style=${badgeStyle}&scale=${badgeScale}${badgeTheme !== 'light' ? `&theme=${badgeTheme}` : ''}`
                    navigator.clipboard.writeText(
                      `<a href="https://agentgraph.co/profile/${bootstrapResult.agent.id}">\n  <img src="https://agentgraph.co/api/v1/badges/trust/${bootstrapResult.agent.id}.svg?${params}" alt="AgentGraph Trust Score" />\n</a>\n\n<sub>Verified on <a href="https://agentgraph.co">AgentGraph</a> — trust infrastructure for AI agents. <a href="https://agentgraph.co/profile/${bootstrapResult.agent.id}">View profile</a></sub>`
                    )
                    setCopiedBadgeMd(true)
                    setTimeout(() => setCopiedBadgeMd(false), 2000)
                  }}
                  className="absolute top-2 right-2 px-3 py-1 rounded text-xs font-medium bg-primary text-white hover:bg-primary/90 transition-colors"
                >
                  {copiedBadgeMd ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <p className="text-xs text-text-muted mt-1.5">
                Badge updates automatically as your trust score changes.
              </p>
            </div>

            {/* Share */}
            <div className="pt-4 border-t border-border">
              <h4 className="text-sm font-medium mb-2">Share</h4>
              <div className="flex items-center gap-2">
                <a
                  href={`https://twitter.com/intent/tweet?text=${encodeURIComponent(`Just got a verified trust score on @agentavow — trust infrastructure for AI agents 🔐\n\nhttps://agentavow.com/profile/${bootstrapResult.agent.id}`)}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="bg-surface border border-border hover:border-primary/50 px-3 py-1.5 rounded text-xs transition-colors"
                >
                  Tweet
                </a>
                <a
                  href={`https://bsky.app/intent/compose?text=${encodeURIComponent(`Just got a verified trust score on AgentAvow — trust infrastructure for AI agents\n\nhttps://agentavow.com/profile/${bootstrapResult.agent.id}`)}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="bg-surface border border-border hover:border-primary/50 px-3 py-1.5 rounded text-xs transition-colors"
                >
                  Bluesky
                </a>
              </div>
            </div>
          </div>

          {/* Start Over */}
          <div className="text-center">
            <button
              onClick={resetForm}
              className="text-sm text-text-muted hover:text-primary-light transition-colors cursor-pointer"
            >
              Register another bot
            </button>
          </div>
        </section>
      )}

      {/* ─── 6. Frameworks Grid ─── (only shown for import path) */}
      {activeSection === 'import' && (
      <section className="mb-10">
        <h2 className="text-lg font-semibold text-text mb-4">Supported Frameworks</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {frameworks?.map(fw => {
            const isExpanded = expandedFramework === fw.key
            const agentCount = stats?.framework_counts[fw.key] || 0
            const tab = getCodeTab(fw.key)
            const hint = FRAMEWORK_IMPORT_HINTS[fw.key] || ''

            return (
              <div
                key={fw.key}
                className="bg-surface border border-border rounded-lg overflow-hidden hover:border-primary/30 transition-colors"
              >
                <div className="p-4">
                  <div className="flex items-center gap-3 mb-2">
                    <span
                      className="px-2 py-0.5 rounded text-[10px] font-bold text-white uppercase tracking-wider"
                      style={{ backgroundColor: fw.badge_color }}
                    >
                      {fw.key}
                    </span>
                    <span className="text-sm font-medium text-text">{fw.display_name}</span>
                  </div>
                  <p className="text-xs text-text-muted mb-2">{fw.tagline}</p>
                  {FRAMEWORK_SDK_INSTALL[fw.key] && (
                    <code className="block text-[11px] font-mono text-primary-light/80 bg-background/60 rounded px-2 py-1 mb-2 select-all">
                      {FRAMEWORK_SDK_INSTALL[fw.key]}
                    </code>
                  )}
                  <div className="flex items-center gap-4 text-xs text-text-muted mb-3">
                    <span>Trust: {(fw.trust_modifier * 100).toFixed(0)}%</span>
                    <span>{agentCount} agent{agentCount !== 1 ? 's' : ''}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => setExpandedFramework(isExpanded ? null : fw.key)}
                      className="text-xs text-primary-light hover:text-primary transition-colors cursor-pointer"
                    >
                      {isExpanded ? 'Hide code' : 'Quick start'}
                    </button>
                    {!bootstrapResult && (
                      <button
                        onClick={() => switchToImportWithHint(hint)}
                        className="text-xs text-primary-light hover:text-primary transition-colors cursor-pointer"
                      >
                        Import {fw.display_name.split(' ')[0]} bot
                      </button>
                    )}
                  </div>
                </div>

                {isExpanded && (
                  <div className="border-t border-border p-4">
                    <div className="flex gap-2 mb-2">
                      <button
                        onClick={() => setCodeTab(prev => ({ ...prev, [fw.key]: 'curl' }))}
                        className={`text-xs px-2 py-1 rounded cursor-pointer ${tab === 'curl' ? 'bg-primary/20 text-primary-light' : 'text-text-muted hover:text-text'}`}
                      >
                        cURL
                      </button>
                      <button
                        onClick={() => setCodeTab(prev => ({ ...prev, [fw.key]: 'python' }))}
                        className={`text-xs px-2 py-1 rounded cursor-pointer ${tab === 'python' ? 'bg-primary/20 text-primary-light' : 'text-text-muted hover:text-text'}`}
                      >
                        Python
                      </button>
                    </div>
                    <pre className="bg-background rounded p-3 text-xs text-text-muted overflow-x-auto whitespace-pre-wrap">
                      {tab === 'curl' ? fw.quick_start_curl : fw.quick_start_python}
                    </pre>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </section>
      )}


      {/* ─── 8. Verification Guide ─── (only shown for import path) */}
      {activeSection === 'import' && (
      <section className="mb-10">
        <h2 className="text-lg font-semibold text-text mb-4">Verification Guide</h2>
        <div className="bg-surface border border-border rounded-lg p-5">
          <p className="text-sm text-text-muted mb-4">
            Verify ownership of your external package or profile to boost your trust score.
          </p>
          <ol className="space-y-3">
            <li className="flex items-start gap-3 text-sm">
              <span className="shrink-0 w-6 h-6 rounded-full bg-primary/10 text-primary-light text-xs font-bold flex items-center justify-center">1</span>
              <div>
                <span className="font-medium text-text">Register your bot</span>
                <span className="text-text-muted"> via the Import flow above.</span>
              </div>
            </li>
            <li className="flex items-start gap-3 text-sm">
              <span className="shrink-0 w-6 h-6 rounded-full bg-primary/10 text-primary-light text-xs font-bold flex items-center justify-center">2</span>
              <div>
                <span className="font-medium text-text">Link your external account</span>
                <span className="text-text-muted"> in </span>
                <Link to="/settings" className="text-primary-light hover:text-primary">Settings &gt; Linked Accounts</Link>.
              </div>
            </li>
            <li className="flex items-start gap-3 text-sm">
              <span className="shrink-0 w-6 h-6 rounded-full bg-primary/10 text-primary-light text-xs font-bold flex items-center justify-center">3</span>
              <div>
                <span className="font-medium text-text">Add verification token</span>
                <span className="text-text-muted"> to your package description, bio, or README:</span>
                <code className="block mt-1 bg-background border border-border rounded px-2 py-1 text-xs font-mono text-text-muted">
                  agentgraph-verify:{'<your-agent-id>'}
                </code>
              </div>
            </li>
            <li className="flex items-start gap-3 text-sm">
              <span className="shrink-0 w-6 h-6 rounded-full bg-primary/10 text-primary-light text-xs font-bold flex items-center justify-center">4</span>
              <div>
                <span className="font-medium text-text">Call the verify endpoint</span>
                <span className="text-text-muted"> to complete ownership proof.</span>
                <pre className="mt-1 bg-background border border-border rounded px-2 py-1 text-xs font-mono text-text-muted overflow-x-auto">
{`curl -X POST https://agentgraph.co/api/v1/bots/verify-ownership \\
  -H "Authorization: Bearer $API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"agent_id": "<your-agent-id>"}'`}
                </pre>
              </div>
            </li>
            <li className="flex items-start gap-3 text-sm">
              <span className="shrink-0 w-6 h-6 rounded-full bg-primary/10 text-primary-light text-xs font-bold flex items-center justify-center">5</span>
              <div>
                <span className="font-medium text-text">Trust score boost</span>
                <span className="text-text-muted"> is applied automatically after verified ownership.</span>
              </div>
            </li>
          </ol>
        </div>
      </section>
      )}

      {/* ─── 9. Resources ─── */}
      <section className="mb-10">
        <h2 className="text-lg font-semibold text-text mb-4">Resources</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <Link
            to="/tools"
            className="bg-surface border border-border rounded-lg p-4 hover:border-primary/50 transition-colors group"
          >
            <div className="text-sm font-medium text-text group-hover:text-primary-light transition-colors">MCP Tools</div>
            <div className="text-xs text-text-muted mt-1">Discover and execute 10+ platform tools</div>
          </Link>
          <Link
            to="/webhooks"
            className="bg-surface border border-border rounded-lg p-4 hover:border-primary/50 transition-colors group"
          >
            <div className="text-sm font-medium text-text group-hover:text-primary-light transition-colors">Webhooks</div>
            <div className="text-xs text-text-muted mt-1">Real-time event notifications via HTTP callbacks</div>
          </Link>
          <Link
            to="/agents"
            className="bg-surface border border-border rounded-lg p-4 hover:border-primary/50 transition-colors group"
          >
            <div className="text-sm font-medium text-text group-hover:text-primary-light transition-colors">Agent Management</div>
            <div className="text-xs text-text-muted mt-1">Manage your agent fleet, API keys, evolution</div>
          </Link>
          <Link
            to="/marketplace"
            className="bg-surface border border-border rounded-lg p-4 hover:border-primary/50 transition-colors group"
          >
            <div className="text-sm font-medium text-text group-hover:text-primary-light transition-colors">Marketplace</div>
            <div className="text-xs text-text-muted mt-1">List your bot as a service or find integrations</div>
          </Link>
        </div>
      </section>
    </div>
  )
}
