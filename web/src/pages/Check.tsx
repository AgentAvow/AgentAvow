/**
 * Check — "Is This Agent Safe?" web checker page.
 *
 * The #1 consumer-facing page. One search bar that accepts bot names,
 * GitHub URLs, package names, or MCP server names. Routes to a result
 * page with a giant letter grade and plain-English safety summary.
 *
 * URL patterns:
 *   /check              — search bar landing
 *   /check/:owner/:repo — direct result (shareable URL)
 */

import { useState, useEffect, useRef, type FormEvent } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import axios from 'axios'
import SEOHead from '../components/SEOHead'
import { PageTransition } from '../components/Motion'
import { scoreToGrade, getGradeInfo, type LetterGrade } from '../components/trust/gradeSystem'
import { getCategoryInfo, SUBSCORE_LABELS, SUBSCORE_ORDER, type ScoreFamily } from '../components/trust/scanCategories'
import TrustEnvelopePanel, { type TrustEnvelope } from '../components/trust/TrustEnvelopePanel'
import GradeCard from '../components/check/GradeCard'
import SafetySummary from '../components/check/SafetySummary'
import FindingsPanel from '../components/check/FindingsPanel'
import ScanHistoryPanel from '../components/check/ScanHistoryPanel'
import ToolIntegrityPanel from '../components/check/ToolIntegrityPanel'
import AttestationPanel from '../components/check/AttestationPanel'
import ScanFactsPanel from '../components/check/ScanFactsPanel'
import ShareCard from '../components/check/ShareCard'
import { fetchPublicScan, fetchWalletScan, badgeUrl as buildBadgeUrl, publicApi } from '../lib/scanApi'
import type { RecommendedLimits, ScanMetadata, ToolDrift } from '../types/scan'
import { Pulse } from '../components/Skeleton'

// ─── Types ───

interface ScanFinding {
  severity: string
  category: string
  description: string
  file_path?: string
  line?: number
  remediation?: string
}

interface CategoryScore {
  name: string
  score: number
  finding_count: number
}

interface ScanResult {
  owner: string
  repo: string
  overall_score: number
  grade: string
  total_findings: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  categories: CategoryScore[]
  top_findings: ScanFinding[]
  scanned_at: string
  cached: boolean
  provider_count?: number
  trust_envelope?: TrustEnvelope | null
  // Full API surface (audit fix — previously dropped)
  positive_signals?: string[]
  trust_tier?: string
  recommended_limits?: RecommendedLimits
  metadata?: ScanMetadata
  suppressed_lines?: number
  tool_manifest_digest?: string | null
  tool_digests?: Record<string, string>
  tool_drift?: ToolDrift | null
  jws?: string
  key_id?: string
  algorithm?: string
  jwks_url?: string
  entity_trust?: Record<string, unknown> | null
}

interface SearchEntity {
  id: string
  type: string
  display_name: string
  bio_markdown: string
  trust_score: number | null
  source_url?: string
}

// ─── Input Parsing ───

interface ParsedInput {
  type: 'github_url' | 'owner_repo' | 'search' | 'wallet'
  owner?: string
  repo?: string
  query?: string
  wallet?: string
}

function parseInput(raw: string): ParsedInput {
  const trimmed = raw.trim()

  // Wallet address (0x + 40 hex) — resolve to the linked agent's repo scan
  if (/^0x[a-fA-F0-9]{40}$/.test(trimmed)) {
    return { type: 'wallet', wallet: trimmed }
  }

  // GitHub URL: https://github.com/owner/repo or github.com/owner/repo
  const ghUrlMatch = trimmed.match(
    /(?:https?:\/\/)?github\.com\/([a-zA-Z0-9._-]+)\/([a-zA-Z0-9._-]+)/
  )
  if (ghUrlMatch) {
    return { type: 'github_url', owner: ghUrlMatch[1], repo: ghUrlMatch[2] }
  }

  // owner/repo pattern (no spaces, has a slash)
  const ownerRepoMatch = trimmed.match(/^([a-zA-Z0-9._-]+)\/([a-zA-Z0-9._-]+)$/)
  if (ownerRepoMatch) {
    return { type: 'owner_repo', owner: ownerRepoMatch[1], repo: ownerRepoMatch[2] }
  }

  // Anything else is a name/search query
  return { type: 'search', query: trimmed }
}

// ─── Trust Dimensions (consumer-friendly icons) ───

function TrustDimensions({ scanResult }: { scanResult: ScanResult }) {
  const score = scanResult.overall_score
  const hasIdentity = false // Scan-only results don't have identity data yet
  const hasCommunity = false // Same — no community data from scanner

  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
      {/* Identity */}
      <div className="bg-surface border border-border rounded-lg p-3 flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-surface-2 flex items-center justify-center">
          <svg className="w-5 h-5 text-text-muted" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M16.403 12.652a3 3 0 000-5.304 3 3 0 00-3.75-3.751 3 3 0 00-5.305 0 3 3 0 00-3.751 3.75 3 3 0 000 5.305 3 3 0 003.75 3.751 3 3 0 005.305 0 3 3 0 003.751-3.75zm-2.546-4.46a.75.75 0 00-1.214-.883l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clipRule="evenodd" />
          </svg>
        </div>
        <div>
          <p className="text-sm font-medium text-text-primary">Identity</p>
          <p className="text-xs text-text-muted">
            {hasIdentity ? 'Verified' : 'Not yet claimed'}
          </p>
        </div>
      </div>

      {/* Code Security */}
      <div className="bg-surface border border-border rounded-lg p-3 flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ backgroundColor: `${getGradeInfo(score).color}15` }}>
          <span className="font-bold text-sm" style={{ color: getGradeInfo(score).color }}>
            {scoreToGrade(score)}
          </span>
        </div>
        <div>
          <p className="text-sm font-medium text-text-primary">Code Security</p>
          <p className="text-xs text-text-muted">
            {score >= 81 ? 'Strong' : score >= 61 ? 'Good' : score >= 41 ? 'Fair' : 'Needs work'}
          </p>
        </div>
      </div>

      {/* Community Trust */}
      <div className="bg-surface border border-border rounded-lg p-3 flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-surface-2 flex items-center justify-center">
          <svg className="w-5 h-5 text-text-muted" viewBox="0 0 20 20" fill="currentColor">
            <path d="M7 8a3 3 0 100-6 3 3 0 000 6zM14.5 9a2.5 2.5 0 100-5 2.5 2.5 0 000 5zM1.615 16.428a1.224 1.224 0 01-.569-1.175 6.002 6.002 0 0111.908 0c.058.467-.172.92-.57 1.174A9.953 9.953 0 017 18a9.953 9.953 0 01-5.385-1.572zM14.5 16h-.106c.07-.297.088-.611.048-.933a7.47 7.47 0 00-1.588-3.755 4.502 4.502 0 015.874 2.636.818.818 0 01-.36.98A7.465 7.465 0 0114.5 16z" />
          </svg>
        </div>
        <div>
          <p className="text-sm font-medium text-text-primary">Community</p>
          <p className="text-xs text-text-muted">
            {hasCommunity ? 'Peer reviewed' : 'No reviews yet'}
          </p>
        </div>
      </div>
    </div>
  )
}

// ─── Scan Loading Skeleton ───

function ScanSkeleton() {
  return (
    <div className="max-w-2xl mx-auto space-y-6 mt-8">
      <div className="flex flex-col items-center gap-4">
        <Pulse className="w-36 h-36 rounded-2xl" />
        <Pulse className="w-20 h-8" />
        <Pulse className="w-32 h-4" />
      </div>
      <Pulse className="w-full h-24 rounded-lg" />
      <div className="grid grid-cols-3 gap-3">
        <Pulse className="h-16 rounded-lg" />
        <Pulse className="h-16 rounded-lg" />
        <Pulse className="h-16 rounded-lg" />
      </div>
    </div>
  )
}

// ─── Search Results (when user types a name instead of URL) ───

function SearchResults({ query }: { query: string }) {
  const { data, isLoading, isError } = useQuery<{ entities: SearchEntity[] }>({
    queryKey: ['check-search', query],
    queryFn: async () => {
      const { data } = await publicApi.get('/search', { params: { q: query, type: 'agent' } })
      return data
    },
    enabled: !!query,
    staleTime: 60_000,
  })

  if (isLoading) {
    return (
      <div className="space-y-2 mt-6">
        {[1, 2, 3].map(i => <Pulse key={i} className="w-full h-16 rounded-lg" />)}
      </div>
    )
  }

  if (isError) {
    return (
      <div className="text-center py-10 text-text-muted">
        Search failed. Please try again.
      </div>
    )
  }

  if (!data || data.entities.length === 0) {
    // Try to interpret query as a potential owner/repo or well-known package
    const slashMatch = query.match(/^([a-zA-Z0-9._-]+)\/([a-zA-Z0-9._-]+)$/)
    return (
      <div className="text-center py-10">
        <p className="text-text-muted mb-3">No agents found for &ldquo;{query}&rdquo; on AgentAvow yet.</p>
        {slashMatch ? (
          <Link
            to={`/check/${slashMatch[1]}/${slashMatch[2]}`}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary-dark text-white rounded-lg text-sm font-medium transition-colors"
          >
            Scan {slashMatch[1]}/{slashMatch[2]} on GitHub &rarr;
          </Link>
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-text-muted">
              Try a GitHub repo like <span className="font-mono text-primary-light">owner/repo</span> for a direct scan.
            </p>
            <div className="flex flex-wrap gap-2 justify-center">
              {['langchain-ai/langchain', 'crewaiinc/crewai', 'openai/swarm', 'anthropics/anthropic-sdk-python'].map(repo => (
                <Link
                  key={repo}
                  to={`/check/${repo}`}
                  className="px-3 py-1.5 bg-surface border border-border rounded-md text-xs text-primary-light hover:border-primary/50 transition-colors"
                >
                  {repo}
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-2 mt-6">
      <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-2">
        Search Results
      </h2>
      {data.entities.map((entity) => {
        // Extract owner/repo from source_url if available
        const ghMatch = entity.source_url?.match(/github\.com\/([^/]+)\/([^/]+)/)
        const checkPath = ghMatch ? `/check/${ghMatch[1]}/${ghMatch[2]}` : `/profile/${entity.id}`
        return (
        <Link
          key={entity.id}
          to={checkPath}
          className="block bg-surface border border-border rounded-lg p-3 hover:border-primary/50 transition-colors"
        >
          <div className="flex items-center gap-2">
            <span className="font-medium text-text-primary">{entity.display_name}</span>
            <span className="px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider bg-blue-400/20 text-blue-400">
              {entity.type}
            </span>
            {entity.trust_score != null && (
              <span className="ml-auto">
                <span
                  className={`inline-flex items-center gap-1 font-semibold text-xs px-1.5 py-0.5 rounded-md ${getGradeInfo(Math.round(entity.trust_score <= 1 ? entity.trust_score * 100 : entity.trust_score)).bgClass}`}
                  style={{ color: getGradeInfo(Math.round(entity.trust_score <= 1 ? entity.trust_score * 100 : entity.trust_score)).color }}
                >
                  {scoreToGrade(Math.round(entity.trust_score <= 1 ? entity.trust_score * 100 : entity.trust_score))}
                </span>
              </span>
            )}
          </div>
          {entity.bio_markdown && (
            <p className="text-xs text-text-muted mt-1 line-clamp-2">{entity.bio_markdown}</p>
          )}
          {ghMatch && (
            <p className="text-xs text-primary-light mt-1 font-mono">{ghMatch[1]}/{ghMatch[2]}</p>
          )}
        </Link>
        )
      })}
    </div>
  )
}

// ─── Embed badge snippet (the billboard loop) ───

function EmbedSnippet({ badgeUrl, checkUrl, repo }: { badgeUrl: string; checkUrl: string; repo: string }) {
  const [copied, setCopied] = useState(false)
  const markdown = `[![AgentAvow Trust](${badgeUrl})](${checkUrl})`
  const copy = () => {
    navigator.clipboard?.writeText(markdown).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    })
  }
  return (
    <div className="rounded-lg border border-border bg-surface p-3">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-medium text-text-muted">
          Add the badge to {repo}'s README
        </span>
        <button
          type="button"
          onClick={copy}
          className="text-xs text-primary-light hover:underline"
        >
          {copied ? 'Copied ✓' : 'Copy markdown'}
        </button>
      </div>
      <code className="block overflow-x-auto whitespace-nowrap rounded bg-surface-2 px-2 py-1.5 text-[11px] text-text-muted">
        {markdown}
      </code>
    </div>
  )
}

// ─── Scan Result View ───

function ScanResultView({ owner, repo }: { owner: string; repo: string }) {
  const { data: scan, isLoading, isError, error } = useQuery<ScanResult>({
    queryKey: ['public-scan', owner, repo],
    queryFn: async () => {
      const data = await fetchPublicScan(owner, repo)
      const findings = data.findings || {}
      const catScores = data.category_scores || {}
      const items = findings.items ?? []

      // Per-family finding counts (map the 12 threat categories into the 5 sub-score axes)
      const familyCounts: Partial<Record<ScoreFamily, number>> = {}
      Object.entries(findings.categories ?? {}).forEach(([key, count]) => {
        const fam = getCategoryInfo(key).family
        familyCounts[fam] = (familyCounts[fam] ?? 0) + (count as number)
      })

      return {
        ...data,
        owner,
        repo,
        overall_score: data.trust_score ?? data.security_score ?? 0,
        grade: scoreToGrade(data.trust_score ?? data.security_score ?? 0),
        total_findings: findings.total ?? 0,
        critical_findings: findings.critical ?? 0,
        high_findings: findings.high ?? 0,
        medium_findings: findings.medium ?? 0,
        low_findings: (findings as { low?: number }).low ?? 0,
        categories: SUBSCORE_ORDER.filter((fam) => fam in catScores).map((fam) => ({
          name: SUBSCORE_LABELS[fam],
          score: (catScores as Record<string, number>)[fam],
          finding_count: familyCounts[fam] ?? 0,
        })),
        top_findings: items.map((it) => ({
          severity: it.severity,
          category: it.category,
          description: it.name,
          file_path: it.file_path,
          line: it.line_number,
          remediation: it.remediation,
        })),
        suppressed_lines: findings.suppressed_lines ?? 0,
        provider_count: 1,
      } as ScanResult
    },
    staleTime: 5 * 60_000,
    retry: 1,
  })

  if (isLoading) return <ScanSkeleton />

  if (isError) {
    const status = axios.isAxiosError(error) ? error.response?.status : null
    return (
      <div className="text-center py-10">
        <div className="w-16 h-16 mx-auto mb-4 rounded-xl bg-surface-2 flex items-center justify-center">
          <svg className="w-8 h-8 text-text-muted" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-8-5a.75.75 0 01.75.75v4.5a.75.75 0 01-1.5 0v-4.5A.75.75 0 0110 5zm0 10a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
          </svg>
        </div>
        <h2 className="text-lg font-bold text-text-primary mb-2">
          {status === 404 ? 'Repository Not Found' : 'Scan Failed'}
        </h2>
        <p className="text-sm text-text-muted mb-4">
          {status === 404
            ? `Could not find ${owner}/${repo}. Make sure the repository exists and is public.`
            : 'Something went wrong while scanning this repository. Please try again.'}
        </p>
        <Link
          to="/check"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-primary hover:bg-primary-dark text-white text-sm transition-colors"
        >
          Try another search
        </Link>
      </div>
    )
  }

  if (!scan) return null

  // When entity exists on AgentAvow, use composite score as primary
  const entityTrust = scan.entity_trust as {
    imported?: boolean
    composite_score?: number
    grade?: string
    entity_id?: string
  } | null | undefined
  const isOnAgentAvow = entityTrust?.imported === true
  const securityScore = Math.round(scan.overall_score)
  const score = isOnAgentAvow ? Math.round(entityTrust?.composite_score ?? 0) : securityScore
  const grade: LetterGrade = isOnAgentAvow
    ? ((entityTrust?.grade as LetterGrade) || scoreToGrade(score))
    : scoreToGrade(score)
  const badgeUrl = buildBadgeUrl(owner, repo)
  const checkUrl = `https://agentavow.com/check/${owner}/${repo}`
  const ogImageUrl = `https://agentavow.com/api/v1/public/scan/${owner}/${repo}/og-image`

  // Build a consumer-friendly safety verdict for OG description
  const verdictLabel = score >= 81 ? 'Safe to Use' : score >= 61 ? 'Generally Safe' : score >= 41 ? 'Use with Caution' : score >= 21 ? 'Significant Risks' : 'Not Recommended'
  const findingsParts: string[] = []
  if (scan.critical_findings > 0) findingsParts.push(`${scan.critical_findings} critical`)
  if (scan.high_findings > 0) findingsParts.push(`${scan.high_findings} high`)
  const findingsText = findingsParts.length > 0 ? findingsParts.join(', ') + ' findings' : 'No critical or high findings'
  const ogDescription = `Security scan: ${findingsText}. ${verdictLabel}. Check any AI agent at agentavow.com/check`

  return (
    <>
      <SEOHead
        title={`Is ${owner}/${repo} Safe? Grade: ${grade} (${score}/100)`}
        description={ogDescription}
        path={`/check/${owner}/${repo}`}
        image={ogImageUrl}
        jsonLd={{
          '@context': 'https://schema.org',
          '@type': 'Review',
          name: `Is This Agent Safe?: ${owner}/${repo}`,
          reviewBody: `Trust Score: ${grade} (${score}/100). ${scan.total_findings} security findings.`,
          itemReviewed: {
            '@type': 'SoftwareApplication',
            name: repo,
            url: `https://github.com/${owner}/${repo}`,
          },
          reviewRating: {
            '@type': 'Rating',
            ratingValue: score,
            bestRating: 100,
            worstRating: 0,
          },
          author: {
            '@type': 'Organization',
            name: 'AgentAvow',
            url: 'https://agentavow.com',
          },
        }}
      />

      <div className="space-y-6">
        {/* Giant Grade — composite when on AgentAvow, security scan otherwise */}
        <GradeCard grade={grade} score={score} repoName={`${owner}/${repo}`} />

        {/* Safety Verdict */}
        <SafetySummary
          grade={grade}
          totalFindings={scan.total_findings}
          criticalFindings={scan.critical_findings}
          providerCount={isOnAgentAvow ? 3 : (scan.provider_count ?? 1)}
        />

        {/* Tool-definition pinning + drift (#8) — the rug-pull signal. High in the
            view because a drift warning is the most urgent thing a user can see. */}
        <ToolIntegrityPanel
          manifestDigest={scan.tool_manifest_digest}
          digests={scan.tool_digests}
          drift={scan.tool_drift}
        />

        {/* Trust Score v2 — signed, verifiable methodology (design §5.2) */}
        {scan.trust_envelope && <TrustEnvelopePanel env={scan.trust_envelope} />}

        {/* Trust Dimensions — enriched when on AgentAvow */}
        {isOnAgentAvow ? (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {/* Identity */}
            <div className="bg-surface border border-border rounded-lg p-3 flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
                <svg className="w-5 h-5 text-primary" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M16.403 12.652a3 3 0 000-5.304 3 3 0 00-3.75-3.751 3 3 0 00-5.305 0 3 3 0 00-3.751 3.75 3 3 0 000 5.305 3 3 0 003.75 3.751 3 3 0 005.305 0 3 3 0 003.751-3.75zm-2.546-4.46a.75.75 0 00-1.214-.883l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clipRule="evenodd" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-text-primary">Identity</p>
                <p className="text-xs text-primary">Verified on AgentAvow</p>
              </div>
            </div>
            {/* Code Security */}
            <div className="bg-surface border border-border rounded-lg p-3 flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-surface-2 flex items-center justify-center">
                <span className={`text-sm font-bold ${securityScore >= 80 ? 'text-emerald-400' : securityScore >= 60 ? 'text-amber-400' : 'text-red-400'}`}>
                  {scoreToGrade(securityScore)}
                </span>
              </div>
              <div>
                <p className="text-sm font-medium text-text-primary">Code Security</p>
                <p className="text-xs text-text-muted">{securityScore}/100</p>
              </div>
            </div>
            {/* Community */}
            <div className="bg-surface border border-border rounded-lg p-3 flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-surface-2 flex items-center justify-center">
                <svg className="w-5 h-5 text-text-muted" viewBox="0 0 20 20" fill="currentColor">
                  <path d="M10 9a3 3 0 100-6 3 3 0 000 6zM6 8a2 2 0 11-4 0 2 2 0 014 0zM1.49 15.326a.78.78 0 01-.358-.442 3 3 0 014.308-3.516 6.484 6.484 0 00-1.905 3.959c-.023.222-.014.442.025.654a4.97 4.97 0 01-2.07-.655zM16.44 15.98a4.97 4.97 0 002.07-.654.78.78 0 00.357-.442 3 3 0 00-4.308-3.517 6.484 6.484 0 011.907 3.96 2.32 2.32 0 01-.026.654zM18 8a2 2 0 11-4 0 2 2 0 014 0zM5.304 16.19a.844.844 0 01-.277-.71 5 5 0 019.947 0 .843.843 0 01-.277.71A6.975 6.975 0 0110 18a6.974 6.974 0 01-4.696-1.81z" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-text-primary">Community</p>
                <p className="text-xs text-text-muted">On AgentAvow platform</p>
              </div>
            </div>
          </div>
        ) : (
          <TrustDimensions scanResult={scan} />
        )}

        {/* AgentAvow Platform Links — when entity exists */}
        {isOnAgentAvow && (
          <div className="flex gap-2 justify-center">
            <Link
              to={`/profile/${entityTrust.entity_id}`}
              className="px-4 py-2 bg-primary/10 border border-primary/30 rounded-lg text-sm text-primary hover:bg-primary/20 transition-colors"
            >
              View full profile
            </Link>
            <Link
              to={`/trust/${entityTrust.entity_id}`}
              className="px-4 py-2 bg-surface border border-border rounded-lg text-sm text-text-muted hover:border-primary/50 transition-colors"
            >
              Trust breakdown
            </Link>
          </div>
        )}

        {/* Import CTA — when NOT on AgentAvow */}
        {!isOnAgentAvow && (
          <div className="bg-surface border border-border border-dashed rounded-xl p-4 text-center">
            <p className="text-sm text-text-muted mb-2">
              This is a code security scan only. Import this agent to AgentAvow for a full trust score including identity verification and community signals.
            </p>
            <Link
              to="/onboarding"
              className="inline-flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary-dark text-white rounded-lg text-sm font-medium transition-colors"
            >
              Import to AgentAvow
            </Link>
          </div>
        )}

        {/* Good practices, recommended limits, scan facts */}
        <ScanFactsPanel
          positiveSignals={scan.positive_signals}
          trustTier={scan.trust_tier}
          limits={scan.recommended_limits}
          metadata={scan.metadata}
          suppressedLines={scan.suppressed_lines}
        />

        {/* Developer Details (expandable) — real findings + threat breakdown */}
        <FindingsPanel
          categories={scan.categories ?? []}
          findings={scan.top_findings ?? []}
          owner={owner}
          repo={repo}
          badgeUrl={badgeUrl}
          checkUrl={checkUrl}
        />

        {/* Signed, verifiable attestation */}
        <AttestationPanel
          jws={scan.jws}
          keyId={scan.key_id}
          algorithm={scan.algorithm}
          jwksUrl={scan.jwks_url}
          owner={owner}
          repo={repo}
        />

        {/* Living-record history — score timeline + framework scan badges */}
        <ScanHistoryPanel owner={owner} repo={repo} />

        {/* Share + CTAs */}
        <ShareCard owner={owner} repo={repo} grade={grade} score={score} />

        {/* Embed badge — the billboard loop: repos that add it link back here */}
        <EmbedSnippet badgeUrl={badgeUrl} checkUrl={checkUrl} repo={`${owner}/${repo}`} />

        {/* Scan another — the repeat-use loop */}
        <div className="text-center">
          <Link
            to="/check"
            className="inline-block rounded-lg bg-primary/15 px-5 py-2 text-sm font-medium text-primary-light hover:bg-primary/25 transition-colors"
          >
            ← Scan another repo
          </Link>
        </div>

        {/* Scan metadata */}
        <div className="text-center text-xs text-text-muted pb-2">
          Scanned {scan.cached ? '(cached)' : ''} {new Date(scan.scanned_at).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
          })}
          {' '}by AgentAvow Security Scanner
        </div>
        <div className="text-center pb-4">
          <Link to="/scans" className="text-xs text-primary-light hover:underline">
            How does this compare? Browse our full scan corpus &rarr;
          </Link>
        </div>
      </div>
    </>
  )
}

// ─── Main Check Page ───

export default function Check() {
  const { owner, repo } = useParams<{ owner: string; repo: string }>()
  const navigate = useNavigate()
  const [input, setInput] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [walletStatus, setWalletStatus] = useState<'idle' | 'loading' | 'notfound'>('idle')
  const inputRef = useRef<HTMLInputElement>(null)
  const hasResult = !!(owner && repo)

  useEffect(() => {
    if (!hasResult && inputRef.current) {
      inputRef.current.focus()
    }
  }, [hasResult])

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!input.trim()) return

    const parsed = parseInput(input)

    if (parsed.type === 'github_url' || parsed.type === 'owner_repo') {
      navigate(`/check/${parsed.owner}/${parsed.repo}`)
      setInput('')
      setSearchQuery('')
    } else if (parsed.type === 'wallet') {
      // Resolve a wallet address to the linked agent's repo, then scan it
      setWalletStatus('loading')
      setSearchQuery('')
      fetchWalletScan(parsed.wallet!)
        .then((res) => {
          const repoSlug = res.scan?.repo
          if (res.found && repoSlug && repoSlug.includes('/')) {
            const [o, r] = repoSlug.split('/')
            setWalletStatus('idle')
            setInput('')
            navigate(`/check/${o}/${r}`)
          } else {
            setWalletStatus('notfound')
          }
        })
        .catch(() => setWalletStatus('notfound'))
    } else {
      setWalletStatus('idle')
      setSearchQuery(parsed.query ?? '')
    }
  }

  return (
    <PageTransition className="max-w-2xl mx-auto px-4">
      {!hasResult && (
        <SEOHead
          title="Is This Agent Safe? — Free AI Agent Security Checker"
          description="Check the security posture of any AI agent, MCP server, or OpenClaw skill. Instant trust grades, findings breakdown, and safety verdicts. No signup required."
          path="/check"
          jsonLd={{
            '@context': 'https://schema.org',
            '@type': 'WebApplication',
            name: 'AgentAvow Safety Checker',
            url: 'https://agentavow.com/check',
            applicationCategory: 'SecurityApplication',
            description: 'Check the security posture of any AI agent, MCP server, or OpenClaw skill. Instant trust grades, findings breakdown, and safety verdicts. No signup required.',
          }}
        />
      )}

      {/* Header */}
      <div className="text-center mb-8 pt-4">
        <h1 className="text-4xl sm:text-5xl font-extrabold leading-tight tracking-tight mb-3">
          <span className="gradient-text">Is This Agent</span>{' '}
          <span className="gradient-text-bio">Safe?</span>
        </h1>
        {!hasResult && (
          <p className="text-sm text-text-muted max-w-md mx-auto">
            Paste a GitHub URL, package name, or search by name to get an instant security report.
          </p>
        )}
      </div>

      {/* Search Bar — only on landing/search, not on result pages */}
      {!hasResult ? (
        <form onSubmit={handleSubmit} className="mb-6">
          <div className="relative">
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="owner/repo, package, agent name, or 0x wallet..."
              aria-label="Check an agent"
              className="w-full bg-surface border border-border rounded-lg pl-6 pr-28 py-4 sm:py-5 text-text focus:outline-none focus:border-primary text-base sm:text-lg"
            />
            <button
              type="submit"
              disabled={!input.trim()}
              className="absolute right-2 top-1/2 -translate-y-1/2 px-4 py-1.5 sm:py-2 rounded-md bg-primary hover:bg-primary-dark text-white text-sm font-medium transition-colors disabled:opacity-40 cursor-pointer"
            >
              Check
            </button>
          </div>
        </form>
      ) : (
        <div className="mb-4">
          <Link to="/check" className="text-xs text-primary-light hover:underline">
            &larr; New search
          </Link>
        </div>
      )}

      {/* Result or Search */}
      {hasResult ? (
        <ScanResultView owner={owner} repo={repo} />
      ) : walletStatus === 'loading' ? (
        <div className="text-center py-10 text-sm text-text-muted">
          Resolving wallet to its linked agent…
        </div>
      ) : walletStatus === 'notfound' ? (
        <div className="text-center py-10">
          <p className="text-sm text-text-primary mb-1">No agent linked to that wallet</p>
          <p className="text-xs text-text-muted">
            This wallet isn&rsquo;t mapped to an imported agent yet. Try a GitHub repo or agent name.
          </p>
        </div>
      ) : searchQuery ? (
        <SearchResults query={searchQuery} />
      ) : (
        /* Empty state — tips and examples */
        <div className="text-center py-8">
          <div className="grid grid-cols-3 gap-2 max-w-xl mx-auto mb-8">
            <div className="bg-surface border border-border rounded-lg px-3 py-2.5 text-center overflow-hidden">
              <p className="text-xs font-semibold text-text-primary mb-0.5">GitHub</p>
              <p className="text-[11px] text-text-muted font-mono truncate">owner/repo</p>
            </div>
            <div className="bg-surface border border-border rounded-lg px-3 py-2.5 text-center overflow-hidden">
              <p className="text-xs font-semibold text-text-primary mb-0.5">Package</p>
              <p className="text-[11px] text-text-muted font-mono truncate">langchain</p>
            </div>
            <div className="bg-surface border border-border rounded-lg px-3 py-2.5 text-center overflow-hidden">
              <p className="text-xs font-semibold text-text-primary mb-0.5">MCP Server</p>
              <p className="text-[11px] text-text-muted font-mono truncate">filesystem</p>
            </div>
          </div>

          <p className="text-xs text-text-muted mb-2">
            Free, no account required. Results are cached for 1 hour.
          </p>
          <Link to="/scans" className="text-xs text-primary-light hover:underline">
            Or browse all 35,689 scans we&rsquo;ve already run &rarr;
          </Link>
        </div>
      )}
    </PageTransition>
  )
}
