/**
 * FindingsPanel — expandable developer view with category scores,
 * findings list, remediation hints, and badge/CI embed code.
 */

import { useState } from 'react'
import { getGradeInfo, scoreToGrade } from '../trust/gradeSystem'
import { getCategoryInfo } from '../trust/scanCategories'

interface Finding {
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

interface FindingsPanelProps {
  categories: CategoryScore[]
  findings: Finding[]
  owner: string
  repo: string
  badgeUrl: string
  checkUrl: string
}

const SEVERITY_CONFIG: Record<string, { label: string; colorClass: string; order: number }> = {
  critical: { label: 'Critical', colorClass: 'text-red-500 bg-red-500/10', order: 0 },
  high: { label: 'High', colorClass: 'text-orange-500 bg-orange-500/10', order: 1 },
  medium: { label: 'Medium', colorClass: 'text-amber-500 bg-amber-500/10', order: 2 },
  low: { label: 'Low', colorClass: 'text-blue-400 bg-blue-400/10', order: 3 },
  info: { label: 'Info', colorClass: 'text-text-muted bg-surface-2', order: 4 },
}

function SeverityBadge({ severity }: { severity: string }) {
  const config = SEVERITY_CONFIG[severity] ?? SEVERITY_CONFIG.info
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider font-medium ${config.colorClass}`}>
      {config.label}
    </span>
  )
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <button
      onClick={handleCopy}
      className="text-xs text-primary-light hover:text-primary transition-colors cursor-pointer"
      aria-label={`Copy ${label}`}
    >
      {copied ? 'Copied!' : `Copy ${label}`}
    </button>
  )
}

export default function FindingsPanel({
  categories,
  findings,
  owner,
  repo,
  badgeUrl,
  checkUrl,
}: FindingsPanelProps) {
  const [expanded, setExpanded] = useState(false)
  const [showAllFindings, setShowAllFindings] = useState(false)

  // Sort findings by severity
  const sortedFindings = [...findings].sort((a, b) => {
    const aOrder = SEVERITY_CONFIG[a.severity]?.order ?? 99
    const bOrder = SEVERITY_CONFIG[b.severity]?.order ?? 99
    return aOrder - bOrder
  })

  const displayFindings = showAllFindings ? sortedFindings : sortedFindings.slice(0, 5)

  // Group findings by threat category (the 12-category granularity) for an
  // at-a-glance "what kind of threats" summary — e.g. Rug-Pull ×9, Prompt Injection ×2.
  const threatGroups = Object.entries(
    findings.reduce<Record<string, number>>((acc, f) => {
      acc[f.category] = (acc[f.category] ?? 0) + 1
      return acc
    }, {}),
  )
    .map(([key, count]) => ({ info: getCategoryInfo(key), count }))
    .sort((a, b) => b.count - a.count)

  const badgeMarkdown = `[![AgentGraph Trust Score](${badgeUrl})](${checkUrl})`
  const ciYaml = `# Add to .github/workflows/trust-scan.yml
name: Trust Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: AgentAvow/trust-scan-action@v1
        with:
          repo: ${owner}/${repo}`

  return (
    <div className="bg-surface border border-border rounded-lg overflow-hidden">
      {/* Toggle header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-text-primary hover:bg-surface-hover transition-colors cursor-pointer"
        aria-expanded={expanded}
      >
        <span>Developer Details</span>
        <svg
          className={`w-4 h-4 text-text-muted transition-transform ${expanded ? 'rotate-180' : ''}`}
          viewBox="0 0 20 20"
          fill="currentColor"
        >
          <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
        </svg>
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-5 border-t border-border">
          {/* Threats detected — grouped by category with registry labels/icons */}
          {threatGroups.length > 0 && (
            <div className="pt-4">
              <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">
                Threats Detected
              </h3>
              <div className="flex flex-wrap gap-2">
                {threatGroups.map(({ info, count }) => (
                  <span
                    key={info.key}
                    title={info.description}
                    className="inline-flex items-center gap-1.5 rounded-full bg-background border border-border px-2.5 py-1 text-xs text-text-primary"
                  >
                    <span aria-hidden="true">{info.icon}</span>
                    {info.label}
                    <span className="tabular-nums text-text-muted">×{count}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Category Scores */}
          {categories.length > 0 && (
            <div className="pt-4">
              <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">
                Category Breakdown
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {categories.map((cat) => {
                  const grade = scoreToGrade(cat.score)
                  const info = getGradeInfo(cat.score)
                  return (
                    <div key={cat.name} className="flex items-center gap-3 bg-background rounded-lg px-3 py-2">
                      <span
                        className={`w-8 h-8 rounded-md flex items-center justify-center font-bold text-sm ${info.bgClass}`}
                        style={{ color: info.color }}
                      >
                        {grade}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-text-primary capitalize">
                          {cat.name.replace(/_/g, ' ')}
                        </p>
                        <p className="text-xs text-text-muted">{cat.finding_count} finding{cat.finding_count !== 1 ? 's' : ''}</p>
                      </div>
                      <span className="text-xs tabular-nums text-text-muted">{cat.score}/100</span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Top Findings */}
          {sortedFindings.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">
                Findings ({sortedFindings.length})
              </h3>
              <div className="space-y-2">
                {displayFindings.map((f, i) => {
                  const cat = getCategoryInfo(f.category)
                  return (
                  <div key={i} className="bg-background rounded-lg px-3 py-2">
                    <div className="flex items-start gap-2">
                      <SeverityBadge severity={f.severity} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-text-primary">{f.description}</p>
                        <p className="text-[11px] text-text-muted mt-0.5">
                          <span aria-hidden="true">{cat.icon}</span> {cat.label}
                        </p>
                        {f.file_path && (
                          <p className="text-xs text-text-muted font-mono mt-0.5 truncate">
                            {f.file_path}{f.line ? `:${f.line}` : ''}
                          </p>
                        )}
                        {f.remediation && (
                          <p className="text-xs text-primary-light mt-1">{f.remediation}</p>
                        )}
                      </div>
                    </div>
                  </div>
                  )
                })}
              </div>
              {sortedFindings.length > 5 && !showAllFindings && (
                <button
                  onClick={() => setShowAllFindings(true)}
                  className="text-xs text-primary-light hover:underline mt-2 cursor-pointer"
                >
                  Show all {sortedFindings.length} findings
                </button>
              )}
            </div>
          )}

          {/* Badge Embed */}
          <div>
            <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
              Add Badge to README
            </h3>
            <div className="bg-background rounded-lg px-3 py-2 flex items-center justify-between gap-2">
              <code className="text-xs text-text-muted font-mono truncate flex-1">
                {badgeMarkdown}
              </code>
              <CopyButton text={badgeMarkdown} label="badge markdown" />
            </div>
          </div>

          {/* CI Integration */}
          <div>
            <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
              Add to CI
            </h3>
            <div className="bg-background rounded-lg px-3 py-2">
              <pre className="text-xs text-text-muted font-mono whitespace-pre overflow-x-auto">{ciYaml}</pre>
              <div className="mt-2 text-right">
                <CopyButton text={ciYaml} label="CI YAML" />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
