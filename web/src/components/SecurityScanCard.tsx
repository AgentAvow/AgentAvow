import { useState, useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import { useToast } from './Toasts'
import { getCategoryInfo } from './trust/scanCategories'

interface ScanCategory {
  category: string
  count: number
  status: 'clear' | 'warning' | 'critical'
}

interface ScanFinding {
  category: string
  name: string
  severity: string
  file_path: string
  line_number: number
}

export interface SecurityScanData {
  entity_id: string
  scan_result: 'clean' | 'warnings' | 'critical' | 'error' | 'pending'
  trust_score: number
  files_scanned: number
  categories: ScanCategory[]
  positive_signals: string[]
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  findings: ScanFinding[]
  scanned_at: string | null
  repo: string | null
  category_scores?: {
    secret_hygiene: number
    code_safety: number
    data_handling: number
    filesystem_access: number
    dependency_health?: number
  }
}

const STATUS_CONFIG = {
  clean: { label: 'Clean', color: 'text-success', bg: 'bg-success/10', icon: '\u2713' },
  warnings: { label: 'Warnings', color: 'text-warning', bg: 'bg-warning/10', icon: '\u26A0' },
  critical: { label: 'Critical', color: 'text-danger', bg: 'bg-danger/10', icon: '\u2717' },
  error: { label: 'Error', color: 'text-text-muted', bg: 'bg-surface-hover', icon: '?' },
  pending: { label: 'Pending', color: 'text-text-muted', bg: 'bg-surface-hover', icon: '\u2026' },
}

const CATEGORY_ICONS: Record<string, string> = {
  'Credential Theft': '\uD83D\uDD11',
  'Data Exfiltration': '\uD83D\uDCE1',
  'Unsafe Execution': '\u26A0\uFE0F',
  'Filesystem Access': '\uD83D\uDCC1',
  'Code Obfuscation': '\uD83D\uDD75\uFE0F',
}

const SCAN_CATEGORIES = [
  'Credential Theft',
  'Data Exfiltration',
  'Unsafe Execution',
  'Filesystem Access',
  'Code Obfuscation',
]

const PULSE_DELAYS = [
  'animate-scan-pulse',
  'animate-scan-pulse-d1',
  'animate-scan-pulse-d2',
  'animate-scan-pulse-d3',
  'animate-scan-pulse-d4',
]

function ScanningAnimation() {
  return (
    <div className="bg-surface border border-primary/30 rounded-lg p-4 relative overflow-hidden">
      <div
        className="absolute left-0 right-0 h-px animate-scan-sweep pointer-events-none"
        style={{
          background: 'linear-gradient(90deg, transparent 0%, var(--color-primary) 30%, var(--color-primary) 70%, transparent 100%)',
          boxShadow: '0 0 8px var(--color-primary-glow), 0 0 2px var(--color-primary)',
        }}
      />
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-text-muted uppercase tracking-wider">
          Security Scan
        </h3>
        <span className="text-xs px-2 py-0.5 rounded bg-primary/10 text-primary-light animate-scan-counter">
          Scanning...
        </span>
      </div>
      <div className="flex items-center gap-3 mb-4">
        <div className="font-mono text-xs text-text-muted flex items-center gap-1.5">
          <span className="text-primary-light animate-scan-counter">&gt;</span>
          <span>Analyzing source files</span>
          <span className="animate-scan-pulse">...</span>
        </div>
      </div>
      <div className="space-y-2.5">
        {SCAN_CATEGORIES.map((cat, i) => (
          <div key={cat} className={`flex items-center gap-2 text-xs ${PULSE_DELAYS[i]}`}>
            <span className="w-3.5 h-3.5 rounded border border-border flex items-center justify-center text-[10px] text-text-muted">
              {CATEGORY_ICONS[cat] || '\uD83D\uDD0D'}
            </span>
            <span className="text-text-muted">{cat}</span>
            <span className="ml-auto font-mono text-[10px] text-text-muted">--</span>
          </div>
        ))}
      </div>
      <div className="mt-4 h-0.5 bg-border/40 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full"
          style={{
            background: 'var(--color-primary)',
            animation: 'scan-sweep 2.5s ease-in-out infinite',
            width: '30%',
            position: 'relative',
          }}
        />
      </div>
    </div>
  )
}

/** Tiny inline badge showing scan status — for use next to trust badges */
export function ScanStatusBadge({ entityId }: { entityId: string }) {
  const { data: scan } = useQuery<SecurityScanData>({
    queryKey: ['security-scan', entityId],
    queryFn: async () => (await api.get(`/bots/${entityId}/security-scan`)).data,
    staleTime: 5 * 60_000,
    retry: false,
  })

  if (!scan) return null

  const cfg = STATUS_CONFIG[scan.scan_result] || STATUS_CONFIG.error
  const detail = scan.scan_result === 'clean'
    ? `Scan score ${scan.trust_score}`
    : scan.scan_result === 'error'
      ? 'Scan error'
      : `${scan.total_findings} finding${scan.total_findings !== 1 ? 's' : ''}`

  return (
    <span
      className={`inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded border text-[10px] font-medium ${cfg.bg} ${cfg.color} border-current/20`}
      title={`Security scan: ${cfg.label} — ${detail}`}
    >
      <span className="text-[9px]">{cfg.icon}</span>
      Scan: {cfg.label}
    </span>
  )
}

export default function SecurityScanCard({
  entityId,
  compact = false,
  waitForScan = false,
  canManage = false,
}: {
  entityId: string
  canRescan?: boolean  // deprecated — use canManage
  compact?: boolean
  waitForScan?: boolean
  /** True if the viewer is the bot's operator or an admin. Controls re-scan and findings detail. */
  canManage?: boolean
}) {
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [pollCount, setPollCount] = useState(0)
  const [showAnim, setShowAnim] = useState(waitForScan)
  const [showFindings, setShowFindings] = useState(false)
  const maxPolls = 20

  // Minimum 3s animation on mount when waitForScan
  useEffect(() => {
    if (!waitForScan) return
    const t = setTimeout(() => setShowAnim(false), 3000)
    return () => clearTimeout(t)
  }, [waitForScan])

  const [scanResolved, setScanResolved] = useState(false)

  const { data: scan, isLoading, isError } = useQuery<SecurityScanData>({
    queryKey: ['security-scan', entityId],
    queryFn: async () => (await api.get(`/bots/${entityId}/security-scan`)).data,
    staleTime: 5 * 60_000,
    retry: false,
    refetchInterval: (query) => {
      const data = query.state.data as SecurityScanData | undefined
      if (showAnim) return 3000
      if (data && data.scan_result !== 'pending' && data.scan_result !== 'error') {
        // Scan finished — refresh trust-related queries so badges update
        if (waitForScan && !scanResolved) {
          setScanResolved(true)
          queryClient.invalidateQueries({ queryKey: ['trust'] })
          queryClient.invalidateQueries({ queryKey: ['profile'] })
          queryClient.invalidateQueries({ queryKey: ['entity'] })
        }
        return false
      }
      if (waitForScan && pollCount < maxPolls) {
        if (query.state.error || data?.scan_result === 'error') {
          setPollCount(c => c + 1)
          return 3000
        }
      }
      if (data?.scan_result === 'pending') return 3000
      return false
    },
  })

  const rescanMutation = useMutation({
    mutationFn: async () => (await api.post(`/bots/${entityId}/security-scan`)).data,
    onMutate: () => {
      setShowAnim(true)
    },
    onSuccess: (data) => {
      queryClient.setQueryData(['security-scan', entityId], data)
      setTimeout(() => setShowAnim(false), 2000)
      // Refresh trust queries so badges reflect updated scan score
      queryClient.invalidateQueries({ queryKey: ['trust'] })
      queryClient.invalidateQueries({ queryKey: ['profile'] })
      queryClient.invalidateQueries({ queryKey: ['entity'] })
      addToast('Security scan complete', 'success')
    },
    onError: () => {
      setShowAnim(false)
      addToast('Failed to trigger scan', 'error')
    },
  })

  // Show scanning animation
  if (showAnim || rescanMutation.isPending) {
    return <ScanningAnimation />
  }

  if (isLoading) {
    return (
      <div className="bg-surface border border-border rounded-lg p-4 animate-pulse">
        <div className="h-4 bg-background rounded w-32 mb-3" />
        <div className="h-3 bg-background rounded w-48" />
      </div>
    )
  }

  // Also show animation while waitForScan is polling through errors
  if (waitForScan && (isError || scan?.scan_result === 'error') && pollCount < maxPolls && pollCount > 0) {
    return <ScanningAnimation />
  }

  if (!scan || isError) {
    if (compact) return null
    return (
      <div className="bg-surface border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-2">Security Scan</h3>
        <p className="text-xs text-text-muted">No security scan available.</p>
        {canManage && (
          <button
            onClick={() => rescanMutation.mutate()}
            disabled={rescanMutation.isPending}
            className="mt-3 text-xs bg-primary/10 text-primary-light hover:bg-primary/20 px-3 py-1.5 rounded-md transition-colors cursor-pointer disabled:opacity-50"
          >
            Run Security Scan
          </button>
        )}
      </div>
    )
  }

  const status = STATUS_CONFIG[scan.scan_result] || STATUS_CONFIG.error

  return (
    <div className={`bg-surface border rounded-lg p-4 ${
      scan.scan_result === 'critical' ? 'border-danger/40' :
      scan.scan_result === 'warnings' ? 'border-warning/40' :
      scan.scan_result === 'clean' ? 'border-success/40' : 'border-border'
    }`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-text-muted uppercase tracking-wider">Security Scan</h3>
        <div className="flex items-center gap-2">
          <span className={`text-xs px-2 py-0.5 rounded ${status.bg} ${status.color}`}>
            {status.icon} {status.label}
          </span>
          {canManage && (
            <button
              onClick={() => rescanMutation.mutate()}
              disabled={rescanMutation.isPending}
              className="text-xs bg-primary/10 text-primary-light hover:bg-primary/20 px-2 py-0.5 rounded transition-colors cursor-pointer disabled:opacity-50"
            >
              Re-scan
            </button>
          )}
        </div>
      </div>

      {/* Scan score + stats */}
      <div className="flex items-center gap-4 mb-4">
        <div className="text-center">
          <div className={`text-2xl font-bold ${
            scan.trust_score >= 70 ? 'text-success' :
            scan.trust_score >= 40 ? 'text-warning' : 'text-danger'
          }`}>
            {scan.trust_score}
          </div>
          <div className="text-[10px] text-text-muted uppercase">Scan Score</div>
        </div>
        <div className="flex-1 grid grid-cols-3 gap-2 text-center">
          <div>
            <div className="text-sm font-medium">{scan.files_scanned}</div>
            <div className="text-[10px] text-text-muted">Files</div>
          </div>
          <div>
            <div className="text-sm font-medium">{scan.total_findings}</div>
            <div className="text-[10px] text-text-muted">Findings</div>
          </div>
          <div>
            <div className={`text-sm font-medium ${scan.critical_count > 0 ? 'text-danger' : 'text-text'}`}>
              {scan.critical_count}
            </div>
            <div className="text-[10px] text-text-muted">Critical</div>
          </div>
        </div>
      </div>

      {/* Category sub-scores — letter grades per dimension */}
      {!compact && scan.category_scores && (
        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 mb-3 p-2 rounded-lg bg-surface-2/50">
          {([
            ['Secret Hygiene', scan.category_scores.secret_hygiene],
            ['Code Safety', scan.category_scores.code_safety],
            ['Data Handling', scan.category_scores.data_handling],
            ['Filesystem Access', scan.category_scores.filesystem_access],
            ...(scan.category_scores.dependency_health != null
              ? [['Dependency Health', scan.category_scores.dependency_health] as const]
              : []),
          ] as const).map(([name, score]) => {
            const grade = score >= 96 ? 'A+' : score >= 81 ? 'A' : score >= 61 ? 'B' : score >= 41 ? 'C' : score >= 21 ? 'D' : 'F'
            const color = score >= 81 ? 'text-success' : score >= 61 ? 'text-green-500' : score >= 41 ? 'text-warning' : score >= 21 ? 'text-orange-500' : 'text-danger'
            return (
              <div key={name} className="flex items-center justify-between text-xs">
                <span className="text-text-muted">{name}</span>
                <span className={`font-semibold ${color}`}>{grade}</span>
              </div>
            )
          })}
        </div>
      )}

      {/* Category breakdown — visible to everyone */}
      {!compact && (
        <div className="space-y-1.5 mb-3">
          {scan.categories.map((cat) => (
            <div key={cat.category} className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5">
                <span>{CATEGORY_ICONS[cat.category] || getCategoryInfo(cat.category).icon}</span>
                <span className={cat.status === 'clear' ? 'text-text-muted' : 'text-text'}>
                  {cat.category}
                </span>
              </span>
              <span className={
                cat.status === 'critical' ? 'text-danger font-medium' :
                cat.status === 'warning' ? 'text-warning' :
                'text-success'
              }>
                {cat.count > 0 ? `${cat.count} finding${cat.count !== 1 ? 's' : ''}` : 'Clear'}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Findings detail — only for operator/admin */}
      {canManage && !compact && scan.findings && scan.findings.length > 0 && (
        <div className="mb-3">
          <div className="flex items-center gap-2 mb-2">
            <button
              onClick={() => setShowFindings(!showFindings)}
              className="text-xs text-primary-light hover:text-primary flex items-center gap-1 cursor-pointer"
            >
              <span className="text-[10px]">{showFindings ? '\u25BC' : '\u25B6'}</span>
              {showFindings ? 'Hide' : 'Show'} {scan.findings.length} finding{scan.findings.length !== 1 ? 's' : ''}
            </button>
            <a
              href="https://github.com/AgentAvow/AgentAvow/blob/main/docs/security-scan-false-positives.md"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[10px] text-text-muted hover:text-primary-light transition-colors"
              title="Learn how to suppress false positives"
            >
              False positive?
            </a>
          </div>
          {showFindings && (
            <div className="space-y-1 max-h-64 overflow-y-auto">
              {scan.findings.map((f, i) => (
                <div
                  key={i}
                  className="flex items-start gap-2 text-[11px] bg-background/50 rounded px-2 py-1.5 border border-border/50"
                >
                  <span className={`shrink-0 font-medium uppercase text-[9px] px-1.5 py-0.5 rounded ${
                    f.severity === 'critical' ? 'bg-danger/15 text-danger' :
                    f.severity === 'high' ? 'bg-danger/10 text-danger' :
                    f.severity === 'medium' ? 'bg-warning/15 text-warning' :
                    'bg-surface text-text-muted'
                  }`}>
                    {f.severity}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="text-text font-medium truncate">{f.name}</div>
                    <div className="text-text-muted font-mono text-[10px] truncate">
                      {f.file_path}{f.line_number ? `:${f.line_number}` : ''}
                    </div>
                  </div>
                  {scan.repo && (
                    <a
                      href={`https://github.com/${scan.repo}/blob/main/${f.file_path}${f.line_number ? `#L${f.line_number}` : ''}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="shrink-0 text-[10px] text-primary-light hover:text-primary"
                      title="View on GitHub"
                    >
                      View
                    </a>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Positive signals */}
      {!compact && scan.positive_signals.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-3">
          {scan.positive_signals.map((signal) => (
            <span key={signal} className="text-[10px] bg-success/10 text-success px-1.5 py-0.5 rounded">
              {signal}
            </span>
          ))}
        </div>
      )}

      {/* Error state — re-scan prompt (only for managers) */}
      {canManage && scan.scan_result === 'error' && (
        <div className="bg-warning/5 border border-warning/20 rounded p-2 mb-3">
          <p className="text-xs text-text-muted mb-2">Scan encountered an error. Try re-scanning.</p>
          <button
            onClick={() => rescanMutation.mutate()}
            disabled={rescanMutation.isPending}
            className="text-xs bg-primary text-white hover:bg-primary-light px-3 py-1.5 rounded-md transition-colors cursor-pointer disabled:opacity-50"
          >
            Re-scan Now
          </button>
        </div>
      )}

      {/* Footer */}
      {scan.scanned_at && (
        <div className="flex items-center justify-between text-[10px] text-text-muted pt-2 border-t border-border">
          <span>Scanned {new Date(scan.scanned_at).toLocaleDateString()}</span>
          <div className="flex items-center gap-2">
            <a
              href="https://github.com/AgentAvow/AgentAvow/blob/main/docs/security-scan-false-positives.md"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-primary-light transition-colors"
            >
              Scan docs
            </a>
            {scan.repo && <span className="font-mono">{scan.repo}</span>}
          </div>
        </div>
      )}
    </div>
  )
}
