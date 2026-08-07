import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import api from '../lib/api'
import { formatDate } from '../lib/formatters'
import { EvolutionSkeleton } from '../components/Skeleton'
import SEOHead from '../components/SEOHead'

interface EvolutionRecord {
  id: string
  entity_id: string
  version: string
  parent_record_id: string | null
  forked_from_entity_id: string | null
  change_type: string
  change_summary: string
  capabilities_snapshot: string[]
  extra_metadata: Record<string, unknown>
  anchor_hash: string | null
  risk_tier: number
  approval_status: string
  approved_by: string | null
  approval_note: string | null
  approved_at: string | null
  created_at: string
}

interface LineageData {
  entity_id: string
  entity_name: string
  total_versions: number
  current_version: string | null
  forked_from: string | null
  fork_count: number
  timeline: EvolutionRecord[]
}

interface DiffData {
  version_a: string
  version_b: string
  capabilities: {
    added: string[]
    removed: string[]
    unchanged: string[]
  }
  change_types: { from: string; to: string }
  summaries: { version_a: string; version_b: string }
  risk_tiers: { from: number; to: number }
  metadata_diff: Record<string, { from: unknown; to: unknown }>
}

const CHANGE_TYPE_STYLES: Record<string, string> = {
  initial: 'bg-success/20 text-success',
  update: 'bg-accent/20 text-accent',
  capability_add: 'bg-warning/20 text-warning',
  capability_remove: 'bg-danger/20 text-danger',
  fork: 'bg-primary/20 text-primary-light',
}

const APPROVAL_STYLES: Record<string, string> = {
  auto_approved: 'bg-success/20 text-success',
  approved: 'bg-success/20 text-success',
  pending: 'bg-warning/20 text-warning',
  rejected: 'bg-danger/20 text-danger',
}

const RISK_LABELS: Record<number, { label: string; color: string }> = {
  1: { label: 'Low', color: 'text-success' },
  2: { label: 'Medium', color: 'text-warning' },
  3: { label: 'High', color: 'text-danger' },
}

export default function Evolution() {
  const { entityId } = useParams<{ entityId: string }>()
  const [diffA, setDiffA] = useState<string | null>(null)
  const [diffB, setDiffB] = useState<string | null>(null)

  useEffect(() => { document.title = 'Evolution - AgentAvow' }, [])

  const { data: lineage, isLoading, isError, refetch } = useQuery<LineageData>({
    queryKey: ['evolution-lineage', entityId],
    queryFn: async () => {
      const { data } = await api.get(`/evolution/${entityId}/lineage`)
      return data
    },
    enabled: !!entityId,
    staleTime: 5 * 60_000,
  })

  const { data: diff } = useQuery<DiffData>({
    queryKey: ['evolution-diff', entityId, diffA, diffB],
    queryFn: async () => {
      const { data } = await api.get(`/evolution/${entityId}/diff/${diffA}/${diffB}`)
      return data
    },
    enabled: !!entityId && !!diffA && !!diffB && diffA !== diffB,
    staleTime: 5 * 60_000,
  })

  if (isError) {
    return (
      <div className="text-center py-10">
        <p className="text-danger mb-2">Failed to load evolution data</p>
        <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="max-w-3xl mx-auto mt-6 space-y-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <EvolutionSkeleton key={i} />
        ))}
      </div>
    )
  }

  if (!lineage) {
    return <div className="text-danger text-center mt-10">Entity not found</div>
  }

  const versions = lineage.timeline.map((r) => r.version)

  return (
    <div className="max-w-3xl mx-auto">
      <SEOHead title={`${lineage.entity_name} Evolution`} description={`Version history and evolution timeline for ${lineage.entity_name} on AgentAvow.`} path={`/evolution/${entityId}`} />
      <Link to={`/profile/${entityId}`} className="text-xs text-text-muted hover:text-text transition-colors mb-3 inline-block">&larr; Back to Profile</Link>
      {/* Header */}
      <div className="flex items-center gap-2 mb-1 text-xs text-text-muted">
        <Link to={`/profile/${entityId}`} className="hover:text-primary-light transition-colors">
          {lineage.entity_name}
        </Link>
        <span>/</span>
        <span>Evolution</span>
      </div>

      <div className="bg-surface border border-border rounded-lg p-5 mb-6">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-xl font-bold mb-2">Evolution Timeline</h1>
            <div className="flex items-center gap-4 text-sm text-text-muted">
              <span>{lineage.total_versions} version{lineage.total_versions !== 1 ? 's' : ''}</span>
              {lineage.current_version && (
                <span className="text-primary-light font-medium">
                  Current: v{lineage.current_version}
                </span>
              )}
              {lineage.fork_count > 0 && (
                <span>{lineage.fork_count} fork{lineage.fork_count !== 1 ? 's' : ''}</span>
              )}
            </div>
          </div>
          {lineage.forked_from && (
            <Link
              to={`/evolution/${lineage.forked_from}`}
              className="text-xs px-2.5 py-1 rounded-md border border-primary/30 text-primary-light hover:bg-primary/10 transition-colors"
            >
              Forked from {lineage.forked_from.slice(0, 8)}...
            </Link>
          )}
        </div>
      </div>

      {/* Version Diff Comparison */}
      {versions.length >= 2 && (
        <div className="bg-surface border border-border rounded-lg p-4 mb-6">
          <h2 className="text-sm font-semibold mb-3">Compare Versions</h2>
          <div className="flex items-center gap-3">
            <select
              value={diffA || ''}
              onChange={(e) => setDiffA(e.target.value || null)}
              className="bg-background border border-border rounded-md px-2 py-1 text-sm text-text focus:outline-none focus:border-primary cursor-pointer"
            >
              <option value="">Select version A</option>
              {versions.map((v) => (
                <option key={v} value={v}>v{v}</option>
              ))}
            </select>
            <span className="text-text-muted text-sm">vs</span>
            <select
              value={diffB || ''}
              onChange={(e) => setDiffB(e.target.value || null)}
              className="bg-background border border-border rounded-md px-2 py-1 text-sm text-text focus:outline-none focus:border-primary cursor-pointer"
            >
              <option value="">Select version B</option>
              {versions.map((v) => (
                <option key={v} value={v}>v{v}</option>
              ))}
            </select>
          </div>

          {diff && (
            <div className="mt-4 space-y-3">
              {/* Capability diff */}
              <div>
                <h3 className="text-xs font-medium text-text-muted mb-1">Capabilities</h3>
                <div className="flex flex-wrap gap-1">
                  {diff.capabilities.added.map((cap) => (
                    <span key={cap} className="text-[10px] px-1.5 py-0.5 bg-success/20 text-success rounded">
                      + {cap}
                    </span>
                  ))}
                  {diff.capabilities.removed.map((cap) => (
                    <span key={cap} className="text-[10px] px-1.5 py-0.5 bg-danger/20 text-danger rounded">
                      - {cap}
                    </span>
                  ))}
                  {diff.capabilities.unchanged.map((cap) => (
                    <span key={cap} className="text-[10px] px-1.5 py-0.5 bg-surface-hover text-text-muted rounded">
                      {cap}
                    </span>
                  ))}
                  {diff.capabilities.added.length === 0 &&
                    diff.capabilities.removed.length === 0 &&
                    diff.capabilities.unchanged.length === 0 && (
                      <span className="text-xs text-text-muted">No capability changes</span>
                    )}
                </div>
              </div>

              {/* Risk tier change */}
              {diff.risk_tiers.from !== diff.risk_tiers.to && (
                <div className="text-xs text-text-muted">
                  Risk tier: {RISK_LABELS[diff.risk_tiers.from]?.label} → {RISK_LABELS[diff.risk_tiers.to]?.label}
                </div>
              )}

              {/* Metadata diff */}
              {Object.keys(diff.metadata_diff).length > 0 && (
                <div>
                  <h3 className="text-xs font-medium text-text-muted mb-1">Metadata Changes</h3>
                  {Object.entries(diff.metadata_diff).map(([key, val]) => (
                    <div key={key} className="text-xs text-text-muted">
                      <span className="font-mono">{key}</span>:{' '}
                      <span className="text-danger">{String(val.from ?? 'null')}</span>
                      {' → '}
                      <span className="text-success">{String(val.to ?? 'null')}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Timeline */}
      <div className="relative">
        <div className="absolute left-3 top-2 bottom-2 w-px bg-border" />

        <div className="space-y-4">
          {lineage.timeline.slice().reverse().map((record, i) => {
            const risk = RISK_LABELS[record.risk_tier] || RISK_LABELS[1]
            const approvalStyle = APPROVAL_STYLES[record.approval_status] || 'bg-surface-hover text-text-muted'
            const changeStyle = CHANGE_TYPE_STYLES[record.change_type] || 'bg-surface-hover text-text-muted'

            return (
              <div key={record.id} className="relative flex gap-4 pl-8">
                {/* Timeline dot */}
                <div className={`absolute left-1.5 top-2 w-3 h-3 rounded-full border-2 border-background ${
                  i === 0 ? 'bg-primary' : 'bg-border'
                }`} />

                <div className="bg-surface border border-border rounded-lg p-4 flex-1">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="text-sm font-medium">v{record.version}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider ${changeStyle}`}>
                      {record.change_type.replace('_', ' ')}
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider ${approvalStyle}`}>
                      {record.approval_status.replace('_', ' ')}
                    </span>
                    <span className={`text-[10px] ${risk.color}`}>
                      Risk: {risk.label}
                    </span>
                    <span className="text-[10px] text-text-muted ml-auto">
                      {formatDate(record.created_at)}
                    </span>
                  </div>

                  <p className="text-xs text-text-muted mb-2">{record.change_summary}</p>

                  {record.capabilities_snapshot.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-2">
                      {record.capabilities_snapshot.map((cap, j) => (
                        <span key={j} className="text-[10px] px-1.5 py-0.5 bg-primary/10 text-primary-light rounded">
                          {cap}
                        </span>
                      ))}
                    </div>
                  )}

                  {record.anchor_hash && (
                    <div className="text-[10px] text-text-muted font-mono truncate">
                      Anchor: {record.anchor_hash.slice(0, 16)}...
                    </div>
                  )}

                  {record.forked_from_entity_id && (
                    <Link
                      to={`/evolution/${record.forked_from_entity_id}`}
                      className="text-[10px] text-primary-light hover:underline"
                    >
                      Forked from {record.forked_from_entity_id.slice(0, 8)}...
                    </Link>
                  )}

                  {record.approval_note && (
                    <div className="mt-1 text-[10px] text-text-muted italic">
                      Note: {record.approval_note}
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {lineage.timeline.length === 0 && (
        <div className="text-text-muted text-center py-10">
          No evolution records yet.
        </div>
      )}
    </div>
  )
}
