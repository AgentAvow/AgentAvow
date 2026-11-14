/**
 * "Do not connect review": the admin queue behind the Trust Index card "Do not connect
 * this week". Owner rule (2026-11-11): no Do not connect result is highlighted to the
 * public until a person has read its finding. Lists every catalog tool that reads Do not
 * connect now and was checked in the last 7 days, with its reason and top critical
 * finding; Confirm puts it on the card, Not confirmed keeps it off. Full admins only:
 * the dashboard does not render this for a viewer, and the API refuses one.
 */
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import api from '../../lib/api'
import { rp } from '../basePath'
import { Section } from './adminMetricsKit'

interface Candidate {
  page_key: string
  page_path: string
  surface: string
  name: string
  full_name: string | null
  trust_score: number | null
  decision_reason: string | null
  last_scanned_at: string | null
  from_catalog_growth: boolean
  top_critical: { category?: string | null; name?: string | null; file_path?: string | null; line_number?: number | null } | null
  status: 'pending' | 'changed' | 'confirmed' | 'not_confirmed'
  reviewed_at: string | null
  note: string | null
}

const STATUS_LABEL: Record<Candidate['status'], string> = {
  pending: 'Not read yet',
  changed: 'Reason changed since the last read',
  confirmed: 'Confirmed: on the card',
  not_confirmed: 'Not confirmed: kept off',
}

function Row({ c, onDone }: { c: Candidate; onDone: () => void }) {
  const [note, setNote] = useState('')
  const act = useMutation({
    mutationFn: (verdict: 'confirmed' | 'not_confirmed') =>
      api.post('/admin/dnc-reviews', { page_path: c.page_path, verdict, note: note || null }),
    onSuccess: onDone,
  })
  const tc = c.top_critical
  const where = tc?.file_path ? `${tc.file_path}${tc.line_number ? `:${tc.line_number}` : ''}` : null
  const done = c.status === 'confirmed' || c.status === 'not_confirmed'
  return (
    <div className="glass rounded-xl p-4 min-w-0">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <Link to={rp(`/rebrand${c.page_path}`)} target="_blank" className="font-mono text-[13px] text-primary-light hover:text-primary break-all">
          {c.full_name || c.name} ↗
        </Link>
        <span className="font-mono text-[10.5px] text-text-muted uppercase tracking-wide">
          {c.surface}{c.trust_score != null ? ` · trust ${c.trust_score}` : ''}{c.from_catalog_growth ? ' · catalog growth' : ''}
        </span>
      </div>
      <p className="mt-1.5 text-[13px]"><span className="font-semibold text-danger">Do not connect</span>{c.decision_reason ? <span className="text-text-muted"> — {c.decision_reason}</span> : null}</p>
      {tc && (
        <p className="mt-1 font-mono text-[11.5px] text-text-muted break-all">
          top critical: {tc.category || 'finding'}{tc.name ? ` · ${tc.name}` : ''}{where ? ` · ${where}` : ''}
        </p>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <span className={`text-[11.5px] font-semibold ${done ? 'text-text-muted' : 'text-warning'}`}>{STATUS_LABEL[c.status]}</span>
        {c.note && <span className="text-[11.5px] text-text-muted">· “{c.note}”</span>}
      </div>
      <div className="mt-2.5 flex flex-wrap items-center gap-2">
        <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="note (optional)" maxLength={2000}
          className="flex-1 min-w-[160px] bg-surface/60 border border-border rounded-lg px-2.5 py-1.5 text-[12.5px]" />
        <button type="button" disabled={act.isPending} onClick={() => act.mutate('confirmed')}
          className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">
          Confirm
        </button>
        <button type="button" disabled={act.isPending} onClick={() => act.mutate('not_confirmed')}
          className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg border border-border text-text-muted hover:text-text disabled:opacity-60">
          Not confirmed
        </button>
      </div>
      {act.isError && <p className="mt-1.5 text-[12px] text-danger">Could not save. The tool may no longer read Do not connect; reload the list.</p>}
    </div>
  )
}

export default function DncReviewPanel() {
  const qc = useQueryClient()
  const { data, isLoading, isError } = useQuery<{ items: Candidate[] }>({
    queryKey: ['admin-dnc-reviews'],
    queryFn: async () => (await api.get('/admin/dnc-reviews')).data,
    staleTime: 60_000,
  })
  const items = data?.items || []
  const open = items.filter((c) => c.status === 'pending' || c.status === 'changed').length
  const [showAll, setShowAll] = useState(false)
  const shown = showAll ? items : items.slice(0, 8)
  return (
    <Section
      title="Do not connect review"
      scope={isLoading ? 'loading…' : `Last 7 days · ${open} to read · ${items.length} in all`}
      note="Tools that read Do not connect now and were checked in the last 7 days. Read the finding on its result page, then Confirm (it can appear on the Trust Index card “Do not connect this week”) or Not confirmed (it stays off every highlight). A new reason after a re-check needs a new read."
    >
      {isError && <p className="text-[13px] text-danger">Could not load the review list.</p>}
      {!isLoading && !isError && !items.length && <p className="text-[13px] text-text-muted">Nothing reads Do not connect from the last 7 days.</p>}
      <div className="grid gap-3">
        {shown.map((c) => <Row key={c.page_key} c={c} onDone={() => qc.invalidateQueries({ queryKey: ['admin-dnc-reviews'] })} />)}
      </div>
      {items.length > 8 && (
        <button type="button" onClick={() => setShowAll((v) => !v)} className="mt-3 text-[12.5px] font-semibold text-primary-light hover:text-primary">
          {showAll ? 'Show fewer' : `Show all ${items.length}`}
        </button>
      )}
    </Section>
  )
}
