/**
 * "Do not connect: this week's shortlist": the admin read behind the Trust Index card
 * "Do not connect this week". Owner rule (2026-11-11): no Do not connect result is
 * highlighted to the public until a person has read its finding, except the ones that
 * need no judgment (known malicious, a planted credential seen leaving the sandbox),
 * which the API adds to the card on its own. The default view is the API's shortlist:
 * at most 3 Do not connect tools people actually checked this week, most checks first,
 * skipping ones already read unless the reason changed. The full list from the last 7
 * days stays behind a collapsed toggle, as a reference only. Full admins only: the
 * dashboard does not render this for a viewer, and the API refuses one.
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
  checks_week: number
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
          {c.surface}{c.trust_score != null ? ` · trust ${c.trust_score}` : ''}{c.checks_week > 0 ? ` · ${c.checks_week} ${c.checks_week === 1 ? 'check' : 'checks'} this week` : ''}{c.from_catalog_growth ? ' · catalog growth' : ''}
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
  const { data, isLoading, isError } = useQuery<{ shortlist: Candidate[]; items: Candidate[]; counts_unavailable?: boolean }>({
    queryKey: ['admin-dnc-reviews'],
    queryFn: async () => (await api.get('/admin/dnc-reviews')).data,
    staleTime: 60_000,
  })
  const shortlist = data?.shortlist || []
  const items = data?.items || []
  const countsDown = !!data?.counts_unavailable
  const [showAll, setShowAll] = useState(false)
  const refresh = () => qc.invalidateQueries({ queryKey: ['admin-dnc-reviews'] })
  return (
    <Section
      title="Do not connect: this week's shortlist"
      scope={isLoading ? 'loading…' : 'Last 7 days'}
      note="Up to 3 a week, the ones people actually checked. Confirm the ones you're happy to show on the Trust Index; Claude brings a two-line read on each on Mondays. Known-malicious packages, known-malicious dependencies and planted credentials seen leaving the sandbox go on the card by themselves, unless you marked them Not confirmed."
    >
      {isError && <p className="text-[13px] text-danger">Could not load the shortlist.</p>}
      {!isLoading && !isError && countsDown && <p className="text-[13px] text-warning">This week's check counts could not be loaded, so there is no shortlist right now. Try again later; the full list below still works.</p>}
      {!isLoading && !isError && !countsDown && !shortlist.length && <p className="text-[13px] text-text-muted">Nothing needs a look this week.</p>}
      <div className="grid gap-3">
        {shortlist.map((c) => <Row key={c.page_key} c={c} onDone={refresh} />)}
      </div>
      {!isLoading && !isError && items.length > 0 && (
        <div className="mt-4">
          <button type="button" onClick={() => setShowAll((v) => !v)} aria-expanded={showAll}
            className="text-[12.5px] font-semibold text-primary-light hover:text-primary">
            {showAll ? 'Hide the full list' : 'Show all Do not connect from the last 7 days'}
          </button>
          {showAll && (
            <>
              <p className="mt-2 text-[12px] text-text-muted">For reference only: every tool that reads Do not connect and was checked or re-scanned in the last 7 days.</p>
              <div className="mt-3 grid gap-3">
                {items.map((c) => <Row key={c.page_key} c={c} onDone={refresh} />)}
              </div>
            </>
          )}
        </div>
      )}
    </Section>
  )
}
