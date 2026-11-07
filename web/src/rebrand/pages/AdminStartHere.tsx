/** The five numbers to read first on the admin dashboard, in plain English. Everything
 * else on the Metrics tab stays below this panel. */
import { useQuery } from '@tanstack/react-query'

import api from '../../lib/api'

// Update by hand when a listing goes live. The list is in the growth plan, section 0.
const LISTINGS = ['Claude directory', 'ChatGPT', 'Cursor', 'VS Code', 'Glama', 'awesome-mcp-servers']

interface Row {
  day: string
  cc_machines_7d?: number | null; checked_machines_7d?: number | null
  cc_new_machines_30d?: number | null; d7_cohort?: number | null; d7_returned?: number | null
  calls_claude_code?: number | null; calls_claude?: number | null; calls_chatgpt?: number | null
}

const sum = (rows: Row[], pick: (r: Row) => number | null | undefined) =>
  rows.reduce((total, r) => total + (pick(r) ?? 0), 0)

function Card({ label, value, meaning }: { label: string; value: string; meaning: string }) {
  return (
    <div className="glass rounded-xl p-4">
      <div className="text-[12.5px] font-semibold text-text-muted">{label}</div>
      <div className="mt-1 text-2xl font-extrabold tabular-nums">{value}</div>
      <p className="mt-1 text-[12px] text-text-muted">{meaning}</p>
    </div>
  )
}

export default function StartHerePanel() {
  const { data } = useQuery<{ rows?: Row[] }>({
    queryKey: ['admin-start-here'],
    queryFn: async () => (await api.get('/admin/metrics/traffic', { params: { days: 14 } })).data,
  })
  const week = (data?.rows || []).slice(-7)
  const latest = week[week.length - 1]
  const protectedMachines = latest?.checked_machines_7d
  const connected = latest?.cc_machines_7d
  const share = protectedMachines != null && connected ? ` of ${connected.toLocaleString()} (${Math.round((protectedMachines / connected) * 100)}%)` : ''
  const cohort = sum(week, (r) => r.d7_cohort)
  const returned = sum(week, (r) => r.d7_returned)
  const calls = sum(week, (r) => (r.calls_claude_code ?? 0) + (r.calls_claude ?? 0) + (r.calls_chatgpt ?? 0))

  return (
    <section className="mt-8">
      <h2 className="text-lg font-bold">Start here</h2>
      <p className="mt-1 text-text-muted text-[13px]">The five numbers that matter, for the last 7 days. Higher is better on all of them.</p>
      <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        <Card label="Protected machines" value={protectedMachines != null ? `${protectedMachines.toLocaleString()}${share}` : 'Not ready'} meaning="Machines where AgentAvow checked something. This is the main goal. Full count from Nov 14." />
        <Card label="New machines" value={sum(week, (r) => r.cc_new_machines_30d).toLocaleString()} meaning="Machines connecting for the first time in 30 days. Shows whether people are finding us." />
        <Card label="Came back after a week" value={cohort ? `${Math.round((returned / cohort) * 100)}%` : 'Not ready'} meaning="New machines that connected again 7 days later. Shows whether people keep it." />
        <Card label="Hand-run checks" value={calls.toLocaleString()} meaning="Tool calls in Claude Code, claude.ai and ChatGPT. Shows people asking on purpose." />
        <Card label="Listings live" value={String(LISTINGS.length)} meaning={LISTINGS.join(', ')} />
      </div>
    </section>
  )
}
