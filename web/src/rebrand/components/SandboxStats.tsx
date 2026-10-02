import { Link } from 'react-router-dom'
import { rp } from '../basePath'
import { SANDBOX_RULE_LABEL, useSandboxStats } from '../lib/sandboxStats'

const fmt = (n: number | undefined) => (n ?? 0).toLocaleString()

/**
 * One line of live sandbox totals ("N sandbox runs · N tools called · …"). Runs, not
 * distinct tools: a re-run of the same package counts again, so the label says runs.
 * Renders nothing until the sandbox has run something, or if the request fails.
 */
export function SandboxTotalsStrip({ className = '', align = 'center', linkLabel = 'How the sandbox works →' }: { className?: string; align?: 'center' | 'start'; linkLabel?: string | null }) {
  const { data } = useSandboxStats()
  if (!data) return null
  const t = data.totals
  const items: [number, string][] = [
    [t.runs, t.runs === 1 ? 'sandbox run' : 'sandbox runs'],
    [t.tools_called, 'tools called'],
    [t.canary_leaks, t.canary_leaks === 1 ? 'canary leak caught' : 'canary leaks caught'],
    [t.findings, t.findings === 1 ? 'behavioral finding' : 'behavioral findings'],
  ]
  return (
    <div className={`flex flex-wrap items-baseline ${align === 'start' ? 'justify-start' : 'justify-center'} gap-x-5 gap-y-1.5 text-[13px] text-text-muted ${className}`}>
      {items.map(([n, l], i) => (
        <span key={l} className="whitespace-nowrap">
          {i > 0 && <span aria-hidden className="mr-5 text-text-muted/40">·</span>}
          <b className="tabular-nums font-bold text-text">{fmt(n)}</b> {l}
        </span>
      ))}
      {linkLabel && <Link to={rp('/rebrand/docs/behavioral-sandbox')} className="font-semibold text-primary-light hover:text-primary whitespace-nowrap">{linkLabel}</Link>}
    </div>
  )
}

/** "From the sandbox": the last 30 days of behavioral findings by rule. Hidden when empty. */
export function SandboxFindingsBlock() {
  const { data } = useSandboxStats()
  if (!data) return null
  const l30 = data.last_30_days
  const rows = Object.entries(l30.findings_by_rule || {}).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1])
  const max = Math.max(...rows.map(([, n]) => n), 1)
  return (
    <div className="glass rounded-2xl p-6">
      <div className="flex items-baseline justify-between gap-3 flex-wrap">
        <h2 className="text-[16px] font-bold">From the sandbox</h2>
        <span className="font-mono text-[11px] text-text-muted">last 30 days</span>
      </div>
      <p className="mt-1.5 text-text-muted text-[13.5px] max-w-[64ch]">
        Beyond reading the code, we run packages and MCP servers in an isolated sandbox, call every tool, and plant
        canary credentials. In the last 30 days: <strong className="text-text tabular-nums">{fmt(l30.runs)}</strong> runs,{' '}
        <strong className="text-text tabular-nums">{fmt(l30.exercised)}</strong> servers exercised,{' '}
        <strong className="text-text tabular-nums">{fmt(l30.findings)}</strong> behavioral {l30.findings === 1 ? 'finding' : 'findings'}.
      </p>
      {rows.length > 0 ? (
        <div className="mt-4 flex flex-col gap-2">
          {rows.map(([rule, n]) => (
            <div key={rule}>
              <div className="flex justify-between text-[13px] mb-1"><span className="text-text-muted">{SANDBOX_RULE_LABEL[rule] || rule}</span><span className="tabular-nums text-text-muted/80 ml-3">{fmt(n)}</span></div>
              <div className="h-1.5 rounded-full bg-surface overflow-hidden"><div className="h-full rounded-full" style={{ width: `${(n / max) * 100}%`, background: 'linear-gradient(90deg,#f59e0b,#e879f9)' }} /></div>
            </div>
          ))}
        </div>
      ) : (
        <p className="mt-3 text-[13px] text-text-muted/80">No behavioral findings in the last 30 days.</p>
      )}
      <p className="mt-4 text-[12px] text-text-muted/70">
        Aggregate counts only. Each run is signed as a separate observation shown beside the score.{' '}
        <Link to={rp('/rebrand/docs/behavioral-sandbox')} className="text-primary-light hover:text-primary font-semibold">How the sandbox works →</Link>
      </p>
    </div>
  )
}
