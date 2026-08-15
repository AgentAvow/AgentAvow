import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { rp } from '../basePath'
import { Reveal } from '../components/motion'
import { TrustMini, AdoptionMini } from '../components/TrustMark'
import { fetchCatalog, rowIdentity, type CatalogRow, type CatalogSummary } from '../catalog'

/**
 * The public index — the outside-in, independent, signed leaderboard of agent-tool
 * safety. Our land-grab move vs. inside-in scorers (they grade the agent you build;
 * we grade the third-party tools an agent connects to). Editorial + shareable: a
 * headline stat computed from the live catalog, then ranked boards per surface.
 */

const SURFACE_LABEL: Record<string, string> = {
  mcp: 'MCP server', npm: 'npm package', pypi: 'PyPI package',
  crates: 'crate', openclaw: 'skill', huggingface: 'model', docker: 'image',
}

function useBoard(params: Parameters<typeof fetchCatalog>[0], key: string) {
  return useQuery({
    queryKey: ['trust-index', key],
    queryFn: () => fetchCatalog(params),
    staleTime: 300_000,
  })
}

function Row({ row, rank }: { row: CatalogRow; rank: number }) {
  const id = rowIdentity(row)
  const inner = (
    <div className="flex items-center gap-3 py-2.5 px-3 rounded-xl hover:bg-surface-hover/60 transition-colors">
      <span className="w-6 text-right font-mono text-[12px] text-text-muted tabular-nums shrink-0">{rank}</span>
      <div className="min-w-0 flex-1">
        <div className="font-mono text-[13.5px] truncate">{id.display}</div>
        <div className="font-mono text-[10.5px] uppercase tracking-wide text-text-muted/70">{SURFACE_LABEL[row.surface] || row.surface}</div>
      </div>
      {row.adoption_count != null && row.adoption_count > 0 && <AdoptionMini count={row.adoption_count} />}
      {row.trust_score != null && <TrustMini score={row.trust_score} />}
    </div>
  )
  return id.repoPath
    ? <Link to={rp(`/rebrand/check/${id.repoPath}`)} className="block">{inner}</Link>
    : <div>{inner}</div>
}

function Board({ title, note, rows, isLoading }: { title: string; note: string; rows?: CatalogRow[]; isLoading: boolean }) {
  return (
    <div className="glass rounded-2xl p-5">
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="text-[16px] font-bold">{title}</h2>
        <span className="font-mono text-[10.5px] text-text-muted uppercase tracking-wide shrink-0">{note}</span>
      </div>
      <div className="mt-3 flex flex-col divide-y divide-border/40">
        {isLoading && <div className="py-8 text-center text-text-muted text-[13px]">loading…</div>}
        {!isLoading && (!rows || !rows.length) && <div className="py-8 text-center text-text-muted text-[13px]">no tools yet</div>}
        {rows?.map((r, i) => <Row key={rowIdentity(r).display + i} row={r} rank={i + 1} />)}
      </div>
    </div>
  )
}

function statFromSummary(s?: CatalogSummary): { flagged: number; scanned: number; pct: number } | null {
  if (!s) return null
  const crit = Object.values(s.by_surface_critical || {}).reduce((a, b) => a + b, 0)
  const high = Object.values(s.by_surface_high || {}).reduce((a, b) => a + b, 0)
  const scanned = s.repo_scans_total || Object.values(s.by_surface || {}).reduce((a, b) => a + b, 0)
  const flagged = crit + high
  if (!scanned) return null
  return { flagged, scanned, pct: Math.round((flagged / scanned) * 100) }
}

export default function RebrandTrustIndex() {
  // Top-scored per surface + most-adopted + certified, from the live catalog.
  // `severity: 'clean'` keeps the "Safest" boards honest — only tools with no critical
  // or high finding rank here, regardless of any stale pre-recalibration score still in
  // the corpus (the re-score is working through it in the background).
  const mcp = useBoard({ surface: 'mcp', sort: 'score-desc', severity: 'clean', limit: 10 }, 'mcp')
  const npm = useBoard({ surface: 'npm', sort: 'score-desc', severity: 'clean', limit: 10 }, 'npm')
  const pypi = useBoard({ surface: 'pypi', sort: 'score-desc', severity: 'clean', limit: 10 }, 'pypi')
  const relied = useBoard({ sort: 'adoption', limit: 10 }, 'adoption')
  const certified = useBoard({ grade: 'certified', sort: 'score-desc', limit: 10 }, 'certified')

  const summary = mcp.data?.summary || npm.data?.summary
  const stat = statFromSummary(summary)
  const totalScanned = summary ? (summary.total_scans || 0).toLocaleString() : '—'

  return (
    <div className="max-w-[1080px] mx-auto px-6 py-16">
      {/* hero — the thesis */}
      <Reveal>
        <div className="max-w-[64ch]">
          <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">The public index</span>
          <h1 className="mt-3 text-3xl md:text-5xl font-extrabold tracking-tight leading-[1.05]">
            The state of <span className="gradient-text-bio">agent tool</span> safety.
          </h1>
          <p className="mt-4 text-text-muted text-[16px] leading-relaxed">
            An independent, <strong className="text-text">signed</strong> index of the tools, MCP servers, and packages AI agents
            connect to — graded from the outside, no repo access, verifiable offline. Not the agent you build; the things it trusts.
          </p>
        </div>
      </Reveal>

      {/* the manufactured headline stat */}
      <Reveal>
        <div className="mt-10 grid sm:grid-cols-3 gap-3">
          <div className="glass rounded-2xl p-6 sm:col-span-2 relative overflow-hidden">
            <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(420px 160px at 15% -20%, rgba(239,68,68,0.12), transparent 70%)' }} />
            <div className="relative">
              <div className="text-[52px] md:text-[64px] font-extrabold leading-none tabular-nums" style={{ color: '#f59e0b' }}>
                {stat ? `${stat.pct}%` : '—'}
              </div>
              <p className="mt-2 text-text text-[15px] max-w-[46ch]">
                of scanned agent tools carry a <strong>high or critical</strong> safety finding.
                {stat && <span className="text-text-muted"> ({stat.flagged.toLocaleString()} of {stat.scanned.toLocaleString()} graded.)</span>}
              </p>
            </div>
          </div>
          <div className="glass rounded-2xl p-6 flex flex-col justify-center">
            <div className="text-[40px] font-extrabold leading-none tabular-nums gradient-text">{totalScanned}</div>
            <p className="mt-2 text-text-muted text-[13.5px]">tools, servers &amp; packages graded — every score signed &amp; recomputable.</p>
          </div>
        </div>
      </Reveal>

      {/* leaderboards */}
      <Reveal>
        <h2 className="mt-14 text-xl font-bold">The leaderboards</h2>
        <p className="mt-1.5 text-text-muted text-[14px] max-w-[62ch]">Ranked from the live catalog — click any tool for its full signed report.</p>
      </Reveal>
      <div className="mt-5 grid md:grid-cols-2 gap-4">
        <Board title="Safest MCP servers" note="by trust" rows={mcp.data?.rows} isLoading={mcp.isLoading} />
        <Board title="Most relied upon" note="by adoption" rows={relied.data?.rows} isLoading={relied.isLoading} />
        <Board title="Safest npm packages" note="by trust" rows={npm.data?.rows} isLoading={npm.isLoading} />
        <Board title="Safest PyPI packages" note="by trust" rows={pypi.data?.rows} isLoading={pypi.isLoading} />
      </div>

      {certified.data?.rows && certified.data.rows.length > 0 && (
        <div className="mt-4">
          <Board title="AgentAvow Certified" note="the top tier · gated" rows={certified.data.rows} isLoading={certified.isLoading} />
        </div>
      )}

      {/* CTA */}
      <Reveal>
        <div className="mt-14 glass rounded-2xl p-8 text-center relative overflow-hidden">
          <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(500px 180px at 50% -30%, rgba(45,212,191,0.14), transparent 70%)' }} />
          <div className="relative">
            <h2 className="text-2xl font-extrabold">Check the tool you're about to connect.</h2>
            <p className="mt-2 text-text-muted text-[14.5px] max-w-[52ch] mx-auto">Paste any repo, package, or MCP server — get a signed, offline-verifiable grade in seconds. Free, no account.</p>
            <div className="mt-5 flex gap-3 justify-center flex-wrap">
              <Link to={rp('/rebrand/check')} className="font-semibold px-6 py-3 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25">Check a tool →</Link>
              <Link to={rp('/rebrand/browse')} className="font-semibold px-6 py-3 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Browse the full catalog</Link>
            </div>
          </div>
        </div>
      </Reveal>
    </div>
  )
}
