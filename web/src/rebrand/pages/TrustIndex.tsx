import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { rp } from '../basePath'
import { Reveal } from '../components/motion'
import { TrustMini, AdoptionMini } from '../components/TrustMark'
import { fetchCatalog, fetchFlaggedStat, rowIdentity, type CatalogRow } from '../catalog'
import { publicApi } from '../../lib/scanApi'

interface RecentItem { surface: string; name: string; full_name: string | null; trust_score: number | null; at: string | null }

/** Live "just scanned…" feed — real recent scans, refreshed on an interval. */
function RecentFeed() {
  const { data } = useQuery({
    queryKey: ['recent-scans'],
    queryFn: async () => (await publicApi.get<{ items: RecentItem[] }>('/public/scan-catalog/recent?limit=12')).data,
    staleTime: 30_000, refetchInterval: 45_000,
  })
  const items = data?.items || []
  if (!items.length) return null
  const ago = (iso: string | null) => {
    if (!iso) return ''
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
    if (s < 90) return 'just now'
    if (s < 3600) return `${Math.round(s / 60)}m ago`
    if (s < 86400) return `${Math.round(s / 3600)}h ago`
    return `${Math.round(s / 86400)}d ago`
  }
  return (
    <div className="glass rounded-2xl p-5">
      <div className="flex items-center gap-2">
        <span className="relative flex h-2 w-2"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-60" /><span className="relative inline-flex rounded-full h-2 w-2 bg-success" /></span>
        <h2 className="text-[16px] font-bold">Just scanned</h2>
      </div>
      <div className="mt-3 flex flex-col divide-y divide-border/40">
        {items.map((it, i) => {
          const href = linkFor(it as unknown as CatalogRow)
          const inner = (
            <div className="flex items-center gap-3 py-2 px-2 rounded-lg hover:bg-surface-hover/50 transition-colors">
              <div className="min-w-0 flex-1">
                <div className="font-mono text-[12.5px] truncate">{it.name || it.full_name}</div>
                <div className="font-mono text-[10px] text-text-muted/70">{SURFACE_LABEL[it.surface] || it.surface} · {ago(it.at)}</div>
              </div>
              {it.trust_score != null && <TrustMini score={it.trust_score} />}
            </div>
          )
          return href ? <Link key={i} to={href} className="block">{inner}</Link> : <div key={i}>{inner}</div>
        })}
      </div>
    </div>
  )
}

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

const PKG_SURFACES = ['npm', 'pypi', 'crates', 'huggingface', 'docker']

/** Route a catalog row to its correct score page by surface (mirrors Browse). */
function linkFor(row: CatalogRow): string | null {
  const fn = row.full_name || ''
  if (PKG_SURFACES.includes(row.surface)) {
    // package coordinate; strip any leading "surface:" prefix from the name
    const nm = (row.name || '').includes(':') ? (row.name || '').split(':').slice(1).join(':') : row.name
    return nm ? rp(`/rebrand/check/pkg/${row.surface}/${nm}`) : null
  }
  if (row.surface === 'openclaw' && fn.includes('/')) return rp(`/rebrand/check/skill/${fn}`)
  if (row.surface === 'mcp') {
    const ep = row.endpoint_url
    if (ep && /^https?:/.test(ep)) return rp(`/rebrand/check/mcp?endpoint=${encodeURIComponent(ep)}`)
  }
  if (fn.includes('/')) return rp(`/rebrand/check/${fn}`)
  return null
}

function Row({ row, rank, certified = false }: { row: CatalogRow; rank: number; certified?: boolean }) {
  const id = rowIdentity(row)
  const href = linkFor(row)
  const inner = (
    <div className="flex items-center gap-3 py-2.5 px-3 rounded-xl hover:bg-surface-hover/60 transition-colors">
      <span className="w-6 text-right font-mono text-[12px] text-text-muted tabular-nums shrink-0">{rank}</span>
      <div className="min-w-0 flex-1">
        <div className="font-mono text-[13.5px] truncate">{id.display}</div>
        <div className="font-mono text-[10.5px] uppercase tracking-wide text-text-muted/70">{SURFACE_LABEL[row.surface] || row.surface}</div>
      </div>
      {row.adoption_count != null && row.adoption_count > 0 && <AdoptionMini count={row.adoption_count} />}
      {certified
        ? <span className="inline-flex items-center gap-1 font-mono text-[10.5px] font-extrabold tracking-[0.12em] px-2 py-1 rounded-full shrink-0" style={{ background: 'linear-gradient(120deg,#2dd4bf,#e879f9)', color: '#06231f' }}>✓ {row.trust_score}</span>
        : row.trust_score != null && <TrustMini score={row.trust_score} />}
    </div>
  )
  return href
    ? <Link to={href} className="block">{inner}</Link>
    : <div>{inner}</div>
}

function Board({ title, note, rows, isLoading, certified = false, href }: { title: string; note: string; rows?: CatalogRow[]; isLoading: boolean; certified?: boolean; href?: string }) {
  return (
    // min-w-0: grid items default to min-width:auto and won't shrink below their
    // content — a long tool name in a row was forcing the card past the viewport
    // on mobile (horizontal scroll). Let it clamp to its grid track.
    <div className="glass rounded-2xl p-5 min-w-0">
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="text-[16px] font-bold">
          {href ? <Link to={href} className="hover:text-primary-light transition-colors">{title}</Link> : title}
        </h2>
        {href
          ? <Link to={href} className="font-mono text-[10.5px] text-primary-light hover:text-primary uppercase tracking-wide shrink-0">{note} · what's this? →</Link>
          : <span className="font-mono text-[10.5px] text-text-muted uppercase tracking-wide shrink-0">{note}</span>}
      </div>
      <div className="mt-3 flex flex-col divide-y divide-border/40">
        {isLoading && <div className="py-8 text-center text-text-muted text-[13px]">loading…</div>}
        {!isLoading && (!rows || !rows.length) && <div className="py-8 text-center text-text-muted text-[13px]">no tools yet</div>}
        {rows?.map((r, i) => <Row key={rowIdentity(r).display + i} row={r} rank={i + 1} certified={certified} />)}
      </div>
    </div>
  )
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
  const { data: stat } = useQuery({ queryKey: ['flagged-stat'], queryFn: fetchFlaggedStat, staleTime: 60_000 })
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
            {/* stack on mobile; on desktop the number + copy sit side-by-side so the
                wide 2-col box doesn't leave a big empty right half. */}
            <div className="relative flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-6">
              <div className="text-[52px] md:text-[64px] font-extrabold leading-none tabular-nums shrink-0" style={{ color: '#f59e0b' }}>
                {stat ? `${stat.pct}%` : '—'}
              </div>
              <p className="text-text text-[15px]">
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

      {/* live feed — real recent scans */}
      <div className="mt-4"><Reveal><RecentFeed /></Reveal></div>

      {certified.data?.rows && certified.data.rows.length > 0 && (
        <div className="mt-4">
          <Board title="AgentAvow Certified" note="the top tier · gated" rows={certified.data.rows} isLoading={certified.isLoading} certified href={rp('/rebrand/certified')} />
        </div>
      )}

      {/* CTA — frameless, sits on the page */}
      <Reveal>
        <div className="mt-16 text-center">
          <h2 className="text-2xl font-extrabold">Check the tool you're about to connect.</h2>
          <p className="mt-2 text-text-muted text-[14.5px] max-w-[52ch] mx-auto">Paste any repo, package, or MCP server — get a signed, offline-verifiable grade in seconds. Free, no account.</p>
          <div className="mt-5 flex gap-3 justify-center flex-wrap">
            <Link to={rp('/rebrand/check')} className="font-semibold px-6 py-3 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25">Check a tool →</Link>
            <Link to={rp('/rebrand/browse')} className="font-semibold px-6 py-3 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Browse the full catalog</Link>
          </div>
        </div>
      </Reveal>
    </div>
  )
}
