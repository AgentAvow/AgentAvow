import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { rp } from '../basePath'
import { Reveal } from '../components/motion'
import { ScorePairMini, TrustOrCertifiedMini } from '../components/TrustMark'
import { CtaBand, PageHeader, SECTION_CLASS, SectionH2 } from '../components/PageBits'
import { fetchCatalog, fetchFlaggedStat, fetchRecent, rowIdentity, type CatalogRow, type FlaggedStat } from '../catalog'
import { AnswerMixBar, StatCards } from '../components/AnswerMix'
import { SandboxFindingsBlock } from '../components/SandboxStats'
import SEOHead from '../../components/SEOHead'

/** Live "just scanned…" feed — real recent scans, refreshed on an interval. */
function RecentFeed() {
  const { data } = useQuery({
    queryKey: ['recent-scans', 8],
    queryFn: () => fetchRecent(8),
    staleTime: 30_000, refetchInterval: 45_000,
  })
  const items = data || []
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
    <div className="glass rounded-2xl p-5 min-w-0 h-full">
      <div className="flex items-center gap-2">
        <span className="relative flex h-2 w-2"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-60" /><span className="relative inline-flex rounded-full h-2 w-2 bg-success" /></span>
        <h2 className="text-[16px] font-bold">Just checked</h2>
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
              {it.trust_score != null && <TrustOrCertifiedMini row={it as unknown as Record<string, unknown> & { trust_score: number }} />}
            </div>
          )
          return href ? <Link key={i} to={href} className="block">{inner}</Link> : <div key={i}>{inner}</div>
        })}
      </div>
    </div>
  )
}

const RISK_LABEL: Record<string, string> = {
  openclaw: 'Agent skills', mcp: 'MCP servers', npm: 'npm packages', github: 'GitHub repos',
  crates: 'Rust crates', pypi: 'PyPI packages', docker: 'Container images', huggingface: 'Hugging Face models',
}
// A share over a few dozen rows says little, so small surfaces stay off the chart.
const RISK_MIN_ROWS = 100

/** Share of checked tools with a critical finding, by kind. Catalog rows, not unique repos. */
function WhereTheRiskIs({ stat }: { stat: FlaggedStat | undefined }) {
  const rows = Object.entries(stat?.by_surface ?? {})
    .filter(([k, v]) => RISK_LABEL[k] && v.scanned_total >= RISK_MIN_ROWS)
    .map(([k, v]) => ({ k, label: RISK_LABEL[k], share: v.critical / v.scanned_total }))
    .sort((a, b) => b.share - a.share)
  const top = rows[0]?.share || 1
  return (
    <div className="glass rounded-2xl p-5 min-w-0">
      <h2 className="font-mono text-[11px] tracking-[0.12em] uppercase text-primary-light">Where the risk is</h2>
      <p className="mt-1 text-[13.5px] text-text-muted">Share of checked tools with a critical finding, by kind</p>
      {rows.length ? (
        <div className="mt-2">
          {rows.map((r) => (
            <div key={r.k} className="grid grid-cols-[120px_1fr_52px] gap-2.5 items-center text-[13px] mt-2">
              <span className="text-text-muted">{r.label}</span>
              <div className="h-2.5 rounded-full bg-surface-hover overflow-hidden">
                <b className="block h-full rounded-full" style={{ width: `${Math.max(2, (r.share / top) * 100)}%`, background: 'linear-gradient(90deg,#F59E0B,#f43f5e)' }} />
              </div>
              <span className="text-right tabular-nums text-text">{(r.share * 100).toFixed(1)}%</span>
            </div>
          ))}
        </div>
      ) : <div className="mt-3 h-[150px] rounded-xl bg-surface-hover/40 animate-pulse" aria-hidden="true" />}
      <p className="mt-3 text-[11.5px] text-text-muted">Critical findings over tools checked, per kind. Counted in catalog rows, not unique repos.</p>
    </div>
  )
}

/**
 * The Trust Index — the outside-in, independent, signed leaderboard of agent-tool
 * safety. Our land-grab move vs. inside-in scorers (they grade the agent you build;
 * we grade the third-party tools an agent connects to). Editorial + shareable: a
 * headline stat computed from the live catalog, then ranked boards per surface.
 */

const SURFACE_LABEL: Record<string, string> = {
  mcp: 'MCP server', npm: 'npm package', pypi: 'PyPI package',
  crates: 'crate', openclaw: 'skill', huggingface: 'model', docker: 'image',
}

// Our own packages (the bridge SDKs, the scanner) would otherwise top the "Safest"
// boards, and one repo can publish several packages; neither reads as an
// independent ranking, so boards skip ours and show one row per repo.
const OWN_RE = /^(agentgraph|agentavow)[-_]|github\.com\/(agentgraph-co|agentavow)\//i

function independent(rows: CatalogRow[], limit: number): CatalogRow[] {
  const seen = new Set<string>()
  const out: CatalogRow[] = []
  for (const r of rows) {
    const repo = (r.repository_url || r.full_name || '').toLowerCase().replace(/\.git$/, '').replace(/\/$/, '')
    if (OWN_RE.test(r.name || '') || OWN_RE.test(repo) || /^(agentgraph-co|agentavow)\//i.test(r.full_name || '')) continue
    if (repo && seen.has(repo)) continue
    if (repo) seen.add(repo)
    out.push(r)
    if (out.length >= limit) break
  }
  return out
}

function useBoard(params: Parameters<typeof fetchCatalog>[0], key: string) {
  const limit = Number(params?.limit ?? 10)
  return useQuery({
    queryKey: ['trust-index', key],
    // Over-fetch so the filter below still leaves a full board.
    queryFn: async () => {
      const data = await fetchCatalog({ ...params, limit: limit * 3 })
      return { ...data, rows: independent(data.rows || [], limit) }
    },
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

function Row({ row, rank }: { row: CatalogRow; rank: number }) {
  const id = rowIdentity(row)
  const href = linkFor(row)
  const inner = (
    <div className="flex items-center gap-3 py-2.5 px-3 rounded-xl hover:bg-surface-hover/60 transition-colors">
      <span className="w-6 text-right font-mono text-[12px] text-text-muted tabular-nums shrink-0">{rank}</span>
      <div className="min-w-0 flex-1">
        <div className="font-mono text-[13.5px] truncate">{id.display}</div>
        <div className="font-mono text-[10.5px] uppercase tracking-wide text-text-muted/70">{SURFACE_LABEL[row.surface] || row.surface}</div>
      </div>
      {/* The trust or Certified mark, then adoption (muted "New" with no signal), in
          the Browse order. The Certified mark follows certified_mark on every board,
          so a certified tool reads the same wherever it is listed. */}
      <ScorePairMini row={row as unknown as Record<string, unknown> & { trust_score: number }} />
    </div>
  )
  return href
    ? <Link to={href} className="block">{inner}</Link>
    : <div>{inner}</div>
}

function Board({ title, note, rows, isLoading: fetching, href }: { title: string; note: string; rows?: CatalogRow[]; isLoading: boolean; certified?: boolean; href?: string }) {
  // The prerender keeps the page's totals but not its tool rows (see prerender-entry.tsx).
  const isLoading = fetching || import.meta.env.SSR
  return (
    // min-w-0: grid items default to min-width:auto and won't shrink below their
    // content — a long tool name in a row was forcing the card past the viewport
    // on mobile (horizontal scroll). Let it clamp to its grid track.
    <div className="glass rounded-2xl p-5 min-w-0">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
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
        {rows?.map((r, i) => <Row key={rowIdentity(r).display + i} row={r} rank={i + 1} />)}
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
  // /index#certified (linked from the Certified page): the boards above it load on
  // their own schedule and push it down, so scroll once every board has settled, then
  // once more on the next frame in case a late row changed the height.
  const certifiedReady = !!certified.data?.rows?.length
  const allSettled = certifiedReady && !mcp.isLoading && !npm.isLoading && !pypi.isLoading && !relied.isLoading
  useEffect(() => {
    if (!allSettled || window.location.hash !== '#certified') return
    const go = () => document.getElementById('certified')?.scrollIntoView({ block: 'start' })
    go()
    const raf = requestAnimationFrame(() => requestAnimationFrame(go))
    return () => cancelAnimationFrame(raf)
  }, [allSettled])

  const { data: stat } = useQuery({ queryKey: ['flagged-stat'], queryFn: fetchFlaggedStat, staleTime: 60_000 })

  return (
    <div>
      <SEOHead
        title="Trust Index — the state of agent tool safety"
        description="An independent index of signed results for the tools AI agents connect to: trust scores, adoption scores, and the critical-finding rate."
        path="/index"
      />
      {/* hero — the thesis */}
      <PageHeader
        eyebrow="Trust Index"
        title={<>The state of <span className="gradient-text-bio">agent tool</span> safety.</>}
        lede={<>An independent, <b className="font-medium text-text">signed</b> index of the tools, MCP servers, and packages AI agents connect to — checked from the outside, no repo access, verifiable offline. Not the agent you build; the things it trusts.</>}
      />
      <div className="relative z-[2] max-w-[1080px] mx-auto px-6 pb-[60px]">
      {/* how the catalog reads: the answer mix and the counts under it, all live */}
      <Reveal>
        <div className="mt-2">
          <AnswerMixBar size="big" />
          <StatCards set="index" />
        </div>
      </Reveal>

      {/* the highlight cards. "Do not connect this week", "Most checked this week" and
          the share-with-a-serious-finding headline wait on their data (spec 2026-11-07). */}
      <Reveal>
        <div className="mt-4 grid md:grid-cols-12 gap-4">
          <div className="md:col-span-8 min-w-0"><WhereTheRiskIs stat={stat} /></div>
          <div className="md:col-span-4 min-w-0"><RecentFeed /></div>
        </div>
      </Reveal>

      {/* From the sandbox — 30-day behavioral findings by rule (hidden until the sandbox has run) */}
      <Reveal><div className="mt-4"><SandboxFindingsBlock /></div></Reveal>

      {/* leaderboards */}
      <Reveal>
        <SectionH2 className="mt-[60px]">The leaderboards</SectionH2>
        <p className="mt-2.5 text-text-muted max-w-[62ch]">Ranked from the live catalog — click any tool for its full signed report.</p>
      </Reveal>
      <div className="mt-5 grid md:grid-cols-2 gap-4">
        <Board title="Safest MCP servers" note="by trust" rows={mcp.data?.rows} isLoading={mcp.isLoading} />
        <Board title="Most relied upon" note="by adoption" rows={relied.data?.rows} isLoading={relied.isLoading} />
        <Board title="Safest npm packages" note="by trust" rows={npm.data?.rows} isLoading={npm.isLoading} />
        <Board title="Safest PyPI packages" note="by trust" rows={pypi.data?.rows} isLoading={pypi.isLoading} />
      </div>

      {certified.data?.rows && certified.data.rows.length > 0 && (
        <div id="certified" className="mt-4 scroll-mt-24">
          <Board title="AgentAvow Certified" note="the earned mark · gated" rows={certified.data.rows} isLoading={certified.isLoading} certified href={rp('/rebrand/certified')} />
        </div>
      )}

      </div>

      <section className={SECTION_CLASS}>
        <div className="max-w-[1080px] mx-auto px-6">
          <Reveal>
            <CtaBand
              title="Check the tool you're about to connect."
              line="Paste any repo, package, or MCP server — get an answer and a signed, offline-verifiable trust score in seconds. Free, no account."
              primary={{ label: 'Check a tool →', to: rp('/rebrand/check') }}
              secondary={{ label: 'Browse the full catalog', to: rp('/rebrand/browse') }}
            />
          </Reveal>
        </div>
      </section>
    </div>
  )
}
