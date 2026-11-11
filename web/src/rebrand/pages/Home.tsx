import { useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { rp } from '../basePath'
import { unsupportedRepoHost, unsupportedRepoHostMessage } from '../lib/unsupportedHost'
import { NoticeText } from '../components/NoticeText'
import { motion, useReducedMotion } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import { fetchCatalog, type CatalogRow } from '../catalog'
import { decisionOf, decisionPhrase, getTrustTier, isCertified } from '../../components/trust/gradeSystem'
import { TrustBar, AdoptionNeedle, CertifiedBadge } from '../components/TrustMark'
import { Reveal } from '../components/motion'
import { currentPath, trackCheckSubmit, trackEvent } from '../../lib/analytics'
import { useRotatingPlaceholder } from '../lib/hooks'
import SEOHead from '../../components/SEOHead'
import { inSnapshot } from '../lib/snapshot'
import { AnswerMixBar, StatCards } from '../components/AnswerMix'
import { DNC_LIST, useAnswerMix } from '../lib/answerMix'
import { BuiltInTheOpen } from '../components/BuiltInTheOpen'
import { WhereItWorks } from '../components/WhereItWorks'
import { CtaBand, SECTION_CLASS, SectionH2 } from '../components/PageBits'

const CHECK_HINTS = ['Paste a link to check', 'github.com/owner/repo', 'npmjs.com/package/…', 'https://mcp.example.com/mcp', 'pypi:requests', 'an A2A agent card URL']

/**
 * AgentAvow homepage (approved mockup 2026-11-10, "Home order"). Five sections:
 * hero (the check itself + one "works with" line) → the three answers on live
 * examples, with how the catalog reads → where it works (Claude Code first) → why
 * trust it (findings, signatures, limits, built in the open) → closing band. Certified
 * sits as one compact row under the three answers (Kenne, 11-11).
 */

/**
 * The example chips. Each fills the check box and shows that tool's live catalog row
 * in the card below; the card links to the full report.
 */
type ExampleKey = 'safe' | 'deep' | 'review'
const EXAMPLES: { key: ExampleKey; chip: string; input: string; surface: string; q: string; match: (r: CatalogRow) => boolean }[] = [
  { key: 'safe', chip: 'A Certified package', input: 'npmjs.com/package/zod', surface: 'npm', q: 'zod', match: (r) => r.full_name === 'npm:zod' },
  { key: 'deep', chip: 'A live MCP server', input: 'https://mcp.deepwiki.com/mcp', surface: 'mcp', q: 'mcp.deepwiki.com', match: (r) => r.endpoint_url === 'https://mcp.deepwiki.com/mcp' },
  { key: 'review', chip: 'A deprecated server', input: 'npmjs.com/package/@modelcontextprotocol/server-puppeteer', surface: 'npm', q: '@modelcontextprotocol/server-puppeteer', match: (r) => r.full_name === 'npm:@modelcontextprotocol/server-puppeteer' },
]
type Tab = ExampleKey | 'dnc'

/** Large animated trust-seal for the hero — echoes the logo, draws itself in on load. */
function HeroSeal() {
  const reduce = useReducedMotion()
  return (
    <motion.svg
      viewBox="0 0 96 96" className="w-[72px] h-[72px] mx-auto mb-6" aria-hidden="true"
      initial={reduce || inSnapshot() ? false : { opacity: 0, scale: 0.85 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.6, ease: 'easeOut' }}
    >
      <defs>
        <linearGradient id="seal-g" gradientUnits="userSpaceOnUse" x1="8" y1="8" x2="88" y2="88">
          <stop stopColor="#2DD4BF" /><stop offset="1" stopColor="#E879F9" />
        </linearGradient>
        <linearGradient id="seal-check" x1="0" y1="0" x2="1" y2="1">
          <stop stopColor="#2DD4BF" /><stop offset="1" stopColor="#E879F9" />
        </linearGradient>
      </defs>
      <motion.circle
        cx="48" cy="48" r="40" fill="none" stroke="url(#seal-g)" strokeWidth="3"
        style={{ transformBox: 'fill-box', transformOrigin: 'center' }}
        animate={reduce ? {} : { rotate: 360 }}
        transition={{ duration: 16, ease: 'linear', repeat: Infinity }}
        strokeDasharray="4 10" strokeLinecap="round"
      />
      <circle cx="48" cy="48" r="30" fill="none" stroke="var(--color-primary-light)" strokeWidth="1.5" opacity="0.35" />
      <motion.path
        d="M34 49l9 9 19-20" fill="none" stroke="url(#seal-check)" strokeWidth="5"
        strokeLinecap="round" strokeLinejoin="round" pathLength={1}
        initial={reduce || inSnapshot() ? false : { pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 0.7, ease: 'easeOut', delay: 0.35 }}
      />
    </motion.svg>
  )
}

/**
 * A pasted link with no scheme ("npmjs.com/package/x", "mcp.example.com/mcp") gets
 * https:// so it routes like the full URL. GitHub user and org names can't contain a
 * dot, so a first segment with one is a host, not an owner/repo.
 */
function withScheme(v: string): string {
  if (/^[a-z][\w+.-]*:/i.test(v)) return v
  const host = v.split('/')[0]
  const dots = (host.match(/\./g) ?? []).length
  if (!/^[\w-]+(\.[\w-]+)+(:\d+)?$/.test(host) || !/\.[a-z]{2,}(:\d+)?$/i.test(host)) return v
  if (v.includes('/') || dots >= 2) return `https://${v}`
  return v
}

const SEG_STYLE: Record<Tab, string> = {
  safe: 'text-success border-success/50 bg-success/[0.08]',
  deep: 'text-success border-success/50 bg-success/[0.08]',
  review: 'text-warning border-warning/50 bg-warning/[0.08]',
  dnc: 'text-danger border-danger/50 bg-danger/[0.08]',
}

const sentence = (s: string) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s)

function reportHref(row: CatalogRow): string {
  if (row.surface === 'mcp' && row.endpoint_url) return rp('/rebrand/check/mcp') + '?endpoint=' + encodeURIComponent(row.endpoint_url)
  if (['npm', 'pypi', 'crates', 'huggingface', 'docker'].includes(row.surface)) return rp(`/rebrand/check/pkg/${row.surface}/${row.name}`)
  return rp(row.full_name?.includes('/') ? `/rebrand/check/${row.full_name}` : '/rebrand/check')
}

/** The answer line. Certified is never tagged here: it shows once, as the badge in the
 * trust-score slot. */
function VerdictLine({ value }: { value: 'safe' | 'review' | 'do_not_connect' }) {
  const p = decisionPhrase(value)
  const icon = value === 'safe' ? '✓' : value === 'review' ? '!' : '✕'
  // Theme tokens (success / warning / danger), so the line reads in light theme too.
  const tone = value === 'safe' ? 'text-success' : value === 'review' ? 'text-warning' : 'text-danger'
  const toneBg = value === 'safe' ? 'bg-success/15' : value === 'review' ? 'bg-warning/15' : 'bg-danger/15'
  return (
    <div className={`mt-[7px] flex items-center gap-[9px] flex-wrap text-[21px] font-bold tracking-[-0.01em] ${tone}`} data-decision={value}>
      <span className={`w-6 h-6 rounded-full inline-grid place-items-center text-[13px] font-extrabold shrink-0 ${toneBg}`} aria-hidden="true">{icon}</span>
      {p.phrase}
    </div>
  )
}

function ExampleCard({ row }: { row: CatalogRow }) {
  const d = decisionOf({ ...row, findings: { critical: row.critical ?? 0, high: row.high ?? 0 } }).decision
  const certified = d === 'safe' && isCertified(row)
  const score = row.trust_score as number
  const t = getTrustTier(score)
  const n = row.findings_count ?? 0
  const finds = [
    row.critical ? `${row.critical} critical` : null,
    row.high ? `${row.high} high` : null,
    `${n} ${n === 1 ? 'finding' : 'findings'} (any severity)`,
  ].filter(Boolean).join(' · ')
  return (
    <>
      <div className="px-5 py-[18px] border-b border-border/60">
        <div className="font-mono text-[13.5px] break-all text-text-muted">{row.endpoint_url || row.name}</div>
        <VerdictLine value={d} />
        {row.decision_reason && <p className="mt-1.5 text-[14.5px] text-text">{sentence(row.decision_reason)}.</p>}
      </div>
      <div className="grid grid-cols-2">
        <div className="px-5 py-[18px] max-[520px]:px-2 flex flex-col items-center gap-[9px] text-center">
          <div className="min-h-[90px] flex items-center justify-center">{certified ? <CertifiedBadge score={score} size="md" /> : <TrustBar score={score} />}</div>
          <div className="font-mono text-[10.5px] font-bold uppercase tracking-[0.14em]" style={{ color: certified ? undefined : t.color }}>Trust score</div>
        </div>
        <div className="px-5 py-[18px] max-[520px]:px-2 flex flex-col items-center gap-[9px] text-center border-l border-border/60">
          <div className="min-h-[90px] flex items-center justify-center"><AdoptionNeedle count={row.adoption_count} unit={row.adoption_unit ?? undefined} scorePct={row.adoption_score} /></div>
          <div className="font-mono text-[10.5px] font-bold uppercase tracking-[0.14em] text-text-muted">Adoption score</div>
        </div>
      </div>
      <div className="px-5 py-3 border-t border-border/60 text-[13px] text-text-muted">{finds}</div>
      <div className="flex gap-3.5 flex-wrap items-center px-5 py-[13px] border-t border-dashed border-border text-[13px]">
        <span className="font-mono text-[12px] text-success">✓ Signed · Ed25519 / JWS</span>
        <Link to={reportHref(row)} className="sm:ml-auto font-semibold text-primary-light hover:text-primary">See the full report →</Link>
      </div>
    </>
  )
}

/** No named tool here until someone has read its report: the answer, what triggers it, and the live list. */
function DoNotConnectCard() {
  const { data: mix } = useAnswerMix()
  return (
    <>
      <div className="px-5 py-[18px] border-b border-border/60">
        <VerdictLine value="do_not_connect" />
        <p className="mt-1.5 text-[14.5px] text-text">A critical finding in what the tool ships caps its trust score at 45. The report names the finding and points at the exact file and line.</p>
      </div>
      <div className="flex gap-3.5 flex-wrap items-center px-5 py-[13px] text-[13px]">
        <span className="font-mono text-[12px] text-success">✓ Signed · Ed25519 / JWS</span>
        <Link to={rp(DNC_LIST)} className="sm:ml-auto font-semibold text-primary-light hover:text-primary">
          {mix ? `See the ${mix.dnc.toLocaleString()} tools that read Do not connect →` : 'See the tools that read Do not connect →'}
        </Link>
      </div>
    </>
  )
}

function Card3({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="glass rounded-2xl border border-border/60 p-[22px] flex flex-col gap-[9px] min-w-0">
      <h3 className="text-[19px] font-bold tracking-[-0.01em]">{title}</h3>
      {children}
    </div>
  )
}

/**
 * The Certified row, right under the three answers. The badge is the Safe example's
 * live row (zod) when that row carries the mark; with no certified row to show (and
 * in the prerender, which names no tool) it falls back to the plain seal. The full
 * checklist lives on /certified.
 */
function CertifiedRow({ row }: { row: CatalogRow | null }) {
  const earned = row != null && row.trust_score != null && decisionOf({ ...row, findings: { critical: row.critical ?? 0, high: row.high ?? 0 } }).decision === 'safe' && isCertified(row)
  return (
    <div className="mt-8 max-w-[760px] mx-auto flex flex-col sm:flex-row items-center gap-x-5 gap-y-3 rounded-2xl px-5 py-4 text-center sm:text-left"
      style={{ background: 'linear-gradient(100deg,rgba(45,212,191,.10),rgba(232,121,249,.08) 70%), var(--color-surface)', border: '1px solid rgba(232,121,249,.30)' }}>
      <div className="shrink-0 flex flex-col items-center gap-1">
        {earned
          ? <><CertifiedBadge score={row.trust_score as number} size="md" /><small className="text-[11.5px] text-text-muted">{row.name}, today</small></>
          : <>
              <div className="w-[52px] h-[52px] rounded-full grid place-items-center text-[24px] font-black text-[#06231f]" style={{ background: 'conic-gradient(from 210deg,#2DD4BF,#E879F9,#2DD4BF)' }} aria-hidden="true">✓</div>
              <div className="font-mono text-[10.5px] font-extrabold tracking-[0.18em] gradient-text">CERTIFIED</div>
            </>}
      </div>
      <p className="min-w-0 text-[14.5px] text-text-muted">
        <b className="text-text font-semibold">Certified is the top mark:</b> every check passes, no averaging, and it comes off the moment one fails.{' '}
        <Link to={rp('/rebrand/certified')} className="font-semibold text-primary-light hover:text-primary whitespace-nowrap">See the gate and who's Certified →</Link>
      </p>
    </div>
  )
}

export default function RebrandHome() {
  const [value, setValue] = useState('')
  const [notice, setNotice] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('safe')
  const resultRef = useRef<HTMLElement>(null)
  const navigate = useNavigate()
  const hint = useRotatingPlaceholder(CHECK_HINTS)
  const runCheck = (input: string) => {
    const v = withScheme(input.trim())
    if (v) {
      trackEvent('guest_cta_click', currentPath(), 'check_a_tool')
      trackCheckSubmit()
    }
    setNotice(null)
    // A repo host we know but can't read yet: say so instead of scanning the same-named GitHub repo.
    const host = unsupportedRepoHost(v)
    if (host) { setNotice(unsupportedRepoHostMessage(host)); return }
    // Live MCP server: `mcp:https://…`.
    const mcp = v.match(/^mcp\s*:\s*(https?:\/\/.+)$/i)
    if (mcp) { navigate(rp('/rebrand/check/mcp') + '?endpoint=' + encodeURIComponent(mcp[1].trim())); return }
    // A2A Agent Card: `a2a:https://…`, or a pasted URL to a well-known card path.
    const a2a = v.match(/^a2a\s*:\s*(https?:\/\/.+)$/i)
    if (a2a || /^https?:\/\/\S+\/\.well-known\/agent(?:-card)?\.json(?:[?#]\S*)?$/i.test(v)) {
      navigate(rp('/rebrand/check/a2a') + '?card=' + encodeURIComponent(a2a ? a2a[1].trim() : v)); return
    }
    // Agent Skill: `skill:owner/repo`.
    const sk = v.match(/^skill\s*:\s*(?:github\.com\/)?([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/i)
    if (sk) { navigate(rp(`/rebrand/check/skill/${sk[1]}/${sk[2]}`)); return }
    // Package coordinate: `npm:chalk`, `pypi:requests`, `npm:@scope/pkg`.
    const pkg = v.match(/^(npm|pypi|python|crates|cargo|rust|hf|huggingface|docker|container|oci)\s*:\s*(.+)$/i)
    if (pkg) {
      const k = pkg[1].toLowerCase()
      const surface = k === 'python' ? 'pypi'
        : (k === 'cargo' || k === 'rust') ? 'crates'
        : k === 'hf' ? 'huggingface'
        : (k === 'container' || k === 'oci') ? 'docker' : k
      navigate(rp(`/rebrand/check/pkg/${surface}/${pkg[2].trim()}`))
      return
    }
    // A pasted registry URL → the right package scan (before the bare-URL→MCP rule).
    let ru
    if ((ru = v.match(/^https?:\/\/(?:www\.)?crates\.io\/crates\/([\w-]+)/i))) { navigate(rp(`/rebrand/check/pkg/crates/${ru[1]}`)); return }
    if ((ru = v.match(/^https?:\/\/huggingface\.co\/([\w.-]+\/[\w.-]+)(?:$|[/?#])/i)) &&
        !/^(datasets|spaces|models|organizations|settings)\//i.test(ru[1])) {
      navigate(rp(`/rebrand/check/pkg/huggingface/${ru[1]}`)); return
    }
    if ((ru = v.match(/^https?:\/\/hub\.docker\.com\/_\/([\w.-]+)/i))) { navigate(rp(`/rebrand/check/pkg/docker/${ru[1]}`)); return }
    if ((ru = v.match(/^https?:\/\/hub\.docker\.com\/r\/([\w.-]+\/[\w.-]+)/i))) { navigate(rp(`/rebrand/check/pkg/docker/${ru[1]}`)); return }
    if ((ru = v.match(/^https?:\/\/ghcr\.io\/([\w.-]+\/[\w.-]+)/i))) { navigate(rp(`/rebrand/check/pkg/docker/ghcr.io/${ru[1]}`)); return }
    if ((ru = v.match(/^https?:\/\/(?:www\.)?npmjs\.com\/package\/((?:@[\w.-]+\/)?[\w.-]+)/i))) { navigate(rp(`/rebrand/check/pkg/npm/${ru[1]}`)); return }
    if ((ru = v.match(/^https?:\/\/pypi\.org\/project\/([\w.-]+)/i))) { navigate(rp(`/rebrand/check/pkg/pypi/${ru[1]}`)); return }
    // A bare URL (no prefix) that isn't a GitHub/GitLab repo link → a live MCP
    // endpoint. Users paste the endpoint URL directly, without the `mcp:` prefix.
    if (/^https?:\/\/\S+$/i.test(v) && !/^https?:\/\/(www\.)?(github|gitlab)\.com\//i.test(v)) {
      navigate(rp('/rebrand/check/mcp') + '?endpoint=' + encodeURIComponent(v)); return
    }
    const m = v.match(/(?:github\.com\/)?([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/)
    navigate(rp(m ? `/rebrand/check/${m[1]}/${m[2]}` : '/rebrand/check'))
  }

  // The example rows, live from the catalog. Kept out of the prerender: static HTML
  // names no tool and its answer (see prerender-entry.tsx).
  const { data: examples, isError: examplesFailed } = useQuery({
    queryKey: ['home-examples'],
    queryFn: async () => {
      const found = await Promise.all(EXAMPLES.map(async (ex) => {
        const data = await fetchCatalog({ surface: ex.surface, q: ex.q, limit: 5 })
        const row = (data.rows ?? []).find((r) => ex.match(r) && r.trust_score != null)
        return [ex.key, row ?? null] as const
      }))
      return Object.fromEntries(found) as Record<ExampleKey, CatalogRow | null>
    },
    staleTime: 60 * 60_000,
  })
  const chooseExample = (key: ExampleKey) => {
    const ex = EXAMPLES.find((e) => e.key === key)!
    setValue(ex.input)
    setTab(key)
    resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
  const pressed = (k: Tab) => tab === k || (k === 'safe' && tab === 'deep')
  const shown = tab === 'dnc' ? null : examples?.[tab]

  return (
    <div>
      <SEOHead
        title="Is this AI tool safe to connect?"
        description="Is this AI tool safe to connect? Get Safe to connect, Review before you connect, or Do not connect, with a signed trust score and an adoption score."
        path="/"
      />

      {/* 1 · HERO = the check itself */}
      <section className="text-center pt-16 pb-10 px-6">
        <motion.div
          className="max-w-[1080px] mx-auto"
          initial={inSnapshot() ? false : { opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
        >
          <HeroSeal />
          <h1 className="text-4xl sm:text-5xl md:text-6xl font-extrabold leading-[1.06] tracking-tight">
            Is this AI tool <span className="gradient-text-bio">safe</span> to connect?
          </h1>
          <p className="mt-5 mx-auto max-w-[58ch] text-lg text-text-muted font-light">
            Paste a link to any app, connector or package. Get a clear answer, <b className="text-text font-semibold">Safe to connect</b>, <b className="text-text font-semibold">Review before you connect</b>, or <b className="text-text font-semibold">Do not connect</b>, with the reasons.
          </p>

          <form
            onSubmit={(e) => { e.preventDefault(); runCheck(value) }}
            className="glass mt-8 mx-auto max-w-[600px] flex gap-2.5 rounded-2xl p-2 pl-4 shadow-lg shadow-primary/10"
          >
            <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5 self-center text-text-muted shrink-0" aria-hidden="true">
              <path d="M11 19a8 8 0 1 1 5.7-2.3L21 21" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
            </svg>
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              aria-label="Link to check"
              placeholder={value ? '' : hint}
              className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[15.5px] text-text placeholder:text-text-muted"
            />
            <button type="submit" className="font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow whitespace-nowrap">
              Check
            </button>
          </form>
          {notice && <p role="alert" className="mt-3 mx-auto max-w-[600px] text-[13px] text-warning"><NoticeText text={notice} /></p>}

          <div className="mt-4 flex flex-wrap gap-2 justify-center items-center">
            <span className="text-[13px] text-text-muted">Try one:</span>
            {EXAMPLES.map((ex) => (
              <button
                key={ex.key}
                type="button"
                onClick={() => chooseExample(ex.key)}
                className="text-[13px] text-text-muted bg-surface border border-border rounded-full px-[13px] py-1.5 hover:border-primary-light hover:text-primary-light transition-colors"
              >
                {ex.chip}
              </button>
            ))}
          </div>
          <p className="mt-3.5 text-[13px] text-text-muted">Free. No account. Every answer is signed.</p>
          <p className="mt-3.5 mx-auto max-w-[62ch] text-[14px] text-text-muted">
            Works with Claude Code, Claude, ChatGPT, Codex, Cursor, VS Code, Gemini CLI and CI.{' '}
            <a href="#where" onClick={(e) => { e.preventDefault(); document.getElementById('where')?.scrollIntoView({ behavior: 'smooth', block: 'start' }) }}
              className="font-semibold text-primary-light hover:text-primary whitespace-nowrap">See where it works ↓</a>
          </p>
        </motion.div>
      </section>

      {/* 2 · THE THREE ANSWERS, on live examples, how the catalog reads, then Certified */}
      <section ref={resultRef} id="result" className={`${SECTION_CLASS} scroll-mt-20`}>
        <div className="max-w-[1080px] mx-auto px-6">
          <Reveal>
            <div className="text-center max-w-[60ch] mx-auto">
              <SectionH2>Every check ends in one of three answers.</SectionH2>
              <p className="mt-2.5 text-text-muted">The answer comes first, with its reason. Under it sit two scores: a signed 0-100 trust score and an adoption score.</p>
            </div>
            <div className="mt-[22px] flex gap-1.5 flex-wrap justify-center" role="group" aria-label="Example answers">
              {([['safe', 'Safe to connect'], ['review', 'Review before you connect'], ['dnc', 'Do not connect']] as [Tab, string][]).map(([k, label]) => (
                <button key={k} type="button" aria-pressed={pressed(k)} onClick={() => setTab(k)}
                  className={`rounded-[10px] border px-[13px] py-2 text-[13.5px] font-semibold transition-colors ${pressed(k) ? SEG_STYLE[k] : 'bg-surface border-border text-text-muted hover:text-text'}`}>
                  {label}
                </button>
              ))}
            </div>
            <div className="glass rounded-2xl overflow-hidden max-w-[640px] mx-auto mt-[18px] text-left">
              {tab === 'dnc'
                ? <DoNotConnectCard />
                : shown
                  ? <ExampleCard row={shown} />
                  : examplesFailed || examples
                    ? <div className="p-8 text-center text-[14px] text-text-muted">This example isn't available right now. <Link to={rp('/rebrand/browse')} className="text-primary-light hover:text-primary font-semibold">Browse the catalog →</Link></div>
                    : <div className="h-[300px] animate-pulse" aria-hidden="true" />}
            </div>
            <div className="grid sm:grid-cols-2 gap-3.5 max-w-[640px] mx-auto mt-4 text-[14px] text-text-muted text-left">
              <p><b className="text-text font-semibold">Trust score.</b> How safe the tool looks, worked out from what the check found.</p>
              <p><b className="text-text font-semibold">Adoption score.</b> How much people really use it. Popular doesn't mean safe, so the two stay separate.</p>
            </div>
          </Reveal>
          <Reveal>
            <div className="max-w-[980px] mx-auto mt-10">
              <AnswerMixBar size="big" />
              <StatCards set="home" />
            </div>
            <p className="mt-3.5 text-center text-[13px] text-text-muted">Hundreds of Claude Code machines connect every day. A check you run here is normally no more than an hour old.</p>
          </Reveal>
          <Reveal>
            <CertifiedRow row={examples?.safe ?? null} />
          </Reveal>
        </div>
      </section>

      {/* 3 · WHERE IT WORKS — Claude Code first */}
      <section id="where" className={`${SECTION_CLASS} scroll-mt-20`}>
        <div className="max-w-[1080px] mx-auto px-6">
          <Reveal>
            <SectionH2>Get the check where you work.</SectionH2>
            <WhereItWorks />
            <p className="mt-1.5 text-[14.5px] text-text-muted">For your team: gate CI on the answer, get an alert when a tool changes, and verify every result offline. <Link to={rp('/rebrand/teams')} className="font-semibold text-primary-light hover:text-primary">See how teams use it →</Link></p>
            <p className="mt-1.5 text-[14.5px] text-text-muted">Publish a tool? Get a signed badge and claim your listing. <Link to={rp('/rebrand/for-developers')} className="font-semibold text-primary-light hover:text-primary">For developers →</Link></p>
          </Reveal>
        </div>
      </section>

      {/* 4 · WHY TRUST IT — the three cards, then built in the open */}
      <section className={SECTION_CLASS}>
        <div className="max-w-[1080px] mx-auto px-6">
          <Reveal>
            <SectionH2>You don't have to take our word for it.</SectionH2>
            <div className="grid md:grid-cols-3 gap-3.5 mt-[26px]">
              <Card3 title="Findings you can read"><p className="text-text-muted text-[14.5px]">Each finding has a severity and points at the exact file, line or manifest entry.</p></Card3>
              <Card3 title="Results you can verify"><p className="text-text-muted text-[14.5px]">Every result is signed with Ed25519. Anyone can check it offline against our public keys.</p></Card3>
              <Card3 title="Limits we state"><p className="text-text-muted text-[14.5px]">A check reads code, dependencies, advisories and tool definitions. It can miss things, so the report says what it couldn't read.</p></Card3>
            </div>
          </Reveal>
          <Reveal>
            <BuiltInTheOpen className="mt-[30px]" />
          </Reveal>
        </div>
      </section>

      {/* 5 · CLOSING BAND */}
      <section className={SECTION_CLASS}>
        <div className="max-w-[1080px] mx-auto px-6">
          <Reveal>
            <CtaBand
              title="Check the next tool before you connect it."
              line="Free. No account. Every answer is signed."
              primary={{ label: 'Check a tool', to: rp('/rebrand/check') }}
              secondary={{ label: 'Get AgentAvow', to: rp('/rebrand/get') }}
            />
          </Reveal>
        </div>
      </section>
    </div>
  )
}
