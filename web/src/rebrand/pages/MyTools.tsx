import { useState, useEffect } from 'react'
import { Link, useNavigate, useSearchParams, useLocation } from 'react-router-dom'
import { rp } from '../basePath'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion, useReducedMotion } from 'framer-motion'
import api from '../../lib/api'
import { useAuth } from '../../hooks/useAuth'
import { getGradeInfo } from '../../components/trust/gradeSystem'
import { Reveal } from '../components/motion'

// Confetti pieces — fixed trajectories so the burst is stable across renders.
// Colors pull from the brand palette (primary / accent / success / warning).
const CONFETTI = [
  { x: -68, y: -30, r: -140, c: '#2DD4BF', d: 0 }, { x: -40, y: -52, r: 120, c: '#8B5CF6', d: 0.04 },
  { x: -14, y: -60, r: -90, c: '#22C55E', d: 0.02 }, { x: 12, y: -58, r: 160, c: '#F59E0B', d: 0.06 },
  { x: 40, y: -50, r: -120, c: '#2DD4BF', d: 0.03 }, { x: 66, y: -28, r: 100, c: '#8B5CF6', d: 0.05 },
  { x: -58, y: 6, r: 150, c: '#22C55E', d: 0.08 }, { x: 58, y: 4, r: -150, c: '#F59E0B', d: 0.07 },
  { x: -30, y: -12, r: 80, c: '#F59E0B', d: 0.1 }, { x: 30, y: -14, r: -80, c: '#22C55E', d: 0.09 },
  { x: -48, y: -40, r: 110, c: '#F59E0B', d: 0.12 }, { x: 48, y: -38, r: -110, c: '#2DD4BF', d: 0.11 },
]

/** A brief, tasteful confetti burst from the row's center. Absolutely positioned
 * spans, ~1.2s, no dependency beyond framer-motion (already used app-wide). */
function ConfettiBurst() {
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden="true">
      {CONFETTI.map((p, i) => (
        <motion.span
          key={i}
          className="absolute left-1/2 top-1/2 w-1.5 h-2.5 rounded-[1px]"
          style={{ background: p.c }}
          initial={{ opacity: 1, x: 0, y: 0, rotate: 0, scale: 1 }}
          animate={{ opacity: [1, 1, 0], x: p.x, y: p.y, rotate: p.r, scale: [1, 1, 0.5] }}
          transition={{ duration: 1.2, ease: 'easeOut', delay: p.d }}
        />
      ))}
    </div>
  )
}

interface ClaimProof {
  kind: 'topic' | 'keyword' | 'mcp-challenge'
  topic?: string; keyword?: string; registry?: string; header?: string; value?: string
}
interface Claim {
  id: string; surface?: string; owner: string; repo: string; full_name: string; status: string; topic: string
  proof?: ClaimProof; proof_method?: string | null
  private?: boolean; scanned?: boolean; published?: boolean; grade?: string | null; score?: number | null
}
interface Installation { id: string; installation_id: string; account_login: string | null; revoked: boolean; repos?: { full_name: string; private: boolean }[] }

/** Parse a free-form coordinate the way the Check page does →
 * { surface, owner, repo } for POST /account/claims. */
function parseClaimCoord(raw: string): { surface: string; owner: string; repo: string } | null {
  const s = raw.trim()
  if (!s) return null
  let m
  if ((m = s.match(/^(npm|pypi):(.+)$/i))) return { surface: m[1].toLowerCase(), owner: '', repo: m[2].trim() }
  if ((m = s.match(/^mcp:(.+)$/i))) return { surface: 'mcp', owner: '', repo: m[1].trim() }
  if ((m = s.match(/^skill:([\w.-]+)\/([\w.-]+)$/i))) return { surface: 'openclaw', owner: m[1], repo: m[2] }
  if (/^https?:\/\//i.test(s)) return { surface: 'mcp', owner: '', repo: s } // bare URL → MCP endpoint
  if ((m = s.match(/^([\w.-]+)\/([\w.-]+)$/))) return { surface: 'github', owner: m[1], repo: m[2] }
  return null
}

/** Route a claim to its correct public report page per surface. */
function claimReportHref(c: Claim): string {
  const s = (c.surface || 'github').toLowerCase()
  if (s === 'npm' || s === 'pypi') return rp(`/rebrand/check/pkg/${s}/${c.repo}`)
  if (s === 'mcp') return rp(`/rebrand/check/mcp?endpoint=${encodeURIComponent(c.repo)}`)
  if (s === 'openclaw') return rp(`/rebrand/check/skill/${c.owner}/${c.repo}`)
  return rp(`/rebrand/check/${c.owner}/${c.repo}`)
}

// ── shared query hooks (react-query dedupes by key across components) ─────────
const CLAIMS_KEY = ['rebrand-claims']
const APP_KEY = ['github-app-status']
function useClaims(enabled: boolean) {
  return useQuery({
    queryKey: CLAIMS_KEY,
    queryFn: async () => (await api.get<{ claims: Claim[] }>('/account/claims')).data,
    enabled,
    // While a just-verified repo is still being scanned (private via the App, or
    // public into the catalog), poll so its grade + actions appear on their own —
    // no manual refresh needed.
    refetchInterval: (query) => {
      const cs = (query.state.data as { claims: Claim[] } | undefined)?.claims ?? []
      return cs.some((c) => c.status === 'verified' && !c.scanned) ? 5000 : false
    },
  })
}
function useAppStatus() {
  return useQuery({
    queryKey: APP_KEY,
    queryFn: async () => (await api.get<{ installations: Installation[]; app_configured: boolean }>('/account/github-app/status')).data,
    retry: 0,
  })
}

/** A small grade pill — same color scale as the score pages. */
function GradeBadge({ score, grade }: { score?: number | null; grade?: string | null }) {
  if (score == null && !grade) return null
  const info = score != null ? getGradeInfo(score) : null
  const label = grade || info?.grade || '—'
  const color = info?.color || 'var(--color-text-muted)'
  return (
    <span
      className="grid place-items-center min-w-[30px] h-[24px] px-1.5 rounded-md font-mono text-[12px] font-bold shrink-0"
      style={{ background: `${color}1f`, color }}
      title={score != null ? `${label} · ${score}/100` : label}
    >{label}</span>
  )
}

// ── ZONE 1 — Add a tool ──────────────────────────────────────────────────────

/** The single entry point for claiming ANY tool — a repo, npm/PyPI package, MCP
 * server, or skill. One smart input detects the surface (npm:, pypi:, mcp:,
 * skill:, a URL, or owner/repo). Each surface has its own proof, shown on the row. */
function AddToolForm() {
  const qc = useQueryClient()
  const [coord, setCoord] = useState('')
  const [privateHint, setPrivateHint] = useState<string | null>(null)
  const [parseErr, setParseErr] = useState(false)
  const create = useMutation({
    mutationFn: async () => {
      const parsed = parseClaimCoord(coord)
      if (!parsed) { setParseErr(true); throw new Error('unparseable') }
      setParseErr(false)
      return (await api.post<{ needs_private_flow?: boolean; detail?: string }>('/account/claims', parsed)).data
    },
    onSuccess: async (data) => {
      if (data?.needs_private_flow) { setPrivateHint(data.detail || 'This looks like a private repo — connect the GitHub App in Connections below.'); return }
      setPrivateHint(null); setCoord(''); await qc.refetchQueries({ queryKey: CLAIMS_KEY })
    },
  })
  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="flex gap-2">
        <input value={coord} onChange={(e) => setCoord(e.target.value)} placeholder="owner/repo · npm:chalk · pypi:requests · mcp:https://… · skill:owner/repo" className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light font-mono" />
        <button type="submit" disabled={create.isPending || !coord.trim()} className="text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60 shrink-0">{create.isPending ? 'Claiming…' : 'Claim'}</button>
      </form>
      <p className="mt-2 text-[12.5px] text-text-muted">Claim any tool you own. <span className="text-text">Repos/skills</span> verify by GitHub topic (private repos: connect the App in <span className="text-text">Connections</span>). <span className="text-text">npm/PyPI</span> auto-link to a repo you&apos;ve claimed. <span className="text-text">MCP servers</span> verify by a challenge your endpoint returns.</p>
      {parseErr && <div className="mt-2 text-[12.5px] text-danger">Couldn&apos;t read that — try <span className="font-mono">owner/repo</span>, <span className="font-mono">npm:name</span>, <span className="font-mono">mcp:https://…</span>, or <span className="font-mono">skill:owner/repo</span>.</div>}
      {create.isError && !parseErr && <div className="mt-2 text-[12.5px] text-danger">Couldn&apos;t claim — check the coordinate and try again.</div>}
      {privateHint && <div className="mt-2 text-[12.5px] text-warning">🔒 {privateHint}</div>}
    </div>
  )
}

/** The full roster of repos the connected GitHub App can scan — claim any to
 * track it. Each row reflects live state (Claim → scanning… → claimed ✓) so the
 * App list mirrors the same transitions as "Your tools" below. */
function AppRepoPicker({ repos, claimByName }: { repos: { full_name: string; private: boolean }[]; claimByName: Map<string, Claim> }) {
  const qc = useQueryClient()
  const reduce = useReducedMotion()
  const [celebrating, setCelebrating] = useState(false)
  const claim = useMutation({
    mutationFn: async (fullName: string) => {
      const [o, r] = fullName.split('/')
      return (await api.post('/account/github-app/claim-repo', { owner: o, repo: r })).data
    },
    onSuccess: () => {
      if (!reduce) { setCelebrating(true); setTimeout(() => setCelebrating(false), 1600) }
      qc.refetchQueries({ queryKey: CLAIMS_KEY })
      qc.refetchQueries({ queryKey: APP_KEY })
      setTimeout(() => qc.refetchQueries({ queryKey: CLAIMS_KEY }), 8000)
    },
  })
  if (repos.length === 0) return null
  return (
    <div className="relative mt-4">
      {celebrating && <ConfettiBurst />}
      <div className="text-[12.5px] text-text-muted mb-2">Repos your GitHub App can scan — claim any to track it:</div>
      <div className="glass rounded-xl divide-y divide-border/50">
        {repos.map((r) => {
          const c = claimByName.get(r.full_name.toLowerCase())
          const busy = claim.isPending && claim.variables === r.full_name
          return (
            <div key={r.full_name} className="flex items-center justify-between gap-3 px-4 py-2.5">
              <span className="font-mono text-[12.5px] break-all min-w-0">{r.full_name} {r.private && <span className="text-text-muted">· private</span>}</span>
              {!c ? (
                <button onClick={() => claim.mutate(r.full_name)} disabled={busy} className="shrink-0 text-[12px] font-semibold px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">{busy ? 'Claiming…' : 'Claim'}</button>
              ) : c.status === 'verified' && c.private && !c.scanned ? (
                <span className="shrink-0 font-mono text-[10.5px] uppercase tracking-wide px-2 py-0.5 rounded bg-primary/15 text-primary-light">scanning…</span>
              ) : (
                <span className="shrink-0 inline-flex items-center gap-2 text-[12px] text-success">claimed ✓ <Link to={rp(`/rebrand/check/${c.owner}/${c.repo}`)} className="text-primary-light hover:text-primary font-semibold">Report →</Link></span>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── ZONE 2 — Connections ─────────────────────────────────────────────────────

/** GitHub App connection as a single account-level row — connect / status /
 * disconnect. The repos it grants are claimed from "Add a tool" and live in
 * "Your tools"; this row is just the connection itself. */
function GitHubAppConnection() {
  const qc = useQueryClient()
  const [params, setParams] = useSearchParams()
  const { data, isLoading } = useAppStatus()
  const connect = useMutation({
    mutationFn: async (installation_id: string) => (await api.post('/account/github-app/connect', { installation_id })).data,
    onSuccess: () => qc.refetchQueries({ queryKey: APP_KEY }),
  })
  const disconnect = useMutation({
    mutationFn: async (pk: string) => api.delete(`/account/github-app/${pk}`),
    onSuccess: () => { qc.refetchQueries({ queryKey: APP_KEY }); qc.refetchQueries({ queryKey: CLAIMS_KEY }) },
  })
  // GitHub redirects back with ?gh_installation_id= after an install — associate it.
  useEffect(() => {
    const gid = params.get('gh_installation_id')
    if (gid && !connect.isPending && !connect.isSuccess) {
      connect.mutate(gid)
      params.delete('gh_installation_id'); params.delete('gh_setup')
      setParams(params, { replace: true })
    }
  }, [params, connect, setParams])

  const [installing, setInstalling] = useState(false)
  const [installErr, setInstallErr] = useState<string | null>(null)
  const startInstall = async () => {
    setInstalling(true); setInstallErr(null)
    try {
      const { url } = (await api.get<{ url: string }>('/account/github-app/install-url')).data
      window.location.href = url  // navigates away to GitHub
    } catch {
      setInstalling(false)
      setInstallErr("Couldn't open the GitHub install page. Try again in a moment.")
    }
  }

  const configured = data?.app_configured
  const installs = (data?.installations ?? []).filter((i) => !i.revoked)

  if (isLoading || configured === undefined) {
    return <div className="glass rounded-xl h-[60px] animate-pulse" />
  }
  if (!configured) {
    return <div className="glass rounded-xl p-4 text-[13px] text-text-muted">GitHub App — coming soon. Until then, use the one-time token scan below.</div>
  }
  return (
    <div className="flex flex-col gap-2">
      {connect.isPending && <div className="text-[12.5px] text-text-muted">Linking your installation…</div>}
      {installs.length === 0 ? (
        <div className="glass rounded-xl p-4 flex items-center justify-between gap-3 flex-wrap">
          <div className="min-w-0">
            <div className="text-[13.5px] font-semibold">GitHub App</div>
            <div className="text-[12.5px] text-text-muted">Continuous private-repo scans + drop alerts. No token to paste; revocable in GitHub anytime.</div>
          </div>
          <button onClick={startInstall} disabled={installing} className="shrink-0 text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">{installing ? 'Opening…' : 'Connect GitHub App'}</button>
        </div>
      ) : (
        installs.map((i) => (
          <div key={i.id} className="glass rounded-xl p-4 flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-2.5 min-w-0">
              <span className="grid place-items-center w-7 h-7 rounded-full bg-success/15 text-success text-[13px] shrink-0">🔗</span>
              <div className="min-w-0">
                <div className="text-[13.5px] font-semibold">GitHub App connected</div>
                <div className="font-mono text-[12px] text-text-muted truncate">@{i.account_login || 'installed'} · {(i.repos?.length ?? 0)} repos available</div>
              </div>
            </div>
            <button onClick={() => disconnect.mutate(i.id)} className="shrink-0 text-[12px] text-text-muted hover:text-danger">Disconnect</button>
          </div>
        ))
      )}
      {installErr && <div className="text-[12.5px] text-danger">{installErr}</div>}
    </div>
  )
}

/** One-time private scan with a transient read token → hands the result to the
 * score page. The single secondary/expander path (rare, advanced). */
function OneTimeScanExpander() {
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const [owner, setOwner] = useState(params.get('owner') || '')
  const [repo, setRepo] = useState(params.get('repo') || '')
  const [token, setToken] = useState('')
  const scan = useMutation({
    mutationFn: async () => (await api.post('/account/private-scan', { owner: owner.trim(), repo: repo.trim(), token: token.trim() })).data,
    onSuccess: (data) => navigate(
      rp(`/rebrand/check/${owner.trim()}/${repo.trim()}`),
      { state: { privateResult: data, token: token.trim() } },
    ),
  })
  return (
    <details className="mt-3">
      <summary className="cursor-pointer text-[12.5px] text-text-muted hover:text-text">Advanced: one-time scan with a token (no ongoing access) →</summary>
      <div className="mt-3">
        <p className="text-text-muted text-[12.5px] mb-2.5">A single scan with no ongoing access — paste a read token, used for this scan only and <strong className="text-text">never stored or logged</strong>. For continuous scanning + alerts, connect the GitHub App above instead.</p>
        <form onSubmit={(e) => { e.preventDefault(); scan.mutate() }} className="glass rounded-2xl p-5 flex flex-col gap-2.5">
          <div className="flex gap-2">
            <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="owner" className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light" />
            <span className="self-center text-text-muted">/</span>
            <input value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="repo" className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light" />
          </div>
          <input value={token} onChange={(e) => setToken(e.target.value)} type="password" placeholder="github token (ghp_… / github_pat_…)" className="bg-surface border border-border rounded-xl px-3.5 py-2 font-mono text-[13px] outline-none focus:border-primary-light" />
          <details className="text-[12px]">
            <summary className="cursor-pointer text-primary-light hover:text-primary font-medium">How to create a read-only token (30 seconds)</summary>
            <ol className="mt-2 flex flex-col gap-1.5 list-decimal pl-4 marker:text-primary-light marker:font-semibold text-text-muted">
              <li>On GitHub, go to <a href="https://github.com/settings/personal-access-tokens/new" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary">Settings → Developer settings → Personal access tokens → Fine-grained tokens → <span className="text-text font-medium">Generate new token</span></a>.</li>
              <li>Under <span className="text-text font-medium">Repository access</span>, choose <span className="text-text font-medium">Only select repositories</span> and pick just this one repo.</li>
              <li>Under <span className="text-text font-medium">Permissions → Repository</span>, set <span className="text-text font-medium">Contents</span> to <span className="text-text font-medium">Read-only</span>. Nothing else is needed.</li>
              <li>Click <span className="text-text font-medium">Generate token</span> and copy it into the field above.</li>
            </ol>
          </details>
          <button type="submit" disabled={scan.isPending || !owner || !repo || !token} className="self-start text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">{scan.isPending ? 'Scanning…' : 'Scan privately'}</button>
          {scan.isError && <div className="text-[13px] text-danger">Scan failed — check the token has access to this repo.</div>}
        </form>
      </div>
    </details>
  )
}

// ── ZONE 3 — Your tools ──────────────────────────────────────────────────────

/** A copy-able verification code chip. */
function CodeChip({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="mt-2 flex items-center gap-2 flex-wrap">
      <code className="inline-block font-mono text-[12px] bg-surface border border-border rounded px-2 py-1 break-all select-all">{value}</code>
      <button type="button" onClick={() => { navigator.clipboard?.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500) }} className="text-[11.5px] font-medium px-2 py-1 rounded-md border border-border text-text-muted hover:text-text hover:border-primary-light">{copied ? 'Copied ✓' : 'Copy'}</button>
    </div>
  )
}

/** npm/PyPI proof panel — two ways to verify: link the source repo (auto), or
 * publish a keyword challenge. */
function ClaimPkgProof({ c, onVerify, pending, msg }: { c: Claim; onVerify: () => void; pending: boolean; msg: string | null }) {
  const kw = c.proof?.keyword || c.topic
  const reg = c.surface === 'pypi' ? 'PyPI' : 'npm'
  const field = c.surface === 'pypi' ? 'keywords (or a classifier) in pyproject.toml / setup.cfg' : 'the "keywords" array in package.json'
  const btn = 'text-[12px] font-semibold px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60'
  return (
    <div>
      <div className="font-semibold text-text">Prove you publish this {reg} package — two ways:</div>
      <ol className="mt-2 flex flex-col gap-1.5 list-decimal pl-4 marker:text-primary-light marker:font-semibold">
        <li><span className="text-text font-medium">Claim its source repo first (easiest).</span> If this package links to a GitHub repo — by build provenance or its declared <span className="font-mono">repository</span> — and you&apos;ve claimed that repo above, we verify this automatically. Just hit Verify.</li>
        <li><span className="text-text font-medium">Or publish a keyword challenge.</span> Add this keyword to {field}, publish a new version, then Verify:</li>
      </ol>
      <CodeChip value={kw} />
      <button onClick={onVerify} disabled={pending} className={btn + ' mt-2.5'}>{pending ? 'Checking…' : 'Verify'}</button>
      {msg && <div className="mt-2 text-warning">{msg}</div>}
    </div>
  )
}

/** MCP proof panel — the endpoint must echo the challenge. */
function ClaimMcpProof({ c, onVerify, pending, msg }: { c: Claim; onVerify: () => void; pending: boolean; msg: string | null }) {
  const header = c.proof?.header || 'X-AgentAvow-Verify'
  const value = c.proof?.value || c.topic
  const btn = 'text-[12px] font-semibold px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60'
  return (
    <div>
      <div className="font-semibold text-text">Prove you control this MCP server — return the challenge:</div>
      <ol className="mt-2 flex flex-col gap-1.5 list-decimal pl-4 marker:text-primary-light marker:font-semibold">
        <li>Have your server return this response header on the endpoint (or include the value anywhere in its <span className="font-mono">serverInfo</span>):</li>
      </ol>
      <CodeChip value={`${header}: ${value}`} />
      <p className="mt-2">We read it on a live MCP <span className="font-mono">initialize</span> handshake — the same connection we grade. Then click Verify.</p>
      <button onClick={onVerify} disabled={pending} className={btn + ' mt-2.5'}>{pending ? 'Checking…' : 'Verify'}</button>
      {msg && <div className="mt-2 text-warning">{msg}</div>}
    </div>
  )
}

/** One claimed tool — a single consistent row for every state: pending
 * (verify in-row, per surface), verified, private scanning, publishable, and
 * listed. Grade/state on the left, one actions cluster on the right. */
function ToolRow({ c }: { c: Claim }) {
  const qc = useQueryClient()
  const reduce = useReducedMotion()
  const [msg, setMsg] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [showVerify, setShowVerify] = useState(false)
  const [celebrating, setCelebrating] = useState(false)
  const refetchAll = () => {
    qc.refetchQueries({ queryKey: CLAIMS_KEY })
    qc.refetchQueries({ queryKey: APP_KEY })
    // Harden cross-page state: this repo's score page reads these — mark them stale
    // so a publish/unpublish/remove reflects on the score card the next time it's
    // viewed, without a manual refresh.
    qc.invalidateQueries({ queryKey: ['rebrand-private-report', c.owner, c.repo] })
    qc.invalidateQueries({ queryKey: ['rebrand-scan', c.owner, c.repo] })
  }
  const verify = useMutation({
    mutationFn: async () => (await api.post<{ verified: boolean; detail?: string }>(`/account/claims/${c.id}/verify`, {})).data,
    onSuccess: (d) => {
      if (!d.verified) { setMsg(d.detail || 'Not verified yet.'); return }
      setMsg(null); setShowVerify(false)
      if (reduce) { refetchAll(); return }
      setCelebrating(true); setTimeout(() => { setCelebrating(false); refetchAll() }, 1500)
    },
  })
  const remove = useMutation({ mutationFn: () => api.delete(`/account/claims/${c.id}`), onSuccess: refetchAll })
  const publish = useMutation({
    mutationFn: async () => (await api.post(`/account/private-report/${c.owner}/${c.repo}/publish`)).data,
    onSuccess: () => { if (!reduce) { setCelebrating(true); setTimeout(() => setCelebrating(false), 1600) } refetchAll() },
  })
  const unpublish = useMutation({
    mutationFn: async () => (await api.post(`/account/private-report/${c.owner}/${c.repo}/unpublish`)).data,
    onSuccess: refetchAll,
  })

  const surface = (c.surface || 'github').toLowerCase()
  const isRepoLike = surface === 'github' || surface === 'openclaw'
  const verified = c.status === 'verified' || celebrating
  const btn = 'text-[12px] font-semibold px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60'
  const link = 'text-[12.5px] font-semibold text-primary-light hover:text-primary'
  const muted = 'text-[12px] text-text-muted hover:text-danger'

  // Left-side state indicator: grade badge once scanned, else a status chip.
  let leftChip: React.ReactNode = null
  if (verified && c.scanned) leftChip = <GradeBadge score={c.score} grade={c.grade} />
  else if (verified && c.private && !c.scanned) leftChip = <span className="font-mono text-[10.5px] uppercase tracking-wide px-2 py-0.5 rounded bg-primary/15 text-primary-light shrink-0">scanning…</span>
  else if (verified) leftChip = <span className="font-mono text-[10.5px] uppercase tracking-wide px-2 py-0.5 rounded bg-success/15 text-success shrink-0">✓ owned</span>
  else leftChip = <span className="font-mono text-[10.5px] uppercase tracking-wide px-2 py-0.5 rounded bg-warning/15 text-warning shrink-0">unverified</span>

  // Right-side actions cluster, consistent order: [state] [primary] [report] [remove]
  const actions: React.ReactNode[] = []
  if (!verified) {
    actions.push(<button key="v" onClick={() => setShowVerify((s) => !s)} className={link}>Verify {showVerify ? '▾' : '▸'}</button>)
  } else {
    if (c.private && c.scanned && !c.published) actions.push(<button key="pub" onClick={() => publish.mutate()} disabled={publish.isPending} className={btn}>{publish.isPending ? 'Publishing…' : '🌐 Publish'}</button>)
    if (c.private && c.published) actions.push(<span key="listed" className="font-mono text-[10.5px] uppercase tracking-wide px-2 py-0.5 rounded bg-primary/15 text-primary-light">🌐 Listed</span>)
    if (c.private && c.published) actions.push(<button key="unpub" onClick={() => unpublish.mutate()} disabled={unpublish.isPending} className={muted + ' hover:text-text'}>{unpublish.isPending ? 'Unlisting…' : 'Unlist'}</button>)
    // Repo claims gate Report on a completed catalog scan; surface claims scan the
    // report live, so always offer it.
    if (c.scanned || !isRepoLike) actions.push(<Link key="rep" to={claimReportHref(c)} className={link}>Report →</Link>)
  }
  actions.push(<button key="rm" onClick={() => remove.mutate()} className={muted}>Remove</button>)

  return (
    <div className="glass rounded-xl p-4 relative overflow-hidden">
      {celebrating && <ConfettiBurst />}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2.5 min-w-0">
          {leftChip}
          {!isRepoLike && <span className="font-mono text-[9.5px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded bg-primary/12 text-primary-light shrink-0">{surface}</span>}
          <span className="font-mono text-[13.5px] break-all min-w-0">{c.full_name}</span>
          {c.private && <span className="text-[11px] text-text-muted shrink-0">🔒 private</span>}
          {verified && c.proof_method && <span className="text-[10.5px] text-text-muted shrink-0" title="How ownership was proven">· {c.proof_method}</span>}
        </div>
        <div className="flex items-center gap-3 shrink-0">{actions}</div>
      </div>

      {/* pending claim → per-surface proof expands in-row (the one expander) */}
      {!verified && showVerify && (
        <div className="mt-3 rounded-lg border border-border/70 p-3 text-[12.5px] text-text-muted">
          {!isRepoLike && (surface === 'npm' || surface === 'pypi') && (
            <ClaimPkgProof c={c} onVerify={() => verify.mutate()} pending={verify.isPending} msg={msg} />
          )}
          {!isRepoLike && surface === 'mcp' && (
            <ClaimMcpProof c={c} onVerify={() => verify.mutate()} pending={verify.isPending} msg={msg} />
          )}
          {isRepoLike && (<>
          <div className="font-semibold text-text">Prove you own this {surface === 'openclaw' ? 'skill' : 'public repo'} — add a GitHub topic:</div>
          <div className="mt-2 flex items-center gap-2 flex-wrap">
            <code className="inline-block font-mono text-[12px] bg-surface border border-border rounded px-2 py-1 break-all select-all">{c.topic}</code>
            <button type="button" onClick={() => { navigator.clipboard?.writeText(c.topic); setCopied(true); setTimeout(() => setCopied(false), 1500) }} className="text-[11.5px] font-medium px-2 py-1 rounded-md border border-border text-text-muted hover:text-text hover:border-primary-light">{copied ? 'Copied ✓' : 'Copy'}</button>
          </div>
          <ol className="mt-2.5 flex flex-col gap-1 list-decimal pl-4 marker:text-primary-light marker:font-semibold">
            <li>Open <a href={`https://github.com/${c.full_name}`} target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary font-mono">github.com/{c.full_name}</a> → the <span className="text-text font-medium">gear ⚙️</span> by <span className="text-text font-medium">&ldquo;About&rdquo;</span>.</li>
            <li>Paste the topic into <span className="text-text font-medium">Topics</span>, press <span className="text-text font-medium">Enter</span>, then <span className="text-text font-medium">Save changes</span>.</li>
            <li>Come back and click <span className="text-text font-medium">Verify</span> (topics can take a few seconds).</li>
          </ol>
          <details className="mt-2">
            <summary className="cursor-pointer hover:text-text">Prefer the command line?</summary>
            <code className="mt-1.5 block font-mono text-[11.5px] bg-surface border border-border rounded px-2 py-1.5 break-all">gh repo edit {c.full_name} --add-topic {c.topic}</code>
          </details>
          <button onClick={() => verify.mutate()} disabled={verify.isPending} className={btn + ' mt-2.5'}>{verify.isPending ? 'Checking…' : 'Verify topic'}</button>
          {msg && <div className="mt-2 text-warning">{msg}</div>}
          </>)}
        </div>
      )}
      {celebrating && (
        <motion.div className="mt-2 text-[12.5px] font-semibold text-success" initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }}>✓ Verified — you own this!</motion.div>
      )}
    </div>
  )
}

// ── Page ─────────────────────────────────────────────────────────────────────

/**
 * "My Tools" — one home for adding + managing the repos you own, organized by
 * job (not method): Add a tool → Connections → Your tools. Every repo lives in
 * one unified list with a consistent row, whatever way it was claimed.
 */
export default function RebrandMyTools() {
  const { user, isLoading: authLoading } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  useEffect(() => {
    if (!authLoading && !user) navigate(rp('/rebrand/login'))
  }, [authLoading, user, navigate])

  const { data, isLoading: cLoading } = useClaims(!!user)
  const { data: appData } = useAppStatus()

  // Owners arriving from a score page's "Manage" land on their tools list.
  useEffect(() => {
    if (location.hash === '#your-repos' && !cLoading) {
      const t = setTimeout(() => document.getElementById('your-repos')?.scrollIntoView({ behavior: 'smooth' }), 250)
      return () => clearTimeout(t)
    }
  }, [location.hash, cLoading])

  if (!user) return null
  const claims = data?.claims ?? []
  const claimByName = new Map(claims.map((c) => [c.full_name.toLowerCase(), c]))
  // Every repo the connected App can reach (deduped across installs). Claimed ones
  // render their live state in the roster, so the App list mirrors "Your tools".
  const appRepos = (appData?.installations ?? [])
    .filter((i) => !i.revoked)
    .flatMap((i) => i.repos ?? [])
    .filter((r, idx, arr) => arr.findIndex((x) => x.full_name === r.full_name) === idx)

  // One list, most-recently-actionable first: pending, then scanning, then rest.
  const rank = (c: Claim) => (c.status !== 'verified' ? 0 : c.private && !c.scanned ? 1 : 2)
  const tools = [...claims].sort((a, b) => rank(a) - rank(b))

  return (
    <div className="max-w-[680px] mx-auto px-6 py-14">
      <Reveal>
        <div>
          <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">My Tools</span>
          <h1 className="mt-1 text-2xl md:text-3xl font-extrabold tracking-tight">Your tools</h1>
          <p className="mt-2 text-text-muted text-[14px] max-w-[62ch]">Claim the repos you own to scan them, get continuous re-scans with change alerts, and control how each is listed. Public repos verify with a GitHub topic; private repos connect through the GitHub App.</p>
        </div>
      </Reveal>

      {/* ZONE 1 — Add a tool */}
      <section className="mt-10">
        <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-3">Add a tool</h2>
        <AddToolForm />
        <AppRepoPicker repos={appRepos} claimByName={claimByName} />
      </section>

      <div className="mt-10 border-t border-border/60" />

      {/* ZONE 2 — Connections */}
      <section className="mt-8">
        <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-3">Connections</h2>
        <GitHubAppConnection />
        <OneTimeScanExpander />
      </section>

      <div className="mt-10 border-t border-border/60" />

      {/* ZONE 3 — Your tools */}
      <section className="mt-8 scroll-mt-24" id="your-repos">
        <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-3">Your tools {tools.length > 0 && `· ${tools.length}`}</h2>
        {cLoading ? (
          <div className="flex flex-col gap-2.5">{[0, 1].map((i) => <div key={i} className="glass rounded-xl h-[64px] animate-pulse" />)}</div>
        ) : tools.length === 0 ? (
          <div className="text-text-muted text-[13px]">No tools yet. Claim a public repo above, or connect the GitHub App to claim a private one.</div>
        ) : (
          <div className="flex flex-col gap-2.5">
            {tools.map((c) => <ToolRow key={c.id} c={c} />)}
          </div>
        )}
      </section>
    </div>
  )
}
