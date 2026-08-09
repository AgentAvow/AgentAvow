import { useState, useEffect } from 'react'
import { Link, useNavigate, useSearchParams, useLocation } from 'react-router-dom'
import { rp } from '../basePath'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion, useReducedMotion } from 'framer-motion'
import api from '../../lib/api'
import { useAuth } from '../../hooks/useAuth'
import { Reveal, RevealStagger } from '../components/motion'

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

/**
 * "My Tools" — the single home for claiming + managing the repos you own. Claim
 * UX at the top (public = GitHub topic, private = read-only token), then the list
 * of your repos with status, a link to each report, and remove. Scan a private
 * repo lives at the bottom. (The old /claim route redirects here.)
 */

interface Claim { id: string; owner: string; repo: string; full_name: string; status: string; topic: string }

/** One claimed repo. Verified → success + report link + remove. Pending → the
 * public-repo topic verification + remove (private repos go through the GitHub
 * App section below, not this form). */
function ClaimRow({ c, onRefetch }: { c: Claim; onRefetch: () => void }) {
  const reduce = useReducedMotion()
  const [msg, setMsg] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  // Brief celebratory moment on a pending → verified transition. We hold the
  // refetch until the burst finishes so the row stays put while it plays.
  const [celebrating, setCelebrating] = useState(false)
  const verify = useMutation({
    mutationFn: async () =>
      (await api.post<{ verified: boolean; detail?: string }>(
        `/account/claims/${c.id}/verify`, {},
      )).data,
    onSuccess: (d) => {
      if (!d.verified) { setMsg(d.detail || 'Not verified yet.'); onRefetch(); return }
      setMsg(null)
      if (reduce) { onRefetch(); return }
      setCelebrating(true)
      setTimeout(() => { setCelebrating(false); onRefetch() }, 1500)
    },
  })
  const remove = useMutation({ mutationFn: () => api.delete(`/account/claims/${c.id}`), onSuccess: onRefetch })
  const verified = c.status === 'verified'
  return (
    <div className="glass rounded-xl p-4 relative overflow-hidden">
      {celebrating && <ConfettiBurst />}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="font-mono text-[14px] break-all">{c.full_name}</div>
        <span className={`font-mono text-[10.5px] uppercase tracking-wide px-2 py-0.5 rounded ${verified || celebrating ? 'bg-success/15 text-success' : 'bg-warning/15 text-warning'}`}>{verified || celebrating ? 'verified' : 'unverified'}</span>
      </div>

      {celebrating ? (
        <motion.div
          className="mt-2 flex items-center gap-2 text-success"
          initial={{ scale: 0.96, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ duration: 0.3, ease: 'easeOut' }}
        >
          <motion.span
            className="grid place-items-center w-6 h-6 rounded-full bg-success/20 text-success text-[13px] shrink-0"
            initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: 'spring', stiffness: 420, damping: 12 }}
          >✓</motion.span>
          <span className="text-[13px] font-semibold">Verified — you own this!</span>
        </motion.div>
      ) : verified ? (
        <div className="mt-2 flex items-center justify-between gap-3 flex-wrap">
          <div className="text-[12.5px] text-success">✓ Verified — you own this.</div>
          <div className="flex items-center gap-3 shrink-0">
            <Link to={rp(`/rebrand/check/${c.owner}/${c.repo}`)} className="text-[12.5px] font-semibold text-primary-light hover:text-primary">View report →</Link>
            <button onClick={() => remove.mutate()} className="text-[12px] text-text-muted hover:text-danger">Remove</button>
          </div>
        </div>
      ) : (
        <div className="mt-3 text-[13px] text-text-muted">
          <p className="text-text font-semibold text-[12.5px]">Prove you own this public repo — add a GitHub topic:</p>

          {/* PUBLIC repo — GitHub topic (private repos use the GitHub App section below) */}
          <div className="mt-2.5 rounded-lg border border-border/70 p-3">
            <div className="text-[12.5px] font-semibold text-text">Public repo → add a GitHub topic</div>
            <div className="mt-2 flex items-center gap-2 flex-wrap">
              <code className="inline-block font-mono text-[12px] bg-surface border border-border rounded px-2 py-1 break-all select-all">{c.topic}</code>
              <button type="button"
                onClick={() => { navigator.clipboard?.writeText(c.topic); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
                className="text-[11.5px] font-medium px-2 py-1 rounded-md border border-border text-text-muted hover:text-text hover:border-primary-light"
              >{copied ? 'Copied ✓' : 'Copy'}</button>
            </div>
            <ol className="mt-2.5 flex flex-col gap-1 list-decimal pl-4 marker:text-primary-light marker:font-semibold text-[12.5px]">
              <li>Open <a href={`https://github.com/${c.full_name}`} target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary font-mono">github.com/{c.full_name}</a> → click the <span className="text-text font-medium">gear ⚙️</span> next to <span className="text-text font-medium">&ldquo;About&rdquo;</span>.</li>
              <li>Paste the topic into <span className="text-text font-medium">Topics</span>, press <span className="text-text font-medium">Enter</span>, then <span className="text-text font-medium">Save changes</span>.</li>
              <li>Come back and click <span className="text-text font-medium">Verify topic</span> (topics can take a few seconds — retry if needed).</li>
            </ol>
            <details className="mt-2 text-[12px]">
              <summary className="cursor-pointer text-text-muted hover:text-text">Prefer the command line?</summary>
              <code className="mt-1.5 block font-mono text-[11.5px] bg-surface border border-border rounded px-2 py-1.5 break-all">gh repo edit {c.full_name} --add-topic {c.topic}</code>
            </details>
            <button onClick={() => verify.mutate()} disabled={verify.isPending} className="mt-2.5 text-[12.5px] font-semibold px-3.5 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">{verify.isPending ? 'Checking…' : 'Verify topic'}</button>
          </div>

          <div className="mt-3">
            <button onClick={() => remove.mutate()} className="text-[12.5px] text-text-muted hover:text-danger">Remove claim</button>
          </div>
          {msg && <div className="mt-2 text-[12.5px] text-warning">{msg}</div>}
        </div>
      )}
    </div>
  )
}

/** Scan a private repo with a transient read token → hands the full result to the
 * score page (with the token) so the owner can Claim / Publish from there. */
function PrivateScan() {
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
    <div>
      <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-1">One-time private repo scan</h2>
      <p className="text-text-muted text-[13px] mb-3">A single scan with no ongoing access — paste a read token, used for this scan only and <strong className="text-text">never stored or logged</strong>. For continuous scanning + alerts, use the GitHub App above.</p>
      <form onSubmit={(e) => { e.preventDefault(); scan.mutate() }} className="glass rounded-2xl p-5 flex flex-col gap-2.5 max-w-[560px]">
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
      </form>
      {scan.isPending && <div className="mt-3 text-[13px] text-text-muted">Scanning privately… we&apos;ll take you to the full report.</div>}
      {scan.isError && <div className="mt-3 text-[13px] text-danger">Scan failed — check the token has access to this repo.</div>}
    </div>
  )
}

interface Installation { id: string; installation_id: string; account_login: string | null; revoked: boolean; repos?: { full_name: string; private: boolean }[] }

/** Connect the AgentAvow GitHub App for scheduled scans of private repos — no
 * token to paste, revocable in GitHub. Gracefully shows "coming soon" until the
 * App is registered (github_app_slug configured). */
function GitHubAppConnect() {
  const qc = useQueryClient()
  const reduce = useReducedMotion()
  const [params, setParams] = useSearchParams()
  const [celebrating, setCelebrating] = useState(false)
  const { data, isLoading } = useQuery({
    queryKey: ['github-app-status'],
    queryFn: async () => (await api.get<{ installations: Installation[]; app_configured: boolean }>('/account/github-app/status')).data,
    retry: 0,
  })
  // Which of the App's repos are already claimed (verified) — shared cache key.
  const { data: claimsData } = useQuery({
    queryKey: ['rebrand-claims'],
    queryFn: async () => (await api.get<{ claims: { full_name: string; status: string }[] }>('/account/claims')).data,
  })
  const claimed = new Set((claimsData?.claims ?? []).filter((c) => c.status === 'verified').map((c) => c.full_name.toLowerCase()))
  const connect = useMutation({
    mutationFn: async (installation_id: string) => (await api.post('/account/github-app/connect', { installation_id })).data,
    // Connecting grants access; the repos are then claimed one-by-one below.
    onSuccess: () => qc.refetchQueries({ queryKey: ['github-app-status'] }),
  })
  const claimRepo = useMutation({
    mutationFn: async (fullName: string) => {
      const [o, r] = fullName.split('/')
      return (await api.post('/account/github-app/claim-repo', { owner: o, repo: r })).data
    },
    // Claiming a repo = celebrate; it moves to "Your repos" as the scan finishes.
    onSuccess: () => {
      if (!reduce) { setCelebrating(true); setTimeout(() => setCelebrating(false), 1600) }
      qc.refetchQueries({ queryKey: ['rebrand-claims'] })
      setTimeout(() => qc.refetchQueries({ queryKey: ['rebrand-claims'] }), 8000)
    },
  })
  const disconnect = useMutation({
    mutationFn: async (pk: string) => api.delete(`/account/github-app/${pk}`),
    // Backend removes the App's claims/results — refetch both so the repos drop
    // out of "Your repos" too, not just the install list.
    onSuccess: () => {
      qc.refetchQueries({ queryKey: ['github-app-status'] })
      qc.refetchQueries({ queryKey: ['rebrand-claims'] })
    },
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

  return (
    <div className="relative">
      {celebrating && <ConfettiBurst />}
      <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-1">Claim a Private repo → GitHub App</h2>
      <p className="text-text-muted text-[13px] mb-3 max-w-[62ch]">Install the AgentAvow App on your private repos, then <span className="text-text">claim each one below to scan it</span> — with automatic re-scans and drop alerts over time. No token to paste, no topic to add, and you can revoke it in GitHub anytime. We never store a long-lived secret.</p>
      {connect.isPending && <div className="mb-2 text-[12.5px] text-text-muted">Linking your installation…</div>}
      {connect.isSuccess && <div className="mb-2 text-[12.5px] text-success">✓ Connected — claim the repos below to scan &amp; list them.</div>}
      {isLoading || configured === undefined ? (
        <div className="glass rounded-xl h-[64px] animate-pulse max-w-[560px]" />
      ) : !configured ? (
        <div className="glass rounded-xl p-4 text-[13px] text-text-muted max-w-[560px]">Coming soon — the GitHub App is being set up. Until then, use the one-time private scan below.</div>
      ) : installs.length > 0 ? (
        <div className="flex flex-col gap-2 max-w-[560px]">
          {installs.map((i) => (
            <div key={i.id} className="glass rounded-xl p-4">
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="font-mono text-[13.5px]">@{i.account_login || 'installed'}</div>
                <button onClick={() => disconnect.mutate(i.id)} className="text-[12px] text-text-muted hover:text-danger">Disconnect</button>
              </div>
              {i.repos && i.repos.length > 0 && (
                <div className="mt-2.5 flex flex-col divide-y divide-border/50">
                  {i.repos.map((r) => {
                    const isClaimed = claimed.has(r.full_name.toLowerCase())
                    const busy = claimRepo.isPending && claimRepo.variables === r.full_name
                    return (
                      <div key={r.full_name} className="flex items-center justify-between gap-3 py-2">
                        <span className="font-mono text-[12.5px] break-all">{r.full_name} {r.private && <span className="text-text-muted">· private</span>}</span>
                        {isClaimed ? (
                          <span className="text-[11.5px] font-semibold text-success shrink-0">claimed ✓</span>
                        ) : (
                          <button onClick={() => claimRepo.mutate(r.full_name)} disabled={busy}
                            className="shrink-0 text-[12px] font-semibold px-3 py-1 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">{busy ? 'Claiming…' : 'Claim'}</button>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          ))}
          <button onClick={startInstall} disabled={installing} className="self-start text-[12.5px] font-semibold text-primary-light hover:text-primary disabled:opacity-60">{installing ? 'Opening GitHub…' : '+ Add or manage repos →'}</button>
        </div>
      ) : (
        <button onClick={startInstall} disabled={installing} className="text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">{installing ? 'Opening GitHub…' : 'Connect GitHub App'}</button>
      )}
      {installErr && <div className="mt-2 text-[12.5px] text-danger">{installErr}</div>}
      {connect.isError && <div className="mt-2 text-[12.5px] text-danger">Couldn&apos;t link that installation — click Connect again.</div>}
    </div>
  )
}

export default function RebrandMyTools() {
  const { user, isLoading: authLoading } = useAuth()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [params] = useSearchParams()
  const location = useLocation()
  const [owner, setOwner] = useState(params.get('owner') || '')
  const [repo, setRepo] = useState(params.get('repo') || '')

  useEffect(() => {
    if (!authLoading && !user) navigate(rp('/rebrand/login'))
  }, [authLoading, user, navigate])

  const { data, isLoading: cLoading } = useQuery({
    queryKey: ['rebrand-claims'],
    queryFn: async () => (await api.get<{ claims: Claim[] }>('/account/claims')).data,
    enabled: !!user,
  })
  const [privateHint, setPrivateHint] = useState<string | null>(null)
  const create = useMutation({
    mutationFn: async () => (await api.post<{ needs_private_flow?: boolean; detail?: string }>('/account/claims', { owner: owner.trim(), repo: repo.trim() })).data,
    // Force an immediate refetch (staleTime would otherwise defer it → the new
    // claim only appeared after a hard refresh).
    onSuccess: async (data) => {
      if (data?.needs_private_flow) { setPrivateHint(data.detail || 'This looks like a private repo — connect the GitHub App below.'); return }
      setPrivateHint(null); setOwner(''); setRepo(''); await qc.refetchQueries({ queryKey: ['rebrand-claims'] })
    },
  })
  const refetch = () => qc.refetchQueries({ queryKey: ['rebrand-claims'] })

  // Owners arriving from a score page's "Manage & fix" land on their verified list.
  useEffect(() => {
    if (location.hash === '#your-repos' && !cLoading) {
      const t = setTimeout(() => document.getElementById('your-repos')?.scrollIntoView({ behavior: 'smooth' }), 250)
      return () => clearTimeout(t)
    }
  }, [location.hash, cLoading])

  if (!user) return null
  const claims = data?.claims ?? []
  const pending = claims.filter((c) => c.status !== 'verified')
  const verified = claims.filter((c) => c.status === 'verified')

  return (
    <div className="max-w-[760px] mx-auto px-6 py-14">
      <Reveal>
        <div className="max-w-[62ch]">
          <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">My Tools</span>
          <h1 className="mt-1 text-2xl md:text-3xl font-extrabold tracking-tight">Claim & manage your tools</h1>
          <p className="mt-2 text-text-muted text-[14px]">Prove you own a repo to scan it privately, get continuous re-scans with change alerts, and own how it’s listed. <span className="text-text">Public repos</span> verify with a GitHub topic; for <span className="text-text">private repos</span>, connect the GitHub App (recommended — continuous scans) or run a one-time token scan.</p>
        </div>
      </Reveal>

      {/* CLAIM UX — form + any in-progress (pending) claims stay here */}
      <div className="mt-8">
        <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-3">Claim a public repo</h2>
        <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="flex gap-2">
          <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="owner" className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light" />
          <span className="self-center text-text-muted">/</span>
          <input value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="repo" className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light" />
          <button type="submit" disabled={create.isPending || !owner.trim() || !repo.trim()} className="text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60 shrink-0">{create.isPending ? 'Claiming…' : 'Claim'}</button>
        </form>
        {create.isError && <div className="mt-2 text-[12.5px] text-danger">Couldn&apos;t claim — check the owner / repo and try again.</div>}
        {privateHint && <div className="mt-2 text-[12.5px] text-warning">🔒 {privateHint}</div>}

        {pending.length > 0 && (
          <div className="mt-4 flex flex-col gap-2.5">
            <div className="text-[12px] font-mono uppercase tracking-wide text-warning">Awaiting verification · {pending.length}</div>
            {pending.map((c) => <ClaimRow key={c.id} c={c} onRefetch={refetch} />)}
          </div>
        )}
      </div>

      {/* divider */}
      <div className="mt-8 border-t border-border/60" />

      {/* PRIVATE REPOS — GitHub App is the primary path; one-time scan is the alt */}
      <div className="mt-8">
        <GitHubAppConnect />
        <details className="mt-5 max-w-[560px]">
          <summary className="cursor-pointer text-[13px] text-text-muted hover:text-text">Just need a one-time scan? Scan a private repo with a token instead →</summary>
          <div className="mt-4"><PrivateScan /></div>
        </details>
      </div>

      {/* divider */}
      <div className="mt-10 border-t border-border/60" />

      {/* YOUR REPOS — verified only */}
      <div className="mt-8 scroll-mt-24" id="your-repos">
        <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-3">Your repos {verified.length > 0 && `· ${verified.length}`}</h2>
        {cLoading ? (
          <div className="flex flex-col gap-2">{[0, 1].map((i) => <div key={i} className="glass rounded-xl h-[64px] animate-pulse" />)}</div>
        ) : verified.length === 0 ? (
          <div className="text-text-muted text-[13px]">No verified repos yet. Verify a claim above to see it here — then jump straight to its report.</div>
        ) : (
          <div className="flex flex-col gap-2.5">
            {verified.map((c) => <ClaimRow key={c.id} c={c} onRefetch={refetch} />)}
          </div>
        )}
      </div>
    </div>
  )
}
