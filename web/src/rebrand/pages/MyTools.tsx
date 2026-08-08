import { useState, useEffect } from 'react'
import { Link, useNavigate, useSearchParams, useLocation } from 'react-router-dom'
import { rp } from '../basePath'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../../lib/api'
import { useAuth } from '../../hooks/useAuth'
import { Reveal, RevealStagger } from '../components/motion'

/**
 * "My Tools" — the single home for claiming + managing the repos you own. Claim
 * UX at the top (public = GitHub topic, private = read-only token), then the list
 * of your repos with status, a link to each report, and remove. Scan a private
 * repo lives at the bottom. (The old /claim route redirects here.)
 */

interface Claim { id: string; owner: string; repo: string; full_name: string; status: string; topic: string }

/** One claimed repo. Verified → success + report link + remove. Pending → the two
 * verification paths (public topic / private token) + remove. */
function ClaimRow({ c, onRefetch }: { c: Claim; onRefetch: () => void }) {
  const [msg, setMsg] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [token, setToken] = useState('')
  const verify = useMutation({
    mutationFn: async (tok?: string) =>
      (await api.post<{ verified: boolean; detail?: string }>(
        `/account/claims/${c.id}/verify`, tok ? { token: tok } : {},
      )).data,
    onSuccess: (d) => { setMsg(d.verified ? null : (d.detail || 'Not verified yet.')); onRefetch() },
  })
  const remove = useMutation({ mutationFn: () => api.delete(`/account/claims/${c.id}`), onSuccess: onRefetch })
  const verified = c.status === 'verified'
  return (
    <div className="glass rounded-xl p-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="font-mono text-[14px] break-all">{c.full_name}</div>
        <span className={`font-mono text-[10.5px] uppercase tracking-wide px-2 py-0.5 rounded ${verified ? 'bg-success/15 text-success' : 'bg-warning/15 text-warning'}`}>{verified ? 'verified' : 'unverified'}</span>
      </div>

      {verified ? (
        <div className="mt-2 flex items-center justify-between gap-3 flex-wrap">
          <div className="text-[12.5px] text-success">✓ Verified — you own this.</div>
          <div className="flex items-center gap-3 shrink-0">
            <Link to={rp(`/rebrand/check/${c.owner}/${c.repo}`)} className="text-[12.5px] font-semibold text-primary-light hover:text-primary">View report →</Link>
            <button onClick={() => remove.mutate()} className="text-[12px] text-text-muted hover:text-danger">Remove</button>
          </div>
        </div>
      ) : (
        <div className="mt-3 text-[13px] text-text-muted">
          <p className="text-text font-semibold text-[12.5px]">Prove you own this repo — pick the one that fits:</p>

          {/* PUBLIC repo — GitHub topic */}
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
            <button onClick={() => verify.mutate(undefined)} disabled={verify.isPending} className="mt-2.5 text-[12.5px] font-semibold px-3.5 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">{verify.isPending ? 'Checking…' : 'Verify topic'}</button>
          </div>

          {/* PRIVATE repo — read token */}
          <details className="mt-2.5 rounded-lg border border-border/70 p-3">
            <summary className="cursor-pointer text-[12.5px] font-semibold text-text">Private repo → verify with a read-only token</summary>
            <p className="mt-2 text-[12.5px]">Private repos can&apos;t use a topic (we can&apos;t read them). Paste a fine-grained <span className="text-text font-medium">read-only</span> token for this repo — it proves access, is used once, and is <span className="text-text font-medium">never stored</span>.</p>
            <div className="mt-2 flex gap-2 flex-wrap">
              <input value={token} onChange={(e) => setToken(e.target.value)} type="password" placeholder="github_pat_…" className="flex-1 min-w-[200px] bg-surface border border-border rounded-lg px-3 py-1.5 font-mono text-[12.5px] outline-none focus:border-primary-light" />
              <button onClick={() => verify.mutate(token.trim())} disabled={!token.trim() || verify.isPending} className="text-[12.5px] font-semibold px-3.5 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">{verify.isPending ? 'Checking…' : 'Verify with token'}</button>
            </div>
          </details>

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
      <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-1">Scan a private repo</h2>
      <p className="text-text-muted text-[13px] mb-3">Paste a GitHub token with read access. It&apos;s used for this scan only — <strong className="text-text">never stored or logged</strong>.</p>
      <details className="mb-3 text-[12.5px] max-w-[560px]">
        <summary className="cursor-pointer text-primary-light hover:text-primary font-medium">How to create a read-only token (30 seconds)</summary>
        <ol className="mt-2.5 flex flex-col gap-1.5 list-decimal pl-4 marker:text-primary-light marker:font-semibold text-text-muted">
          <li>On GitHub, go to <a href="https://github.com/settings/personal-access-tokens/new" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary">Settings → Developer settings → Personal access tokens → Fine-grained tokens → <span className="text-text font-medium">Generate new token</span></a>.</li>
          <li>Under <span className="text-text font-medium">Repository access</span>, choose <span className="text-text font-medium">Only select repositories</span> and pick just this one repo.</li>
          <li>Under <span className="text-text font-medium">Permissions → Repository</span>, set <span className="text-text font-medium">Contents</span> to <span className="text-text font-medium">Read-only</span>. Nothing else is needed.</li>
          <li>Click <span className="text-text font-medium">Generate token</span> and copy it.</li>
          <li>Paste it below and scan. The token is used for this scan only and <strong className="text-text">never stored</strong>.</li>
        </ol>
      </details>
      <form onSubmit={(e) => { e.preventDefault(); scan.mutate() }} className="glass rounded-2xl p-5 flex flex-col gap-2.5 max-w-[560px]">
        <div className="flex gap-2">
          <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="owner" className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light" />
          <span className="self-center text-text-muted">/</span>
          <input value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="repo" className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light" />
        </div>
        <input value={token} onChange={(e) => setToken(e.target.value)} type="password" placeholder="github token (ghp_… / github_pat_…)" className="bg-surface border border-border rounded-xl px-3.5 py-2 font-mono text-[13px] outline-none focus:border-primary-light" />
        <button type="submit" disabled={scan.isPending || !owner || !repo || !token} className="self-start text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">{scan.isPending ? 'Scanning…' : 'Scan privately'}</button>
      </form>
      {scan.isPending && <div className="mt-3 text-[13px] text-text-muted">Scanning privately… we&apos;ll take you to the full report.</div>}
      {scan.isError && <div className="mt-3 text-[13px] text-danger">Scan failed — check the token has access to this repo.</div>}
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
  const create = useMutation({
    mutationFn: async () => (await api.post('/account/claims', { owner: owner.trim(), repo: repo.trim() })).data,
    onSuccess: () => { setOwner(''); setRepo(''); qc.invalidateQueries({ queryKey: ['rebrand-claims'] }) },
  })
  const refetch = () => qc.invalidateQueries({ queryKey: ['rebrand-claims'] })

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
          <p className="mt-2 text-text-muted text-[14px]">Prove you own a repo to unlock a fix-it view, respond to findings, and scan it privately. <span className="text-text">Public repos</span> verify with a GitHub topic; <span className="text-text">private repos</span> with a read-only token — no topic needed.</p>
        </div>
      </Reveal>

      {/* CLAIM UX — form + any in-progress (pending) claims stay here */}
      <div className="mt-8">
        <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-3">Claim a repo</h2>
        <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="flex gap-2">
          <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="owner" className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light" />
          <span className="self-center text-text-muted">/</span>
          <input value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="repo" className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light" />
          <button type="submit" disabled={create.isPending || !owner.trim() || !repo.trim()} className="text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60 shrink-0">{create.isPending ? 'Claiming…' : 'Claim'}</button>
        </form>
        {create.isError && <div className="mt-2 text-[12.5px] text-danger">Couldn&apos;t claim — check the owner / repo and try again.</div>}

        {pending.length > 0 && (
          <div className="mt-4 flex flex-col gap-2.5">
            <div className="text-[12px] font-mono uppercase tracking-wide text-warning">Awaiting verification · {pending.length}</div>
            {pending.map((c) => <ClaimRow key={c.id} c={c} onRefetch={refetch} />)}
          </div>
        )}
      </div>

      {/* divider */}
      <div className="mt-8 border-t border-border/60" />

      {/* PRIVATE SCAN */}
      <div className="mt-8">
        <PrivateScan />
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
          <RevealStagger className="flex flex-col gap-2.5" stagger={0.04}>
            {verified.map((c) => <ClaimRow key={c.id} c={c} onRefetch={refetch} />)}
          </RevealStagger>
        )}
      </div>
    </div>
  )
}
