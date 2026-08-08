import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { rp } from '../basePath'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../../lib/api'
import { useAuth } from '../../hooks/useAuth'
import { Reveal } from '../components/motion'

/**
 * Claim a repo (prove ownership via a GitHub topic — no token) and scan a private
 * repo (using a token supplied transiently, never stored). Both require sign-in.
 */

interface Claim { id: string; owner: string; repo: string; full_name: string; status: string; topic: string }

function ClaimRow({ c, onRefetch }: { c: Claim; onRefetch: () => void }) {
  const [msg, setMsg] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [token, setToken] = useState('')
  // One endpoint, two paths: no token → verify the public topic; with token →
  // verify a private repo by proving read access.
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
          <div className="text-[12.5px] text-success">✓ Verified — you own this. Private scans &amp; listing control are unlocked.</div>
          <button onClick={() => remove.mutate()} className="text-[12px] text-text-muted hover:text-danger">Remove</button>
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
              <li>Open <a href={`https://github.com/${c.full_name}`} target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary font-mono">github.com/{c.full_name}</a> → click the <span className="text-text font-medium">gear ⚙️</span> next to <span className="text-text font-medium">“About”</span>.</li>
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
            <p className="mt-2 text-[12.5px]">Private repos can't use a topic (we can't read them). Paste a fine-grained <span className="text-text font-medium">read-only</span> token for this repo — it proves access, is used once, and is <span className="text-text font-medium">never stored</span>.</p>
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

function PrivateScan() {
  const navigate = useNavigate()
  const [owner, setOwner] = useState('')
  const [repo, setRepo] = useState('')
  const [token, setToken] = useState('')
  // On success, hand the full result to the real score page (a private repo
  // can't be re-fetched publicly) — the token rides along so the owner can Claim
  // or Publish-to-search from there, with the complete detailed report.
  const scan = useMutation({
    mutationFn: async () => (await api.post('/account/private-scan', { owner: owner.trim(), repo: repo.trim(), token: token.trim() })).data,
    onSuccess: (data) => navigate(
      rp(`/rebrand/check/${owner.trim()}/${repo.trim()}`),
      { state: { privateResult: data, token: token.trim() } },
    ),
  })
  return (
    <div className="mt-10">
      <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-1">Scan a private repo</h2>
      <p className="text-text-muted text-[13px] mb-3">Paste a GitHub token with read access. It's used for this scan only — <strong className="text-text">never stored or logged</strong>. Use a fine-grained token, read-only, this repo only.</p>
      <details className="mb-3 text-[12.5px] max-w-[560px]">
        <summary className="cursor-pointer text-primary-light hover:text-primary font-medium">How to create a read-only token (30 seconds)</summary>
        <ol className="mt-2.5 flex flex-col gap-1.5 list-decimal pl-4 marker:text-primary-light marker:font-semibold text-text-muted">
          <li>On GitHub, go to <a href="https://github.com/settings/personal-access-tokens/new" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary">Settings → Developer settings → Personal access tokens → Fine-grained tokens → <span className="text-text font-medium">Generate new token</span></a>.</li>
          <li>Under <span className="text-text font-medium">Repository access</span>, choose <span className="text-text font-medium">Only select repositories</span> and pick just this one repo.</li>
          <li>Under <span className="text-text font-medium">Permissions → Repository</span>, set <span className="text-text font-medium">Contents</span> to <span className="text-text font-medium">Read-only</span>. Nothing else is needed.</li>
          <li>Click <span className="text-text font-medium">Generate token</span> and copy it.</li>
          <li>Paste it below and scan. The token is used for this scan only and <strong className="text-text">never stored</strong> — you can delete it on GitHub right after.</li>
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
      {scan.isPending && <div className="mt-3 text-[13px] text-text-muted">Scanning privately… we'll take you to the full report.</div>}
      {scan.isError && <div className="mt-3 text-[13px] text-danger">Scan failed — check the token has access to this repo.</div>}
    </div>
  )
}

export default function RebrandClaim() {
  const { user, isLoading } = useAuth()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [params] = useSearchParams()
  const [owner, setOwner] = useState(params.get('owner') || '')
  const [repo, setRepo] = useState(params.get('repo') || '')

  useEffect(() => { if (!isLoading && !user) navigate(rp('/rebrand/login')) }, [isLoading, user, navigate])

  const { data } = useQuery({
    queryKey: ['rebrand-claims'],
    queryFn: async () => (await api.get<{ claims: Claim[] }>('/account/claims')).data,
    enabled: !!user,
  })
  const create = useMutation({
    mutationFn: async () => (await api.post('/account/claims', { owner: owner.trim(), repo: repo.trim() })).data,
    onSuccess: () => { setOwner(''); setRepo(''); qc.invalidateQueries({ queryKey: ['rebrand-claims'] }) },
  })
  const refetch = () => qc.invalidateQueries({ queryKey: ['rebrand-claims'] })
  if (!user) return null
  const claims = data?.claims ?? []

  return (
    <div className="max-w-[760px] mx-auto px-6 py-14">
      <Reveal>
        <div className="max-w-[60ch]">
          <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Claim</span>
          <h1 className="mt-2 text-3xl font-extrabold tracking-tight">Own a tool? Claim it.</h1>
          <p className="mt-2 text-text-muted">Prove you own a repo to unlock a fix-it view, respond to findings, and scan it privately. <span className="text-text">Public repos</span> verify with a GitHub topic; <span className="text-text">private repos</span> verify with a read-only token — no topic needed.</p>
        </div>
      </Reveal>

      <Reveal>
        <ol className="mt-6 grid gap-3 sm:grid-cols-3">
          {[
            { n: '1', t: 'Claim the repo', d: 'Enter owner / repo below. We generate a one-time verification topic for it.' },
            { n: '2', t: 'Add the topic on GitHub', d: 'Paste the topic into your repo’s About → Topics. It proves you can edit the repo.' },
            { n: '3', t: 'Verify', d: 'Public: click Verify topic. Private: paste a read-only token instead — no topic needed.' },
          ].map((s) => (
            <li key={s.n} className="glass rounded-xl p-4">
              <div className="w-6 h-6 rounded-md grid place-items-center font-mono text-[12px] font-bold bg-primary/15 text-primary-light">{s.n}</div>
              <div className="mt-2 font-semibold text-[13.5px]">{s.t}</div>
              <div className="mt-1 text-[12.5px] text-text-muted">{s.d}</div>
            </li>
          ))}
        </ol>
      </Reveal>

      <div className="mt-8">
        <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-3">Claim a repo</h2>
        <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="flex gap-2 mb-4">
          <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="owner" className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light" />
          <span className="self-center text-text-muted">/</span>
          <input value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="repo" className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light" />
          <button type="submit" disabled={create.isPending || !owner || !repo} className="text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60 shrink-0">Claim</button>
        </form>
        {claims.length > 0 ? (
          <div className="flex flex-col gap-2.5">{claims.map((c) => <ClaimRow key={c.id} c={c} onRefetch={refetch} />)}</div>
        ) : (
          <div className="text-text-muted text-[13px]">No claims yet. <Link to={rp("/rebrand/browse")} className="text-primary-light hover:text-primary">Find your tool →</Link></div>
        )}
      </div>

      <PrivateScan />
    </div>
  )
}
