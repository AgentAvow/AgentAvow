import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { rp } from '../basePath'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../../lib/api'
import { useAuth } from '../../hooks/useAuth'
import { getGradeInfo } from '../../components/trust/gradeSystem'
import { Reveal } from '../components/motion'

/**
 * Claim a repo (prove ownership via a GitHub topic — no token) and scan a private
 * repo (using a token supplied transiently, never stored). Both require sign-in.
 */

interface Claim { id: string; owner: string; repo: string; full_name: string; status: string; topic: string }

function ClaimRow({ c, onRefetch }: { c: Claim; onRefetch: () => void }) {
  const [msg, setMsg] = useState<string | null>(null)
  const verify = useMutation({
    mutationFn: async () => (await api.post<{ verified: boolean; detail?: string }>(`/account/claims/${c.id}/verify`)).data,
    onSuccess: (d) => { setMsg(d.verified ? null : (d.detail || 'Not verified yet.')); onRefetch() },
  })
  const remove = useMutation({ mutationFn: () => api.delete(`/account/claims/${c.id}`), onSuccess: onRefetch })
  return (
    <div className="glass rounded-xl p-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="font-mono text-[14px] break-all">{c.full_name}</div>
        <span className={`font-mono text-[10.5px] uppercase tracking-wide px-2 py-0.5 rounded ${c.status === 'verified' ? 'bg-success/15 text-success' : 'bg-warning/15 text-warning'}`}>{c.status}</span>
      </div>
      {c.status !== 'verified' && (
        <div className="mt-3 text-[13px] text-text-muted">
          <p>To verify, add this <a href={`https://github.com/${c.full_name}/settings`} target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary">GitHub topic</a> to the repo, then click Verify:</p>
          <code className="inline-block mt-1.5 font-mono text-[12px] bg-surface border border-border rounded px-2 py-1 break-all">{c.topic}</code>
          <div className="mt-3 flex gap-2">
            <button onClick={() => verify.mutate()} disabled={verify.isPending} className="text-[12.5px] font-semibold px-3.5 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">{verify.isPending ? 'Checking…' : 'Verify'}</button>
            <button onClick={() => remove.mutate()} className="text-[12.5px] text-text-muted hover:text-danger">Remove</button>
          </div>
          {msg && <div className="mt-2 text-[12.5px] text-warning">{msg}</div>}
        </div>
      )}
      {c.status === 'verified' && <div className="mt-2 text-[12.5px] text-success">✓ You own this — private scans and listing control unlocked.</div>}
    </div>
  )
}

function PrivateScan() {
  const [owner, setOwner] = useState('')
  const [repo, setRepo] = useState('')
  const [token, setToken] = useState('')
  const scan = useMutation({
    mutationFn: async () => (await api.post<{ trust_score: number; findings?: { critical?: number; high?: number; total?: number } }>('/account/private-scan', { owner: owner.trim(), repo: repo.trim(), token: token.trim() })).data,
  })
  const g = scan.data ? getGradeInfo(scan.data.trust_score) : null
  return (
    <div className="mt-10">
      <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-1">Scan a private repo</h2>
      <p className="text-text-muted text-[13px] mb-3">Paste a GitHub token with read access. It's used for this scan only — <strong className="text-text">never stored or logged</strong>. Use a fine-grained token, read-only, this repo only.</p>
      <form onSubmit={(e) => { e.preventDefault(); scan.mutate() }} className="glass rounded-2xl p-5 flex flex-col gap-2.5 max-w-[560px]">
        <div className="flex gap-2">
          <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="owner" className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light" />
          <span className="self-center text-text-muted">/</span>
          <input value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="repo" className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light" />
        </div>
        <input value={token} onChange={(e) => setToken(e.target.value)} type="password" placeholder="github token (ghp_… / github_pat_…)" className="bg-surface border border-border rounded-xl px-3.5 py-2 font-mono text-[13px] outline-none focus:border-primary-light" />
        <button type="submit" disabled={scan.isPending || !owner || !repo || !token} className="self-start text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">{scan.isPending ? 'Scanning…' : 'Scan privately'}</button>
      </form>
      {scan.isError && <div className="mt-3 text-[13px] text-danger">Scan failed — check the token has access to this repo.</div>}
      {g && scan.data && (
        <div className="mt-3 glass rounded-xl p-4 flex items-center gap-4 max-w-[560px]">
          <div className={`w-12 h-12 rounded-xl grid place-items-center font-extrabold ${g.textClass} ${g.bgClass}`}>{g.grade}</div>
          <div className="text-[13px] text-text-muted">
            <div className="font-semibold text-text">{scan.data.trust_score}/100 · private scan</div>
            <div className="font-mono text-[12px] mt-0.5">{scan.data.findings?.critical ?? 0}C · {scan.data.findings?.high ?? 0}H · {scan.data.findings?.total ?? 0} findings</div>
          </div>
        </div>
      )}
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
          <p className="mt-2 text-text-muted">Prove you own a repo to unlock a fix-it view, respond to findings, and scan private repos. Verification is a GitHub topic — no access token needed to claim.</p>
        </div>
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
