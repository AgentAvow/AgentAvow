import { Link, useNavigate } from 'react-router-dom'
import { rp } from '../basePath'
import { useQuery } from '@tanstack/react-query'
import { useEffect } from 'react'
import api from '../../lib/api'
import { useAuth } from '../../hooks/useAuth'
import { Reveal, RevealStagger } from '../components/motion'

/**
 * "My Tools" — the repos you've claimed. Verified ones link to their signed
 * report & fix-it view; pending ones link back to finish verifying. Split out of
 * the Account page so ownership (tools) and monitoring (watches) each get room.
 */

interface Claim { id: string; owner: string; repo: string; full_name: string; status: string; topic: string }

/** A claimed tool — status + a link to view/fix or finish verifying.
 * Claims carry no score, so we link straight to the check view where the current
 * signed grade is shown rather than doing an N-query grade fetch. */
function ClaimedRow({ c }: { c: Claim }) {
  const verified = c.status === 'verified'
  const to = verified ? rp(`/rebrand/check/${c.owner}/${c.repo}`) : rp('/rebrand/claim')
  return (
    <Link to={to} className="glass rounded-xl p-4 flex items-center gap-4 hover:border-primary-light transition-colors">
      <div className="min-w-0 flex-1">
        <div className="font-mono text-[14px] break-all">{c.full_name}</div>
        <div className="font-mono text-[11.5px] text-text-muted mt-0.5">{verified ? 'view report & fixes' : 'finish verifying →'}</div>
      </div>
      <span className={`font-mono text-[10.5px] uppercase tracking-wide px-2 py-0.5 rounded shrink-0 ${verified ? 'bg-success/15 text-success' : 'bg-warning/15 text-warning'}`}>{c.status}</span>
      <span className="text-text-muted text-[15px] shrink-0" aria-hidden="true">→</span>
    </Link>
  )
}

export default function RebrandMyTools() {
  const { user, isLoading: authLoading } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    if (!authLoading && !user) navigate(rp('/rebrand/login'))
  }, [authLoading, user, navigate])

  const { data: claimsData, isLoading: cLoading } = useQuery({
    queryKey: ['rebrand-claims'],
    queryFn: async () => (await api.get<{ claims: Claim[] }>('/account/claims')).data,
    enabled: !!user,
  })

  if (!user) return null

  const claims = claimsData?.claims ?? []

  return (
    <div className="max-w-[860px] mx-auto px-6 py-14">
      <Reveal>
        <div className="flex items-end justify-between gap-4 flex-wrap">
          <div>
            <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Your tools</span>
            <h1 className="mt-1 text-2xl md:text-3xl font-extrabold tracking-tight">My Tools</h1>
            <p className="mt-1 text-text-muted text-[14px] max-w-[52ch]">Repos you've claimed. Verified ones link to the report &amp; fix-it view; pending ones link back to finish verifying.</p>
          </div>
          <div className="flex gap-2 shrink-0">
            <Link to={rp("/rebrand/claim")} className="text-[13.5px] font-semibold px-4 py-2 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Claim a repo</Link>
            <Link to={rp("/rebrand/check")} className="text-[13.5px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark">Check a tool</Link>
          </div>
        </div>
      </Reveal>

      <div className="mt-8">
        <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-3">Claimed {claims.length > 0 && `· ${claims.length}`}</h2>
        {cLoading ? (
          <div className="flex flex-col gap-2">{[0, 1].map((i) => <div key={i} className="glass rounded-xl h-[76px] animate-pulse" />)}</div>
        ) : claims.length === 0 ? (
          <div className="glass rounded-2xl p-8 text-center">
            <p className="text-text-muted text-[14px]">No claimed tools yet. Prove you own a repo to unlock a fix-it view, respond to findings, and scan it privately.</p>
            <div className="mt-4 flex items-center justify-center gap-3 flex-wrap">
              <Link to={rp("/rebrand/claim")} className="text-[13.5px] font-semibold text-primary-light hover:text-primary">Claim a repo →</Link>
              <Link to={rp("/rebrand/check")} className="text-[13.5px] font-semibold text-primary-light hover:text-primary">Check a tool →</Link>
            </div>
          </div>
        ) : (
          <RevealStagger className="flex flex-col gap-2" stagger={0.04}>
            {claims.map((c) => <ClaimedRow key={c.id} c={c} />)}
          </RevealStagger>
        )}
      </div>
    </div>
  )
}
