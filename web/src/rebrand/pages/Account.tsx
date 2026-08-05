import { Link, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import api from '../../lib/api'
import { useAuth } from '../../hooks/useAuth'
import { getGradeInfo } from '../../components/trust/gradeSystem'
import { Reveal, RevealStagger } from '../components/motion'

/**
 * Signed-in home — "My watches". The earned surface for the tool-safety product:
 * the tools you're watching, their current grade, and the change-alerts fired.
 * Settings/Admin are reused from the existing app (linked from the header menu);
 * the social-era Profile/Agents/Feed are intentionally not ported here.
 */

interface Watch {
  id: string
  owner: string
  repo: string
  last_score: number | null
  active: boolean
}

interface Notif {
  id: string
  kind: string
  title: string
  body: string
  reference_id: string | null
  is_read: boolean
  created_at: string
}

function WatchRow({ w, onRemove, removing }: { w: Watch; onRemove: () => void; removing: boolean }) {
  const g = w.last_score != null ? getGradeInfo(w.last_score) : null
  return (
    <div className="glass rounded-xl p-4 flex items-center gap-4">
      {g ? (
        <div className={`w-11 h-11 rounded-xl grid place-items-center font-extrabold text-[15px] shrink-0 ${g.textClass} ${g.bgClass}`}>{g.grade}</div>
      ) : (
        <div className="w-11 h-11 rounded-xl grid place-items-center font-mono text-[10px] text-text-muted bg-surface-hover shrink-0">n/a</div>
      )}
      <div className="min-w-0 flex-1">
        <Link to={`/rebrand/check/${w.owner}/${w.repo}`} className="font-mono text-[14px] break-all hover:text-primary-light">{w.owner}/{w.repo}</Link>
        <div className="font-mono text-[11.5px] text-text-muted mt-0.5">{w.last_score != null ? `${w.last_score}/100 at last check` : 'awaiting first check'}</div>
      </div>
      <button onClick={onRemove} disabled={removing} className="text-[12px] text-text-muted hover:text-danger transition-colors disabled:opacity-50 shrink-0">
        {removing ? '…' : 'Unwatch'}
      </button>
    </div>
  )
}

export default function RebrandAccount() {
  const { user, isLoading: authLoading } = useAuth()
  const navigate = useNavigate()
  const qc = useQueryClient()

  useEffect(() => {
    if (!authLoading && !user) navigate('/rebrand/login')
  }, [authLoading, user, navigate])

  const { data: watches, isLoading: wLoading } = useQuery({
    queryKey: ['rebrand-watches'],
    queryFn: async () => (await api.get<Watch[]>('/watches')).data,
    enabled: !!user,
  })

  const { data: notifs } = useQuery({
    queryKey: ['rebrand-notifs'],
    queryFn: async () => (await api.get<{ notifications: Notif[] }>('/notifications', { params: { limit: 20 } })).data,
    enabled: !!user,
  })

  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/watches/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rebrand-watches'] }),
  })

  if (!user) return null

  const rows = watches ?? []
  const alerts = (notifs?.notifications ?? []).filter((n) => n.kind === 'watch_alert')

  return (
    <div className="max-w-[860px] mx-auto px-6 py-14">
      <Reveal>
        <div className="flex items-end justify-between gap-4 flex-wrap">
          <div>
            <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Your account</span>
            <h1 className="mt-2 text-3xl font-extrabold tracking-tight">Welcome back, {user.display_name}.</h1>
            <p className="mt-2 text-text-muted">The tools you watch, their current grade, and every change we've alerted you to.</p>
          </div>
          <Link to="/rebrand/check" className="text-[13.5px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shrink-0">Check a tool</Link>
        </div>
      </Reveal>

      {/* recent alerts */}
      {alerts.length > 0 && (
        <Reveal>
          <div className="mt-8">
            <h2 className="text-[13px] font-mono uppercase tracking-wide text-warning mb-3">Recent alerts</h2>
            <div className="flex flex-col gap-2">
              {alerts.slice(0, 5).map((n) => (
                <div key={n.id} className={`glass rounded-xl px-4 py-3 border-l-4 ${n.is_read ? 'border-border' : 'border-warning'}`}>
                  <div className="text-[14px] font-semibold">{n.title}</div>
                  <div className="text-[13px] text-text-muted mt-0.5">{n.body}</div>
                  {n.reference_id && <Link to={`/rebrand/check/${n.reference_id}`} className="inline-block mt-1.5 text-[12.5px] text-primary-light hover:text-primary">Re-check →</Link>}
                </div>
              ))}
            </div>
          </div>
        </Reveal>
      )}

      {/* watches */}
      <div className="mt-8">
        <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-3">Watching {rows.length > 0 && `· ${rows.length}`}</h2>
        {wLoading ? (
          <div className="flex flex-col gap-2">{[0, 1, 2].map((i) => <div key={i} className="glass rounded-xl h-[76px] animate-pulse" />)}</div>
        ) : rows.length === 0 ? (
          <div className="glass rounded-2xl p-8 text-center">
            <p className="text-text-muted text-[14px]">You're not watching any tools yet. Watch a tool and we'll re-scan it and alert you if its grade drops or its signed definition changes.</p>
            <Link to="/rebrand/browse" className="inline-block mt-4 text-[13.5px] font-semibold text-primary-light hover:text-primary">Browse scored tools →</Link>
          </div>
        ) : (
          <RevealStagger className="flex flex-col gap-2" stagger={0.04}>
            {rows.map((w) => (
              <WatchRow key={w.id} w={w} onRemove={() => remove.mutate(w.id)} removing={remove.isPending && remove.variables === w.id} />
            ))}
          </RevealStagger>
        )}
      </div>
    </div>
  )
}
