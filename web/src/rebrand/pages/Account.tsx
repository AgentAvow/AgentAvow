import { Link } from 'react-router-dom'
import { rp } from '../basePath'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import api from '../../lib/api'
import { useAuth } from '../../hooks/useAuth'
import { TrustMini } from '../components/TrustMark'
import { NotifRow } from '../components/NotificationBits'
import { RELEVANT_KIND_PARAM } from '../lib/notifKinds'
import { AccountSkeleton, ConfirmAction, LoadError } from '../components/AccountBits'
import { useRequireUser } from '../lib/useRequireUser'
import { Reveal, RevealStagger } from '../components/motion'
import { toolLink } from '../lib/toolLinks'

/**
 * Signed-in home — "Watches & alerts" (route /account). The earned surface for the tool-safety product:
 * the tools you're watching, their current grade, and the change-alerts fired.
 * Settings/Admin are reused from the existing app (linked from the header menu);
 * the social-era Profile/Agents/Feed are intentionally not ported here.
 */

interface Watch {
  id: string
  surface?: string
  owner: string
  repo: string
  last_score: number | null
  active: boolean
}

/** A watch is stored by coordinate; the shared helper gives its label, chip and route. */
function watchLabel(w: Watch) {
  return toolLink(w.surface, w.owner, w.repo)
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

interface WebhookState { url: string | null; active: boolean; signed?: boolean; last_status: number | null }

/** Alert webhook — POST score-change alerts to a URL (Slack/CI/your app). */
function AlertWebhook() {
  const qc = useQueryClient()
  const [url, setUrl] = useState('')
  const [testResult, setTestResult] = useState<string | null>(null)
  const [freshSecret, setFreshSecret] = useState<string | null>(null)
  const { data } = useQuery({
    queryKey: ['rebrand-webhook'],
    queryFn: async () => (await api.get<WebhookState>('/account/alert-webhook')).data,
  })
  const save = useMutation({
    mutationFn: async () => (await api.put<{ signing_secret?: string }>('/account/alert-webhook', { url: url.trim() })).data,
    onSuccess: (d) => { setFreshSecret(d.signing_secret ?? null); setUrl(''); qc.invalidateQueries({ queryKey: ['rebrand-webhook'] }) },
  })
  const rotate = useMutation({
    mutationFn: async () => (await api.post<{ signing_secret: string }>('/account/alert-webhook/rotate-secret')).data,
    onSuccess: (d) => { setFreshSecret(d.signing_secret); qc.invalidateQueries({ queryKey: ['rebrand-webhook'] }) },
  })
  const remove = useMutation({
    mutationFn: () => api.delete('/account/alert-webhook'),
    onSuccess: () => { setFreshSecret(null); qc.invalidateQueries({ queryKey: ['rebrand-webhook'] }) },
  })
  const test = useMutation({
    mutationFn: async () => (await api.post<{ delivered: boolean; status: number }>('/account/alert-webhook/test')).data,
    onSuccess: (d) => setTestResult(d.delivered ? `Delivered ✓ (HTTP ${d.status})` : `Failed (HTTP ${d.status})`),
  })
  const current = data?.url
  return (
    <div className="mt-10">
      <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-1">Alert webhook</h2>
      <p className="text-text-muted text-[13px] mb-3">Get score-change alerts POSTed to a URL — Slack, your CI, your app — in addition to email. Each delivery is HMAC-signed with your webhook's secret.</p>
      {freshSecret && (
        <div className="glass rounded-xl p-4 mb-3 border-l-4 border-success/60">
          <div className="text-[12.5px] text-success font-semibold mb-1">Copy this signing secret now — it won't be shown again.</div>
          <code className="font-mono text-[12px] break-all bg-surface px-2 py-1 rounded">{freshSecret}</code>
        </div>
      )}
      {current ? (
        <div className="glass rounded-xl px-4 py-3 flex items-center justify-between gap-3 flex-wrap">
          <div className="min-w-0">
            <div className="font-mono text-[13px] break-all">{current}</div>
            {data?.last_status != null && <div className="text-[11.5px] text-text-muted">last delivery: HTTP {data.last_status}</div>}
            {data?.signed === false && <div className="text-[11.5px] text-text-muted">Not signed yet. Rotate the secret to start signing.</div>}
          </div>
          <div className="flex gap-2 shrink-0">
            <button onClick={() => rotate.mutate()} disabled={rotate.isPending} className="text-[12px] text-text-muted hover:text-primary-light">Rotate secret</button>
            <button onClick={() => { setTestResult(null); test.mutate() }} disabled={test.isPending} className="text-[12px] font-semibold px-3 py-1.5 rounded-lg border border-border text-text-muted hover:border-primary-light hover:text-primary-light">{test.isPending ? 'Testing…' : 'Send test'}</button>
            <ConfirmAction label="Remove" question="Stop sending alerts here?" confirmLabel="Remove webhook"
              onConfirm={() => remove.mutate()} pending={remove.isPending} pendingLabel="Removing…" />
          </div>
        </div>
      ) : (
        <form onSubmit={(e) => { e.preventDefault(); save.mutate() }} className="flex gap-2">
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://your-app.com/webhook" type="url"
            className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light" />
          <button type="submit" disabled={save.isPending} className="text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60 shrink-0">Save</button>
        </form>
      )}
      {testResult && <div className="mt-2 text-[12.5px] text-text-muted">{testResult}</div>}
    </div>
  )
}

interface ApiKey { id: string; label: string; created_at: string | null }

/** Developer API keys — create (shown once), list, revoke. */
function ApiKeys() {
  const qc = useQueryClient()
  const [label, setLabel] = useState('')
  const [fresh, setFresh] = useState<string | null>(null)
  const { data } = useQuery({
    queryKey: ['rebrand-apikeys'],
    queryFn: async () => (await api.get<{ keys: ApiKey[] }>('/account/api-keys')).data,
  })
  const create = useMutation({
    mutationFn: async () => (await api.post<{ key: string }>('/account/api-keys', { label: label.trim() || 'default' })).data,
    onSuccess: (d) => { setFresh(d.key); setLabel(''); qc.invalidateQueries({ queryKey: ['rebrand-apikeys'] }) },
  })
  const revoke = useMutation({
    mutationFn: (id: string) => api.delete(`/account/api-keys/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rebrand-apikeys'] }),
  })
  const keys = data?.keys ?? []
  return (
    <div className="mt-10">
      <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-1">API keys</h2>
      <p className="text-text-muted text-[13px] mb-3">Call the scan API programmatically. Keys carry your higher rate limit. <a href="/api/v1/redoc" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary">API reference ↗</a></p>
      {fresh && (
        <div className="glass rounded-xl p-4 mb-3 border-l-4 border-success/60">
          <div className="text-[12.5px] text-success font-semibold mb-1">Copy this key now — it won't be shown again.</div>
          <code className="font-mono text-[12px] break-all bg-surface px-2 py-1 rounded">{fresh}</code>
        </div>
      )}
      <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="flex gap-2 mb-3">
        <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="key label (e.g. ci-pipeline)"
          className="flex-1 min-w-0 bg-surface border border-border rounded-xl px-3.5 py-2 text-[14px] outline-none focus:border-primary-light" />
        <button type="submit" disabled={create.isPending} className="text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60 shrink-0">Create key</button>
      </form>
      {keys.length > 0 ? (
        <div className="flex flex-col gap-2">
          {keys.map((k) => (
            <div key={k.id} className="glass rounded-xl px-4 py-3 flex items-center justify-between gap-3">
              <div>
                <div className="text-[14px] font-semibold">{k.label}</div>
                <div className="font-mono text-[11.5px] text-text-muted">created {k.created_at ? new Date(k.created_at).toLocaleDateString() : '—'}</div>
              </div>
              <span className="shrink-0">
                <ConfirmAction label="Revoke" question="Calls with this key will stop working." confirmLabel="Revoke key"
                  onConfirm={() => revoke.mutate(k.id)} pending={revoke.isPending && revoke.variables === k.id} pendingLabel="Revoking…" />
              </span>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-text-muted text-[13px]">No keys yet.</div>
      )}
    </div>
  )
}

function WatchRow({ w, onRemove, removing }: { w: Watch; onRemove: () => void; removing: boolean }) {
  const { label, badge, href } = watchLabel(w)
  return (
    <div className="glass rounded-xl p-4 flex items-center gap-4">
      {w.last_score != null ? (
        <TrustMini score={w.last_score} />
      ) : (
        <div className="w-11 h-11 rounded-xl grid place-items-center font-mono text-[10px] text-text-muted bg-surface-hover shrink-0">n/a</div>
      )}
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[9.5px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded bg-primary/12 text-primary-light shrink-0">{badge}</span>
          <span className="font-mono text-[14px] break-all">{label}</span>
        </div>
        <div className="font-mono text-[11.5px] text-text-muted mt-0.5">{w.last_score != null ? `${w.last_score}/100 at last check` : 'awaiting first check'}</div>
      </div>
      <div className="flex items-center gap-3 shrink-0">
        <Link to={href} className="text-[12.5px] font-semibold text-primary-light hover:text-primary">View report →</Link>
        <ConfirmAction label="Unwatch" question="Stop alerts for this tool?" confirmLabel="Unwatch"
          onConfirm={onRemove} pending={removing} pendingLabel="Removing…" />
      </div>
    </div>
  )
}

export default function RebrandAccount() {
  const { user, isLoading: authLoading } = useAuth()
  const qc = useQueryClient()
  useRequireUser(user, authLoading)

  const { data: watches, isLoading: wLoading, isError: wError, refetch: refetchWatches, isRefetching: wRefetching } = useQuery({
    queryKey: ['rebrand-watches'],
    queryFn: async () => (await api.get<Watch[]>('/watches')).data,
    enabled: !!user,
  })

  const { data: notifs } = useQuery({
    queryKey: ['rebrand-notifs'],
    // Fetch only the tool-safety kinds, so old social-era rows can't crowd them out.
    queryFn: async () => (await api.get<{ notifications: Notif[] }>('/notifications', { params: { kind: RELEVANT_KIND_PARAM, limit: 10 } })).data,
    enabled: !!user,
  })

  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/watches/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rebrand-watches'] }),
  })

  const invalidateNotifs = () => qc.invalidateQueries({ queryKey: ['rebrand-notifs'] })
  const markReadNotif = useMutation({ mutationFn: (id: string) => api.post(`/notifications/${id}/read`), onSuccess: invalidateNotifs })
  const deleteNotif = useMutation({ mutationFn: (id: string) => api.delete(`/notifications/${id}`), onSuccess: invalidateNotifs })

  if (!user) return <AccountSkeleton />

  const rows = watches ?? []
  const alerts = notifs?.notifications ?? []

  return (
    <div className="max-w-[860px] mx-auto px-6 py-14">
      <Reveal>
        <div className="flex items-end justify-between gap-4 flex-wrap">
          <div className="max-w-[60ch]">
            <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Watches &amp; alerts</span>
            <h1 className="mt-1 text-2xl md:text-3xl font-extrabold tracking-tight">Watch tools for changes</h1>
            <p className="mt-2 text-text-muted text-[14px]">We re-scan the tools you watch and tell you when something changes — a <span className="text-text">score drops</span>, a <span className="text-text">signed definition changes</span>, or a tool you flagged gets <span className="text-text">safer</span> — so you always know where the tools your agents rely on stand.</p>
          </div>
        </div>
      </Reveal>

      {/* recent alerts */}
      {alerts.length > 0 && (
        <Reveal>
          <div className="mt-8">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-[13px] font-mono uppercase tracking-wide text-warning">Recent alerts</h2>
              <Link to={rp('/rebrand/notifications')} className="text-[12.5px] font-semibold text-primary-light hover:text-primary">See all &amp; manage →</Link>
            </div>
            <div className="flex flex-col gap-2">
              {alerts.slice(0, 3).map((n) => (
                <NotifRow key={n.id} n={n} onRead={markReadNotif.mutate} onDelete={deleteNotif.mutate} />
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
        ) : wError ? (
          <LoadError what="your watches" onRetry={() => void refetchWatches()} retrying={wRefetching} />
        ) : rows.length === 0 ? (
          <div className="glass rounded-2xl p-8 text-center">
            <p className="text-text-muted text-[14px]">You're not watching any tools yet. Watch a tool and we'll re-scan it and alert you if its score drops or its signed definition changes.</p>
            <Link to={rp("/rebrand/browse")} className="inline-block mt-4 text-[13.5px] font-semibold text-primary-light hover:text-primary">Browse scored tools →</Link>
          </div>
        ) : (
          <RevealStagger className="flex flex-col gap-2" stagger={0.04}>
            {rows.map((w) => (
              <WatchRow key={w.id} w={w} onRemove={() => remove.mutate(w.id)} removing={remove.isPending && remove.variables === w.id} />
            ))}
          </RevealStagger>
        )}
      </div>

      {/* alert delivery */}
      <AlertWebhook />

      {/* developer API keys */}
      <ApiKeys />
    </div>
  )
}
