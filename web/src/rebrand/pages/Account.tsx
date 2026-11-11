import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { rp } from '../basePath'
import api from '../../lib/api'
import { NotifRow, type Notif } from '../components/NotificationBits'
import { RELEVANT_KIND_PARAM } from '../lib/notifKinds'
import { ALERT_QUERY_KEYS } from '../lib/useUnreadAlerts'
import {
  AccList, AccRow, AccSection, AccountShell, ConfirmAction, EmptyCard, LoadError, PhraseText,
  SkeletonRows, ToolArt, btnSm, rowAct, type RowArt,
} from '../components/AccountBits'
import { toolLink } from '../lib/toolLinks'

/**
 * "Watches & alerts" (route /account), a tab of the account shell: recent alerts, the
 * tools you watch (each row with the Browse-row artwork), and the alert webhook, which
 * stays here beside the alerts it delivers (Kenne's pick, 11-10). API keys moved to
 * Settings → Developer.
 */

interface Watch extends RowArt {
  id: string
  surface?: string
  owner: string
  repo: string
  last_score: number | null
  active: boolean
}

interface WebhookState { url: string | null; active: boolean; signed?: boolean; last_status: number | null }

const inputCls = 'flex-1 min-w-0 bg-surface border border-border rounded-[10px] px-3 py-2 text-[14px] outline-none focus:border-primary-light'
const errText = (e: unknown) => (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Something went wrong. Try again.'

/** Alert webhook: POST watch alerts to a URL (Slack, CI, your app), HMAC-signed. */
function AlertWebhook({ data, loading }: { data?: WebhookState; loading: boolean }) {
  const qc = useQueryClient()
  const [url, setUrl] = useState('')
  const [testResult, setTestResult] = useState<string | null>(null)
  const [freshSecret, setFreshSecret] = useState<string | null>(null)
  const refresh = () => qc.invalidateQueries({ queryKey: ['rebrand-webhook'] })
  const save = useMutation({
    mutationFn: async () => (await api.put<{ signing_secret?: string }>('/account/alert-webhook', { url: url.trim() })).data,
    onSuccess: (d) => { setFreshSecret(d.signing_secret ?? null); setUrl(''); refresh() },
  })
  const rotate = useMutation({
    mutationFn: async () => (await api.post<{ signing_secret: string }>('/account/alert-webhook/rotate-secret')).data,
    onSuccess: (d) => { setFreshSecret(d.signing_secret); refresh() },
  })
  const remove = useMutation({
    mutationFn: () => api.delete('/account/alert-webhook'),
    onSuccess: () => { setFreshSecret(null); refresh() },
  })
  const test = useMutation({
    mutationFn: async () => (await api.post<{ delivered: boolean; status: number }>('/account/alert-webhook/test')).data,
    onSuccess: (d) => setTestResult(d.delivered ? `Delivered ✓ (HTTP ${d.status})` : `Failed (HTTP ${d.status})`),
  })
  const current = data?.url
  const err = save.error ?? rotate.error ?? remove.error ?? test.error
  return (
    <AccSection title="Alert webhook">
      <p className="text-text-muted text-[13.5px] mb-2.5">Alerts can also go to a URL: Slack, your CI, your app. Each delivery is signed with HMAC. <Link to={rp('/rebrand/docs/gate-on-the-grade')} className="text-primary-light hover:text-primary">Verify the signature →</Link></p>
      {freshSecret && (
        <div className="glass rounded-xl p-3.5 mb-2.5 border-l-4 border-success/60">
          <div className="text-[12.5px] text-success font-semibold mb-1">Copy this signing secret now. It won&apos;t be shown again.</div>
          <code className="font-mono text-[12px] break-all bg-surface px-2 py-1 rounded">{freshSecret}</code>
        </div>
      )}
      {loading ? <SkeletonRows n={1} /> : current ? (
        <AccList>
          <AccRow
            name={current}
            sub={<>{data?.last_status != null ? `Last delivery: HTTP ${data.last_status}` : 'No deliveries yet'}{data?.signed === false && ' · not signed yet: rotate the secret to start signing'}</>}
            actions={<>
              <button type="button" onClick={() => { setTestResult(null); test.mutate() }} disabled={test.isPending} className={rowAct}>{test.isPending ? 'Testing…' : 'Send test'}</button>
              <button type="button" onClick={() => rotate.mutate()} disabled={rotate.isPending} className={rowAct}>{rotate.isPending ? 'Rotating…' : 'Rotate secret'}</button>
              <ConfirmAction label="Remove" question="Stop sending alerts here?" confirmLabel="Remove webhook" className={rowAct}
                onConfirm={() => remove.mutate()} pending={remove.isPending} pendingLabel="Removing…" />
            </>}
          />
        </AccList>
      ) : (
        <form onSubmit={(e) => { e.preventDefault(); save.mutate() }} className="flex gap-2 flex-wrap">
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://your-app.com/webhook" type="url" aria-label="Webhook URL" className={inputCls} />
          <button type="submit" disabled={save.isPending || !url.trim()} className={btnSm}>{save.isPending ? 'Saving…' : 'Save'}</button>
        </form>
      )}
      {testResult && <div className="mt-2 text-[12.5px] text-text-muted">{testResult}</div>}
      {err && <div className="mt-2 text-[12.5px] text-danger" role="alert">{errText(err)}</div>}
    </AccSection>
  )
}

function WatchRow({ w, delivery, onRemove, removing }: { w: Watch; delivery: string; onRemove: () => void; removing: boolean }) {
  const { label, badge, href } = toolLink(w.surface, w.owner, w.repo)
  const phrase = <PhraseText row={w} />
  return (
    <AccRow
      name={label}
      chip={badge}
      sub={<>{w.trust_score != null ? phrase : 'Waiting for its first check'} · {delivery}</>}
      art={<ToolArt row={w} />}
      actions={<>
        <Link to={href} className={rowAct}>Re-check</Link>
        <ConfirmAction label="Unwatch" question="Stop alerts for this tool?" confirmLabel="Unwatch" className={rowAct}
          onConfirm={onRemove} pending={removing} pendingLabel="Removing…" />
      </>}
    />
  )
}

function WatchesBody() {
  const qc = useQueryClient()
  const { data: watches, isLoading: wLoading, isError: wError, refetch: refetchWatches, isRefetching: wRefetching } = useQuery({
    queryKey: ['rebrand-watches'],
    queryFn: async () => (await api.get<Watch[]>('/watches')).data,
  })
  const { data: notifs, isLoading: nLoading, isError: nError, refetch: refetchNotifs, isRefetching: nRefetching } = useQuery({
    queryKey: ['rebrand-notifs'],
    // Only the tool-safety kinds, so old social-era rows can't crowd them out.
    queryFn: async () => (await api.get<{ notifications: Notif[] }>('/notifications', { params: { kind: RELEVANT_KIND_PARAM, limit: 3 } })).data,
  })
  const { data: hook, isLoading: hookLoading } = useQuery({
    queryKey: ['rebrand-webhook'],
    queryFn: async () => (await api.get<WebhookState>('/account/alert-webhook')).data,
  })
  const { data: prefs } = useQuery<{ email_notifications_enabled: boolean }>({
    queryKey: ['rebrand-notif-prefs'],
    queryFn: async () => (await api.get('/notifications/preferences')).data,
    staleTime: 5 * 60_000,
  })

  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/watches/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rebrand-watches'] }),
  })
  const invalidateNotifs = () => ALERT_QUERY_KEYS.forEach((k) => qc.invalidateQueries({ queryKey: [k] }))
  const markRead = useMutation({ mutationFn: (id: string) => api.post(`/notifications/${id}/read`), onSuccess: invalidateNotifs })
  const deleteNotif = useMutation({ mutationFn: (id: string) => api.delete(`/notifications/${id}`), onSuccess: invalidateNotifs })

  const rows = watches ?? []
  const alerts = notifs?.notifications ?? []
  const emailOn = prefs?.email_notifications_enabled ?? true
  const delivery = [emailOn && 'email', hook?.url && 'webhook'].filter(Boolean).join(' + ') || 'in-app only'

  return (
    <>
      <AccSection title="Recent alerts" right={alerts.length > 0 && <Link to={rp('/rebrand/notifications')} className="text-[12.5px] font-semibold text-primary-light hover:text-primary">See all →</Link>}>
        {nLoading ? <SkeletonRows n={1} />
          : nError ? <LoadError what="alerts" onRetry={() => void refetchNotifs()} retrying={nRefetching} />
            : alerts.length === 0 ? <p className="text-text-muted text-[14px]">No alerts yet. You&apos;ll see changes to tools you watch here.</p>
              : <AccList>{alerts.map((n) => <NotifRow key={n.id} n={n} onRead={markRead.mutate} onDelete={deleteNotif.mutate} />)}</AccList>}
      </AccSection>

      <AccSection title={<>Watching{rows.length > 0 && ` · ${rows.length}`}</>}>
        {wLoading ? <SkeletonRows n={3} />
          : wError ? <LoadError what="your watches" note="Your watches and alerts still run." onRetry={() => void refetchWatches()} retrying={wRefetching} />
            : rows.length === 0 ? (
              <EmptyCard title="You're not watching any tools yet" action={<Link to={rp('/rebrand/browse')} className={btnSm}>Browse tools</Link>}>
                Open any result and press &ldquo;Watch this tool&rdquo;. You&apos;ll get an alert when its answer gets worse, its score drops, or its tool definitions change.
              </EmptyCard>
            ) : (
              <AccList>
                {rows.map((w) => (
                  <WatchRow key={w.id} w={w} delivery={delivery} onRemove={() => remove.mutate(w.id)} removing={remove.isPending && remove.variables === w.id} />
                ))}
              </AccList>
            )}
      </AccSection>

      <AlertWebhook data={hook} loading={hookLoading} />

      <p className="mt-4 text-text-muted text-[13px]">API keys are in <Link to={rp('/rebrand/settings') + '#developer'} className="text-primary-light hover:text-primary">Settings → Developer</Link>. Which changes email you is in <Link to={rp('/rebrand/settings') + '#alerts'} className="text-primary-light hover:text-primary">Settings</Link>.</p>
    </>
  )
}

export default function RebrandAccount() {
  return (
    <AccountShell tab="watch">
      <WatchesBody />
    </AccountShell>
  )
}
