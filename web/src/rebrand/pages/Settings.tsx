import { useState, type ReactNode } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { rp } from '../basePath'
import api from '../../lib/api'
import { useAuth } from '../../hooks/useAuth'
import { useTheme } from '../../hooks/useTheme'
import { ConfirmAction, LoadError, SkeletonRows, btnGhostSm, btnSm, rowAct } from '../components/AccountBits'

/**
 * Settings, a tab of the account shell: profile, sign-in, appearance, which alerts
 * email you, Developer (API keys, moved here from Watches & alerts), your data, and
 * deactivation. The alert webhook stays on Watches & alerts, beside the alerts.
 */

interface NotifPrefs { email_notifications_enabled: boolean }
interface ApiKey { id: string; label: string; created_at: string | null }

const inputCls = 'w-full min-w-0 bg-surface border border-border rounded-[10px] px-3 py-2 text-[14px] outline-none focus:border-primary-light'
const errText = (m: unknown) => (m as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Something went wrong. Try again.'

function SetCard({ title, id, tone, children }: { title: string; id?: string; tone?: 'danger'; children: ReactNode }) {
  return (
    <div id={id} className={`mt-3 glass rounded-2xl border border-border/60 px-[18px] py-4 scroll-mt-24 ${tone === 'danger' ? 'border-l-4 border-l-danger/50' : ''}`}>
      <h3 className={`text-[15px] font-bold ${tone === 'danger' ? 'text-danger' : ''}`}>{title}</h3>
      {children}
    </div>
  )
}

function Toggle({ on, onClick, disabled, label }: { on: boolean; onClick: () => void; disabled?: boolean; label: string }) {
  return (
    <button type="button" onClick={onClick} disabled={disabled} aria-pressed={on} aria-label={label}
      className={`relative w-9 h-5 rounded-full transition-colors shrink-0 disabled:opacity-60 ${on ? 'bg-primary' : 'bg-border'}`}>
      <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${on ? 'left-[18px]' : 'left-0.5'}`} />
    </button>
  )
}

/** Developer API keys: create (shown once), list, revoke. */
function ApiKeys() {
  const qc = useQueryClient()
  const [label, setLabel] = useState('')
  const [fresh, setFresh] = useState<string | null>(null)
  const { data, isLoading, isError, refetch, isRefetching } = useQuery({
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
    <>
      <div className="mt-3 font-mono text-[11px] uppercase tracking-wide text-text-muted">API keys</div>
      <p className="text-text-muted text-[13.5px] mt-1">Call the scan API from your code; keys carry your higher rate limit. <a href="/api/v1/redoc" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary">API reference ↗</a></p>
      {fresh && (
        <div className="mt-2.5 glass rounded-xl p-3.5 border-l-4 border-success/60">
          <div className="text-[12.5px] text-success font-semibold mb-1">Copy this key now. It won&apos;t be shown again.</div>
          <code className="font-mono text-[12px] break-all bg-surface px-2 py-1 rounded">{fresh}</code>
        </div>
      )}
      <div className="mt-2.5">
        {isLoading ? <SkeletonRows n={1} />
          : isError ? <LoadError what="your API keys" onRetry={() => void refetch()} retrying={isRefetching} />
            : keys.length === 0 ? <p className="text-text-muted text-[13px]">No keys yet.</p>
              : keys.map((k) => (
                <div key={k.id} className="flex flex-wrap items-center gap-x-3 gap-y-1.5 py-2 border-t border-border/60 text-[13.5px]">
                  <span className="font-semibold min-w-0 [overflow-wrap:anywhere]">{k.label}</span>
                  <span className="text-text-muted text-[12.5px]">created {k.created_at ? new Date(k.created_at).toLocaleDateString() : '—'}</span>
                  <span className="ml-auto">
                    <ConfirmAction label="Revoke" question="Anything using this key stops working now." confirmLabel="Revoke key" className={rowAct}
                      onConfirm={() => revoke.mutate(k.id)} pending={revoke.isPending && revoke.variables === k.id} pendingLabel="Revoking…" />
                  </span>
                </div>
              ))}
      </div>
      <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="mt-2.5 flex gap-2 flex-wrap">
        <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Key label (for example ci-pipeline)" aria-label="Key label" className={`${inputCls} flex-[1_1_200px] w-auto`} />
        <button type="submit" disabled={create.isPending} className={btnSm}>{create.isPending ? 'Creating…' : 'New API key'}</button>
      </form>
      {(create.isError || revoke.isError) && <div className="mt-2 text-[12.5px] text-danger" role="alert">{errText(create.error ?? revoke.error)}</div>}
    </>
  )
}

function SettingsBody() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const { theme, toggleTheme } = useTheme()

  const [curPass, setCurPass] = useState('')
  const [newPass, setNewPass] = useState('')
  const [newEmail, setNewEmail] = useState('')
  const [emailPass, setEmailPass] = useState('')

  const changePassword = useMutation({
    mutationFn: () => api.post('/account/change-password', { current_password: curPass, new_password: newPass }),
    onSuccess: () => { setCurPass(''); setNewPass('') },
  })
  const changeEmail = useMutation({
    mutationFn: () => api.post('/auth/change-email', { new_email: newEmail.trim(), current_password: emailPass }),
    onSuccess: () => { setNewEmail(''); setEmailPass('') },
  })
  const resendVerify = useMutation({ mutationFn: () => api.post('/auth/resend-verification') })

  const { data: prefs, isError: prefsError } = useQuery<NotifPrefs>({
    queryKey: ['rebrand-notif-prefs'],
    queryFn: async () => (await api.get('/notifications/preferences')).data,
    staleTime: 5 * 60_000,
  })
  const updatePref = useMutation({
    mutationFn: (update: Partial<NotifPrefs>) => api.patch('/notifications/preferences', update),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rebrand-notif-prefs'] }),
  })

  const exportData = useMutation({
    mutationFn: async () => (await api.get('/export/me')).data,
    onSuccess: (data) => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'agentavow-export.json'
      a.click()
      URL.revokeObjectURL(url)
    },
  })
  const deactivate = useMutation({
    mutationFn: () => api.post('/account/deactivate'),
    onSuccess: () => { logout(); navigate(rp('/rebrand')) },
  })

  if (!user) return null
  const emailOn = prefs?.email_notifications_enabled ?? true

  return (
    <div className="mt-[22px]">
      <SetCard title="Profile">
        <div className="mt-3 flex items-center gap-3.5">
          {user.avatar_url
            ? <img src={user.avatar_url} alt="" className="w-14 h-14 rounded-full object-cover ring-2 ring-primary/30 shrink-0" />
            : <span className="w-14 h-14 rounded-full grid place-items-center text-xl font-bold text-white bg-gradient-to-br from-primary to-accent shrink-0">{user.display_name?.charAt(0).toUpperCase() || '?'}</span>}
          <div className="min-w-0">
            <div className="text-[16px] font-bold">{user.display_name}</div>
            <div className="text-[13px] text-text-muted break-all">{user.email}</div>
            <Link to={rp('/rebrand/avatar')} className="text-[12.5px] text-primary-light hover:text-primary">Change avatar →</Link>
          </div>
        </div>
        {!user.email_verified && (
          <div className="mt-3 flex items-center justify-between gap-3 flex-wrap rounded-xl bg-warning/10 border border-warning/30 px-3.5 py-2.5">
            <span className="text-[13px] text-warning">Your email isn&apos;t verified.</span>
            <button type="button" onClick={() => resendVerify.mutate()} disabled={resendVerify.isPending || resendVerify.isSuccess} className="text-[12.5px] font-semibold text-primary-light hover:text-primary disabled:opacity-60">{resendVerify.isSuccess ? 'Sent ✓' : resendVerify.isPending ? 'Sending…' : 'Resend'}</button>
          </div>
        )}
      </SetCard>

      <SetCard title="Sign-in">
        <p className="text-text-muted text-[13.5px] mt-0.5">Change your password or email.</p>
        <form onSubmit={(e) => { e.preventDefault(); changePassword.mutate() }} className="mt-3 flex flex-col gap-2">
          <input type="password" autoComplete="current-password" placeholder="Current password" aria-label="Current password" value={curPass} onChange={(e) => setCurPass(e.target.value)} className={inputCls} />
          <input type="password" autoComplete="new-password" placeholder="New password" aria-label="New password" value={newPass} onChange={(e) => setNewPass(e.target.value)} className={inputCls} />
          <button type="submit" disabled={changePassword.isPending || !curPass || !newPass} className={`${btnGhostSm} self-start`}>{changePassword.isPending ? 'Saving…' : 'Change password'}</button>
          {changePassword.isSuccess && <div className="text-[13px] text-success">Password updated ✓</div>}
          {changePassword.isError && <div className="text-[13px] text-danger" role="alert">{errText(changePassword.error)}</div>}
        </form>
        <form onSubmit={(e) => { e.preventDefault(); changeEmail.mutate() }} className="mt-4 pt-3 border-t border-border/60 flex flex-col gap-2">
          <input type="email" placeholder="New email" aria-label="New email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} className={inputCls} />
          <input type="password" autoComplete="current-password" placeholder="Current password" aria-label="Current password for email change" value={emailPass} onChange={(e) => setEmailPass(e.target.value)} className={inputCls} />
          <button type="submit" disabled={changeEmail.isPending || !newEmail || !emailPass} className={`${btnGhostSm} self-start`}>{changeEmail.isPending ? 'Saving…' : 'Change email'}</button>
          {changeEmail.isSuccess && <div className="text-[13px] text-success">Email updated. Check your inbox to verify it.</div>}
          {changeEmail.isError && <div className="text-[13px] text-danger" role="alert">{errText(changeEmail.error)}</div>}
        </form>
      </SetCard>

      <SetCard title="Appearance">
        <div className="mt-2 flex justify-between items-center gap-3 text-[14px]">
          <span>Light theme</span>
          <Toggle on={theme === 'light'} onClick={toggleTheme} label="Light theme" />
        </div>
      </SetCard>

      <SetCard title="Alerts by email" id="alerts">
        <p className="text-text-muted text-[13.5px] mt-0.5">Per-tool delivery is on <Link to={rp('/rebrand/account')} className="text-primary-light hover:text-primary">Watches &amp; alerts</Link>.</p>
        <div className="mt-2 flex justify-between items-center gap-3 py-2 text-[14px]">
          <span>Email me when a tool I watch changes: its answer gets worse or the Certified mark comes off, its trust score drops, a tool definition changes, or it gets safer. Account emails too.</span>
          <Toggle on={emailOn} disabled={updatePref.isPending} onClick={() => updatePref.mutate({ email_notifications_enabled: !emailOn })} label="Email alerts" />
        </div>
        {(prefsError || updatePref.isError) && <div className="text-[12.5px] text-danger" role="alert">Couldn&apos;t {updatePref.isError ? 'save' : 'load'} this setting. Try again.</div>}
      </SetCard>

      <SetCard title="Developer" id="developer">
        <p className="text-text-muted text-[13.5px] mt-0.5">For CI, gates and your own tools. The alert webhook is on <Link to={rp('/rebrand/account')} className="text-primary-light hover:text-primary">Watches &amp; alerts</Link>, beside your alerts.</p>
        <ApiKeys />
      </SetCard>

      <SetCard title="Your data">
        <p className="text-text-muted text-[13.5px] mt-0.5">Download everything we keep about your account, as JSON.</p>
        <div className="mt-2.5"><button type="button" onClick={() => exportData.mutate()} disabled={exportData.isPending} className={btnGhostSm}>{exportData.isPending ? 'Preparing…' : 'Export my data'}</button></div>
        {exportData.isError && <div className="mt-2 text-[12.5px] text-danger" role="alert">{errText(exportData.error)}</div>}
      </SetCard>

      <SetCard title="Deactivate" tone="danger">
        <p className="text-text-muted text-[13.5px] mt-0.5">Deactivating disables your account and signs you out. To delete your data, email privacy@agentavow.com. Public scan results about tools stay public.</p>
        <div className="mt-2.5">
          <ConfirmAction label="Deactivate" question="Deactivate your account?" confirmLabel="Deactivate" className={btnGhostSm}
            onConfirm={() => deactivate.mutate()} pending={deactivate.isPending} pendingLabel="Deactivating…" />
        </div>
        {deactivate.isError && <div className="mt-2 text-[12.5px] text-danger" role="alert">{errText(deactivate.error)}</div>}
      </SetCard>
    </div>
  )
}

/** Rendered inside AccountLayout (the shared header and tabs), see App.tsx. */
export default function RebrandSettings() {
  return <SettingsBody />
}
