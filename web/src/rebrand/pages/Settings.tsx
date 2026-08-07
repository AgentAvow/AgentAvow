import { useEffect, useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { rp } from '../basePath'
import api from '../../lib/api'
import { useAuth } from '../../hooks/useAuth'
import { useTheme } from '../../hooks/useTheme'
import { Reveal } from '../components/motion'

/**
 * AgentAvow account settings — the relevant bits carried over from the legacy
 * settings: profile/avatar, email verification, password, email, appearance,
 * email notifications, data export, and account deletion. Social-era prefs
 * (followers/votes/marketplace/trust-weights) intentionally left out. Watches,
 * alerts and API keys live on /account.
 */

interface NotifPrefs { email_notifications_enabled: boolean }

const inputCls = 'w-full bg-surface border border-border rounded-xl px-3.5 py-2.5 text-[14px] outline-none focus:border-primary-light'
const btnCls = 'text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60'
const errText = (m: unknown) => (m as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Something went wrong.'

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6">
        <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-3">{title}</h2>
        {children}
      </div>
    </Reveal>
  )
}

export default function RebrandSettings() {
  const { user, isLoading, logout } = useAuth()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const { theme, toggleTheme } = useTheme()
  useEffect(() => { if (!isLoading && !user) navigate(rp('/rebrand/login')) }, [isLoading, user, navigate])

  const [curPass, setCurPass] = useState('')
  const [newPass, setNewPass] = useState('')
  const [newEmail, setNewEmail] = useState('')
  const [emailPass, setEmailPass] = useState('')
  const [confirmDelete, setConfirmDelete] = useState(false)

  const changePassword = useMutation({
    mutationFn: () => api.post('/account/change-password', { current_password: curPass, new_password: newPass }),
    onSuccess: () => { setCurPass(''); setNewPass('') },
  })
  const changeEmail = useMutation({
    mutationFn: () => api.post('/auth/change-email', { new_email: newEmail.trim(), current_password: emailPass }),
    onSuccess: () => { setNewEmail(''); setEmailPass('') },
  })
  const resendVerify = useMutation({ mutationFn: () => api.post('/auth/resend-verification') })

  const { data: prefs } = useQuery<NotifPrefs>({
    queryKey: ['rebrand-notif-prefs'],
    queryFn: async () => (await api.get('/notifications/preferences')).data,
    enabled: !!user,
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
    <div className="max-w-[640px] mx-auto px-6 py-14">
      <Reveal>
        <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Settings</span>
        <h1 className="mt-2 text-3xl font-extrabold tracking-tight">Account settings</h1>
      </Reveal>

      {/* profile / avatar */}
      <Card title="Profile">
        <div className="flex items-center gap-4">
          {user.avatar_url
            ? <img src={user.avatar_url} alt="" className="w-16 h-16 rounded-full object-cover ring-2 ring-primary/30 shrink-0" />
            : <span className="w-16 h-16 rounded-full grid place-items-center text-xl font-bold text-white bg-gradient-to-br from-primary to-accent shrink-0">{user.display_name?.charAt(0).toUpperCase() || '?'}</span>}
          <div className="min-w-0">
            <div className="text-[17px] font-bold">{user.display_name}</div>
            <div className="text-[13px] text-text-muted break-all">{user.email}</div>
            <a href="/avatar" className="text-[12.5px] text-primary-light hover:text-primary">Change avatar →</a>
          </div>
        </div>
        {!user.email_verified && (
          <div className="mt-4 flex items-center justify-between gap-3 rounded-xl bg-warning/10 border border-warning/30 px-4 py-2.5">
            <span className="text-[13px] text-warning">Your email isn't verified.</span>
            <button onClick={() => resendVerify.mutate()} disabled={resendVerify.isPending || resendVerify.isSuccess} className="text-[12.5px] font-semibold text-primary-light hover:text-primary disabled:opacity-60">{resendVerify.isSuccess ? 'Sent ✓' : resendVerify.isPending ? 'Sending…' : 'Resend'}</button>
          </div>
        )}
        <p className="mt-3 text-[12px] text-text-muted">Watches, alerts & API keys are on your <Link to={rp('/rebrand/account')} className="text-primary-light hover:text-primary">account page</Link>.</p>
      </Card>

      {/* change password */}
      <Card title="Change password">
        <form onSubmit={(e) => { e.preventDefault(); changePassword.mutate() }} className="flex flex-col gap-2.5">
          <input type="password" autoComplete="current-password" placeholder="Current password" value={curPass} onChange={(e) => setCurPass(e.target.value)} className={inputCls} />
          <input type="password" autoComplete="new-password" placeholder="New password" value={newPass} onChange={(e) => setNewPass(e.target.value)} className={inputCls} />
          <button type="submit" disabled={changePassword.isPending || !curPass || !newPass} className={`${btnCls} self-start`}>{changePassword.isPending ? 'Saving…' : 'Update password'}</button>
          {changePassword.isSuccess && <div className="text-[13px] text-success">Password updated ✓</div>}
          {changePassword.isError && <div className="text-[13px] text-danger">{errText(changePassword.error)}</div>}
        </form>
      </Card>

      {/* change email */}
      <Card title="Change email">
        <form onSubmit={(e) => { e.preventDefault(); changeEmail.mutate() }} className="flex flex-col gap-2.5">
          <input type="email" placeholder="New email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} className={inputCls} />
          <input type="password" autoComplete="current-password" placeholder="Current password" value={emailPass} onChange={(e) => setEmailPass(e.target.value)} className={inputCls} />
          <button type="submit" disabled={changeEmail.isPending || !newEmail || !emailPass} className={`${btnCls} self-start`}>{changeEmail.isPending ? 'Saving…' : 'Update email'}</button>
          {changeEmail.isSuccess && <div className="text-[13px] text-success">Email updated — check your inbox to verify.</div>}
          {changeEmail.isError && <div className="text-[13px] text-danger">{errText(changeEmail.error)}</div>}
        </form>
      </Card>

      {/* appearance */}
      <Card title="Appearance">
        <div className="flex items-center justify-between">
          <span className="text-[14px]">Theme</span>
          <button onClick={toggleTheme} className="text-[13px] font-semibold px-4 py-2 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">
            {theme === 'dark' ? '🌙 Dark' : '☀️ Light'} · switch
          </button>
        </div>
      </Card>

      {/* email notifications */}
      <Card title="Notifications">
        <div className="flex items-center justify-between gap-3">
          <div>
            <div className="text-[14px]">Email notifications</div>
            <div className="text-[12px] text-text-muted">Grade-change alerts, verification, and account emails.</div>
          </div>
          <button
            onClick={() => updatePref.mutate({ email_notifications_enabled: !emailOn })}
            disabled={updatePref.isPending}
            className={`relative w-11 h-6 rounded-full transition-colors shrink-0 ${emailOn ? 'bg-primary' : 'bg-surface-hover'}`}
            aria-pressed={emailOn}
          >
            <span className={`absolute top-0.5 w-5 h-5 rounded-full bg-white transition-all ${emailOn ? 'left-[22px]' : 'left-0.5'}`} />
          </button>
        </div>
        <p className="mt-3 text-[12px] text-text-muted">Per-tool alert delivery (email / webhook) is set on your <Link to={rp('/rebrand/account')} className="text-primary-light hover:text-primary">account page</Link>.</p>
      </Card>

      {/* data export */}
      <Card title="Your data">
        <div className="flex items-center justify-between gap-3">
          <span className="text-[13.5px] text-text-muted">Download everything we hold about your account as JSON.</span>
          <button onClick={() => exportData.mutate()} disabled={exportData.isPending} className="text-[13px] font-semibold px-4 py-2 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors shrink-0">{exportData.isPending ? 'Preparing…' : 'Export'}</button>
        </div>
      </Card>

      {/* danger zone */}
      <Reveal>
        <div className="mt-4 glass rounded-2xl p-6 border-l-4 border-danger/50">
          <h2 className="text-[13px] font-mono uppercase tracking-wide text-danger mb-2">Danger zone</h2>
          <p className="text-[13.5px] text-text-muted mb-3">Deactivating removes your account and signs you out. Public scan results about tools stay public.</p>
          {!confirmDelete ? (
            <button onClick={() => setConfirmDelete(true)} className="text-[13px] font-semibold px-4 py-2 rounded-xl border border-danger/50 text-danger hover:bg-danger/10 transition-colors">Deactivate account</button>
          ) : (
            <div className="flex items-center gap-2 flex-wrap">
              <button onClick={() => deactivate.mutate()} disabled={deactivate.isPending} className="text-[13px] font-semibold px-4 py-2 rounded-xl bg-danger text-white disabled:opacity-60">{deactivate.isPending ? 'Deactivating…' : 'Yes, deactivate my account'}</button>
              <button onClick={() => setConfirmDelete(false)} className="text-[13px] text-text-muted hover:text-text">Cancel</button>
            </div>
          )}
        </div>
      </Reveal>
    </div>
  )
}
