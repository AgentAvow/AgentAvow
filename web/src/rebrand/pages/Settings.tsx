import { useEffect, useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { rp } from '../basePath'
import api from '../../lib/api'
import { useAuth } from '../../hooks/useAuth'
import { Reveal } from '../components/motion'

/**
 * AgentAvow account settings — focused on what's relevant to the product
 * (profile, password, email). Watches / alerts / API keys live on /account.
 */
export default function RebrandSettings() {
  const { user, isLoading } = useAuth()
  const navigate = useNavigate()
  useEffect(() => { if (!isLoading && !user) navigate(rp('/rebrand/login')) }, [isLoading, user, navigate])

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
  if (!user) return null

  const input = 'w-full bg-surface border border-border rounded-xl px-3.5 py-2.5 text-[14px] outline-none focus:border-primary-light'
  const btn = 'text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60'
  const err = (m: unknown) => (m as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Something went wrong.'

  return (
    <div className="max-w-[640px] mx-auto px-6 py-14">
      <Reveal>
        <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Settings</span>
        <h1 className="mt-2 text-3xl font-extrabold tracking-tight">Account settings</h1>
      </Reveal>

      {/* profile */}
      <Reveal>
        <div className="mt-8 glass rounded-2xl p-6 flex items-center gap-4">
          {user.avatar_url
            ? <img src={user.avatar_url} alt="" className="w-16 h-16 rounded-full object-cover ring-2 ring-primary/30 shrink-0" />
            : <span className="w-16 h-16 rounded-full grid place-items-center text-xl font-bold text-white bg-gradient-to-br from-primary to-accent shrink-0">{user.display_name?.charAt(0).toUpperCase() || '?'}</span>}
          <div className="min-w-0">
            <div className="text-[17px] font-bold">{user.display_name}</div>
            <div className="text-[13px] text-text-muted break-all">{user.email}{user.email_verified ? '' : ' · unverified'}</div>
            <Link to={rp('/rebrand/account')} className="text-[12.5px] text-primary-light hover:text-primary">Your watches, alerts & API keys →</Link>
          </div>
        </div>
      </Reveal>

      {/* change password */}
      <Reveal>
        <form onSubmit={(e) => { e.preventDefault(); changePassword.mutate() }} className="mt-4 glass rounded-2xl p-6">
          <h2 className="text-[15px] font-bold mb-3">Change password</h2>
          <div className="flex flex-col gap-2.5">
            <input type="password" autoComplete="current-password" placeholder="Current password" value={curPass} onChange={(e) => setCurPass(e.target.value)} className={input} />
            <input type="password" autoComplete="new-password" placeholder="New password" value={newPass} onChange={(e) => setNewPass(e.target.value)} className={input} />
            <button type="submit" disabled={changePassword.isPending || !curPass || !newPass} className={`${btn} self-start`}>{changePassword.isPending ? 'Saving…' : 'Update password'}</button>
            {changePassword.isSuccess && <div className="text-[13px] text-success">Password updated ✓</div>}
            {changePassword.isError && <div className="text-[13px] text-danger">{err(changePassword.error)}</div>}
          </div>
        </form>
      </Reveal>

      {/* change email */}
      <Reveal>
        <form onSubmit={(e) => { e.preventDefault(); changeEmail.mutate() }} className="mt-4 glass rounded-2xl p-6">
          <h2 className="text-[15px] font-bold mb-3">Change email</h2>
          <div className="flex flex-col gap-2.5">
            <input type="email" placeholder="New email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} className={input} />
            <input type="password" autoComplete="current-password" placeholder="Current password" value={emailPass} onChange={(e) => setEmailPass(e.target.value)} className={input} />
            <button type="submit" disabled={changeEmail.isPending || !newEmail || !emailPass} className={`${btn} self-start`}>{changeEmail.isPending ? 'Saving…' : 'Update email'}</button>
            {changeEmail.isSuccess && <div className="text-[13px] text-success">Email updated — check your inbox to verify.</div>}
            {changeEmail.isError && <div className="text-[13px] text-danger">{err(changeEmail.error)}</div>}
          </div>
        </form>
      </Reveal>

      <Reveal>
        <p className="mt-6 text-[12.5px] text-text-muted">Your display name and avatar come from how you signed up (e.g. your Google profile). Manage watches, alerts, and API keys on your <Link to={rp('/rebrand/account')} className="text-primary-light hover:text-primary">account page</Link>.</p>
      </Reveal>
    </div>
  )
}
