import { useEffect, useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { rp } from '../basePath'
import api from '../../lib/api'
import { useAuth } from '../../hooks/useAuth'
import { Reveal } from '../components/motion'

/**
 * AgentAvow avatar picker — reskinned from the legacy /avatar page, focused on
 * the signed-in user's own avatar (bot/agent avatar management was social-era
 * and is dropped). Generated avatars come from DiceBear; the "Letter" option
 * clears avatar_url so the header falls back to the initial.
 *
 * On save we do a full navigation back to Settings so useAuth re-fetches /auth/me
 * and the new avatar shows everywhere (the auth context has no soft refresh).
 */

const DICEBEAR = 'https://api.dicebear.com/9.x'
const LETTER_OPTION = '__letter__'

const STYLES: { style: string; label: string; seeds: string[] }[] = [
  {
    style: 'adventurer',
    label: 'Characters',
    seeds: ['Felix', 'Aneka', 'Milo', 'Luna', 'Jasper', 'Nora', 'Zoe', 'Kai', 'Aria', 'Leo', 'Maya', 'Oscar'],
  },
  {
    style: 'fun-emoji',
    label: 'Emoji',
    seeds: ['happy', 'cool', 'love', 'star', 'fire', 'rainbow', 'peace', 'rocket', 'sparkle', 'sun', 'moon', 'wave'],
  },
  {
    style: 'lorelei',
    label: 'Illustrated',
    seeds: ['Sophie', 'James', 'Emma', 'Liam', 'Olivia', 'Noah', 'Ava', 'Ethan', 'Mia', 'Alex', 'Chloe', 'Ryan'],
  },
]

const avatarUrl = (style: string, seed: string) =>
  `${DICEBEAR}/${style}/svg?seed=${encodeURIComponent(seed)}&radius=20`

export default function RebrandAvatar() {
  const { user, isLoading } = useAuth()
  const navigate = useNavigate()

  // `undefined` = not yet touched; fall back to the user's saved avatar during render.
  const [picked, setPicked] = useState<string | null | undefined>(undefined)
  const [activeStyle, setActiveStyle] = useState(STYLES[0].style)

  useEffect(() => { if (!isLoading && !user) navigate(rp('/rebrand/login')) }, [isLoading, user, navigate])

  const saved = user?.avatar_url ?? LETTER_OPTION
  const selected = picked === undefined ? saved : picked

  const save = useMutation({
    mutationFn: async () => {
      const avatar_url = selected === LETTER_OPTION ? null : selected
      await api.patch(`/profiles/${user!.id}`, { avatar_url })
    },
    onSuccess: () => {
      // Full navigation so the auth context re-fetches and the new avatar
      // shows in the header + settings immediately.
      window.location.assign(rp('/rebrand/settings'))
    },
  })

  if (isLoading || !user) return null

  const initial = user.display_name?.charAt(0).toUpperCase() || '?'
  const previewUrl = selected === LETTER_OPTION ? null : selected
  const dirty = selected !== saved
  const style = STYLES.find((s) => s.style === activeStyle)!

  return (
    <div className="max-w-[720px] mx-auto px-6 py-14">
      <Reveal>
        <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Profile</span>
        <h1 className="mt-2 text-3xl font-extrabold tracking-tight">Choose your avatar</h1>
        <p className="mt-2 text-text-muted text-[14px]">Pick a generated avatar, or use your initial.</p>
      </Reveal>

      {/* live preview */}
      <Reveal>
        <div className="mt-6 glass rounded-2xl p-6 flex items-center gap-5">
          {previewUrl
            ? <img src={previewUrl} alt="" className="w-20 h-20 rounded-full object-cover ring-2 ring-primary/30 shrink-0" />
            : <span className="w-20 h-20 rounded-full grid place-items-center text-2xl font-bold text-white bg-gradient-to-br from-primary to-accent shrink-0">{initial}</span>}
          <div className="min-w-0">
            <div className="text-[17px] font-bold">{user.display_name}</div>
            <div className="text-[13px] text-text-muted">{previewUrl ? 'Generated avatar' : 'Letter avatar'}</div>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={() => save.mutate()}
              disabled={!dirty || save.isPending || save.isSuccess}
              className="text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-50"
            >
              {save.isPending || save.isSuccess ? 'Saving…' : 'Save avatar'}
            </button>
            <Link to={rp('/rebrand/settings')} className="text-[13px] text-text-muted hover:text-text px-2">Cancel</Link>
          </div>
        </div>
        {save.isError && <div className="mt-2 text-[13px] text-danger">Couldn't save your avatar. Please try again.</div>}
      </Reveal>

      {/* letter option */}
      <Reveal>
        <div className="mt-6">
          <h2 className="text-[13px] font-mono uppercase tracking-wide text-text-muted mb-3">Or use your initial</h2>
          <button
            onClick={() => setPicked(LETTER_OPTION)}
            className={`flex items-center gap-3 rounded-xl px-4 py-3 border transition-colors ${selected === LETTER_OPTION ? 'border-primary bg-primary/10' : 'border-border hover:border-primary-light'}`}
          >
            <span className="w-11 h-11 rounded-full grid place-items-center text-lg font-bold text-white bg-gradient-to-br from-primary to-accent">{initial}</span>
            <span className="text-[14px] font-semibold">Letter avatar</span>
          </button>
        </div>
      </Reveal>

      {/* style tabs */}
      <Reveal>
        <div className="mt-8 flex flex-wrap gap-2">
          {STYLES.map((s) => (
            <button
              key={s.style}
              onClick={() => setActiveStyle(s.style)}
              className={`text-[13px] font-semibold px-4 py-2 rounded-xl border transition-colors ${activeStyle === s.style ? 'border-primary-light text-primary-light bg-primary/10' : 'border-border text-text-muted hover:text-text hover:border-primary-light'}`}
            >
              {s.label}
            </button>
          ))}
        </div>
      </Reveal>

      {/* avatar grid */}
      <Reveal>
        <div className="mt-4 grid grid-cols-4 sm:grid-cols-6 gap-3">
          {style.seeds.map((seed) => {
            const url = avatarUrl(style.style, seed)
            const isSel = selected === url
            return (
              <button
                key={seed}
                onClick={() => setPicked(url)}
                className={`aspect-square rounded-2xl p-1.5 border transition-all ${isSel ? 'border-primary bg-primary/10 scale-105' : 'border-border hover:border-primary-light'}`}
                aria-label={`Avatar ${seed}`}
              >
                <img src={url} alt="" className="w-full h-full rounded-xl" loading="lazy" />
              </button>
            )
          })}
        </div>
      </Reveal>
    </div>
  )
}
