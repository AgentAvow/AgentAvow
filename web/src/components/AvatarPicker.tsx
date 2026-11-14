import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'

const HUMAN_AVATARS = Array.from({ length: 36 }, (_, i) => `/avatars/library/human/h${String(i).padStart(2, '0')}.svg`)
const AGENT_AVATARS = Array.from({ length: 36 }, (_, i) => `/avatars/library/agent/a${String(i).padStart(2, '0')}.svg`)

interface AvatarPickerProps {
  entityId: string
  entityType: 'human' | 'agent'
  currentUrl?: string | null
  onSelect?: (url: string) => void
}

export default function AvatarPicker({ entityId, entityType, currentUrl, onSelect }: AvatarPickerProps) {
  const queryClient = useQueryClient()
  const avatars = entityType === 'agent' ? AGENT_AVATARS : HUMAN_AVATARS
  const [selected, setSelected] = useState<string | null>(currentUrl || null)

  const mutation = useMutation({
    mutationFn: async (avatarUrl: string) => {
      await api.patch(`/profiles/${entityId}`, { avatar_url: avatarUrl })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['profile'] })
      queryClient.invalidateQueries({ queryKey: ['auth-user'] })
    },
  })

  const handleSelect = (url: string) => {
    setSelected(url)
    mutation.mutate(url)
    onSelect?.(url)
  }

  return (
    <div>
      <p className="text-xs text-text-muted mb-3">Choose an avatar</p>
      <div className="grid grid-cols-6 sm:grid-cols-9 gap-2 max-h-64 overflow-y-auto pr-1">
        {avatars.map((url) => (
          <button
            key={url}
            onClick={() => handleSelect(url)}
            className={`relative w-full aspect-square rounded-lg overflow-hidden border-2 transition-all cursor-pointer hover:scale-105 ${
              selected === url
                ? 'border-primary ring-2 ring-primary/30'
                : 'border-border hover:border-primary/50'
            }`}
          >
            <img
              src={url}
              alt=""
              className="w-full h-full object-cover"
              loading="lazy"
            />
            {selected === url && (
              <div className="absolute inset-0 bg-primary/20 flex items-center justify-center">
                <svg className="w-5 h-5 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                </svg>
              </div>
            )}
          </button>
        ))}
      </div>
      {mutation.isPending && (
        <p className="text-xs text-text-muted mt-2">Saving...</p>
      )}
      {mutation.isError && (
        <p className="text-xs text-danger mt-2">Failed to save avatar</p>
      )}
    </div>
  )
}

// eslint-disable-next-line react-refresh/only-export-components -- avatar lists are shared with the picker page; HMR falls back to a full reload here
export { HUMAN_AVATARS, AGENT_AVATARS }
