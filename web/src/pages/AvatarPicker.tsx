import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import EntityAvatar from '../components/EntityAvatar'
import { useToast } from '../components/Toasts'
import SEOHead from '../components/SEOHead'

const DICEBEAR = 'https://api.dicebear.com/9.x'

// Human avatar styles with diverse seeds
const HUMAN_STYLES: { style: string; label: string; seeds: string[] }[] = [
  {
    style: 'adventurer',
    label: 'Characters',
    seeds: [
      'Felix', 'Aneka', 'Milo', 'Luna', 'Jasper', 'Nora',
      'Zoe', 'Kai', 'Aria', 'Leo', 'Maya', 'Oscar',
    ],
  },
  {
    style: 'fun-emoji',
    label: 'Emoji',
    seeds: [
      'happy', 'cool', 'love', 'star', 'fire', 'rainbow',
      'peace', 'rocket', 'sparkle', 'sun', 'moon', 'wave',
    ],
  },
  {
    style: 'lorelei',
    label: 'Illustrated',
    seeds: [
      'Sophie', 'James', 'Emma', 'Liam', 'Olivia', 'Noah',
      'Ava', 'Ethan', 'Mia', 'Alex', 'Chloe', 'Ryan',
    ],
  },
]

// Platform bot SVGs — available for bot avatars only
const PLATFORM_BOT_AVATARS = [
  '/avatars/agentgraph.svg',
  '/avatars/bughunter.svg',
  '/avatars/featurebot.svg',
  '/avatars/marketingbot.svg',
  '/avatars/securitywatch.svg',
  '/avatars/trustguide.svg',
  '/avatars/welcomebot.svg',
]

// Agent/bot avatar styles (DiceBear)
const AGENT_STYLES: { style: string; label: string; seeds: string[] }[] = [
  {
    style: 'bottts',
    label: 'Robots',
    seeds: [
      'CodeReviewBot', 'DataAnalyzerPro', 'SecurityScannerX', 'ContentModerator',
      'ResearchAssistant', 'TranslatorAgent', 'TestRunnerBot', 'DevOpsHelper',
      'MarketAnalyzer', 'CreativeWriter', 'APIIntegrator', 'TrustAuditor',
      'BugHunter', 'FeatureBot', 'SecurityWatch', 'TrustGuide',
      'WelcomeBot', 'AgentGraph',
    ],
  },
  {
    style: 'bottts-neutral',
    label: 'Minimal Bots',
    seeds: [
      'Circuit', 'Spark', 'Pulse', 'Nexus', 'Forge', 'Drift',
      'Echo', 'Core', 'Flux', 'Node', 'Byte', 'Grid',
    ],
  },
  {
    style: 'pixel-art',
    label: 'Pixel Art',
    seeds: [
      'bot1', 'bot2', 'bot3', 'bot4', 'bot5', 'bot6',
      'agent1', 'agent2', 'agent3', 'agent4', 'agent5', 'agent6',
    ],
  },
]

function avatarUrl(style: string, seed: string): string {
  return `${DICEBEAR}/${style}/svg?seed=${encodeURIComponent(seed)}&radius=20`
}

// Letter avatars — clear the avatar_url so EntityAvatar renders the initial
const LETTER_OPTION = '__letter__'

interface ManagedEntity {
  id: string
  display_name: string
  type: 'human' | 'agent'
  avatar_url: string | null
}

export default function AvatarPickerPage() {
  const { user, isLoading: authLoading } = useAuth()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { addToast } = useToast()

  const [selectedEntity, setSelectedEntity] = useState<ManagedEntity | null>(null)
  const [selected, setSelected] = useState<string | null>(null)

  useEffect(() => { document.title = 'Choose Avatar - AgentAvow' }, [])

  useEffect(() => {
    if (!authLoading && !user) {
      navigate('/login', { replace: true })
    }
  }, [authLoading, user, navigate])

  // Build entity list: self + operated bots
  const entities: ManagedEntity[] = []
  if (user) {
    entities.push({
      id: user.id,
      display_name: user.display_name,
      type: user.type as 'human' | 'agent',
      avatar_url: user.avatar_url,
    })
  }

  // Fetch bots owned by this user
  const [bots, setBots] = useState<ManagedEntity[]>([])
  useEffect(() => {
    if (!user) return
    api.get('/agents').then(({ data }) => {
      const agentList = (data.agents || []).map((a: { id: string; display_name: string; avatar_url: string | null }) => ({
        id: a.id,
        display_name: a.display_name,
        type: 'agent' as const,
        avatar_url: a.avatar_url,
      }))
      setBots(agentList)
    }).catch(() => { /* ignore */ })
  }, [user])

  const allEntities = [...entities, ...bots]

  // Default to self
  useEffect(() => {
    if (!selectedEntity && allEntities.length > 0) {
      setSelectedEntity(allEntities[0])
      setSelected(allEntities[0].avatar_url)
    }
  }, [allEntities.length]) // eslint-disable-line react-hooks/exhaustive-deps

  const mutation = useMutation({
    mutationFn: async ({ entityId, avatarUrl }: { entityId: string; avatarUrl: string | null }) => {
      await api.patch(`/profiles/${entityId}`, { avatar_url: avatarUrl })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['profile'] })
      queryClient.invalidateQueries({ queryKey: ['auth-user'] })
      queryClient.invalidateQueries({ queryKey: ['agents'] })
      addToast('Avatar updated', 'success')
      // Update local state
      if (selectedEntity) {
        const newUrl = selected === LETTER_OPTION ? null : selected
        setSelectedEntity({ ...selectedEntity, avatar_url: newUrl })
        setBots(prev => prev.map(b => b.id === selectedEntity.id ? { ...b, avatar_url: newUrl } : b))
      }
    },
    onError: () => {
      addToast('Failed to save avatar', 'error')
    },
  })

  const handleSelect = (url: string) => {
    setSelected(url)
    if (selectedEntity) {
      const avatarUrlValue = url === LETTER_OPTION ? null : url
      mutation.mutate({ entityId: selectedEntity.id, avatarUrl: avatarUrlValue })
    }
  }

  const handleEntitySwitch = (entity: ManagedEntity) => {
    setSelectedEntity(entity)
    setSelected(entity.avatar_url)
  }

  if (authLoading || !user) return null

  const isAgent = selectedEntity?.type === 'agent'
  const styles = isAgent ? AGENT_STYLES : HUMAN_STYLES
  const currentAvatarUrl = selected === LETTER_OPTION ? null : selected

  return (
    <div className="max-w-2xl mx-auto">
      <SEOHead title="Choose Avatar" description="Pick an avatar for your AgentAvow profile." path="/avatar" />

      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Choose Avatar</h1>
        <button
          onClick={() => navigate(-1)}
          className="text-xs text-text-muted hover:text-primary-light transition-colors"
        >
          Back
        </button>
      </div>

      {/* Entity selector — only show if user has bots */}
      {allEntities.length > 1 && (
        <section className="bg-surface border border-border rounded-lg p-4 mb-6">
          <p className="text-xs text-text-muted mb-3">Select who to change avatar for:</p>
          <div className="flex flex-wrap gap-2">
            {allEntities.map((entity) => (
              <button
                key={entity.id}
                onClick={() => handleEntitySwitch(entity)}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border transition-colors cursor-pointer ${
                  selectedEntity?.id === entity.id
                    ? 'border-primary bg-primary/10'
                    : 'border-border hover:border-primary/30'
                }`}
              >
                <EntityAvatar
                  name={entity.display_name}
                  url={entity.avatar_url}
                  entityType={entity.type}
                  size="sm"
                />
                <span className="text-sm">{entity.display_name}</span>
                <span className={`px-1 py-0.5 rounded text-[9px] uppercase tracking-wider ${
                  entity.type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
                }`}>
                  {entity.type}
                </span>
              </button>
            ))}
          </div>
        </section>
      )}

      {/* Current avatar preview */}
      <div className="flex items-center gap-4 mb-6">
        <EntityAvatar
          name={selectedEntity?.display_name || ''}
          url={currentAvatarUrl}
          entityType={selectedEntity?.type || 'human'}
          size="lg"
        />
        <div>
          <p className="text-sm font-medium">{selectedEntity?.display_name}</p>
          <p className="text-xs text-text-muted">
            {currentAvatarUrl ? 'Custom avatar selected' : 'Using letter avatar'}
          </p>
        </div>
        {mutation.isPending && (
          <span className="text-xs text-text-muted ml-auto">Saving...</span>
        )}
      </div>

      {/* Letter avatar option */}
      <section className="bg-surface border border-border rounded-lg p-4 mb-4">
        <button
          onClick={() => handleSelect(LETTER_OPTION)}
          className={`flex items-center gap-3 px-4 py-3 rounded-lg border transition-colors cursor-pointer w-full text-left ${
            selected === LETTER_OPTION || (!selected && !selectedEntity?.avatar_url)
              ? 'border-primary bg-primary/10'
              : 'border-border hover:border-primary/30'
          }`}
        >
          <EntityAvatar
            name={selectedEntity?.display_name || ''}
            url={null}
            entityType={selectedEntity?.type || 'human'}
            size="md"
          />
          <div>
            <p className="text-sm font-medium">Letter Avatar</p>
            <p className="text-xs text-text-muted">Display your first letter as the avatar</p>
          </div>
        </button>
      </section>

      {/* Platform bot SVGs — admin-operated agents only */}
      {isAgent && user?.is_admin && (
        <section className="bg-surface border border-border rounded-lg p-4 mb-4">
          <h2 className="text-sm font-medium mb-3">Platform Bots</h2>
          <div className="grid grid-cols-4 sm:grid-cols-6 gap-3">
            {PLATFORM_BOT_AVATARS.map((url) => (
              <button
                key={url}
                onClick={() => handleSelect(url)}
                className={`relative w-full aspect-square rounded-xl overflow-hidden border-2 transition-all cursor-pointer hover:scale-105 ${
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
        </section>
      )}

      {/* DiceBear avatar style sections */}
      {styles.map(({ style, label, seeds }) => (
        <section key={style} className="bg-surface border border-border rounded-lg p-4 mb-4">
          <h2 className="text-sm font-medium mb-3">{label}</h2>
          <div className="grid grid-cols-4 sm:grid-cols-6 gap-3">
            {seeds.map((seed) => {
              const url = avatarUrl(style, seed)
              return (
                <button
                  key={seed}
                  onClick={() => handleSelect(url)}
                  className={`relative w-full aspect-square rounded-xl overflow-hidden border-2 transition-all cursor-pointer hover:scale-105 ${
                    selected === url
                      ? 'border-primary ring-2 ring-primary/30'
                      : 'border-border hover:border-primary/50'
                  }`}
                >
                  <img
                    src={url}
                    alt={seed}
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
              )
            })}
          </div>
        </section>
      ))}
    </div>
  )
}
