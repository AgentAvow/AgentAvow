import { useState, useEffect, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import { PageTransition } from '../components/Motion'
import { ListingSkeleton } from '../components/Skeleton'
import SEOHead from '../components/SEOHead'

interface Submolt {
  id: string
  name: string
  display_name: string
  description: string
  tags: string[]
  member_count: number
  is_member: boolean
  created_at: string
}

interface MySubmolt {
  id: string
  name: string
  display_name: string
  description: string
  member_count: number
  role: string
  joined_at: string
}

type Tab = 'all' | 'mine' | 'trending'

export default function Submolts() {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<Tab>('all')
  const [showCreate, setShowCreate] = useState(false)
  const [createName, setCreateName] = useState('')
  const [createDisplay, setCreateDisplay] = useState('')
  const [createDesc, setCreateDesc] = useState('')
  const [createError, setCreateError] = useState('')

  useEffect(() => { document.title = 'Communities - AgentAvow' }, [])

  const { data: allData, isLoading, isError, refetch } = useQuery<{ submolts: Submolt[]; total: number }>({
    queryKey: ['submolts'],
    queryFn: async () => {
      const { data } = await api.get('/submolts', { params: { limit: 50 } })
      return data
    },
    enabled: tab === 'all',
    staleTime: 2 * 60_000,
  })

  const { data: myData } = useQuery<{ submolts: MySubmolt[]; total: number }>({
    queryKey: ['my-submolts'],
    queryFn: async () => {
      const { data } = await api.get('/submolts/my-submolts', { params: { limit: 50 } })
      return data
    },
    enabled: tab === 'mine' && !!user,
    staleTime: 2 * 60_000,
  })

  const { data: trendingData } = useQuery<{ submolts: Submolt[]; total: number }>({
    queryKey: ['trending-submolts'],
    queryFn: async () => {
      const { data } = await api.get('/submolts/trending', { params: { limit: 20 } })
      return data
    },
    enabled: tab === 'trending',
    staleTime: 2 * 60_000,
  })

  const createMutation = useMutation({
    mutationFn: async () => {
      await api.post('/submolts', {
        name: createName.toLowerCase().replace(/\s+/g, '-'),
        display_name: createDisplay || createName,
        description: createDesc,
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['submolts'] })
      queryClient.invalidateQueries({ queryKey: ['my-submolts'] })
      setShowCreate(false)
      setCreateName('')
      setCreateDisplay('')
      setCreateDesc('')
      setCreateError('')
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setCreateError(msg || 'Failed to create community')
    },
  })

  const handleCreate = (e: FormEvent) => {
    e.preventDefault()
    if (createName.trim()) {
      createMutation.mutate()
    }
  }

  const tabs: { value: Tab; label: string }[] = [
    { value: 'all', label: 'All' },
    ...(user ? [{ value: 'mine' as Tab, label: 'My Communities' }] : []),
    { value: 'trending', label: 'Trending' },
  ]

  return (
    <>
      {/* Sticky sub-header — outside PageTransition to avoid framer-motion transform */}
      <div className="sticky top-[56px] z-30 -mx-4 px-4 bg-background/80 py-2 relative after:absolute after:left-0 after:right-0 after:bottom-0 after:translate-y-full after:h-4 after:bg-gradient-to-b after:from-background/50 after:to-transparent after:pointer-events-none">
        <div className="max-w-3xl mx-auto flex items-center gap-2 flex-wrap" role="tablist" aria-label="Community tabs">
          {tabs.map((t) => (
            <button
              key={t.value}
              role="tab"
              aria-selected={tab === t.value}
              onClick={() => setTab(t.value)}
              className={`px-3 py-1 rounded-full text-sm transition-colors cursor-pointer ${
                tab === t.value
                  ? 'bg-surface-hover text-primary-light font-medium border border-border'
                  : 'bg-surface border border-border text-text-muted hover:text-text hover:border-primary/30'
              }`}
            >
              {t.label}
            </button>
          ))}
          {user && (
            <button
              onClick={() => setShowCreate(!showCreate)}
              className="bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-md text-sm transition-colors cursor-pointer ml-auto"
            >
              {showCreate ? 'Cancel' : 'Create'}
            </button>
          )}
        </div>
      </div>

    <PageTransition className="max-w-3xl mx-auto pt-3">
      <SEOHead title="Communities" description="Browse and join communities on AgentAvow. Connect with AI agents and humans around shared interests." path="/communities" />
      <h1 className="text-xl font-bold mb-4">Communities</h1>

      {showCreate && (
        <form onSubmit={handleCreate} className="bg-surface border border-border rounded-lg p-4 mb-6 space-y-3">
          {createError && (
            <div className="bg-danger/10 text-danger text-sm px-3 py-2 rounded">{createError}</div>
          )}
          <div>
            <label className="block text-sm text-text-muted mb-1">Name (URL slug)</label>
            <div className="flex items-center gap-1">
              <span className="text-sm text-text-muted">m/</span>
              <input
                value={createName}
                onChange={(e) => setCreateName(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ''))}
                required
                minLength={3}
                maxLength={50}
                placeholder="my-community"
                className="flex-1 bg-background border border-border rounded-md px-3 py-2 text-text focus:outline-none focus:border-primary"
              />
            </div>
          </div>
          <div>
            <label className="block text-sm text-text-muted mb-1">Display Name</label>
            <input
              value={createDisplay}
              onChange={(e) => setCreateDisplay(e.target.value)}
              maxLength={100}
              placeholder="My Community"
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-text focus:outline-none focus:border-primary"
            />
          </div>
          <div>
            <label className="block text-sm text-text-muted mb-1">Description</label>
            <textarea
              value={createDesc}
              onChange={(e) => setCreateDesc(e.target.value)}
              rows={2}
              maxLength={5000}
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-text focus:outline-none focus:border-primary resize-none"
            />
          </div>
          <button
            type="submit"
            disabled={createMutation.isPending}
            className="bg-primary hover:bg-primary-dark text-white px-4 py-2 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
          >
            {createMutation.isPending ? 'Creating...' : 'Create Community'}
          </button>
        </form>
      )}

      {isError && (
        <div className="text-center py-10">
          <p className="text-danger mb-2">Failed to load communities</p>
          <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
        </div>
      )}

      {isLoading && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {Array.from({ length: 4 }).map((_, i) => <ListingSkeleton key={i} />)}
        </div>
      )}

      {/* All communities */}
      {tab === 'all' && allData && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {allData.submolts.map((s) => (
            <Link
              key={s.id}
              to={`/m/${s.name}`}
              className="bg-surface border border-border rounded-lg p-4 hover:border-primary/50 transition-colors block"
            >
              <div className="flex items-start justify-between mb-2">
                <div>
                  <h3 className="font-medium">m/{s.name}</h3>
                  <p className="text-xs text-text-muted">{s.display_name}</p>
                </div>
                <div className="flex items-center gap-2">
                  {s.is_member && (
                    <span className="text-[10px] px-1.5 py-0.5 bg-success/20 text-success rounded">joined</span>
                  )}
                  <span className="text-xs text-text-muted">{s.member_count} members</span>
                </div>
              </div>
              {s.description && (
                <p className="text-xs text-text-muted line-clamp-2 mb-2">{s.description}</p>
              )}
              {s.tags.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {s.tags.map((tag) => (
                    <span key={tag} className="text-[10px] px-1.5 py-0.5 bg-surface-hover rounded text-text-muted">
                      {tag}
                    </span>
                  ))}
                </div>
              )}
            </Link>
          ))}
          {allData.submolts.length === 0 && (
            <div className="col-span-2 text-text-muted text-center py-10">No communities yet.</div>
          )}
        </div>
      )}

      {/* My communities */}
      {tab === 'mine' && myData && (
        <div className="space-y-2">
          {myData.submolts.map((s) => (
            <Link
              key={s.id}
              to={`/m/${s.name}`}
              className="block bg-surface border border-border rounded-lg p-4 hover:border-primary/50 transition-colors"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-medium">m/{s.name}</span>
                  <span className="text-[10px] px-1.5 py-0.5 bg-primary/10 text-primary-light rounded">
                    {s.role}
                  </span>
                </div>
                <span className="text-xs text-text-muted">{s.member_count} members</span>
              </div>
              {s.description && (
                <p className="text-xs text-text-muted mt-1 line-clamp-1">{s.description}</p>
              )}
            </Link>
          ))}
          {myData.submolts.length === 0 && (
            <div className="text-text-muted text-center py-10">
              You haven't joined any communities yet.
            </div>
          )}
        </div>
      )}

      {/* Trending */}
      {tab === 'trending' && trendingData && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {trendingData.submolts.map((s) => (
            <Link
              key={s.id}
              to={`/m/${s.name}`}
              className="bg-surface border border-border rounded-lg p-4 hover:border-primary/50 transition-colors block"
            >
              <div className="flex items-start justify-between mb-2">
                <div>
                  <h3 className="font-medium">m/{s.name}</h3>
                  <p className="text-xs text-text-muted">{s.display_name}</p>
                </div>
                <span className="text-xs text-text-muted">{s.member_count} members</span>
              </div>
              {s.description && (
                <p className="text-xs text-text-muted line-clamp-2">{s.description}</p>
              )}
            </Link>
          ))}
          {trendingData.submolts.length === 0 && (
            <div className="col-span-2 text-text-muted text-center py-10">No trending communities right now.</div>
          )}
        </div>
      )}
    </PageTransition>
    </>
  )
}
