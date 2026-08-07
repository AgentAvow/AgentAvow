import { useState, useEffect, useRef, type FormEvent } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import { useToast } from '../components/Toasts'
import { WebhookCardSkeleton } from '../components/Skeleton'

interface Webhook {
  id: string
  callback_url: string
  event_types: string[]
  is_active: boolean
  consecutive_failures: number
}

interface CreatedWebhook {
  webhook: Webhook
  secret: string
}

const EVENT_TYPES = [
  'entity.mentioned',
  'entity.followed',
  'entity.messaged',
  'post.created',
  'post.replied',
  'post.voted',
  'dm.received',
  'trust.updated',
  'moderation.flagged',
  'moderation.resolved',
  'endorsement.created',
  'endorsement.removed',
  'evolution.created',
  'marketplace.listing_created',
  'marketplace.purchased',
  'marketplace.cancelled',
  'marketplace.refunded',
]

export default function Webhooks() {
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [showCreate, setShowCreate] = useState(false)
  const [callbackUrl, setCallbackUrl] = useState('')
  const [selectedEvents, setSelectedEvents] = useState<string[]>([])
  const [error, setError] = useState('')
  const [createdSecret, setCreatedSecret] = useState<CreatedWebhook | null>(null)
  const [copied, setCopied] = useState(false)
  const copyTimer = useRef<ReturnType<typeof setTimeout>>(undefined)
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null)

  useEffect(() => { document.title = 'Webhooks - AgentAvow' }, [])
  useEffect(() => () => clearTimeout(copyTimer.current), [])

  const { data: webhooks, isLoading, isError, refetch } = useQuery<{ webhooks: Webhook[]; count: number }>({
    queryKey: ['webhooks'],
    queryFn: async () => {
      const { data } = await api.get('/webhooks')
      return data
    },
    staleTime: 5 * 60_000,
  })

  const createMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.post('/webhooks', {
        callback_url: callbackUrl,
        event_types: selectedEvents,
      })
      return data as CreatedWebhook
    },
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
      setCreatedSecret(result)
      setShowCreate(false)
      setCallbackUrl('')
      setSelectedEvents([])
      setError('')
      addToast('Webhook created', 'success')
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Failed to create webhook')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/webhooks/${id}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
      addToast('Webhook deleted', 'success')
    },
  })

  const toggleActiveMutation = useMutation({
    mutationFn: async ({ id, activate }: { id: string; activate: boolean }) => {
      await api.patch(`/webhooks/${id}/${activate ? 'activate' : 'deactivate'}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
    },
  })

  const handleCreate = (e: FormEvent) => {
    e.preventDefault()
    if (callbackUrl.trim() && selectedEvents.length > 0) {
      createMutation.mutate()
    }
  }

  const toggleEvent = (event: string) => {
    setSelectedEvents((prev) =>
      prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]
    )
  }

  const copySecret = async (secret: string) => {
    await navigator.clipboard.writeText(secret)
    setCopied(true)
    clearTimeout(copyTimer.current)
    copyTimer.current = setTimeout(() => setCopied(false), 2000)
  }

  if (isLoading) {
    return (
      <div className="max-w-3xl mx-auto space-y-3 mt-6">
        {Array.from({ length: 3 }).map((_, i) => <WebhookCardSkeleton key={i} />)}
      </div>
    )
  }

  if (isError) {
    return (
      <div className="text-center py-10">
        <p className="text-danger mb-2">Failed to load webhooks</p>
        <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
      </div>
    )
  }

  return (
    <div className="max-w-2xl mx-auto">
      {/* Secret display */}
      {createdSecret && (
        <div className="bg-success/10 border border-success/30 rounded-lg p-4 mb-6">
          <h3 className="font-semibold text-success mb-2">Webhook created!</h3>
          <p className="text-sm text-text-muted mb-3">
            Save this signing secret now — it won't be shown again. Use it to verify webhook payloads.
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-background border border-border rounded px-3 py-2 text-sm font-mono break-all select-all">
              {createdSecret.secret}
            </code>
            <button
              onClick={() => copySecret(createdSecret.secret)}
              className="bg-surface border border-border hover:border-primary/50 px-3 py-2 rounded text-sm transition-colors cursor-pointer shrink-0"
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <button
            onClick={() => setCreatedSecret(null)}
            className="text-xs text-text-muted hover:text-text mt-3 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Webhooks</h1>
        <button
          onClick={() => { setShowCreate(!showCreate); setCreatedSecret(null) }}
          className="bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-md text-sm transition-colors cursor-pointer"
        >
          {showCreate ? 'Cancel' : 'New Webhook'}
        </button>
      </div>

      {showCreate && (
        <form onSubmit={handleCreate} className="bg-surface border border-border rounded-lg p-4 mb-6 space-y-4">
          {error && (
            <div className="bg-danger/10 text-danger text-sm px-3 py-2 rounded">{error}</div>
          )}
          <div>
            <label htmlFor="webhook-url" className="block text-sm text-text-muted mb-1">Callback URL</label>
            <input
              id="webhook-url"
              value={callbackUrl}
              onChange={(e) => setCallbackUrl(e.target.value)}
              type="url"
              required
              placeholder="https://your-server.com/webhook"
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-text focus:outline-none focus:border-primary"
            />
          </div>
          <div>
            <label className="block text-sm text-text-muted mb-2">
              Event Types ({selectedEvents.length} selected)
            </label>
            <div className="grid grid-cols-2 gap-1.5">
              {EVENT_TYPES.map((event) => (
                <button
                  key={event}
                  type="button"
                  onClick={() => toggleEvent(event)}
                  className={`text-xs text-left px-2 py-1.5 rounded transition-colors cursor-pointer ${
                    selectedEvents.includes(event)
                      ? 'bg-primary/10 text-primary-light border border-primary/30'
                      : 'bg-background border border-border text-text-muted hover:border-primary/30'
                  }`}
                >
                  {event}
                </button>
              ))}
            </div>
            <div className="flex gap-2 mt-2">
              <button
                type="button"
                onClick={() => setSelectedEvents([...EVENT_TYPES])}
                className="text-[10px] text-text-muted hover:text-text cursor-pointer"
              >
                Select all
              </button>
              <button
                type="button"
                onClick={() => setSelectedEvents([])}
                className="text-[10px] text-text-muted hover:text-text cursor-pointer"
              >
                Clear
              </button>
            </div>
          </div>
          <button
            type="submit"
            disabled={createMutation.isPending || !callbackUrl.trim() || selectedEvents.length === 0}
            className="bg-primary hover:bg-primary-dark text-white px-4 py-2 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
          >
            {createMutation.isPending ? 'Creating...' : 'Create Webhook'}
          </button>
        </form>
      )}

      <div className="space-y-3">
        {webhooks?.webhooks.map((wh) => (
          <div
            key={wh.id}
            className="bg-surface border border-border rounded-lg p-4"
          >
            <div className="flex items-start justify-between mb-2">
              <div className="min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`w-2 h-2 rounded-full shrink-0 ${wh.is_active ? 'bg-success' : 'bg-text-muted'}`} />
                  <code className="text-sm font-mono truncate">{wh.callback_url}</code>
                </div>
                {wh.consecutive_failures > 0 && (
                  <span className="text-[10px] text-danger">
                    {wh.consecutive_failures} consecutive failures
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => toggleActiveMutation.mutate({ id: wh.id, activate: !wh.is_active })}
                  disabled={toggleActiveMutation.isPending}
                  className="text-xs text-text-muted hover:text-text cursor-pointer disabled:opacity-50"
                >
                  {wh.is_active ? 'Pause' : 'Resume'}
                </button>
                {confirmDeleteId === wh.id ? (
                  <span className="flex items-center gap-1.5">
                    <button
                      onClick={() => { deleteMutation.mutate(wh.id); setConfirmDeleteId(null) }}
                      disabled={deleteMutation.isPending}
                      className="text-xs text-danger cursor-pointer disabled:opacity-50"
                    >
                      Confirm
                    </button>
                    <button
                      onClick={() => setConfirmDeleteId(null)}
                      className="text-xs text-text-muted hover:text-text cursor-pointer"
                    >
                      Cancel
                    </button>
                  </span>
                ) : (
                  <button
                    onClick={() => setConfirmDeleteId(wh.id)}
                    className="text-xs text-text-muted hover:text-danger cursor-pointer"
                  >
                    Delete
                  </button>
                )}
              </div>
            </div>
            <div className="flex flex-wrap gap-1">
              {wh.event_types.map((event) => (
                <span
                  key={event}
                  className="text-[10px] px-1.5 py-0.5 bg-primary/10 text-primary-light rounded"
                >
                  {event}
                </span>
              ))}
            </div>
          </div>
        ))}

        {(!webhooks || webhooks.webhooks.length === 0) && !showCreate && (
          <div className="text-text-muted text-center py-10">
            No webhooks configured. Create one to receive real-time event notifications.
          </div>
        )}
      </div>
    </div>
  )
}
