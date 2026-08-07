import { useState, useEffect, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import { useToast } from '../components/Toasts'
import { PageTransition } from '../components/Motion'
import { formatDate, timeAgo, formatPrice } from '../lib/formatters'
import { DisputeCardSkeleton } from '../components/Skeleton'

interface Dispute {
  id: string
  transaction_id: string
  opened_by: string
  reason: string
  status: string
  resolution: string | null
  resolution_amount_cents: number | null
  resolved_by: string | null
  admin_note: string | null
  deadline: string
  created_at: string
  resolved_at: string | null
}

interface DisputeListResponse {
  disputes: Dispute[]
  total: number
}

const PAGE_SIZE = 20

const STATUS_STYLES: Record<string, string> = {
  open: 'bg-warning/20 text-warning',
  negotiating: 'bg-accent/20 text-accent',
  escalated: 'bg-danger/20 text-danger',
  resolved: 'bg-success/20 text-success',
  closed: 'bg-surface-hover text-text-muted',
}

const STATUS_LABELS: Record<string, string> = {
  open: 'Open',
  negotiating: 'Negotiating',
  escalated: 'Escalated',
  resolved: 'Resolved',
  closed: 'Closed',
}

const RESOLUTION_LABELS: Record<string, string> = {
  release_funds: 'Funds Released',
  cancel_auth: 'Refunded',
  partial_refund: 'Partial Refund',
}

export default function Disputes() {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [searchParams, setSearchParams] = useSearchParams()
  const statusFilter = searchParams.get('status') || 'all'
  const [selectedDispute, setSelectedDispute] = useState<Dispute | null>(null)
  const [escalateId, setEscalateId] = useState<string | null>(null)
  const [messageText, setMessageText] = useState('')
  const [showNewForm, setShowNewForm] = useState(false)
  const [newTransactionId, setNewTransactionId] = useState('')
  const [newReason, setNewReason] = useState('')

  useEffect(() => { document.title = 'Disputes - AgentAvow' }, [])

  const {
    data,
    isLoading,
    isError,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery<DisputeListResponse>({
    queryKey: ['disputes', statusFilter],
    queryFn: async ({ pageParam }) => {
      const params: Record<string, unknown> = {
        limit: PAGE_SIZE,
        offset: pageParam,
      }
      if (statusFilter !== 'all') params.status = statusFilter
      const { data } = await api.get('/disputes', { params })
      return data
    },
    initialPageParam: 0,
    getNextPageParam: (_lastPage, allPages) => {
      const loaded = allPages.reduce((acc, page) => acc + page.disputes.length, 0)
      const total = allPages[0]?.total || 0
      if (loaded >= total) return undefined
      return loaded
    },
    staleTime: 60_000,
  })

  const openDisputeMutation = useMutation({
    mutationFn: async ({ transactionId, reason }: { transactionId: string; reason: string }) => {
      const { data } = await api.post('/disputes', {
        transaction_id: transactionId,
        reason,
      })
      return data
    },
    onSuccess: () => {
      addToast('Dispute opened successfully', 'success')
      queryClient.invalidateQueries({ queryKey: ['disputes'] })
      setShowNewForm(false)
      setNewTransactionId('')
      setNewReason('')
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      addToast(msg || 'Failed to open dispute', 'error')
    },
  })

  const escalateMutation = useMutation({
    mutationFn: async (disputeId: string) => {
      await api.post(`/disputes/${disputeId}/escalate`)
    },
    onSuccess: () => {
      addToast('Dispute escalated to admin review', 'success')
      queryClient.invalidateQueries({ queryKey: ['disputes'] })
      setEscalateId(null)
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      addToast(msg || 'Failed to escalate', 'error')
    },
  })

  const messageMutation = useMutation({
    mutationFn: async ({ disputeId, message }: { disputeId: string; message: string }) => {
      const { data } = await api.post(`/disputes/${disputeId}/message`, { message })
      return data
    },
    onSuccess: () => {
      addToast('Message sent', 'success')
      setMessageText('')
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      addToast(msg || 'Failed to send message', 'error')
    },
  })

  const allDisputes = data?.pages.flatMap(p => p.disputes) ?? []
  const total = data?.pages[0]?.total ?? 0

  const filterButtons = ['all', 'open', 'negotiating', 'escalated', 'resolved', 'closed']

  const handleNewDisputeSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (newTransactionId.trim() && newReason.trim().length >= 10) {
      openDisputeMutation.mutate({
        transactionId: newTransactionId.trim(),
        reason: newReason.trim(),
      })
    }
  }

  return (
    <PageTransition className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Disputes</h1>
          <p className="text-sm text-text-muted mt-1">
            Manage disputes on your marketplace transactions
          </p>
        </div>
        <div className="flex items-center gap-3">
          {total > 0 && (
            <span className="text-sm text-text-muted">{total} total</span>
          )}
          <button
            onClick={() => setShowNewForm(!showNewForm)}
            className="bg-primary hover:bg-primary-dark text-white px-3 py-1.5 rounded-md text-sm transition-colors cursor-pointer"
          >
            {showNewForm ? 'Cancel' : 'File Dispute'}
          </button>
        </div>
      </div>

      {/* File New Dispute Form */}
      {showNewForm && (
        <form
          onSubmit={handleNewDisputeSubmit}
          className="bg-surface border border-border rounded-lg p-4 space-y-3"
          aria-label="File a new dispute"
        >
          <h3 className="text-sm font-semibold">Open a New Dispute</h3>
          <div>
            <label htmlFor="dispute-tx-id" className="block text-xs text-text-muted mb-1">
              Transaction ID
            </label>
            <input
              id="dispute-tx-id"
              type="text"
              value={newTransactionId}
              onChange={e => setNewTransactionId(e.target.value)}
              placeholder="Enter the transaction ID"
              required
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm text-text focus:outline-none focus:border-primary"
            />
            <p className="text-[10px] text-text-muted mt-1">
              Find this on your <Link to="/transactions" className="text-primary-light hover:underline">transaction history</Link> page.
            </p>
          </div>
          <div>
            <label htmlFor="dispute-reason" className="block text-xs text-text-muted mb-1">
              Reason for Dispute
            </label>
            <textarea
              id="dispute-reason"
              value={newReason}
              onChange={e => setNewReason(e.target.value)}
              placeholder="Describe the issue in detail (minimum 10 characters)..."
              required
              minLength={10}
              maxLength={2000}
              rows={3}
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm text-text focus:outline-none focus:border-primary resize-none"
            />
            <span className="text-[10px] text-text-muted">{newReason.length}/2000</span>
          </div>
          <div className="flex gap-2">
            <button
              type="submit"
              disabled={!newTransactionId.trim() || newReason.trim().length < 10 || openDisputeMutation.isPending}
              className="bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
            >
              {openDisputeMutation.isPending ? 'Opening...' : 'Open Dispute'}
            </button>
            <button
              type="button"
              onClick={() => { setShowNewForm(false); setNewTransactionId(''); setNewReason('') }}
              className="text-sm text-text-muted hover:text-text cursor-pointer"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* Status filter tabs */}
      <div className="flex gap-2 flex-wrap" role="tablist" aria-label="Dispute status filters">
        {filterButtons.map(s => (
          <button
            key={s}
            role="tab"
            aria-selected={statusFilter === s}
            onClick={() => {
              const params = new URLSearchParams(searchParams)
              if (s === 'all') params.delete('status')
              else params.set('status', s)
              setSearchParams(params)
            }}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
              statusFilter === s
                ? 'bg-primary/10 text-primary-light border border-primary/30'
                : 'bg-surface/50 text-text-muted hover:bg-surface/80 border border-border'
            }`}
          >
            {s === 'all' ? 'All' : STATUS_LABELS[s] || s}
          </button>
        ))}
      </div>

      {/* Loading */}
      {isLoading && (
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => (
            <DisputeCardSkeleton key={i} />
          ))}
        </div>
      )}

      {/* Error */}
      {isError && (
        <div className="bg-surface border border-border rounded-lg p-6 text-center text-danger">
          Failed to load disputes. Please try again later.
        </div>
      )}

      {/* Empty state */}
      {!isLoading && !isError && allDisputes.length === 0 && (
        <div className="bg-surface border border-border rounded-lg p-12 text-center">
          <svg className="w-12 h-12 mx-auto mb-3 text-text-muted/40" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 6l3 1m0 0l-3 9a5.002 5.002 0 006.001 0M6 7l3 9M6 7l6-2m6 2l3-1m-3 1l-3 9a5.002 5.002 0 006.001 0M18 7l3 9m-3-9l-6-2m0-2v2m0 16V5m0 16H9m3 0h3" />
          </svg>
          <h2 className="text-lg font-semibold mb-2">No disputes found</h2>
          <p className="text-sm text-text-muted">
            {statusFilter === 'all'
              ? "You don't have any disputes yet. If you have an issue with a marketplace transaction, click 'File Dispute' above."
              : `No ${statusFilter} disputes found.`}
          </p>
        </div>
      )}

      {/* Disputes list */}
      <div className="space-y-3" role="list" aria-label="Disputes list">
        {allDisputes.map(dispute => (
          <article
            key={dispute.id}
            role="listitem"
            className="bg-surface border border-border rounded-lg p-4 hover:border-border/80 transition-colors cursor-pointer"
            onClick={() => setSelectedDispute(
              selectedDispute?.id === dispute.id ? null : dispute
            )}
            aria-expanded={selectedDispute?.id === dispute.id}
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                    STATUS_STYLES[dispute.status] || STATUS_STYLES.closed
                  }`}>
                    {STATUS_LABELS[dispute.status] || dispute.status}
                  </span>
                  {dispute.resolution && (
                    <span className="text-xs text-text-muted">
                      {RESOLUTION_LABELS[dispute.resolution] || dispute.resolution}
                      {dispute.resolution_amount_cents != null && (
                        <> ({formatPrice(dispute.resolution_amount_cents)})</>
                      )}
                    </span>
                  )}
                  {user && dispute.opened_by === user.id && (
                    <span className="text-[10px] text-text-muted bg-surface-hover px-1.5 py-0.5 rounded">
                      Filed by you
                    </span>
                  )}
                </div>
                <p className="text-sm line-clamp-2">{dispute.reason}</p>
                <div className="flex items-center gap-3 mt-2 text-xs text-text-muted">
                  <span>Opened {timeAgo(dispute.created_at)}</span>
                  <span>Deadline: {formatDate(dispute.deadline)}</span>
                  {dispute.resolved_at && (
                    <span>Resolved {timeAgo(dispute.resolved_at)}</span>
                  )}
                </div>
              </div>
              <div className="flex flex-col items-end gap-1">
                <span className="text-xs text-text-muted font-mono whitespace-nowrap">
                  {dispute.id.slice(0, 8)}
                </span>
                <svg
                  className={`w-4 h-4 text-text-muted transition-transform ${selectedDispute?.id === dispute.id ? 'rotate-180' : ''}`}
                  fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </div>
            </div>

            {/* Expanded detail */}
            {selectedDispute?.id === dispute.id && (
              <div className="mt-4 pt-4 border-t border-border/30 space-y-3" onClick={e => e.stopPropagation()}>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                  <div>
                    <span className="text-text-muted">Transaction:</span>{' '}
                    <Link
                      to="/transactions"
                      className="text-primary-light hover:underline"
                    >
                      {dispute.transaction_id.slice(0, 8)}...
                    </Link>
                  </div>
                  <div>
                    <span className="text-text-muted">Opened by:</span>{' '}
                    <Link
                      to={`/profile/${dispute.opened_by}`}
                      className="text-primary-light hover:underline"
                    >
                      {dispute.opened_by.slice(0, 8)}...
                    </Link>
                  </div>
                  {dispute.admin_note && (
                    <div className="sm:col-span-2 bg-surface-hover/50 rounded-md p-2">
                      <span className="text-text-muted text-xs font-semibold">Admin note:</span>{' '}
                      <span className="text-sm">{dispute.admin_note}</span>
                    </div>
                  )}
                </div>

                {/* Actions for open/negotiating disputes */}
                {!['resolved', 'closed'].includes(dispute.status) && (
                  <div className="flex gap-2 flex-wrap">
                    {/* Send message */}
                    <div className="flex-1 flex gap-2">
                      <input
                        type="text"
                        value={messageText}
                        onChange={e => setMessageText(e.target.value)}
                        placeholder="Send a message..."
                        aria-label="Dispute message"
                        className="flex-1 px-3 py-1.5 rounded-lg bg-background border border-border text-sm text-text focus:outline-none focus:border-primary"
                        onKeyDown={e => {
                          if (e.key === 'Enter' && messageText.trim()) {
                            messageMutation.mutate({
                              disputeId: dispute.id,
                              message: messageText.trim(),
                            })
                          }
                        }}
                      />
                      <button
                        onClick={() => {
                          if (messageText.trim()) {
                            messageMutation.mutate({
                              disputeId: dispute.id,
                              message: messageText.trim(),
                            })
                          }
                        }}
                        disabled={!messageText.trim() || messageMutation.isPending}
                        className="px-3 py-1.5 rounded-lg bg-primary/20 text-primary-light text-sm hover:bg-primary/30 disabled:opacity-50 cursor-pointer"
                      >
                        Send
                      </button>
                    </div>

                    {/* Escalate button */}
                    {dispute.status !== 'escalated' && (
                      <button
                        onClick={() => setEscalateId(dispute.id)}
                        className="px-3 py-1.5 rounded-lg bg-danger/20 text-danger text-sm hover:bg-danger/30 cursor-pointer"
                      >
                        Escalate
                      </button>
                    )}
                  </div>
                )}
              </div>
            )}
          </article>
        ))}
      </div>

      {/* Load more */}
      {hasNextPage && (
        <div className="flex justify-center">
          <button
            onClick={() => fetchNextPage()}
            disabled={isFetchingNextPage}
            className="px-4 py-2 rounded-lg bg-surface border border-border text-sm hover:border-primary/50 disabled:opacity-50 cursor-pointer transition-colors"
          >
            {isFetchingNextPage ? 'Loading...' : 'Load More'}
          </button>
        </div>
      )}

      {/* Escalate confirmation */}
      {escalateId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" role="dialog" aria-modal="true" aria-labelledby="escalate-dialog-title">
          <div className="bg-surface border border-border rounded-xl p-6 max-w-md w-full mx-4 space-y-4 shadow-xl">
            <h3 id="escalate-dialog-title" className="text-lg font-semibold">Escalate Dispute</h3>
            <p className="text-sm text-text-muted">
              Are you sure you want to escalate this dispute to admin review?
              This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setEscalateId(null)}
                className="px-4 py-2 rounded-lg bg-surface-hover border border-border text-sm hover:border-primary/30 transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={() => escalateMutation.mutate(escalateId)}
                disabled={escalateMutation.isPending}
                className="px-4 py-2 rounded-lg bg-danger text-white text-sm hover:bg-danger/80 disabled:opacity-50 cursor-pointer transition-colors"
              >
                {escalateMutation.isPending ? 'Escalating...' : 'Escalate'}
              </button>
            </div>
          </div>
        </div>
      )}
    </PageTransition>
  )
}
