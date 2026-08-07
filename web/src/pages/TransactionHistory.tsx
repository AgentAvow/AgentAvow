import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import ConfirmDialog from '../components/ConfirmDialog'
import { useToast } from '../components/Toasts'
import { formatDate, timeAgo, formatPrice } from '../lib/formatters'
import { TableRowSkeleton } from '../components/Skeleton'

interface Transaction {
  id: string
  listing_id: string | null
  buyer_entity_id: string
  seller_entity_id: string
  amount_cents: number
  status: string
  listing_title: string
  listing_category: string
  notes: string | null
  completed_at: string | null
  created_at: string
}

interface TransactionListResponse {
  transactions: Transaction[]
  total: number
}

const PAGE_SIZE = 20

const STATUS_STYLES: Record<string, string> = {
  pending: 'bg-warning/20 text-warning',
  completed: 'bg-success/20 text-success',
  refunded: 'bg-accent/20 text-accent',
  cancelled: 'bg-danger/20 text-danger',
}

export default function TransactionHistory() {
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [role, setRole] = useState<'buyer' | 'seller' | 'all'>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')

  useEffect(() => { document.title = 'Transactions - AgentAvow' }, [])
  const [confirmCancel, setConfirmCancel] = useState<string | null>(null)
  const [confirmRefund, setConfirmRefund] = useState<string | null>(null)

  const {
    data,
    isLoading,
    isError,
    refetch,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery<TransactionListResponse>({
    queryKey: ['transactions', role, statusFilter],
    queryFn: async ({ pageParam }) => {
      const params: Record<string, unknown> = {
        role,
        limit: PAGE_SIZE,
        offset: pageParam,
      }
      if (statusFilter !== 'all') params.status = statusFilter
      const { data } = await api.get('/marketplace/purchases/history', { params })
      return data
    },
    initialPageParam: 0,
    getNextPageParam: (_lastPage, allPages) => {
      const loaded = allPages.reduce((acc, page) => acc + page.transactions.length, 0)
      const total = allPages[0]?.total || 0
      if (loaded >= total) return undefined
      return loaded
    },
    staleTime: 2 * 60_000,
  })

  const cancelMutation = useMutation({
    mutationFn: async (txnId: string) => {
      await api.patch(`/marketplace/purchases/${txnId}/cancel`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['transactions'] })
    },
    onError: () => {
      addToast('Failed to cancel transaction', 'error')
    },
  })

  const refundMutation = useMutation({
    mutationFn: async (txnId: string) => {
      await api.patch(`/marketplace/purchases/${txnId}/refund`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['transactions'] })
    },
    onError: () => {
      addToast('Failed to request refund', 'error')
    },
  })

  const allTransactions = data?.pages.flatMap((page) => page.transactions) || []
  const totalCount = data?.pages[0]?.total || 0

  if (isLoading) {
    return (
      <div className="max-w-4xl mx-auto mt-6">
        <table className="w-full"><tbody>
          {Array.from({ length: 6 }).map((_, i) => <TableRowSkeleton key={i} cols={5} />)}
        </tbody></table>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="text-center py-10">
        <p className="text-danger mb-2">Failed to load transactions</p>
        <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
      </div>
    )
  }

  return (
    <div className="max-w-3xl mx-auto">
      <h1 className="text-xl font-bold mb-4">Transaction History</h1>

      {/* Filters */}
      <div className="flex items-center justify-between mb-4 gap-3 flex-wrap">
        <div className="flex gap-1" role="tablist" aria-label="Transaction role filter">
          {(['all', 'buyer', 'seller'] as const).map((r) => (
            <button
              key={r}
              role="tab"
              aria-selected={role === r}
              onClick={() => setRole(r)}
              className={`px-2.5 py-1 rounded text-xs transition-colors cursor-pointer ${
                role === r
                  ? 'bg-primary/10 text-primary-light border border-primary/30'
                  : 'text-text-muted hover:text-text border border-transparent'
              }`}
            >
              {r === 'all' ? 'All' : r === 'buyer' ? 'Purchases' : 'Sales'}
            </button>
          ))}
        </div>
        <div className="flex gap-1" role="tablist" aria-label="Transaction status filter">
          {(['all', 'pending', 'completed', 'refunded', 'cancelled'] as const).map((s) => (
            <button
              key={s}
              role="tab"
              aria-selected={statusFilter === s}
              onClick={() => setStatusFilter(s)}
              className={`px-2.5 py-1 rounded text-xs transition-colors cursor-pointer capitalize ${
                statusFilter === s
                  ? 'bg-primary/10 text-primary-light border border-primary/30'
                  : 'text-text-muted hover:text-text border border-transparent'
              }`}
            >
              {s === 'all' ? 'All Status' : s}
            </button>
          ))}
        </div>
      </div>

      <div className="text-xs text-text-muted mb-3">
        {totalCount} {totalCount === 1 ? 'transaction' : 'transactions'}
      </div>

      {/* Transaction list */}
      <div className="space-y-3">
        {allTransactions.map((txn) => (
          <div
            key={txn.id}
            className="bg-surface border border-border rounded-lg p-4"
          >
            <div className="flex items-start justify-between mb-2">
              <div className="min-w-0">
                {txn.listing_id ? (
                  <Link
                    to={`/marketplace/${txn.listing_id}`}
                    className="font-medium text-sm hover:text-primary-light transition-colors"
                  >
                    {txn.listing_title}
                  </Link>
                ) : (
                  <span className="font-medium text-sm">{txn.listing_title}</span>
                )}
                <div className="flex items-center gap-2 mt-1">
                  <span className="px-1.5 py-0.5 rounded bg-surface-hover text-[10px] capitalize">
                    {txn.listing_category}
                  </span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider ${STATUS_STYLES[txn.status] || ''}`}>
                    {txn.status}
                  </span>
                </div>
              </div>
              <div className="text-right shrink-0 ml-3">
                <div className="text-sm font-medium text-primary-light">
                  {formatPrice(txn.amount_cents)}
                </div>
                <div className="text-[10px] text-text-muted">{timeAgo(txn.created_at)}</div>
              </div>
            </div>

            {txn.notes && (
              <p className="text-xs text-text-muted mt-1 mb-2">{txn.notes}</p>
            )}

            <div className="flex items-center justify-between text-xs text-text-muted">
              <div className="flex items-center gap-3">
                <Link
                  to={`/profile/${txn.buyer_entity_id}`}
                  className="hover:text-primary-light transition-colors"
                >
                  Buyer
                </Link>
                <Link
                  to={`/profile/${txn.seller_entity_id}`}
                  className="hover:text-primary-light transition-colors"
                >
                  Seller
                </Link>
                {txn.completed_at && (
                  <span>Completed {formatDate(txn.completed_at)}</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {txn.status === 'pending' && (
                  <button
                    onClick={() => setConfirmCancel(txn.id)}
                    className="text-danger hover:underline cursor-pointer"
                  >
                    Cancel
                  </button>
                )}
                {txn.status === 'completed' && (
                  <button
                    onClick={() => setConfirmRefund(txn.id)}
                    className="text-warning hover:underline cursor-pointer"
                  >
                    Refund
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}

        {allTransactions.length === 0 && (
          <div className="text-text-muted text-center py-10">
            {statusFilter !== 'all' || role !== 'all'
              ? 'No transactions match your filters.'
              : 'No transactions yet.'}
          </div>
        )}

        {hasNextPage && (
          <div className="text-center py-4">
            <button
              onClick={() => fetchNextPage()}
              disabled={isFetchingNextPage}
              className="text-sm text-primary-light hover:underline cursor-pointer disabled:opacity-50"
            >
              {isFetchingNextPage ? 'Loading more...' : 'Load More'}
            </button>
          </div>
        )}
        {!hasNextPage && allTransactions.length > 0 && (
          <p className="text-center text-xs text-text-muted py-4">No more transactions</p>
        )}
      </div>

      {confirmCancel && (
        <ConfirmDialog
          title="Cancel Transaction"
          message="This will cancel the pending purchase. The transaction will be voided and cannot be undone."
          confirmLabel="Cancel Transaction"
          variant="warning"
          isPending={cancelMutation.isPending}
          onConfirm={() => {
            cancelMutation.mutate(confirmCancel, {
              onSettled: () => setConfirmCancel(null),
            })
          }}
          onCancel={() => setConfirmCancel(null)}
        />
      )}

      {confirmRefund && (
        <ConfirmDialog
          title="Refund Transaction"
          message="This will refund the completed transaction. The buyer will be credited and this action cannot be undone."
          confirmLabel="Issue Refund"
          variant="danger"
          isPending={refundMutation.isPending}
          onConfirm={() => {
            refundMutation.mutate(confirmRefund, {
              onSettled: () => setConfirmRefund(null),
            })
          }}
          onCancel={() => setConfirmRefund(null)}
        />
      )}
    </div>
  )
}
