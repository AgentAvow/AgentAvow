import { useState, useEffect, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import ConfirmDialog from '../components/ConfirmDialog'
import { useToast } from '../components/Toasts'
import { formatDate, formatPrice } from '../lib/formatters'
import { ListingSkeleton } from '../components/Skeleton'

interface Listing {
  id: string
  entity_id: string
  title: string
  description: string
  category: string
  tags: string[]
  pricing_model: string
  price_cents: number
  is_active: boolean
  is_featured: boolean
  view_count: number
  average_rating: number | null
  review_count: number
  created_at: string
  updated_at: string
}

interface ListingListResponse {
  listings: Listing[]
  total: number
}

const PAGE_SIZE = 20

export default function MyListings() {
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editTitle, setEditTitle] = useState('')
  const [editDescription, setEditDescription] = useState('')
  const [editPrice, setEditPrice] = useState(0)
  const [editPricingModel, setEditPricingModel] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)

  const { data: paymentStatus } = useQuery<{ payments_enabled: boolean }>({
    queryKey: ['payment-status'],
    queryFn: async () => (await api.get('/marketplace/payment-status')).data,
    staleTime: 5 * 60 * 1000,
  })
  const paymentsEnabled = paymentStatus?.payments_enabled ?? false

  useEffect(() => { document.title = 'My Listings - AgentAvow' }, [])

  const {
    data,
    isLoading,
    isError,
    refetch,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery<ListingListResponse>({
    queryKey: ['my-listings'],
    queryFn: async ({ pageParam }) => {
      const { data } = await api.get('/marketplace/my-listings', {
        params: { limit: PAGE_SIZE, offset: pageParam },
      })
      return data
    },
    initialPageParam: 0,
    getNextPageParam: (_lastPage, allPages) => {
      const loaded = allPages.reduce((acc, page) => acc + page.listings.length, 0)
      const total = allPages[0]?.total || 0
      if (loaded >= total) return undefined
      return loaded
    },
    staleTime: 2 * 60_000,
  })

  const updateMutation = useMutation({
    mutationFn: async ({ id, updates }: { id: string; updates: Record<string, unknown> }) => {
      await api.patch(`/marketplace/${id}`, updates)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-listings'] })
      setEditingId(null)
      addToast('Listing updated', 'success')
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      addToast(msg || 'Failed to update listing', 'error')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/marketplace/${id}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-listings'] })
      addToast('Listing deleted', 'success')
    },
    onError: () => {
      addToast('Failed to delete listing', 'error')
    },
  })

  const toggleActive = (listing: Listing) => {
    updateMutation.mutate({
      id: listing.id,
      updates: { is_active: !listing.is_active },
    })
  }

  const startEditing = (listing: Listing) => {
    setEditingId(listing.id)
    setEditTitle(listing.title)
    setEditDescription(listing.description)
    setEditPrice(listing.price_cents)
    setEditPricingModel(listing.pricing_model)
  }

  const saveEdit = (e: FormEvent) => {
    e.preventDefault()
    if (!editingId) return
    updateMutation.mutate({
      id: editingId,
      updates: {
        title: editTitle,
        description: editDescription,
        pricing_model: editPricingModel,
        price_cents: editPricingModel === 'free' ? 0 : editPrice,
      },
    })
  }

  const allListings = data?.pages.flatMap((page) => page.listings) || []
  const totalCount = data?.pages[0]?.total || 0

  if (isLoading) {
    return (
      <div className="max-w-3xl mx-auto space-y-3 mt-6">
        {Array.from({ length: 4 }).map((_, i) => <ListingSkeleton key={i} />)}
      </div>
    )
  }

  if (isError) {
    return (
      <div className="text-center py-10">
        <p className="text-danger mb-2">Failed to load listings</p>
        <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
      </div>
    )
  }

  return (
    <div className="max-w-3xl mx-auto">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold">My Listings</h1>
          <span className="text-xs text-text-muted">{totalCount} total</span>
        </div>
        <Link
          to="/marketplace/create"
          className="bg-primary hover:bg-primary-dark text-white px-3 py-1.5 rounded-md text-sm transition-colors"
        >
          + New Listing
        </Link>
      </div>

      <div className="space-y-3">
        {allListings.map((listing) => (
          <div
            key={listing.id}
            className={`bg-surface border rounded-lg p-4 transition-colors ${
              listing.is_active ? 'border-border' : 'border-border/50 opacity-60'
            }`}
          >
            {editingId === listing.id ? (
              <form onSubmit={saveEdit} className="space-y-3">
                <input
                  value={editTitle}
                  onChange={(e) => setEditTitle(e.target.value)}
                  className="w-full bg-background border border-border rounded-md px-3 py-1.5 text-sm text-text focus:outline-none focus:border-primary"
                  required
                  maxLength={200}
                />
                <textarea
                  value={editDescription}
                  onChange={(e) => setEditDescription(e.target.value)}
                  rows={3}
                  className="w-full bg-background border border-border rounded-md px-3 py-1.5 text-sm text-text focus:outline-none focus:border-primary resize-none"
                  required
                  maxLength={5000}
                />
                <span className="text-[10px] text-text-muted">{editDescription.length}/5000</span>
                {paymentsEnabled && (
                  <div className="flex items-center gap-3">
                    <select
                      value={editPricingModel}
                      onChange={(e) => setEditPricingModel(e.target.value)}
                      className="bg-background border border-border rounded-md px-2 py-1 text-xs text-text focus:outline-none focus:border-primary"
                    >
                      <option value="free">Free</option>
                      <option value="one_time">One-Time</option>
                      <option value="subscription">Subscription</option>
                    </select>
                    {editPricingModel !== 'free' && (
                      <div className="relative">
                        <span className="absolute left-2 top-1 text-text-muted text-xs">$</span>
                        <input
                          type="number"
                          value={(editPrice / 100).toFixed(2)}
                          onChange={(e) => setEditPrice(Math.round(parseFloat(e.target.value || '0') * 100))}
                          min="0.01"
                          step="0.01"
                          className="bg-background border border-border rounded-md pl-5 pr-2 py-1 text-xs text-text focus:outline-none focus:border-primary w-24"
                        />
                      </div>
                    )}
                  </div>
                )}
                <div className="flex gap-2">
                  <button
                    type="submit"
                    disabled={updateMutation.isPending}
                    className="bg-primary hover:bg-primary-dark text-white px-3 py-1 rounded-md text-xs transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    {updateMutation.isPending ? 'Saving...' : 'Save'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setEditingId(null)}
                    className="bg-surface-hover text-text px-3 py-1 rounded-md text-xs border border-border cursor-pointer"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            ) : (
              <>
                <div className="flex items-start justify-between mb-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Link
                        to={`/marketplace/${listing.id}`}
                        className="font-medium text-sm hover:text-primary-light transition-colors"
                      >
                        {listing.title}
                      </Link>
                      {!listing.is_active && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-danger/20 text-danger uppercase">
                          Inactive
                        </span>
                      )}
                      {listing.is_featured && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-warning/20 text-warning uppercase">
                          Featured
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-text-muted line-clamp-1 mt-0.5">{listing.description}</p>
                  </div>
                  <span className="text-sm font-medium text-primary-light whitespace-nowrap ml-3">
                    {paymentsEnabled ? formatPrice(listing.price_cents, listing.pricing_model) : 'Free'}
                  </span>
                </div>

                <div className="flex items-center justify-between text-xs text-text-muted">
                  <div className="flex items-center gap-3">
                    <span className="px-1.5 py-0.5 rounded bg-surface-hover capitalize">{listing.category}</span>
                    <span>{listing.view_count} views</span>
                    {listing.average_rating !== null && (
                      <span className="text-warning">
                        {'★'.repeat(Math.round(listing.average_rating))} ({listing.review_count})
                      </span>
                    )}
                    <span>Updated {formatDate(listing.updated_at)}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => startEditing(listing)}
                      className="hover:text-primary-light transition-colors cursor-pointer"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => toggleActive(listing)}
                      disabled={updateMutation.isPending}
                      className="hover:text-warning transition-colors cursor-pointer disabled:opacity-50"
                    >
                      {listing.is_active ? 'Deactivate' : 'Activate'}
                    </button>
                    <button
                      onClick={() => setDeleteTarget(listing.id)}
                      disabled={deleteMutation.isPending}
                      className="hover:text-danger transition-colors cursor-pointer disabled:opacity-50"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        ))}

        {allListings.length === 0 && (
          <div className="text-text-muted text-center py-10">
            No listings yet.{' '}
            <Link to="/marketplace/create" className="text-primary-light hover:underline">
              Create your first listing
            </Link>
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
        {!hasNextPage && allListings.length > 0 && (
          <p className="text-center text-xs text-text-muted py-4">No more listings</p>
        )}
      </div>

      {deleteTarget && (
        <ConfirmDialog
          title="Delete Listing"
          message="This will permanently delete this listing and all associated reviews. This cannot be undone."
          confirmLabel="Delete"
          variant="danger"
          isPending={deleteMutation.isPending}
          onConfirm={() => {
            deleteMutation.mutate(deleteTarget)
            setDeleteTarget(null)
          }}
          onCancel={() => setDeleteTarget(null)}
        />
      )}
    </div>
  )
}
