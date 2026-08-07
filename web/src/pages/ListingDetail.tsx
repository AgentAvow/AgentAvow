import { useState, useEffect, type FormEvent } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import GuestPrompt from '../components/GuestPrompt'
import { useToast } from '../components/Toasts'
import { formatDate, formatPrice } from '../lib/formatters'
import { ListingDetailSkeleton } from '../components/Skeleton'
import SEOHead from '../components/SEOHead'

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
}

interface Review {
  id: string
  listing_id: string
  reviewer_entity_id: string
  reviewer_display_name: string
  rating: number
  text: string | null
  created_at: string
}

function Stars({ rating }: { rating: number }) {
  return (
    <span className="text-warning">
      {'★'.repeat(rating)}{'☆'.repeat(5 - rating)}
    </span>
  )
}

export default function ListingDetail() {
  const { listingId } = useParams<{ listingId: string }>()
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [showReview, setShowReview] = useState(false)
  const [rating, setRating] = useState(5)
  const [reviewText, setReviewText] = useState('')
  const [showPurchase, setShowPurchase] = useState(false)
  const [purchaseNotes, setPurchaseNotes] = useState('')
  const [purchaseSuccess, setPurchaseSuccess] = useState(false)

  const { data: paymentStatus } = useQuery<{ payments_enabled: boolean }>({
    queryKey: ['payment-status'],
    queryFn: async () => (await api.get('/marketplace/payment-status')).data,
    staleTime: 5 * 60 * 1000,
  })

  const { data: listing, isLoading, isError, refetch } = useQuery<Listing>({
    queryKey: ['listing', listingId],
    queryFn: async () => {
      const { data } = await api.get(`/marketplace/${listingId}`)
      return data
    },
    enabled: !!listingId,
    staleTime: 5 * 60_000,
  })

  useEffect(() => {
    document.title = listing ? `${listing.title} - AgentAvow` : 'Listing - AgentAvow'
  }, [listing])

  // View count is incremented server-side by the GET detail endpoint

  const { data: reviews } = useQuery<{ reviews: Review[]; total: number; average_rating: number | null }>({
    queryKey: ['listing-reviews', listingId],
    queryFn: async () => {
      const { data } = await api.get(`/marketplace/${listingId}/reviews`)
      return data
    },
    enabled: !!listingId,
    staleTime: 5 * 60_000,
  })

  const submitReview = useMutation({
    mutationFn: async () => {
      await api.post(`/marketplace/${listingId}/reviews`, {
        rating,
        text: reviewText || null,
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['listing-reviews', listingId] })
      queryClient.invalidateQueries({ queryKey: ['listing', listingId] })
      setShowReview(false)
      setReviewText('')
    },
    onError: () => {
      addToast('Failed to submit review', 'error')
    },
  })

  const purchaseMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.post(`/marketplace/${listingId}/purchase`, {
        notes: purchaseNotes || null,
      })
      return data
    },
    onSuccess: (data: { status: string; client_secret: string | null }) => {
      if (data.client_secret) {
        // Paid listing: redirect to Stripe or show payment UI
        // For now, store the client_secret and show instructions
        setPurchaseSuccess(true)
        setShowPurchase(false)
        setPurchaseNotes('')
        addToast('Payment initiated. Complete payment with Stripe.', 'success')
      } else {
        // Free listing: auto-completed
        setPurchaseSuccess(true)
        setShowPurchase(false)
        setPurchaseNotes('')
      }
      queryClient.invalidateQueries({ queryKey: ['listing', listingId] })
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      addToast(msg || 'Failed to complete purchase', 'error')
    },
  })

  const handleReview = (e: FormEvent) => {
    e.preventDefault()
    submitReview.mutate()
  }

  if (isLoading) {
    return <ListingDetailSkeleton />
  }

  if (isError) {
    return (
      <div className="text-center py-10">
        <p className="text-danger mb-2">Failed to load listing</p>
        <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
      </div>
    )
  }

  if (!listing) {
    return <div className="text-danger text-center mt-10">Listing not found</div>
  }

  const isOwner = user?.id === listing.entity_id

  return (
    <div className="max-w-2xl mx-auto">
      <SEOHead title={listing.title} description={listing.description?.slice(0, 160)} path={`/marketplace/${listingId}`} />
      <Link to="/marketplace" className="text-xs text-text-muted hover:text-text transition-colors mb-3 inline-block">&larr; Back to Marketplace</Link>
      <div className="bg-surface border border-border rounded-lg p-6 mb-6">
        <div className="flex items-start justify-between mb-3">
          <div>
            <h1 className="text-xl font-bold">{listing.title}</h1>
            <div className="flex items-center gap-2 mt-1">
              <span className="px-2 py-0.5 rounded text-xs bg-surface-hover capitalize">
                {listing.category}
              </span>
              {listing.is_featured && (
                <span className="px-2 py-0.5 rounded text-xs bg-warning/20 text-warning">
                  Featured
                </span>
              )}
            </div>
          </div>
          <div className="text-right">
            <div className="text-lg font-bold text-primary-light">
              {paymentStatus?.payments_enabled ? formatPrice(listing.price_cents, listing.pricing_model) : 'Free'}
            </div>
            {paymentStatus?.payments_enabled && (
              <div className="text-xs text-text-muted capitalize">{listing.pricing_model}</div>
            )}
          </div>
        </div>

        <p className="text-sm whitespace-pre-wrap mb-4">{listing.description}</p>

        {listing.tags.length > 0 && (
          <div className="flex flex-wrap gap-1 mb-4">
            {listing.tags.map((tag) => (
              <span key={tag} className="text-xs px-2 py-0.5 bg-primary/10 text-primary-light rounded">
                {tag}
              </span>
            ))}
          </div>
        )}

        <div className="flex items-center gap-6 text-xs text-text-muted mb-4">
          <span>{listing.view_count} views</span>
          {listing.average_rating !== null && (
            <span>
              <Stars rating={Math.round(listing.average_rating)} />{' '}
              ({listing.review_count} reviews)
            </span>
          )}
          <span>Listed {formatDate(listing.created_at)}</span>
          <Link
            to={`/profile/${listing.entity_id}`}
            className="hover:text-primary-light transition-colors ml-auto"
          >
            View Provider
          </Link>
        </div>

        {/* Purchase button */}
        {!user && (
          <div className="bg-surface-hover border border-border rounded-md p-4 text-center">
            <GuestPrompt variant="inline" action="purchase" />
          </div>
        )}
        {user && !isOwner && (
          <div>
            {purchaseSuccess ? (
              <div className="bg-success/10 border border-success/30 rounded-md px-4 py-3 text-sm">
                <span className="text-success font-medium">Purchase successful!</span>
                <span className="text-text-muted ml-2">
                  View your{' '}
                  <Link to="/transactions" className="text-primary-light hover:underline">
                    transaction history
                  </Link>
                </span>
              </div>
            ) : showPurchase ? (
              <div className="bg-surface-hover border border-border rounded-md p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Confirm Purchase</span>
                  <span className="text-lg font-bold text-primary-light">
                    {paymentStatus?.payments_enabled ? formatPrice(listing.price_cents, listing.pricing_model) : 'Free'}
                  </span>
                </div>
                <div>
                  <label className="block text-xs text-text-muted mb-1">Notes (optional)</label>
                  <textarea
                    value={purchaseNotes}
                    onChange={(e) => setPurchaseNotes(e.target.value)}
                    rows={2}
                    maxLength={500}
                    placeholder="Any notes for the provider..."
                    className="w-full bg-background border border-border rounded-md px-3 py-2 text-text text-sm focus:outline-none focus:border-primary resize-none"
                  />
                </div>
                {purchaseMutation.isError && (
                  <div className="text-xs text-danger">
                    {(purchaseMutation.error as Error)?.message || 'Purchase failed. Please try again.'}
                  </div>
                )}
                <div className="flex gap-2">
                  <button
                    onClick={() => purchaseMutation.mutate()}
                    disabled={purchaseMutation.isPending}
                    className="bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    {purchaseMutation.isPending
                      ? 'Processing...'
                      : listing.pricing_model === 'free'
                        ? 'Get for Free'
                        : 'Confirm Purchase'}
                  </button>
                  <button
                    onClick={() => { setShowPurchase(false); setPurchaseNotes('') }}
                    className="text-text-muted hover:text-text px-4 py-1.5 rounded-md text-sm transition-colors cursor-pointer border border-border"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : listing.pricing_model !== 'free' && !paymentStatus?.payments_enabled ? (
              <button
                onClick={() => setShowPurchase(true)}
                className="w-full bg-primary hover:bg-primary-dark text-white py-2.5 rounded-md text-sm font-medium transition-colors cursor-pointer"
              >
                Get for Free <span className="text-xs opacity-75">(Early Access)</span>
              </button>
            ) : (
              <button
                onClick={() => setShowPurchase(true)}
                className="w-full bg-primary hover:bg-primary-dark text-white py-2.5 rounded-md text-sm font-medium transition-colors cursor-pointer"
              >
                {listing.pricing_model === 'free' ? 'Get for Free' : `Purchase for ${formatPrice(listing.price_cents, listing.pricing_model)}`}
              </button>
            )}
          </div>
        )}
      </div>

      {/* Reviews */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider">
          Reviews ({reviews?.total || 0})
        </h2>
        {user ? (
          !isOwner && (
            <button
              onClick={() => setShowReview(!showReview)}
              className="text-xs text-primary-light hover:underline cursor-pointer"
            >
              {showReview ? 'Cancel' : 'Write a Review'}
            </button>
          )
        ) : (
          <GuestPrompt variant="inline" action="review" />
        )}
      </div>

      {showReview && (
        <form onSubmit={handleReview} className="bg-surface border border-border rounded-lg p-4 mb-4 space-y-3">
          <div>
            <label className="block text-sm text-text-muted mb-1">Rating</label>
            <div className="flex gap-1">
              {[1, 2, 3, 4, 5].map((n) => (
                <button
                  key={n}
                  type="button"
                  onClick={() => setRating(n)}
                  className={`text-2xl cursor-pointer ${n <= rating ? 'text-warning' : 'text-border'}`}
                >
                  ★
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-sm text-text-muted mb-1">Review (optional)</label>
            <textarea
              value={reviewText}
              onChange={(e) => setReviewText(e.target.value)}
              rows={3}
              maxLength={5000}
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-text text-sm focus:outline-none focus:border-primary resize-none"
            />
            <span className="text-[10px] text-text-muted">{reviewText.length}/5000</span>
          </div>
          <button
            type="submit"
            disabled={submitReview.isPending}
            className="bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
          >
            {submitReview.isPending ? 'Submitting...' : 'Submit Review'}
          </button>
        </form>
      )}

      <div className="space-y-3">
        {reviews?.reviews.map((review) => (
          <div key={review.id} className="bg-surface border border-border rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <Link
                to={`/profile/${review.reviewer_entity_id}`}
                className="text-sm font-medium hover:text-primary-light transition-colors"
              >
                {review.reviewer_display_name}
              </Link>
              <Stars rating={review.rating} />
              <span className="text-xs text-text-muted ml-auto">
                {formatDate(review.created_at)}
              </span>
            </div>
            {review.text && <p className="text-xs text-text-muted">{review.text}</p>}
          </div>
        ))}
      </div>
    </div>
  )
}
