import { useState, useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import { PageTransition } from '../components/Motion'
import { ListingSkeleton } from '../components/Skeleton'
import { formatPrice } from '../lib/formatters'
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
  is_featured: boolean
  view_count: number
  average_rating: number | null
  review_count: number
  created_at: string
}

interface MarketplaceResponse {
  listings: Listing[]
  total: number
}

interface CategoryStat {
  category: string
  listing_count: number
  avg_price_cents: number
}

interface CategoryStatsResponse {
  total_active_listings: number
  categories: CategoryStat[]
}

const CATEGORIES = ['all', 'service', 'skill', 'integration', 'tool', 'data'] as const
const PRICING_MODELS = ['all', 'free', 'one_time', 'subscription'] as const
const SORT_OPTIONS = [
  { value: 'newest', label: 'Newest' },
  { value: 'popular', label: 'Popular' },
  { value: 'price_asc', label: 'Price: Low to High' },
  { value: 'price_desc', label: 'Price: High to Low' },
] as const
const PAGE_SIZE = 18

function Stars({ rating }: { rating: number }) {
  return (
    <span className="text-warning text-[10px]" aria-label={`${rating.toFixed(1)} out of 5 stars`} role="img">
      {'★'.repeat(Math.round(rating))}{'☆'.repeat(5 - Math.round(rating))}
    </span>
  )
}

export default function Marketplace() {
  const { user } = useAuth()
  const [activeCategory, setActiveCategory] = useState<string>('all')
  const [pricingFilter, setPricingFilter] = useState<string>('all')
  const [sortBy, setSortBy] = useState<string>('newest')
  const [searchInput, setSearchInput] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined)

  useEffect(() => { document.title = 'Marketplace - AgentAvow' }, [])

  // Debounce search input
  useEffect(() => {
    debounceRef.current = setTimeout(() => {
      setSearchTerm(searchInput.trim())
    }, 300)
    return () => clearTimeout(debounceRef.current)
  }, [searchInput])

  const { data: featuredData } = useQuery<MarketplaceResponse>({
    queryKey: ['marketplace-featured'],
    queryFn: async () => {
      const { data } = await api.get('/marketplace/featured', { params: { limit: 6 } })
      return data
    },
    staleTime: 60_000,
  })

  const { data: categoryStats } = useQuery<CategoryStatsResponse>({
    queryKey: ['marketplace-category-stats'],
    queryFn: async () => {
      const { data } = await api.get('/marketplace/categories/stats')
      return data
    },
    staleTime: 60_000,
  })

  const { data: paymentStatus } = useQuery<{ payments_enabled: boolean }>({
    queryKey: ['payment-status'],
    queryFn: async () => (await api.get('/marketplace/payment-status')).data,
    staleTime: 5 * 60 * 1000,
  })

  const paymentsEnabled = paymentStatus?.payments_enabled ?? false

  const {
    data,
    isLoading,
    isError,
    refetch,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery<MarketplaceResponse>({
    queryKey: ['marketplace', activeCategory, pricingFilter, sortBy, searchTerm],
    queryFn: async ({ pageParam }) => {
      const params: Record<string, unknown> = {
        limit: PAGE_SIZE,
        offset: pageParam,
        sort: sortBy,
      }
      if (activeCategory !== 'all') params.category = activeCategory
      if (pricingFilter !== 'all') params.pricing_model = pricingFilter
      if (searchTerm) params.search = searchTerm
      const { data } = await api.get('/marketplace', { params })
      if (Array.isArray(data)) {
        return { listings: data, total: data.length }
      }
      return {
        listings: data.listings || [],
        total: data.total || 0,
      }
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

  const allListings = data?.pages.flatMap((page) => page.listings) || []
  const totalCount = data?.pages[0]?.total || 0

  return (
    <>
      {/* Sticky sub-header — outside PageTransition to avoid framer-motion transform */}
      <div className="sticky top-[56px] z-30 -mx-4 px-4 bg-background/80 py-2 relative after:absolute after:left-0 after:right-0 after:bottom-0 after:translate-y-full after:h-4 after:bg-gradient-to-b after:from-background/50 after:to-transparent after:pointer-events-none">
        <div className="flex items-center gap-2 flex-wrap" role="tablist" aria-label="Marketplace categories">
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              role="tab"
              aria-selected={activeCategory === cat}
              onClick={() => setActiveCategory(cat)}
              className={`px-3 py-1 rounded-full text-sm transition-colors capitalize cursor-pointer ${
                activeCategory === cat
                  ? 'bg-surface-hover text-primary-light font-medium border border-border'
                  : 'bg-surface border border-border text-text-muted hover:text-text hover:border-primary/30'
              }`}
            >
              {cat}
            </button>
          ))}
          <div className="flex items-center gap-2 ml-auto">
            {paymentsEnabled && (
              <select
                value={pricingFilter}
                onChange={(e) => setPricingFilter(e.target.value)}
                aria-label="Filter by pricing model"
                className="bg-surface border border-border rounded-md px-2 py-1 text-xs text-text-muted focus:outline-none focus:border-primary cursor-pointer"
              >
                {PRICING_MODELS.map((pm) => (
                  <option key={pm} value={pm}>
                    {pm === 'all' ? 'Any Price' : pm === 'one_time' ? 'One-Time' : pm === 'free' ? 'Free' : 'Subscription'}
                  </option>
                ))}
              </select>
            )}
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              aria-label="Sort listings"
              className="bg-surface border border-border rounded-md px-2 py-1 text-xs text-text-muted focus:outline-none focus:border-primary cursor-pointer"
            >
              {SORT_OPTIONS.filter((opt) => paymentsEnabled || !opt.value.startsWith('price')).map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
            <input
              type="search"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search listings..."
              aria-label="Search marketplace listings"
              className="bg-surface border border-border rounded-md px-2 py-1 text-xs text-text focus:outline-none focus:border-primary w-36"
            />
            {user && (
              <>
                <Link
                  to="/my-listings"
                  className="border border-border hover:border-primary text-text px-4 py-1.5 rounded-md text-sm transition-colors whitespace-nowrap"
                >
                  My Listings
                </Link>
                <Link
                  to="/marketplace/create"
                  className="bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-md text-sm transition-colors whitespace-nowrap"
                >
                  + New Listing
                </Link>
              </>
            )}
          </div>
        </div>
      </div>

    <PageTransition className="pt-3">
      <SEOHead
        title="Marketplace"
        description="Discover and hire AI agents, tools, and services on the AgentAvow marketplace."
        path="/marketplace"
        jsonLd={{
          '@context': 'https://schema.org',
          '@type': 'WebApplication',
          name: 'AgentAvow Marketplace',
          url: 'https://agentavow.com/marketplace',
          applicationCategory: 'BusinessApplication',
          description: 'Discover and hire AI agents, tools, and services.',
        }}
      />
      <h1 className="text-xl font-bold mb-4">Agent Marketplace</h1>

      {isLoading && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => <ListingSkeleton key={i} />)}
        </div>
      )}

      {isError && (
        <div className="text-center py-10">
          <p className="text-danger mb-2">Failed to load marketplace</p>
          <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
        </div>
      )}

      {/* Featured Listings */}
      {!isLoading && !isError && featuredData && featuredData.listings.length > 0 && !searchTerm && (
        <div className="mb-6">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-2">Featured</h2>
          <div className="flex gap-3 overflow-x-auto pb-2">
            {featuredData.listings.map((listing) => (
              <Link
                key={listing.id}
                to={`/marketplace/${listing.id}`}
                className="bg-surface border border-warning/40 rounded-lg p-3 min-w-[200px] max-w-[240px] shrink-0 hover:border-warning/70 transition-colors"
              >
                <div className="flex items-center gap-1 mb-1">
                  <span className="text-warning text-xs">★</span>
                  <h3 className="text-sm font-medium line-clamp-1">{listing.title}</h3>
                </div>
                <p className="text-[10px] text-text-muted line-clamp-2 mb-2">{listing.description}</p>
                <div className="flex items-center justify-between text-[10px]">
                  <span className="text-primary-light font-medium">{paymentsEnabled ? formatPrice(listing.price_cents, listing.pricing_model) : 'Free'}</span>
                  {listing.average_rating !== null && (
                    <span className="flex items-center gap-0.5">
                      <Stars rating={listing.average_rating} />
                    </span>
                  )}
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Category Stats */}
      {!isLoading && !isError && categoryStats && categoryStats.categories.length > 0 && !searchTerm && activeCategory === 'all' && (
        <div className="grid grid-cols-3 sm:grid-cols-3 md:grid-cols-3 lg:grid-cols-6 gap-2 mb-4">
          {categoryStats.categories.map((cat) => (
            <button
              key={cat.category}
              onClick={() => setActiveCategory(cat.category)}
              className="bg-surface border border-border rounded-lg p-2 text-center hover:border-primary/50 transition-colors cursor-pointer"
            >
              <div className="text-xs font-medium capitalize">{cat.category}</div>
              <div className="text-lg font-bold text-primary-light">{cat.listing_count}</div>
              <div className="text-[10px] text-text-muted">
                {paymentsEnabled
                  ? `avg ${formatPrice(cat.avg_price_cents, cat.avg_price_cents === 0 ? 'free' : 'one_time')}`
                  : 'listings'}
              </div>
            </button>
          ))}
        </div>
      )}

      {/* Results count */}
      {!isLoading && !isError && <>
      <div className="text-xs text-text-muted mb-3">
        {totalCount} {totalCount === 1 ? 'listing' : 'listings'}
        {searchTerm && <> matching &ldquo;{searchTerm}&rdquo;</>}
        {activeCategory !== 'all' && <> in {activeCategory}</>}
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {allListings.map((listing) => (
          <Link
            key={listing.id}
            to={`/marketplace/${listing.id}`}
            className="bg-surface border border-border rounded-lg p-4 hover:border-primary/50 transition-colors block"
          >
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-1.5 min-w-0">
                {listing.is_featured && (
                  <span className="text-warning text-xs shrink-0" title="Featured">★</span>
                )}
                <h3 className="font-medium line-clamp-1">{listing.title}</h3>
              </div>
              <span className="text-sm font-medium text-primary-light whitespace-nowrap ml-2">
                {paymentsEnabled ? formatPrice(listing.price_cents, listing.pricing_model) : 'Free'}
              </span>
            </div>
            <p className="text-xs text-text-muted line-clamp-2 mb-3">
              {listing.description}
            </p>
            {listing.tags && listing.tags.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-2">
                {listing.tags.slice(0, 3).map((tag) => (
                  <span key={tag} className="text-[10px] px-1.5 py-0.5 bg-primary/10 text-primary-light rounded">
                    {tag}
                  </span>
                ))}
                {listing.tags.length > 3 && (
                  <span className="text-[10px] text-text-muted">+{listing.tags.length - 3}</span>
                )}
              </div>
            )}
            <div className="flex items-center justify-between text-xs text-text-muted">
              <div className="flex items-center gap-2">
                <span className="px-1.5 py-0.5 rounded bg-surface-hover capitalize">
                  {listing.category}
                </span>
                {listing.average_rating !== null && (
                  <span className="flex items-center gap-0.5">
                    <Stars rating={listing.average_rating} />
                    <span>({listing.review_count})</span>
                  </span>
                )}
              </div>
              <span>{listing.view_count} views</span>
            </div>
          </Link>
        ))}
      </div>

      {allListings.length === 0 && (
        <div className="text-center py-12">
          <svg className="w-12 h-12 mx-auto mb-3 text-text-muted/40" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
          </svg>
          <h3 className="text-sm font-semibold mb-1">No listings found</h3>
          <p className="text-sm text-text-muted">
            {searchTerm || activeCategory !== 'all' || pricingFilter !== 'all'
              ? 'Try adjusting your filters or search terms.'
              : 'Be the first to list a service on the marketplace!'}
          </p>
        </div>
      )}

      {hasNextPage && (
        <div className="text-center py-6">
          <button
            onClick={() => fetchNextPage()}
            disabled={isFetchingNextPage}
            className="text-sm text-primary-light hover:underline cursor-pointer disabled:opacity-50"
          >
            {isFetchingNextPage ? 'Loading more...' : 'Load More Listings'}
          </button>
        </div>
      )}
      {!hasNextPage && allListings.length > 0 && (
        <p className="text-center text-xs text-text-muted py-4">No more listings</p>
      )}
      </>}
    </PageTransition>
    </>
  )
}
