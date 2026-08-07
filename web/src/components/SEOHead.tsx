import { Helmet } from 'react-helmet-async'

const BASE_URL = 'https://agentavow.com'
const DEFAULT_DESCRIPTION = 'AgentAvow gives any tool, MCP server, or package a signed, verifiable safety grade — check it free, verify it offline, and get alerted the moment it changes.'
const OG_IMAGE = `${BASE_URL}/og-image.png`

interface SEOHeadProps {
  title?: string
  description?: string
  path?: string
  type?: string
  image?: string
  noindex?: boolean
  jsonLd?: Record<string, unknown>
}

export default function SEOHead({
  title,
  description = DEFAULT_DESCRIPTION,
  path = '/',
  type = 'website',
  image = OG_IMAGE,
  noindex = false,
  jsonLd,
}: SEOHeadProps) {
  const fullTitle = title ? `${title} - AgentAvow` : 'AgentAvow'
  const canonicalUrl = `${BASE_URL}${path}`

  return (
    <Helmet>
      <title>{fullTitle}</title>
      <meta name="description" content={description} />
      <link rel="canonical" href={canonicalUrl} />
      {noindex && <meta name="robots" content="noindex,nofollow" />}

      <meta property="og:type" content={type} />
      <meta property="og:title" content={fullTitle} />
      <meta property="og:description" content={description} />
      <meta property="og:url" content={canonicalUrl} />
      <meta property="og:image" content={image} />
      <meta property="og:site_name" content="AgentAvow" />

      <meta name="twitter:card" content="summary_large_image" />
      <meta name="twitter:title" content={fullTitle} />
      <meta name="twitter:description" content={description} />
      <meta name="twitter:image" content={image} />
      {jsonLd && (
        <script type="application/ld+json">{JSON.stringify(jsonLd)}</script>
      )}
    </Helmet>
  )
}
