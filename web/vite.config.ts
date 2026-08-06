import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

/**
 * At cutover (VITE_CUTOVER=true) rewrite the static index.html branding
 * AgentGraph → AgentAvow. Flag OFF (default) leaves index.html untouched, so the
 * current live site is unchanged. Driven by the same VITE_CUTOVER that flips the
 * app routing (basePath.ts / import.meta.env), read from .env here via loadEnv.
 */
function cutoverHtmlPlugin(cutover: boolean) {
  const TITLE = 'AgentAvow — Verifiable trust for the tools your agents connect to'
  const DESC =
    'AgentAvow gives any tool, MCP server, or package a signed, verifiable safety grade. ' +
    'Check it free, verify it offline, and get alerted the moment it changes.'
  return {
    name: 'agentavow-cutover-html',
    transformIndexHtml(html: string) {
      if (!cutover) return html
      return html
        .replaceAll('AgentGraph', 'AgentAvow')
        .replaceAll('agentgraph.co', 'agentavow.com')
        .replaceAll('agentgraph.bsky.social', 'agentavow.bsky.social')
        .replaceAll('/favicon.svg', '/favicon-avow.svg')
        .replaceAll('social network and trust infrastructure for AI agents and humans', 'verifiable trust layer for the tools AI agents connect to')
        .replaceAll('social network where AI agents and humans interact as peers', 'verifiable trust layer for the tools AI agents connect to')
        .replace(/<title>[^<]*<\/title>/, `<title>${TITLE}</title>`)
        .replace(/(<meta name="description" content=")[^"]*(")/, `$1${DESC}$2`)
        .replace(/(<meta property="og:description" content=")[^"]*(")/, `$1${DESC}$2`)
        .replace(/(<meta name="twitter:description" content=")[^"]*(")/, `$1${DESC}$2`)
    },
  }
}

export default defineConfig(({ mode }) => {
  const backendPort = mode === 'staging' ? 8001 : 8000
  const env = loadEnv(mode, process.cwd(), '')
  const cutover = env.VITE_CUTOVER === 'true'

  return {
    plugins: [react(), tailwindcss(), cutoverHtmlPlugin(cutover)],
    build: {
      rollupOptions: {
        output: {
          manualChunks: {
            vendor: ['react', 'react-dom', 'react-router-dom'],
            query: ['@tanstack/react-query'],
          },
        },
      },
    },
    server: {
      port: 5173,
      host: '0.0.0.0',
      proxy: {
        '/api': {
          target: `http://localhost:${backendPort}`,
          changeOrigin: true,
        },
        '/ws': {
          target: `ws://localhost:${backendPort}`,
          ws: true,
        },
      },
    },
  }
})
