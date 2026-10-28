// Sentry loads on demand. When no DSN is configured (prod today) the SDK is never
// downloaded; when one is, it loads after first render instead of sitting in the
// entry chunk every visitor waits on.
const SENTRY_DSN = import.meta.env.VITE_SENTRY_DSN

let sentry: Promise<typeof import('@sentry/react')> | null = null

export function initSentry() {
  if (!SENTRY_DSN || sentry) return
  sentry = import('@sentry/react').then((Sentry) => {
    Sentry.init({
      dsn: SENTRY_DSN,
      environment: import.meta.env.MODE,
      integrations: [Sentry.browserTracingIntegration(), Sentry.replayIntegration({ maskAllText: false, blockAllMedia: false })],
      tracesSampleRate: import.meta.env.PROD ? 0.2 : 1.0,
      replaysSessionSampleRate: 0.1,
      replaysOnErrorSampleRate: 1.0,
    })
    return Sentry
  })
}

export function captureException(error: unknown, extra?: Record<string, unknown>) {
  sentry?.then((Sentry) => Sentry.captureException(error, extra ? { extra } : undefined)).catch(() => {})
}
