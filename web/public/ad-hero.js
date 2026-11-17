// Runs before first paint (a plain, blocking script in <head>; our CSP allows 'self'
// scripts but not inline ones). On the homepage, a visitor from the X wallet-key ads
// (utm_content x3... / x5..., see web/src/rebrand/lib/adLanding.ts isWalletKeyAd)
// would otherwise see the prerendered usual hero, then the ad hero once the app loads.
// This marks <html data-ad-hero="wallet"> so CSS hides the usual hero until the app
// replaces it. If the app hasn't loaded after 2.5 s, the mark comes off and the usual
// hero shows. The prerendered HTML itself stays the usual homepage.
(function () {
  try {
    var path = location.pathname.replace(/\/+$/, '')
    if (path !== '' && path !== '/rebrand') return
    var content = new URLSearchParams(location.search).get('utm_content')
    if (!content) {
      try {
        content = (JSON.parse(sessionStorage.getItem('ag_utm') || '{}') || {}).utm_content
      } catch (e) {
        content = null
      }
    }
    if (!/^x[35](?:-|$)/i.test(content || '')) return
    var root = document.documentElement
    root.setAttribute('data-ad-hero', 'wallet')
    setTimeout(function () { root.removeAttribute('data-ad-hero') }, 2500)
  } catch (e) {
    // Leave the page as it is
  }
})()
