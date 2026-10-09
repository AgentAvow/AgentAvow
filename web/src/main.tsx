import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './fonts.css'
import './index.css'
import App from './App'

// index.html carries a static description/canonical/OG set for clients that don't run
// JS (crawlers, link unfurlers). Pages declare their own through <Helmet>, which under
// React 19 adds tags without removing these, so every page carried the home page's
// canonical first. Once the app runs, drop the static set.
document.querySelectorAll('[data-static-seo]').forEach((el) => el.remove())

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
