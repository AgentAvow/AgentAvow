#!/usr/bin/env node
/**
 * Build-time prerender. Runs after `vite build` and writes each public page to
 * dist/prerender/<route>/index.html with its own title, description, canonical and
 * body text. nginx serves that file to everyone, crawlers and people alike. A route
 * with no file gets dist/index.html, the app shell, exactly as before.
 *
 * Files live under dist/prerender/ because dist/index.html must stay the bare shell:
 * it is the fallback for every other route. The directory layout also keeps /index
 * (the Trust Index page) apart from that file, and means a path like /home can't
 * start resolving to a page.
 *
 * A failure here must never stop a deploy, so by default this warns and exits 0, and
 * the affected pages fall back to the shell. CI sets PRERENDER_STRICT=1 to turn every
 * warning into a failed build. No browser is needed; plain Node renders the pages.
 *
 * PRERENDER_API_ORIGIN  where the build reads catalog figures (default: production).
 *                       If that's unreachable, pages show their built-in fallbacks.
 */
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { loadEnv } from 'vite'

const WEB = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const DIST = path.join(WEB, 'dist')
const OUT = path.join(DIST, 'prerender')
const SSR_OUT = path.join(WEB, 'dist-ssr')

const STRICT = process.env.PRERENDER_STRICT === '1'
const API_ORIGIN = (process.env.PRERENDER_API_ORIGIN || 'https://agentavow.com').replace(/\/$/, '')
const API_TIMEOUT_MS = 6_000
const RENDER_DEADLINE_MS = 180_000
const MIN_WORDS = 100
const SITE = 'https://agentavow.com'
// #root and its loading spinner. The shell keeps its scripts in the head.
const SHELL_BODY = /<div id="root">[\s\S]*<\/body>/

let problems = 0
function warn(message) {
  problems += 1
  console.warn(`prerender: ${message}`)
}

/** Stop here. Whatever was already written stays: each file is complete on its own. */
function finish() {
  console.log(`prerender: done, ${problems} problem(s)`)
  process.exit(STRICT && problems ? 1 : 0)
}

const attr = (tag, name) => tag.match(new RegExp(`\\s${name}="([^"]*)"`))?.[1]
const tagKey = (tag) => attr(tag, 'name') ?? attr(tag, 'property')

/**
 * React writes a page's <title>, <meta> and <link> ahead of its first element when
 * there's no <head> in the tree, and leaves JSON-LD where the page rendered it.
 * Split those out, so the head tags go in the head and the body stays body.
 */
function splitRendered(rendered) {
  const start = rendered.search(/<div[\s>]/)
  const hoisted = rendered.slice(0, start)
  const jsonLd = []
  const body = rendered.slice(start).replace(/<script type="application\/ld\+json">[\s\S]*?<\/script>/g, (tag) => {
    jsonLd.push(tag)
    return ''
  })
  return {
    body,
    jsonLd,
    // The layout's default title comes first and the page's own comes after it.
    title: [...hoisted.matchAll(/<title>([^<]*)<\/title>/g)].at(-1)?.[1],
    metas: hoisted.match(/<meta\s[^>]*>/g) ?? [],
    canonical: hoisted.match(/<link rel="canonical"[^>]*>/)?.[0],
  }
}

/** Swap the shell's home-page head for this page's. main.tsx drops these tags at startup. */
function buildHead(template, page) {
  const mark = (tag) => tag.replace(/^<(meta|script)\s/, '<$1 data-static-seo ')
  const own = new Map(page.metas.map((tag) => [tagKey(tag), tag]))
  const description = attr(own.get('description') ?? '', 'content')
  const generated = {
    'og:title': page.title,
    'twitter:title': page.title,
    'og:description': description,
    'twitter:description': description,
  }
  const pageUrl = attr(page.canonical ?? '', 'href')
  const pageTags = [`<link data-static-seo rel="canonical" href="${pageUrl}" />`]
  if (!own.has('og:url')) pageTags.push(`<meta data-static-seo property="og:url" content="${pageUrl}" />`)

  // Pages that declare only a title and description still need the rest of the set.
  const html = template.replace(/^\s*<meta\s[^>]*data-static-seo[^>]*>\n/gm, (tag) => {
    const key = tagKey(tag)
    if (own.has(key)) return ''
    pageTags.push(key in generated
      ? tag.trim().replace(/content="[^"]*"/, () => `content="${generated[key]}"`)
      : tag.trim())
    return ''
  })
  pageTags.push(...page.metas.map(mark), ...page.jsonLd.map(mark))
  return html
    .replace(/<title>[^<]*<\/title>/, () => `<title>${page.title}</title>`)
    .replace('</head>', () => `    ${pageTags.join('\n    ')}\n  </head>`)
}

/** Everything a crawler needs to be on the page. Returns what's wrong with it. */
function check(route, page) {
  const faults = []
  const description = page.metas.find((tag) => tagKey(tag) === 'description')
  const words = page.body.replace(/<[^>]+>/g, ' ').split(/\s+/).filter(Boolean).length
  const canonical = `${SITE}${route}`
  if (!page.title) faults.push('no title')
  if (!description) faults.push('no description')
  if (attr(page.canonical ?? '', 'href') !== canonical) faults.push(`canonical is not ${canonical}`)
  if ((page.body.match(/<h1[\s>]/g) ?? []).length !== 1) faults.push('not exactly one H1')
  if (words < MIN_WORDS) faults.push(`only ${words} words`)
  // Text that ships invisible is worse than no text: it's what animations start from.
  if (/style="[^"]*\bopacity:0(?:;|")/.test(page.body)) faults.push('content at opacity 0')
  for (const [, asset] of page.body.matchAll(/(?:src|href)="(\/assets\/[^"]+)"/g)) {
    if (!existsSync(path.join(DIST, asset))) faults.push(`missing asset ${asset}`)
  }
  return faults
}

function buildBundle() {
  const vite = path.join(WEB, 'node_modules', 'vite', 'bin', 'vite.js')
  // A child process, so running out of memory here costs the prerender, not the build.
  const result = spawnSync(
    process.execPath,
    [vite, 'build', '--ssr', 'src/prerender-entry.tsx', '--outDir', 'dist-ssr', '--logLevel', 'warn'],
    { cwd: WEB, stdio: 'inherit', env: { ...process.env, NODE_ENV: 'production' } },
  )
  return result.status === 0
}

async function renderPages(entry, template) {
  const seen = { title: new Map(), description: new Map() }
  for (const route of entry.ROUTES) {
    try {
      const { body: rendered, state, failed } = await entry.render(route, API_ORIGIN, API_TIMEOUT_MS)
      if (failed.length) console.warn(`prerender: ${route}: fell back without ${failed.join(', ')}`)
      const page = splitRendered(rendered)

      const faults = check(route, page)
      const description = attr(page.metas.find((tag) => tagKey(tag) === 'description') ?? '', 'content')
      for (const [field, value] of [['title', page.title], ['description', description]]) {
        if (seen[field].has(value)) faults.push(`same ${field} as ${seen[field].get(value)}`)
        seen[field].set(value, route)
      }
      if (faults.length) {
        warn(`${route}: left on the app shell (${faults.join('; ')})`)
        continue
      }

      // `<` escaped so nothing in the data can close the script tag.
      const stateJson = JSON.stringify(state).replace(/</g, '\\u003c')
      // A replacer function, because page text can hold `$` patterns.
      const html = buildHead(template, page).replace(SHELL_BODY, () => (
        `<div id="prerender">${page.body}</div>\n    <div id="root"></div>\n`
          + `    <script type="application/json" id="prerender-state">${stateJson}</script>\n  </body>`
      ))
      const dir = path.join(OUT, route)
      await mkdir(dir, { recursive: true })
      await writeFile(path.join(dir, 'index.html'), html)
      console.log(`prerender: ${route} -> ${page.title}`)
    } catch (err) {
      warn(`${route}: left on the app shell (${err?.message ?? err})`)
    }
  }
}

async function main() {
  await rm(OUT, { recursive: true, force: true })

  // Before cutover the rebrand lives under /rebrand and these paths are legacy pages.
  if (loadEnv('production', WEB, 'VITE_').VITE_CUTOVER !== 'true') {
    warn('VITE_CUTOVER is not true, skipping')
    return finish()
  }
  const template = await readFile(path.join(DIST, 'index.html'), 'utf8')
  if (!SHELL_BODY.test(template)) {
    warn('dist/index.html has no #root to replace, skipping')
    return finish()
  }
  if (!buildBundle()) {
    warn('the server bundle failed to build, pages stay on the app shell')
    return finish()
  }

  // Modules in the bundle touch these at startup and in useState. Nothing is stored.
  const noStorage = { getItem: () => null, setItem() {}, removeItem() {} }
  for (const name of ['localStorage', 'sessionStorage']) {
    Object.defineProperty(globalThis, name, { value: noStorage, configurable: true })
  }
  const deadline = setTimeout(() => {
    warn(`still rendering after ${RENDER_DEADLINE_MS / 1000}s, stopping`)
    finish()
  }, RENDER_DEADLINE_MS)
  const entry = await import(pathToFileURL(path.join(SSR_OUT, 'prerender-entry.js')).href)
  await renderPages(entry, template)
  clearTimeout(deadline)
  await rm(SSR_OUT, { recursive: true, force: true })
  finish()
}

process.env.NODE_ENV = 'production'
main().catch((err) => {
  warn(`failed: ${err?.stack ?? err}`)
  finish()
})
