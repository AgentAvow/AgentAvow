/**
 * Repo hosts we recognise but cannot scan yet. A gitlab.com / bitbucket.org / Azure DevOps
 * URL used to fall through the input routers to the `owner/repo` rule and silently scan the
 * same-named GitHub repo — a wrong answer. Say so instead, and point at the CI scan that
 * covers that host today.
 */
const HOSTS: Array<[RegExp, string]> = [
  [/^https?:\/\/(?:www\.)?gitlab\.com\//i, 'GitLab'],
  [/^https?:\/\/(?:www\.)?bitbucket\.org\//i, 'Bitbucket'],
  [/^https?:\/\/(?:dev\.azure\.com|[\w-]+\.visualstudio\.com)\//i, 'Azure DevOps'],
]

/** The host's name when `raw` is a URL on a repo host we don't support yet, else null. */
export function unsupportedRepoHost(raw: string): string | null {
  const v = raw.trim()
  for (const [re, name] of HOSTS) if (re.test(v)) return name
  return null
}

/** The docs pointer for each host's CI scan: [link label, docs path]. */
export const HOST_DOCS: Record<string, [string, string]> = {
  'GitLab': ['Docs → GitLab CI', '/rebrand/docs/run-locally#gitlab-ci-self-managed-behind-a-firewall'],
  'Bitbucket': ['Docs → Bitbucket Pipelines', '/rebrand/docs/run-locally#bitbucket-pipelines'],
  'Azure DevOps': ['Docs → Azure DevOps', '/rebrand/docs/run-locally#azure-devops'],
}

/** The one-line message shown in place of a scan. */
export function unsupportedRepoHostMessage(host: string): string {
  const [label] = HOST_DOCS[host] ?? HOST_DOCS['GitLab']
  return `${host} repos can't be checked here yet: the hosted Check reads GitHub repos. ` +
    `Run the same scan in your own ${host} pipeline instead (see ${label}).`
}
