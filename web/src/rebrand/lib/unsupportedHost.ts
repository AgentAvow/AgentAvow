/**
 * Repo hosts we recognise but cannot scan yet. A gitlab.com / bitbucket.org / Azure DevOps
 * URL used to fall through the input routers to the `owner/repo` rule and silently scan the
 * same-named GitHub repo — a wrong answer. Say so instead.
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

export const DOCS_LABEL = 'Docs → Run locally & in CI'
export const DOCS_HREF = '/rebrand/docs/run-locally#gitlab-ci-self-managed-behind-a-firewall'

/** The one-line message shown in place of a scan. */
export function unsupportedRepoHostMessage(host: string): string {
  return `${host} repos aren't supported yet — AgentAvow reads GitHub repos today. ` +
    `You can run the same scanner on any checkout in your own CI (see ${DOCS_LABEL}).`
}
