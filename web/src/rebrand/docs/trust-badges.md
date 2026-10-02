# Add a trust badge to your README

Show that your tool is safe — with proof. An AgentAvow trust badge renders your repo's current signed safety
score — a **0–100 number** and tier word (Trusted → Blocked), coloured green→red — and clicking it opens the
full, verifiable report. It's free, needs no account, and **refreshes on its own, so it never goes stale.**

> Staged rebrand doc. Serving URLs use `agentavow.com` (post-cutover host); verification identifiers stay on
> `agentgraph.co`.

## One line

Paste this into your `README.md` (swap `owner/repo`):

```markdown
[![AgentAvow Trust](https://agentavow.com/api/v1/public/scan/owner/repo/badge)](https://agentavow.com/check/owner/repo)
```

That's it. First render triggers a scan; after that it's cached and refreshed automatically.

## The badge endpoint

```
GET https://agentavow.com/api/v1/public/scan/{owner}/{repo}/badge
```

- Returns an **SVG** (shields.io-compatible), served with `Access-Control-Allow-Origin: *` so it embeds
  anywhere.
- Shows the composite trust score if the repo is imported, else the security-scan score.
- Cached, not static: served with `Cache-Control: public, max-age=300, s-maxage=3600` (five minutes in the
  browser, an hour at the edge) over the hourly scan cache, so it tracks the current score and will not decay
  to "not scanned" in a stranger's README.

## Two badges: trust and adoption

The score answers *is it safe?* Add `?metric=adoption` for the second, separate signal — *do independent
parties rely on it?* (downloads / dependents / stars, never a fabricated number):

```markdown
[![Trust](https://agentavow.com/api/v1/public/scan/owner/repo/badge)](https://agentavow.com/check/owner/repo)
[![Adoption](https://agentavow.com/api/v1/public/scan/owner/repo/badge?metric=adoption)](https://agentavow.com/check/owner/repo)
```

The adoption badge reads "Adopted: 22.6k ★" (or "Adoption: new" when there's no signal yet). Adoption and
trust are deliberately two badges — popular is not the same as safe, and one never inflates the other.

## The badge builder

The builder at `agentavow.com/badge` fills in the Markdown line for you, as either the trust badge or a
combined badge that carries both scores (`?metric=combined`). It emits Markdown only. If your README is
HTML rather than Markdown, the same SVG URL works in an `<img>` tag:

**HTML**

```html
<a href="https://agentavow.com/check/owner/repo">
  <img src="https://agentavow.com/api/v1/public/scan/owner/repo/badge" alt="AgentAvow Trust" />
</a>
```

## Gate your CI on it

The badge is the display; the **GitHub Action** is the enforcement. Run the scan on every pull request and
fail the build if the score drops below a threshold:

```yaml
# .github/workflows/agentavow.yml
- uses: AgentAvow/AgentAvow/github-action@main
  with:
    min_score: 60              # block merges under 60/100
    fail_on_findings: true     # fail the job when the score is under min_score
    fail_on_behavioral: false  # optional: also fail on a high/critical sandbox finding
```

The action scans the repository the workflow runs in. For a private repo, or to scan without a round trip,
see [Run locally & in CI](./run-locally.md).

## The viral loop

Every README reader sees the badge → clicking it lands on that repo's full report → whose primary action is
minting *their own* badge. Each adoption seeds the next.

## Next

- [Verify an AgentAvow attestation](./verify-attestations.md)
- [Reading your scan score](./check-guide.md)
