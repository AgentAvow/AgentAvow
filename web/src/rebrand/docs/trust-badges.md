# Add a trust badge to your README

Show that your tool is safe — with proof. An AgentAvow trust badge renders your repo's current signed safety
grade, and clicking it opens the full, verifiable report. It's free, needs no account, and **regenerates on
every view, so it never goes stale.**

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
- Shows the composite trust grade if the repo is imported, else the security-scan grade.
- Regenerates on request — it will not decay to "not scanned" in a stranger's README.

## Other formats

Prefer HTML or reStructuredText? Generate any style from the badge builder at
`agentavow.com/badge`, which outputs Markdown, HTML, and RST for four styles (compact, detailed, minimal,
flat-square) and light/dark themes.

**HTML**

```html
<a href="https://agentavow.com/check/owner/repo">
  <img src="https://agentavow.com/api/v1/public/scan/owner/repo/badge" alt="AgentAvow Trust" />
</a>
```

## Gate your CI on it

The badge is the display; the **GitHub Action** is the enforcement. Run the scan on every pull request and
fail the build if the grade drops below a threshold:

```yaml
# .github/workflows/agentavow.yml
- uses: AgentAvow/trust-scan-action@v1
  with:
    repo: ${{ github.repository }}
    fail-below: B   # block merges under a B
```

Or from the CLI (ships with `agentgraph-sdk`):

```bash
pip install agentgraph-sdk
agentgraph scan owner/repo
```

## The viral loop

Every README reader sees the badge → clicking it lands on that repo's full report → whose primary action is
minting *their own* badge. Each adoption seeds the next.

## Next

- [Verify an AgentAvow attestation](./verify-attestations.md)
- [Reading your scan grade](./check-guide.md)
