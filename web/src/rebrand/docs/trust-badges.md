# Add a trust badge to your README

Show that your tool is safe, with proof. An AgentAvow badge shows your tool's current answer (**Safe to connect**, **Review before you connect** or **Do not connect**), its signed **trust score** (0–100) on a 10-segment bar, and its **adoption** on a small dial. Clicking it opens the full, verifiable report. It's free, needs no account, and **refreshes on its own, so it never goes stale.**

## One line

Paste this into your `README.md` (swap `owner/repo`):

```markdown
[![AgentAvow](https://agentavow.com/api/v1/public/scan/owner/repo/badge)](https://agentavow.com/check/owner/repo)
```

That's it. First render triggers a scan; after that it's cached and refreshed automatically. Packages work the same way: `/public/scan/npm/semver/badge`, `/public/scan/pypi/requests/badge`.

## Styles

One design runs through the README badge and the website card: the AgentAvow mark, the answer in its colour, the trust bar with the score, and the adoption dial with the count.

| Style | URL | What it is |
|---|---|---|
| **Compact** (default) | `…/badge` | 20px tall, sits in a row of other badges. The mark, the answer, the trust bar + score, the adoption dial + count. |
| **Card** | `…/badge?style=card` or `…/card.svg` | 360×230. The full phrase, the repo name, the trust bar with the score and tier word, the adoption dial with the count and level. This is what the [website widget](#on-your-website) shows. |
| **Classic** | `…/badge?style=classic` | The previous shields-style badge ("Safe · 92/100"). |
| **Adoption only** | `…/badge?metric=adoption` | "Adopted: 22.6k ★", or "Adoption: new". |

Add `&theme=light` or `&theme=dark` to pin the colours. By default (`theme=auto`) the image follows the reader's light or dark setting by itself.

A **Certified** tool shows the teal-to-magenta Certified mark only when it carries the mark: every Certified check passes **and** the answer is Safe to connect at a score of 81 or above, with the sandbox finished (the API's `certified_mark`). A tool that passes the checks but reads Review gets the plain Review badge, and the mark comes back on its own once that's resolved. A badge showing an imported repo's composite score never carries the mark, since the mark belongs to the scan's own score.

## The badge endpoint

```
GET https://agentavow.com/api/v1/public/scan/{owner}/{repo}/badge
```

- Returns an **SVG** served with `Access-Control-Allow-Origin: *`, so it embeds anywhere. It has no scripts or external fonts, so GitHub shows it as-is.
- Shows the composite trust score if the repo is imported, else the security-scan score.
- Cached, not static: the badge is served with `Cache-Control: public, max-age=3600, s-maxage=86400` (an hour in the browser, a day at the edge) and the card with `max-age=300, s-maxage=3600`. Each regenerates from the current scan when its cache expires, so it tracks the current score and will not decay to "not scanned" in a stranger's README.

For a published package, use the package route. It also takes names with a slash, such as scoped npm packages and Hugging Face models (same `style`, `theme` and `metric` options):

```
GET https://agentavow.com/api/v1/public/scan/package/{surface}/{name}/badge
GET https://agentavow.com/api/v1/public/scan/package/npm/@scope/name/badge
GET https://agentavow.com/api/v1/public/scan/package/huggingface/org/model/badge
```

## On your website

For a docs site, landing page or security page, one script tag renders the card, linked to the report, with a **Verify offline** button that checks the Ed25519 signature in the reader's own browser:

```html
<script src="https://agentavow.com/widget.js" data-tool="owner/repo"></script>
```

Optional: `data-theme="light"` or `"dark"`, and `data-verify="false"` to hide the button. If your README is HTML rather than Markdown, the badge URL works in an `<img>` tag:

```html
<a href="https://agentavow.com/check/owner/repo">
  <img src="https://agentavow.com/api/v1/public/scan/owner/repo/badge" alt="AgentAvow" />
</a>
```

## The badge builder

The builder at `agentavow.com/badge` fills in the Markdown line for you in any style, and gives you the widget snippet.

## Gate your CI on it

The badge is the display; the **GitHub Action** is the enforcement. Run the scan on every pull request and
fail the build when the answer is Do not connect:

```yaml
# .github/workflows/agentavow.yml
- uses: AgentAvow/AgentAvow/github-action@main
  with:
    fail_on: do_not_connect    # the default; "review" also fails on Review before you connect
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
