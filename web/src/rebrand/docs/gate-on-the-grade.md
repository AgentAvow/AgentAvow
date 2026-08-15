# Gate on the score

A score you don't act on is trivia. AgentAvow is built so a **machine** can read the verdict and decide — block a risky tool, throttle an unproven one, or wave a Certified one through — in CI and at your agent's runtime. Every path below reads the same signed verdict you can recompute offline.

## What the score tells a machine to do

Each verdict carries a **trust tier** and a **recommended execution posture** — not just a number:

- **80–100 · Trusted** — connect normally.
- **60–79 · Standard** — standard rate + token limits.
- **40–59 · Caution** — rate-limit, cap the token budget, prompt before high-impact tool calls.
- **20–39 · Restricted** — human-in-the-loop; no autonomous execution.
- **0–19 · Blocked** — do not connect.
- **known-malicious (MAL) dependency** — do not connect; disqualifying, regardless of the score.

**Blocked** and **MAL** are a hard stop. Everything above is a **dial**, not a gate — degrade capability instead of failing closed, so an unproven-but-fine tool still runs, just carefully.

## Gate your CI (GitHub Action)

Fail a pull request when a repo's trust score drops below a threshold, and post the score as a sticky PR comment:

```yaml
- uses: AgentAvow/trust-scan-action@v1
  with:
    min_score: 80          # 0–100 threshold to pass
    fail_on_findings: true # fail the job when the score is under min_score
    comment_on_pr: true    # sticky PR comment with score + findings
```

The action scans on AgentAvow's free API and fails the job when the score is below your `min_score` — so a supply-chain regression blocks the merge instead of shipping. Set `min_score` to the level you want to hold (e.g. **80** for Trusted, **60** for Standard).

## Gate your agent at runtime (SDK + bridges)

Check a tool's score **before** your agent connects it. The client SDKs — `agentgraph-trust` (JS) and the Python client — resolve any coordinate's score over the same free API, so you can enforce a floor in code:

```js
import { TrustClient } from 'agentgraph-trust'
const { trust_score, trust_tier } = await new TrustClient().scan('npm:chalk')
if (trust_score < 40) throw new Error(`blocked: ${trust_score}/100 (${trust_tier})`)
// else apply the recommended posture (rate limit / token cap / confirmation)
```

Framework bridges ship in `sdk/bridges/` (MCP, LangChain, CrewAI, AutoGen) so the pre-flight check drops into an existing agent, and the **trust gateway** (`/api/v1/gateway`) enforces a policy server-side when you'd rather not embed the logic.

## Gate anything (the API)

Every surface is one auth-free GET, returning the score, tier, findings, the signed `coverage{}` block, and the JWS attestation:

```
GET /api/v1/public/scan/{owner}/{repo}                       # GitHub repo
GET /api/v1/public/scan/package/{npm|pypi|crates|huggingface|docker}/{name}
GET /api/v1/public/scan/mcp?endpoint=https://…               # live MCP server
GET /api/v1/public/scan/skill/{owner}/{repo}                 # OpenClaw skill
GET /api/v1/public/scan/{owner}/{repo}/adoption              # the second score
```

Read `trust_score` / `trust_tier` to decide, and `attestation` to prove the decision later. The scan response also carries `tool_description` (what the tool is), `package_coordinate` (the registry name a repo maps to), and `coverage{}` (surface, scan depth, artifact digest, DB snapshots). The **adoption** endpoint returns the independent-reliance headline separately — it never moves the trust score. Results cache for an hour; add `?force=true` to re-scan. Don't trust our word for it — **recompute the verdict** from `coverage{}` and check the signature against our public JWKS (see **Verify an attestation**).

## Catch the rug-pull after you've shipped

A one-time gate misses the tool that was clean when you adopted it and turned malicious in v2. **Watch** a tool and AgentAvow re-scans it on a schedule and sends an **HMAC-signed webhook** the moment either its score drops **or its signed tool definition changes** (`tool_manifest_digest` drift — the silent redefinition you'd otherwise miss). Wire the webhook to Slack or your CI to pull a now-unsafe tool automatically.

## Put it together

1. **CI:** the GitHub Action blocks a merge that pulls in a below-threshold dependency.
2. **Runtime:** the MCP server refuses to connect a below-threshold tool, and throttles the ones it admits.
3. **Ongoing:** a watch alerts you — and can auto-revoke — when a tool you already trust regresses or redefines itself.

Same signed score, enforced at every layer, recomputable by anyone.
