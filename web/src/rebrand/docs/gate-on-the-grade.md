# Gate on the score

A score you don't act on is trivia. AgentAvow is built so a **machine** can read the verdict and decide — block a risky tool, throttle an unproven one, or wave a Certified one through — in CI and at your agent's runtime. Every path below reads the same signed verdict you can recompute offline.

## What the score tells a machine to do

Each verdict carries a **trust tier** (`trust_tier`) and a **recommended execution posture** (`recommended_limits`) — not just a number:

- **96–100 · Verified** (`verified`) — connect normally; no limits.
- **81–95 · Trusted** (`trusted`) — auto-approve within budget: 60 requests/min, 8192 tokens/call, no confirmation.
- **51–80 · Standard** (`standard`) — standard rate + token limits: 30 requests/min, 4096 tokens/call, no confirmation.
- **31–50 · Minimal** (`minimal`) — rate-limit and cap the token budget (15 requests/min, 2048 tokens/call); prompt before high-impact tool calls.
- **11–30 · Restricted** (`restricted`) — human-in-the-loop; no autonomous execution (5 requests/min, 1024 tokens/call, confirm every call).
- **0–10 · Blocked** (`blocked`) — do not connect.
- **known-malicious (MAL) dependency** — do not connect; disqualifying, regardless of the score.

**Blocked** and **MAL** are a hard stop. Everything above is a **dial**, not a gate — degrade capability instead of failing closed, so an unproven-but-fine tool still runs, just carefully.

## Gate your CI (GitHub Action)

Fail a pull request when a repo's trust score drops below a threshold, and post the score as a sticky PR comment:

```yaml
- uses: AgentAvow/AgentAvow/github-action@main
  with:
    min_score: 80              # 0–100 threshold to pass
    fail_on_findings: true     # fail the job when the score is under min_score
    comment_on_pr: true        # sticky PR comment with score + findings
    fail_on_behavioral: false  # optional: also fail on a high/critical sandbox finding
```

The action scans on AgentAvow's free API and fails the job when the score is below your `min_score` — so a supply-chain regression blocks the merge instead of shipping. Set `min_score` to the tier floor you want to hold (e.g. **81** for Trusted, **51** for Standard).

## Gate your agent at runtime (SDK + bridges)

Check a tool's score **before** your agent connects it. The client SDKs — `agentavow-trust` (npm) and the Python client — read a repo's score over the same free API, so you can enforce a floor in code. The client takes the API origin; `checkRepo` returns the same JSON as the public scan endpoint:

```js
import { TrustClient } from 'agentavow-trust'
const client = new TrustClient('https://agentavow.com')
const { trust_score, trust_tier } = await client.checkRepo('owner', 'repo')
if (trust_score < 31) throw new Error(`blocked: ${trust_score}/100 (${trust_tier})`)  // below the Minimal floor
// else apply the recommended posture (rate limit / token cap / confirmation)
```

For a package or a live MCP server, call the scan endpoints under **Gate anything** below; the response shape is the same.

Framework bridges ship in `sdk/bridges/` (LangChain, CrewAI, AutoGen, Pydantic AI) so the pre-flight check drops into an existing agent, and the **trust gateway** (`/api/v1/gateway`) enforces a policy server-side when you'd rather not embed the logic.

### LangChain

A one-line middleware gates **every tool call** in a LangChain 1.x agent. Before a tool runs it fetches the server's signed grade, allows the call when the score clears the floor (81, Trusted) with no critical/high finding, and checks the definition the agent was served against the per-tool digest in the attestation — so a tool that was redefined after it was graded is stopped, not run. A block comes back to the model as a tool message that says why; nothing raises.

```python
from langchain.agents import create_agent
from src.bridges.langchain.middleware import AgentAvowGate   # from the AgentAvow repo; not on PyPI yet

gate = AgentAvowGate(
    servers={"deepwiki": "https://mcp.deepwiki.com/mcp"},    # or tool_to_server={tool: server}
    min_score=81,                                             # Trusted floor
    on_fail="block",                                          # or "confirm" | "warn" | "raise"
)
agent = create_agent(model, tools=mcp_tools, middleware=[gate])
```

The mapping is yours to give — a LangChain tool doesn't carry its server's URL — by tool name (`tool_to_server`), by server name (`servers`, matched to `MCPAdapter`'s server name or a `<server>_` tool-name prefix), or a `resolve_server` callable. Tools that map to no server (your own functions) are not gated. `on_fail="confirm"` pauses the graph with a LangGraph interrupt until you resume with `"approve"`; `fail_closed=False` lets a call through, with a warning, when AgentAvow itself can't answer.

### Google ADK

The same gate is a `before_tool_callback`. For an `McpToolset` over HTTP it needs no mapping at all: the server URL comes off the tool's connection, and the drift check runs against the exact definition ADK was served — the raw `tools/list` entry the tool wraps. A block returns `{"error": …}` as the tool's result, so the model is told why and nothing raises.

```python
from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
from src.bridges.google_adk import AgentAvowToolGate            # from the AgentAvow repo; not on PyPI yet

agent = LlmAgent(
    name="assistant", model="gemini-2.5-flash",
    tools=[McpToolset(connection_params=StreamableHTTPConnectionParams(url=SERVER_URL))],
    before_tool_callback=AgentAvowToolGate(min_score=81, on_fail="block"),
)
```

A stdio server has no URL — give it a coordinate with `tool_to_server={"tool": "npm:@scope/server"}` and it's graded as a package (score and findings; nothing was served over the wire, so no drift check). `on_fail="confirm"` uses ADK's own tool-confirmation flow: the first call asks, the call runs once the user confirms.

### Vercel AI SDK

`wrapTools` from `agentavow-trust` wraps each tool's `execute` with the same check — the SDK's `onToolExecutionStart` callback can watch a call but can't stop it, so the gate sits on the hook that decides. A blocked tool returns `{ error, agentavow }` as its output; `onFail: 'confirm'` instead sets `needsApproval` so `generateText`, `streamText` and `ToolLoopAgent` pause for the user through the SDK's own approval flow.

```ts
import { createMCPClient } from '@ai-sdk/mcp'
import { generateText } from 'ai'
import { wrapTools } from 'agentavow-trust/vercel-ai'

const mcp = await createMCPClient({ transport: { type: 'http', url: SERVER_URL } })
const tools = wrapTools(await mcp.tools(), {
  server: SERVER_URL,        // every tool in this set came from one server
  minScore: 81,              // Trusted floor
  onFail: 'block',           // or 'confirm' | 'warn' | 'throw'
})
const { text } = await generateText({ model, tools, prompt })
```

Tools from `createMCPClient().tools()` don't carry their server's URL, so name it once per set (`server`), per tool (`toolToServer`), or with `resolveServer`. Your own function tools map to no server and run ungated. The drift check compares the definition the server serves now (or the `tools/list` you pass as `servedTools`) against the digest in the attestation; `failClosed: false` lets a call through, with a warning, when AgentAvow itself can't answer.

## Gate anything (the API)

Every surface is one auth-free GET, returning the score, tier, findings, the signed `coverage{}` block, and the JWS attestation:

```
GET /api/v1/public/scan/{owner}/{repo}                       # GitHub repo
GET /api/v1/public/scan/package/{npm|pypi|crates|huggingface|docker}/{name}
GET /api/v1/public/scan/mcp?endpoint=https://…               # live MCP server
GET /api/v1/public/scan/skill/{owner}/{repo}                 # OpenClaw skill
GET /api/v1/public/scan/{owner}/{repo}/adoption              # the second score
```

Read `trust_score` / `trust_tier` to decide, and `jws` (the signed attestation) to prove the decision later. The scan response also carries `tool_description` (what the tool is), `package_coordinate` (the registry name a repo maps to), and `coverage{}` (surface, scan depth, artifact digest, DB snapshots). The **adoption** endpoint returns the independent-reliance headline separately — it never moves the trust score. Results cache for an hour; add `?force=true` to re-scan. Don't trust our word for it — **recompute the verdict** from `coverage{}` and check the signature against our public JWKS (see **Verify an attestation**).

## Catch the rug-pull after you've shipped

A one-time gate misses the tool that was clean when you adopted it and turned malicious in v2. **Watch** a tool and AgentAvow re-scans it on a schedule and sends an **HMAC-signed webhook** when its score drops by more than 5 points **or its signed tool definition changes** (`tool_manifest_digest` drift — the silent redefinition you'd otherwise miss). Wire the webhook to Slack or your CI to pull a now-unsafe tool automatically.

Definition-change alerts cover GitHub repos, OpenClaw skills and live MCP servers, where the scan pins the tool definitions. For a live MCP server the digest is per tool name, taken from the `tools/list` the server actually serves. npm and PyPI package watches alert on score only.

Set the webhook under **Account → Alert webhook**, or with the account API (JWT or API key):

```
GET    /api/v1/account/alert-webhook                 # the saved webhook and its last delivery status
PUT    /api/v1/account/alert-webhook  {"url": "…"}   # save or replace the URL
POST   /api/v1/account/alert-webhook/rotate-secret   # new signing secret; the old one stops verifying
POST   /api/v1/account/alert-webhook/test            # deliver a sample payload now
DELETE /api/v1/account/alert-webhook
```

The URL must be a public `https://` address. The first `PUT` (and every `rotate-secret`) returns a `signing_secret` of the form `whsec_…` in that one response only; it is stored encrypted and never shown again. Every delivery then carries two headers, and the signature covers the exact bytes of the body:

```
X-AgentAvow-Timestamp: 1790812800
X-AgentAvow-Signature: sha256=<hex>
```

The body is JSON with a `type` that says what happened:

- `agentavow.alert.grade_change` — `{type, owner, repo, old_score, new_score, reason}`, where `reason` is `score dropped` or `signed definition changed`.
- `agentavow.alert.behavioral_change` — a later [sandbox run](./behavioral-sandbox.md) added findings, leaked a canary or reached a new undeclared host. Carries the run's current state rather than a diff: `findings[]` (`rule`, `severity`, `name`), `unexpected_egress[]`, `canary_exfil[]`, `tools_exercised[]`, `plan`, `score`, and the `package` the sandbox exercised.
- `agentavow.alert.test` — what `POST …/test` sends, shaped like a grade change with a `message`.

Verify before you act on an alert:

```python
import hashlib, hmac

def verify(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

Reject a delivery whose timestamp is more than a few minutes old. Rotating the secret (on the account page or with `rotate-secret`) stops the old one verifying immediately.

## Put it together

1. **CI:** the GitHub Action blocks a merge that pulls in a below-threshold dependency.
2. **Runtime:** the MCP server refuses to connect a below-threshold tool, and throttles the ones it admits.
3. **Ongoing:** a watch alerts you — and can auto-revoke — when a tool you already trust regresses or redefines itself.

Same signed score, enforced at every layer, recomputable by anyone.
