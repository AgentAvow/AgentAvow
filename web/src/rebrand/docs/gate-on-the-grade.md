# Gate on the score

A score you don't act on is trivia. AgentAvow is built so a **machine** can read the answer and decide — block a risky tool, throttle an unproven one, or wave a Certified one through — in CI and at your agent's runtime. Every path below reads the same signed result you can recompute offline.

## The answer to gate on

Every result leads with one of three answers, in `decision`, with the reason in `decision_reason`:

| `decision` | Phrase | What a gate does |
|---|---|---|
| `safe` | Safe to connect | allow |
| `review` | Review before you connect | require approval, or allow with limits |
| `do_not_connect` | Do not connect | deny |

**Do not connect** means a critical finding, a planted credential leaving the sandbox, a critical sandbox finding, or a known-malicious package or dependency. **Review before you connect** means a high finding (code or sandbox), a published advisory on this version, a deprecated package, or a score under 51. A clean scan of very little code reads **Safe to connect**, and its reason says so. Adoption is never an input. `decision_final: false` means the sandbox is still running and the answer may still move to Review. The full rule is in [How scoring works](./how-grading-works.md#the-answer-three-phrases). Certified rides beside the answer (`certified.eligible`), never instead of it.

## What the score tells a machine to do

Under the answer, each result carries the **trust tier** (`trust_tier`) and a **recommended execution posture** (`recommended_limits`) — the detail a gateway uses to throttle what it admits:

- **96–100 · Verified** (`verified`) — connect normally; no limits.
- **81–95 · Trusted** (`trusted`) — auto-approve within budget: 60 requests/min, 8192 tokens/call, no confirmation.
- **51–80 · Standard** (`standard`) — standard rate + token limits: 30 requests/min, 4096 tokens/call, no confirmation.
- **31–50 · Minimal** (`minimal`) — rate-limit and cap the token budget (15 requests/min, 2048 tokens/call); prompt before high-impact tool calls.
- **11–30 · Restricted** (`restricted`) — human-in-the-loop; no autonomous execution (5 requests/min, 1024 tokens/call, confirm every call).
- **0–10 · Blocked** (`blocked`) — execution denied.

**Do not connect** is the hard stop (a known-malicious dependency lands there whatever the score). The tiers are a **dial**, not a gate — degrade capability instead of failing closed, so an unproven-but-fine tool still runs, just carefully.

## Gate your CI (GitHub Action)

Fail a pull request on the answer, and post it as a sticky PR comment that leads with the phrase and its reason:

```yaml
- uses: AgentAvow/AgentAvow/github-action@main
  with:
    fail_on: do_not_connect    # default; or "review" (Review or worse), or "none"
    comment_on_pr: true        # sticky PR comment: answer, reason, score, findings
    fail_on_behavioral: false  # optional: also fail on a high/critical sandbox finding
```

The action scans on AgentAvow's free API and fails the job on **Do not connect** by default, so a supply-chain regression blocks the merge instead of shipping. `fail_on: review` holds the stricter line.

The legacy score floor still works when you set it: `min_score` with `fail_on_findings: true` fails below that number. `min_score` no longer defaults to 60; `fail_on_findings: true` on its own checks against **51**, the score under which the answer reads Review.

```yaml
- uses: AgentAvow/AgentAvow/github-action@main
  with:
    min_score: 81              # legacy: hold the Trusted floor
    fail_on_findings: true
```

For private code, the [local scan](./run-locally.md) gates the same way inside your runner, and nothing leaves it: `agentavow scan . --fail-on do_not_connect` (or `--fail-on review`) exits non-zero on that answer or worse; `--fail-on critical|high|medium` still gates on finding severity.

## Gate your agent at runtime (SDK + bridges)

Check a tool's answer **before** your agent connects it. The client SDKs — `agentavow-trust` (npm) and the Python client — read a repo's result over the same free API, so you can enforce it in code. The client takes the API origin; `checkRepo` returns the same JSON as the public scan endpoint:

```js
import { TrustClient } from 'agentavow-trust'
const client = new TrustClient('https://agentavow.com')
const r = await client.checkRepo('owner', 'repo')
if (r.decision === 'do_not_connect') throw new Error(`Do not connect: ${r.decision_reason}`)
if (r.decision === 'review') await confirmWithUser(`Review before you connect: ${r.decision_reason}`)
// then apply the recommended posture for r.trust_tier (rate limit / token cap / confirmation)
```

For a package or a live MCP server, call the scan endpoints under **Gate anything** below; the response shape is the same.

Framework bridges ship in `sdk/bridges/` (LangChain, CrewAI, AutoGen, Pydantic AI) so the pre-flight check drops into an existing agent, and the **trust gateway** (`/api/v1/gateway`) enforces a policy server-side when you'd rather not embed the logic.

### LangChain

A one-line middleware gates **every tool call** in a LangChain 1.x agent. Before a tool runs it fetches the server's signed result, allows the call when the answer is Safe to connect (and the score clears the floor, 51 by default, with no critical/high finding), and checks the definition the agent was served against the per-tool digest in the attestation — so a tool that was redefined after it was graded is stopped, not run. A block comes back to the model as a tool message that says why, leading with the tool's answer and its reason ("Do not connect (one critical finding: …) · 40/100, tier minimal"); nothing raises. The result also carries `decision`.

```python
from langchain.agents import create_agent
from src.bridges.langchain.middleware import AgentAvowGate   # from the AgentAvow repo; not on PyPI yet

gate = AgentAvowGate(
    servers={"deepwiki": "https://mcp.deepwiki.com/mcp"},    # or tool_to_server={tool: server}
    fail_on="review",                                         # default: stop Review and Do not connect;
                                                              # "do_not_connect" lets Review through
    on_fail="block",                                          # or "confirm" | "warn" | "raise"
)
agent = create_agent(model, tools=mcp_tools, middleware=[gate])
```

The mapping is yours to give — a LangChain tool doesn't carry its server's URL — by tool name (`tool_to_server`), by server name (`servers`, matched to `MCPAdapter`'s server name or a `<server>_` tool-name prefix), or a `resolve_server` callable. Tools that map to no server (your own functions) are not gated. `min_score=81` holds the stricter Trusted floor. `on_fail="confirm"` pauses the graph with a LangGraph interrupt until you resume with `"approve"`; `fail_closed=False` lets a call through, with a warning, when AgentAvow itself can't answer.

### Google ADK

The same gate is a `before_tool_callback`. For an `McpToolset` over HTTP it needs no mapping at all: the server URL comes off the tool's connection, and the drift check runs against the exact definition ADK was served — the raw `tools/list` entry the tool wraps. A block returns `{"error": …}` as the tool's result, so the model is told why and nothing raises.

```python
from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
from src.bridges.google_adk import AgentAvowToolGate            # from the AgentAvow repo; not on PyPI yet

agent = LlmAgent(
    name="assistant", model="gemini-2.5-flash",
    tools=[McpToolset(connection_params=StreamableHTTPConnectionParams(url=SERVER_URL))],
    before_tool_callback=AgentAvowToolGate(fail_on="review", on_fail="block"),
)
```

A stdio server has no URL — give it a coordinate with `tool_to_server={"tool": "npm:@scope/server"}` and it's graded as a package (score and findings; nothing was served over the wire, so no drift check). `on_fail="confirm"` uses ADK's own tool-confirmation flow: the first call asks, the call runs once the user confirms.

### Vercel AI SDK

`wrapTools` from `agentavow-trust/vercel-ai` runs the same gate as the Flue adapter below: one policy object, the three answers, the attestation verified against AgentAvow's public JWKS by default, and a tool whose definition changed since it was graded blocked by default. It wraps each tool's `execute`, because the SDK's `onToolExecutionStart` callback can watch a call but can't stop it. A tool that is not allowed returns `{ error, agentavow }` as its output: `error` leads with the answer ("Do not connect — 'send_email' was not run. …", with "· Certified" beside the answer when the tool carries the mark) and `agentavow` is the decision. `onReview: 'confirm'` sets `needsApproval`, so `generateText`, `streamText` and `ToolLoopAgent` pause for the user on a Review before you connect answer through the SDK's own approval flow. Do not connect is never put to the user.

```ts
import { createMCPClient } from '@ai-sdk/mcp'
import { generateText } from 'ai'
import { wrapTools } from 'agentavow-trust/vercel-ai'

const mcp = await createMCPClient({ transport: { type: 'http', url: SERVER_URL } })
const listing = await mcp.listTools()
const tools = wrapTools(mcp.toolsFromDefinitions(listing), {
  server: SERVER_URL,     // every tool in this set came from one server
  servedTools: listing,   // the exact definitions, for the drift check
  allowFloor: 51,         // trust score that is safe without review (81 is strict)
  onReview: 'confirm',    // or 'block' | 'warn'
  onDrift: 'block',       // a tool whose definition changed since it was graded
})
const { text } = await generateText({ model, tools, prompt })
```

Tools from `createMCPClient().tools()` don't carry their server's URL, so name it once per set (`server`), per tool (`toolToServer`), or with `resolveServer`. Your own function tools map to no server and run ungated. The drift check compares the definition this agent was handed (the `tools/list` you pass as `servedTools`, else the wrapped tool itself, else the server's own listing when it shows the model the same thing) with the per-tool digest in the attestation, so a server that shows the check one definition and the agent another is caught. `onApiError: 'allow'` lets a call through, with a warning, when AgentAvow itself can't answer. Code written for 0.2.x keeps working: `minScore`, `onFail` and `failClosed` are accepted as `allowFloor`, `onReview` and `onApiError`; the default floor is now 51, so pass `allowFloor: 81` to keep the old one.

### Flue

For an agent built on [Flue](https://flueframework.com) (`@flue/runtime` 2.x, remote MCP servers), `agentavow-trust/flue` puts the same check at the two points Flue gives you. One policy object decides `safe`, `review` or `do_not_connect` from the server's signed result; the Certified mark travels next to the decision as its own field.

```ts
// src/app.ts (module scope, once)
import { instrument } from '@flue/runtime'
import { createFlueGate } from 'agentavow-trust/flue'

export const gate = createFlueGate({
  allowFloor: 51,        // trust score that is safe without review (81 is strict)
  onReview: 'block',     // or 'warn' | 'confirm'
  onDrift: 'block',      // a tool whose definition changed since it was graded
  onApiError: 'block',   // fail closed when AgentAvow cannot answer
})
instrument(gate.instrumentation())
```

```ts
// src/agents/assistant.ts
'use agent'
import { useMcpConnection, useModel } from '@flue/runtime'
import { gate } from '../app.ts'

export function Assistant() {
  useModel('anthropic/claude-sonnet-4-6')
  useMcpConnection(gate.connection({ name: 'deepwiki', url: 'https://mcp.deepwiki.com/mcp', optional: true }))
  return 'Answer questions about public repositories.'
}
```

`gate.connection(def)` returns the same connection definition with its `fetch` wrapped. Flue hands that `fetch` to the MCP transport, so the gate sees the `initialize` and `tools/list` exchange: it fetches the server's signed result before the first message, refuses the connection on `do_not_connect` (with `optional: true` Flue mounts no tools from that server and tells the model why; without it the run fails with the reason), and when the listing arrives it checks each served definition against the per-tool digest in the attestation. A definition that changed since the server was graded refuses the connection too.

`gate.instrumentation()` plugs into Flue's `instrument()` so every `mcp__<server>__<tool>` call runs the in-memory check first. A call that is not allowed is denied before it runs; the model gets the reason as the tool's error and the conversation continues. Pin the definitions you reviewed (`gate.pin(server, tools)` or a `pins` entry in the policy) and a server that redefines a tool after it connected is caught on the next call.

The gate verifies the EdDSA attestation against AgentAvow's public JWKS and decides on the signed fields; it needs only `fetch` and WebCrypto, so it runs on Flue's Node and Cloudflare Workers targets. `onReview: 'confirm'` takes a `confirm` hook of yours, since Flue has no built-in approval pause. The same core, `agentavow-trust/gate`, works without Flue: `createGate(policy).check(target)` and `checkToolCall({ server, toolName, servedDefinition })`.

### Where each integration stands

| Integration | Status |
|---|---|
| Claude Code plugin (session-start check, install check, per-call gate) | Shipped; listed in the Claude plugin directory |
| MCP connector (`https://agentavow.com/mcp`) | Shipped; works in any MCP client |
| ChatGPT app | In OpenAI review |
| npm `agentavow-trust`: core gate, Vercel AI SDK, Flue | Shipped |
| LangChain and Google ADK gates | In this repository (`src/bridges/`); not on PyPI yet |
| GitHub Action, local CLI, GitLab CI component | Shipped |
| Claude Agent SDK, OpenAI Agents SDK | No dedicated adapter yet. Use the core gate (`createGate` / `ToolGate`) in a tool-call hook, or add the MCP connector |

## Gate anything (the API)

Every surface is one auth-free GET, returning the score, tier, findings, the signed `coverage{}` block, and the JWS attestation:

```
GET /api/v1/public/scan/{owner}/{repo}                       # GitHub repo
GET /api/v1/public/scan/package/{npm|pypi|crates|huggingface|docker}/{name}
GET /api/v1/public/scan/mcp?endpoint=https://…               # live MCP server
GET /api/v1/public/scan/skill/{owner}/{repo}                 # OpenClaw skill
GET /api/v1/public/scan/{owner}/{repo}/adoption              # the second score
```

Read `decision` / `decision_reason` to decide (`trust_score` / `trust_tier` underneath for throttling), and `jws` (the signed attestation) to prove the decision later. The scan response also carries `tool_description` (what the tool is), `package_coordinate` (the registry name a repo maps to), and `coverage{}` (surface, scan depth, artifact digest, DB snapshots). The **adoption** endpoint returns the independent-reliance headline separately — it never moves the trust score. Results cache for an hour; add `?force=true` to re-scan. Don't trust our word for it — **recompute the verdict** from `coverage{}` and check the signature against our public JWKS (see **Verify an attestation**).

## Catch the rug-pull after you've shipped

A one-time gate misses the tool that was clean when you adopted it and turned malicious in v2. **Watch** a tool and AgentAvow re-scans it on a schedule and sends an **HMAC-signed webhook** when its score drops by more than 5 points **or its signed tool definition changes** (`tool_manifest_digest` drift — the silent redefinition you'd otherwise miss). Wire the webhook to Slack or your CI to pull a now-unsafe tool automatically.

To see it end to end, run the [rug-pull demo](https://github.com/AgentAvow/AgentAvow/tree/main/demos/rugpull): an MCP server that was clean on approval day redefines its `send_email` tool, the ungated agent leaks the message, and the gated agent refuses the call before anything is sent.

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

- `agentavow.alert.grade_change` — `{type, owner, repo, old_score, new_score, reason, decision, decision_final, decision_reason, certified}`, where `reason` is `score dropped` or `signed definition changed` and `decision` is the tool's answer now.
- `agentavow.alert.behavioral_change` — a later [sandbox run](./behavioral-sandbox.md) added findings, leaked a canary or reached a new undeclared host. Carries the run's current state rather than a diff: `findings[]` (`rule`, `severity`, `name`), `unexpected_egress[]`, `canary_exfil[]`, `tools_exercised[]`, `plan`, `score`, the `package` the sandbox exercised, and the tool's answer now (`decision`, `decision_final`, `decision_reason`, `certified`).
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

1. **CI:** the GitHub Action blocks a merge on **Do not connect** (or on Review, if you choose).
2. **Runtime:** your gate refuses a tool that reads **Do not connect**, asks a person on **Review before you connect**, and throttles the ones it admits by tier.
3. **Ongoing:** a watch alerts you (wire the signed webhook to pull the tool) when a tool you already trust regresses or redefines itself.

Same answer, on the same signed score, enforced at every layer, recomputable by anyone.
