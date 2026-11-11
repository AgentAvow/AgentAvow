# ERC-8004 agents

Check any ERC-8004 agent on Ethereum, Base or BNB Chain: we read its registration and answer for every MCP server and A2A agent it lists.

On the [check page](/check), enter `erc8004:<chain>:<agent id>`, for example `erc8004:base:1178486` (AgentAvow's own agent). The chain is `ethereum`, `base` or `bnb`.

## What we read

- **The on-chain record.** From the ERC-8004 identity registry on that chain we read the agent's owner, its agent wallet (if set) and its registration URI, all at one block.
- **The registration file.** The URI can be `ipfs://`, `https://`, a `data:` URI or inline JSON. We fetch it through the same SSRF guard as every other fetch, read at most 256 KB, and parse it as JSON. Its name and description are shown as plain text. We record the file's sha256.
- **Its services.** Each entry in `services` is sorted into one of two groups:
  - **Tools:** services named `MCP` or `A2A`. Each one gets an answer.
  - **Other services:** web pages, metadata, OASF and the like. They are listed but not checked. A source-code GitHub link is listed as a tool but is not checked yet.
- **The tools themselves.** Each MCP server and A2A agent card is answered from the same check as its own page, so the answer on the agent page matches the answer on the tool's page. A tool we haven't checked before is checked in the background, and the agent page updates when the check finishes.
- **The file's endpoints.** A tool endpoint that is plain HTTP, private, or a raw public IP address is a finding on the registration file. So is an agent that marks itself inactive (info only).

## The headline

The agent's answer is about the tools it lists:

- It is the **worst answer** among the tools we checked.
- It is **Safe to connect only if every listed tool was checked and each one reads Safe**.
- If any listed tool could not be checked (unreachable, not https, still being checked, or over the cap), the answer is at most **Review before you connect**, with "N of M listed tools checked".
- A high or critical finding on the registration file makes it at least Review.
- An agent that lists no tools we can check is Review. Identity alone never makes an agent Safe.
- An agent is **never Certified**. Certified belongs to a single tool, so look for it on each tool's own page.

Each tool's answer is signed on its own page with its own attestation, which you can [verify offline](./verify-attestations.md). The agent-level headline is a summary of those signed answers and is not signed separately.

## AgentAvow's own registration

AgentAvow is registered too: **agent 1178486 on Base** ([check it](/check/erc8004/base/1178486)). Its registration file is at [/.well-known/agent-registration.json](https://agentavow.com/.well-known/agent-registration.json) and lists two tools, our MCP server and our signed A2A agent card. Any agent or directory that reads the ERC-8004 registry can find us there and connect to either one.

The registration is identity only. It makes no claims about trust on-chain, and no AgentAvow verdict is written on-chain.

## API

No account needed:

```
GET /api/v1/public/scan/erc8004/{chain}/{agent_id}
```

```
curl https://agentavow.com/api/v1/public/scan/erc8004/base/1178486
```

The response has `agent` (chain, agent id, owner, registration URI and sha256, block), `tools` (each with its `state`, `decision`, `trust_score` and the API path for its own result), `other_services`, `file_findings`, `headline` (`decision`, `reason`, `coverage_note`, `certified: false`) and `coverage_gaps`.

The on-chain read and the registration file are cached for one hour. Add `?force=true` to read them again; this counts against the same fresh-scan limit as every other check. An agent id that isn't minted on that chain returns 404; a chain we can't reach right now returns 503 with `Retry-After`.

## Chains

| Chain | `chain` | Chain id |
|---|---|---|
| Ethereum | `ethereum` | 1 |
| Base | `base` | 8453 |
| BNB Chain | `bnb` | 56 |

All three use the same identity registry address, `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`.

## Limits

- **Identity isn't scored.** The owner, the wallet and the registration record are shown for reference. They are not an input to any answer or trust score, because anyone can register an agent.
- **Unreadable registrations.** A registration file we can't fetch, that isn't JSON, or that is larger than 256 KB is reported as unreadable. With no tools to check, the answer is Review.
- **At most 10 tools per agent.** Tools after the tenth are listed as not checked ("over the 10-tool limit"), which keeps the answer at Review.
- **Background checks are rate-limited.** New background checks are capped per visitor per hour. A tool that hits the cap shows "not checked"; try again later.
