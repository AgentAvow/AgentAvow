# AgentAvow for Open Policy Agent

A Rego policy that refuses an agent's MCP server connection or tool call when AgentAvow's answer for that server is **Do not connect**, or **Review before you connect** if you choose to fail on that too. It also refuses a tool whose served definition no longer matches the per-tool digest signed into AgentAvow's scan (the rug-pull: a tool approved last week that quietly changed what it does).

Use it wherever you already run OPA: a sidecar your agent asks before connecting, an Envoy `ext_authz` filter in front of MCP traffic, or a policy bundle your gateway loads.

Tested with OPA 1.21 (Rego v1).

## What it asks AgentAvow

For each server it calls the public scan API once and caches the answer in OPA for `cache_seconds` (an hour by default, which is how long AgentAvow caches a verdict):

| `input.server` | Lookup |
|---|---|
| `https://mcp.example.com/mcp` or `mcp:https://…` | `GET /api/v1/public/scan/mcp?endpoint=…` |
| `npm:<name>`, `pypi:<name>`, `crates:<name>`, `docker:<name>`, `huggingface:<org/model>` | `GET /api/v1/public/scan/package/<surface>/<name>` |
| `owner/repo` or `github:owner/repo` | `GET /api/v1/public/scan/owner/repo` |
| a name you mapped in `servers` | the coordinate it maps to |

No account or key is needed. The answer is the API's `decision` (`safe`, `review`, `do_not_connect`). For a GitHub repo that is a collection of agent skills, the stricter of the repo's answer and its weakest skill's answer stands.

## Input

```json
{
  "server": "https://mcp.deepwiki.com/mcp",
  "tool": "read_wiki_contents",
  "tool_digest": "sha256:9d4a…"
}
```

`tool` and `tool_digest` are optional. Pass them to get the drift check: `tool_digest` is the digest of the definition the server served you, computed exactly as AgentAvow signs it (`sha256` over the JCS canonical form of `{"profile": "agentavow.mcp-tool-definition.v1", "tool": <name, title, description, inputSchema, outputSchema, annotations>}`). Every AgentAvow SDK exports that function (`toolDigest` in `agentavow-trust` on npm, `tool_digest` in `src/bridges/tool_gate.py`). Rego can't canonicalize JSON the way JCS requires, so the policy compares the digest you send rather than computing it.

## Output

`data.agentavow.authz.allow` is a boolean. `data.agentavow.authz.result` has the details:

```json
{
  "allow": false,
  "decision": "do_not_connect",
  "phrase": "Do not connect",
  "trust_score": 34,
  "report_url": "https://agentavow.com/check/oraios/serena",
  "deny": ["AgentAvow: Do not connect, one critical finding in its code: … (trust 34/100). Report: https://agentavow.com/check/oraios/serena"],
  "warnings": []
}
```

## Configuration

Put overrides under `data.agentavow.config` (a `data.json` in your bundle, or `opa run -s data.json`). Everything is optional:

```json
{
  "agentavow": {
    "config": {
      "fail_on": "do_not_connect",
      "fail_closed": true,
      "cache_seconds": 3600,
      "timeout": "10s",
      "servers": {"wiki": "https://mcp.deepwiki.com/mcp"},
      "base_url": "https://agentavow.com/api/v1",
      "web_url": "https://agentavow.com"
    }
  }
}
```

- **`fail_on`**: `do_not_connect` (default) refuses only Do not connect. `review` also refuses Review before you connect.
- **`fail_closed`**: when AgentAvow can't answer (network error, 5xx, rate limit), `true` (default) refuses and `false` allows with a warning in `result.warnings`. Refusing is the safe default for production; turn it off only where an outage must never block an agent.
- **`servers`**: names your agents use for servers, mapped to coordinates.

The public API is rate-limited per IP (20 scans a minute). OPA's cache means each server is looked up once per `cache_seconds`, which is well within that for normal use.

## Run it

As a sidecar your agent or gateway asks before connecting:

```bash
opa run --server --addr localhost:8181 integrations/opa/policy
curl -s localhost:8181/v1/data/agentavow/authz/result \
  -d '{"input": {"server": "https://mcp.deepwiki.com/mcp"}}'
```

In front of MCP traffic with Envoy and [OPA-Envoy](https://www.openpolicyagent.org/docs/envoy): see `examples/envoy_mcp.rego` (maps each route to its MCP endpoint and reads the tool name from a JSON-RPC `tools/call`) and `examples/envoy.yaml` (the `ext_authz` filter, with `failure_mode_allow: false`).

## Tests

```bash
opa test integrations/opa/policy integrations/opa/examples
```

The tests mock `http.send`, so they need no network: Safe allows, Do not connect refuses, `fail_on: review`, the skill-collection rule, matching and changed digests, an unknown tool, network and server errors with `fail_closed` on and off, and every coordinate form.
