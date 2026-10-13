# AgentAvow guardrail for the LiteLLM proxy

A LiteLLM [custom guardrail](https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail) for the proxy's MCP gateway. Before LiteLLM forwards a `tools/call` to an MCP server, it looks up that server's signed AgentAvow grade and refuses the call when the answer is **Do not connect**, or **Review before you connect** if you choose to fail on that too. For an https server it also checks the tool's served definition against the per-tool digest signed into AgentAvow's scan, and refuses a tool that changed since the scan or that the scan never saw (the rug-pull).

A refused call comes back to the caller as an MCP tool error with the reason, for example:

```
AgentAvow blocked 'find_symbol' on oraios/serena: Do not connect (one critical finding in its code: remote pickle/marshal load from response; …) · 34/100, tier minimal. Not run. Report: https://agentavow.com/check/oraios/serena
```

Tested with `litellm[proxy]` 1.105.0.

## Set up

The guardrail lives in the AgentAvow repository (`src/bridges/litellm`), next to the LangChain, Google ADK, Claude Agent SDK and OpenAI Agents SDK gates, and shares their decision code. It needs only `httpx`, which LiteLLM already installs.

1. Clone the repository somewhere the proxy can read it, and set `AGENTAVOW_REPO` to that path.
2. Put `agentavow_guardrail.py` next to your proxy's `config.yaml`. LiteLLM loads guardrails by file name relative to the config.
3. Add the guardrail to `config.yaml` with `mode: pre_mcp_call` (see `config.yaml` here):

```yaml
guardrails:
  - guardrail_name: agentavow
    litellm_params:
      guardrail: agentavow_guardrail.AgentAvowGuardrail
      mode: pre_mcp_call
      default_on: true
      fail_on: do_not_connect
      servers:
        local_files: "npm:@modelcontextprotocol/server-filesystem"
```

4. Start the proxy: `AGENTAVOW_REPO=/path/to/AgentAvow litellm --config config.yaml`.

## Which server AgentAvow grades

- An https MCP server in `mcp_servers` is graded by its URL, read from LiteLLM's MCP server registry.
- A stdio server (or one you'd rather grade as its published package or repo) needs an entry in `servers`: `{<LiteLLM server name>: <coordinate>}`, where a coordinate is `npm:<name>`, `pypi:<name>`, `owner/repo`, or an https URL.
- A server with neither is allowed with a warning in the proxy log, or refused if you set `unmapped: block`.

## Options

| Option | Default | What it does |
|---|---|---|
| `fail_on` | `do_not_connect` | `review` also refuses Review before you connect. |
| `on_fail` | `block` | `warn` lets a refused call through and logs the reason. |
| `fail_closed` | `true` | When AgentAvow can't answer, refuse (`true`) or allow with a warning (`false`). |
| `check_drift` | `true` | Fetch the server's own `tools/list` (cached) and compare each definition with the signed digest. https servers only. |
| `server_headers` | none | `{coordinate: {header: value}}` for fetching a private server's `tools/list`. |
| `servers` | none | Server name to coordinate, as above. |
| `unmapped` | `allow` | `block` refuses servers with no coordinate. |
| `cache_ttl` | `3600` | Seconds a grade and a served `tools/list` are reused. |
| `timeout` | `10` | Seconds per AgentAvow lookup. |

Under `fail_on: review`, the guardrail also applies the floors the other AgentAvow gates use: a score below 51 or a critical/high finding refuses the call. Under `do_not_connect`, only the answer counts. `min_score` and `block_on` override either default.

No account or key is needed. The public API is rate-limited per IP (20 scans a minute); the cache keeps each server to one lookup per `cache_ttl`.

## Tests

- `pytest --noconftest tests/test_litellm_guardrail.py` runs the guardrail against a mocked AgentAvow API and MCP server, with or without `litellm` installed.
- `integrations/litellm/smoke_test.py` installs nothing itself. Run it in a venv with `litellm[proxy]==1.105.0` and `AGENTAVOW_REPO` set. It loads the guardrail the way the proxy does (from `config.yaml`), confirms it is a real `CustomGuardrail` registered for `pre_mcp_call`, and runs LiteLLM's MCP pre-call hook against the live API: deepwiki is allowed and passes the drift check, and a Do not connect repo is refused.
