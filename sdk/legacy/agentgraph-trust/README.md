# agentgraph-trust has moved to agentavow-trust

AgentGraph is now **AgentAvow**. This package name is retired. The MCP server is
published as **[`agentavow-trust`](https://pypi.org/project/agentavow-trust/)**.

```bash
uvx agentavow-trust
# or: pip install agentavow-trust
```

The import module did not change (`import agentgraph_trust`), and the renamed
package installs both the `agentavow-trust` and the `agentgraph-trust` console
scripts, so an existing MCP client config that runs `agentgraph-trust` keeps
working after you switch.

This final `agentgraph-trust` release contains no code. It only depends on
`agentavow-trust`, so an existing `pip install agentgraph-trust` or
`pip install --upgrade agentgraph-trust` pulls in the renamed package. Note
that the current server exposes the AgentAvow read-only trust tools (scan,
verify, badge, identity) and reads its verdicts from the live
https://agentavow.com API; the legacy registration tools from 0.3.x are gone.
Update your config to `agentavow-trust` when you can; there will be no further
releases under this name.

- Site: https://agentavow.com
- Docs: https://agentavow.com/docs
- Source: https://github.com/AgentAvow/AgentAvow (directory `sdk/mcp-server/`)
- MCP registry name: `com.agentavow/agentavow-trust`

The signing identity (`did:web:agentgraph.co`) and the JWKS host keep the
`agentgraph.co` name on purpose so existing attestations stay verifiable.
