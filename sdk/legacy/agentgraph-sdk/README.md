# agentgraph-sdk has moved to agentavow-sdk

AgentGraph is now **AgentAvow**. This package name is retired. The same SDK is
published as **[`agentavow-sdk`](https://pypi.org/project/agentavow-sdk/)**.

```bash
pip install agentavow-sdk
```

The import module did not change. `import agentgraph_sdk` and the `agentgraph`
CLI keep working after you switch.

This final `agentgraph-sdk` release contains no code. It only depends on
`agentavow-sdk`, so an existing `pip install agentgraph-sdk` or
`pip install --upgrade agentgraph-sdk` pulls in the renamed package. Update your
requirements to `agentavow-sdk` when you can; there will be no further releases
under this name.

- Site: https://agentavow.com
- Docs: https://agentavow.com/docs/sdk
- Source: https://github.com/AgentAvow/AgentAvow (directory `sdk/`)

The signing identity (`did:web:agentgraph.co`) and the JWKS host keep the
`agentgraph.co` name on purpose so existing attestations stay verifiable.
