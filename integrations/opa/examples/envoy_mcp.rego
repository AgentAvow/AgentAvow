# Example: put AgentAvow in front of MCP traffic with Envoy + OPA-Envoy (ext_authz).
#
# Envoy forwards each request to the MCP upstream through ext_authz with the body
# (with_request_body), and OPA-Envoy evaluates data.agentavow.envoy.allow. The MCP
# server is identified by the upstream URL; a JSON-RPC tools/call names the tool.
# Everything that is not a tools/call (initialize, tools/list, notifications) is
# still checked against the server's answer, so a Do not connect server is refused
# before the agent ever lists its tools.
package agentavow.envoy

import data.agentavow.authz

# The MCP endpoint this route proxies. Set it per route in data, e.g.
# {"agentavow": {"envoy": {"routes": {"/mcp/deepwiki": "https://mcp.deepwiki.com/mcp"}}}}
server := data.agentavow.envoy.routes[input.attributes.request.http.path]

tool := input.parsed_body.params.name if input.parsed_body.method == "tools/call"

check := {"server": server, "tool": tool} if tool

check := {"server": server} if not tool

default allow := false

allow if {
	authz.allow with input as check
}

# OPA-Envoy turns this into the denied response's body.
reasons := r if {
	r := authz.deny with input as check
}

result := {"allowed": true} if allow

result := {
	"allowed": false,
	"http_status": 403,
	"body": concat("\n", reasons),
} if not allow
