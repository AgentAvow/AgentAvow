package agentavow.envoy_test

import data.agentavow.envoy

mock_dnc(_) := {"status_code": 200, "body": {"decision": "do_not_connect", "decision_reason": "bad", "trust_score": 10}}

mock_safe(_) := {"status_code": 200, "body": {"decision": "safe", "decision_reason": "ok", "trust_score": 90}}

req(path) := {"attributes": {"request": {"http": {"path": path}}}, "parsed_body": {"method": "tools/call", "params": {"name": "t"}}}

routes := {"/mcp/x": "https://mcp.example.com/mcp"}

test_envoy_denies_do_not_connect if {
	r := envoy.result with input as req("/mcp/x") with data.agentavow.envoy.routes as routes with http.send as mock_dnc
	r.allowed == false
	r.http_status == 403
}

test_envoy_allows_safe if {
	envoy.allow with input as req("/mcp/x") with data.agentavow.envoy.routes as routes with http.send as mock_safe
}

test_envoy_unknown_route_denies if {
	not envoy.allow with input as req("/other") with data.agentavow.envoy.routes as routes with http.send as mock_safe
}
