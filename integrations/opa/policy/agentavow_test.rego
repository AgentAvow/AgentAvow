package agentavow.authz_test

import data.agentavow.authz

# ── mocked AgentAvow responses (no network) ──────────────────────────────────

ok(body) := {"status_code": 200, "body": body}

safe_mcp := ok({
	"decision": "safe",
	"decision_reason": "tool definitions clean; server code not inspected",
	"trust_score": 74,
	"report_url": "https://agentavow.com/check/mcp?endpoint=https%3A%2F%2Fmcp.example.com%2Fmcp",
	"tool_digests": {"tool:ask_question": "sha256:aaaa", "tool:read_wiki": "sha256:bbbb"},
})

mock_safe(_) := safe_mcp

mock_dnc(_) := ok({
	"decision": "do_not_connect",
	"decision_reason": "one critical finding in its code: remote pickle/marshal load",
	"trust_score": 34,
	"report_url": "https://agentavow.com/check/oraios/serena",
	"tool_digests": {},
})

mock_review(_) := ok({"decision": "review", "decision_reason": "deprecated by its maintainer", "trust_score": 74})

mock_collection(_) := ok({
	"decision": "safe",
	"trust_score": 90,
	"skill_collection": {"decision": "do_not_connect", "trust_score": 20},
})

mock_down(_) := {"status_code": 0, "error": {"code": "eval_http_send_network_error"}}

mock_500(_) := {"status_code": 500, "body": {"detail": "boom"}}

# Echo the requested URL back so the coordinate tests can read it.
mock_echo(req) := ok({"decision": "safe", "decision_reason": req.url, "trust_score": 90})

# ── the answer ───────────────────────────────────────────────────────────────

test_safe_allows if {
	authz.allow with input as {"server": "https://mcp.example.com/mcp"} with http.send as mock_safe
}

test_safe_result_shape if {
	r := authz.result with input as {"server": "https://mcp.example.com/mcp"} with http.send as mock_safe
	r.allow == true
	r.decision == "safe"
	r.phrase == "Safe to connect"
	r.trust_score == 74
}

test_do_not_connect_denies if {
	not authz.allow with input as {"server": "oraios/serena"} with http.send as mock_dnc
}

test_do_not_connect_reason_leads_with_phrase if {
	msgs := authz.deny with input as {"server": "oraios/serena"} with http.send as mock_dnc
	some m in msgs
	startswith(m, "AgentAvow: Do not connect, one critical finding")
}

test_review_allowed_by_default if {
	authz.allow with input as {"server": "npm:left-pad"} with http.send as mock_review
}

test_review_denied_when_fail_on_review if {
	not authz.allow with input as {"server": "npm:left-pad"}
		with http.send as mock_review
		with data.agentavow.config as {"fail_on": "review"}
}

test_skill_collection_stricter_answer_wins if {
	r := authz.result with input as {"server": "acme/skills"} with http.send as mock_collection
	r.decision == "do_not_connect"
	r.allow == false
}

# ── drift ────────────────────────────────────────────────────────────────────

test_matching_digest_allows if {
	authz.allow with input as {"server": "https://mcp.example.com/mcp", "tool": "ask_question", "tool_digest": "sha256:aaaa"}
		with http.send as mock_safe
}

test_changed_digest_denies if {
	msgs := authz.deny with input as {"server": "https://mcp.example.com/mcp", "tool": "ask_question", "tool_digest": "sha256:evil"}
		with http.send as mock_safe
	some m in msgs
	contains(m, "changed since it was scanned")
}

test_unknown_tool_denies if {
	msgs := authz.deny with input as {"server": "https://mcp.example.com/mcp", "tool": "exfiltrate", "tool_digest": "sha256:cccc"}
		with http.send as mock_safe
	some m in msgs
	contains(m, "not among the tools AgentAvow scanned")
}

test_no_digest_warns_but_allows if {
	r := authz.result with input as {"server": "https://mcp.example.com/mcp", "tool": "ask_question"} with http.send as mock_safe
	r.allow
	"no tool_digest was given; drift not checked" in r.warnings
}

test_non_ascii_tool_name_not_checked if {
	r := authz.result with input as {"server": "https://mcp.example.com/mcp", "tool": "résumé", "tool_digest": "sha256:x"}
		with http.send as mock_safe
	r.allow
	"a tool_digest was given without a usable tool name; drift not checked" in r.warnings
}

# ── API errors ───────────────────────────────────────────────────────────────

test_network_error_fails_closed if {
	not authz.allow with input as {"server": "npm:semver"} with http.send as mock_down
}

test_server_error_fails_closed if {
	not authz.allow with input as {"server": "npm:semver"} with http.send as mock_500
}

test_fail_open_allows_with_warning if {
	r := authz.result with input as {"server": "npm:semver"}
		with http.send as mock_down
		with data.agentavow.config as {"fail_closed": false}
	r.allow
	count(r.warnings) == 1
}

# ── coordinates ──────────────────────────────────────────────────────────────

url_for(server) := u if {
	u := authz.reason with input as {"server": server} with http.send as mock_echo
}

test_url_mcp_endpoint if {
	url_for("https://mcp.deepwiki.com/mcp") == "https://agentavow.com/api/v1/public/scan/mcp?endpoint=https%3A%2F%2Fmcp.deepwiki.com%2Fmcp"
}

test_url_mcp_prefix if {
	url_for("mcp:https://mcp.deepwiki.com/mcp") == "https://agentavow.com/api/v1/public/scan/mcp?endpoint=https%3A%2F%2Fmcp.deepwiki.com%2Fmcp"
}

test_url_npm_scoped if {
	url_for("npm:@modelcontextprotocol/server-filesystem") == "https://agentavow.com/api/v1/public/scan/package/npm/@modelcontextprotocol/server-filesystem"
}

test_url_pypi if {
	url_for("pypi:requests") == "https://agentavow.com/api/v1/public/scan/package/pypi/requests"
}

test_url_github_bare if {
	url_for("vercel/next.js") == "https://agentavow.com/api/v1/public/scan/vercel/next.js"
}

test_url_github_prefixed if {
	url_for("github:vercel/next.js") == "https://agentavow.com/api/v1/public/scan/vercel/next.js"
}

test_server_alias_and_base_url if {
	r := authz.reason with input as {"server": "wiki"}
		with http.send as mock_echo
		with data.agentavow.config as {"servers": {"wiki": "https://mcp.deepwiki.com/mcp"}, "base_url": "https://avow.internal/api/v1/"}
	r == "https://avow.internal/api/v1/public/scan/mcp?endpoint=https%3A%2F%2Fmcp.deepwiki.com%2Fmcp"
}

test_unrecognized_coordinate_denies if {
	msgs := authz.deny with input as {"server": "ftp:something"} with http.send as mock_safe
	some m in msgs
	startswith(m, "unrecognized server coordinate")
}

test_missing_server_denies if {
	msgs := authz.deny with input as {} with http.send as mock_safe
	"no server coordinate in input.server" in msgs
}
