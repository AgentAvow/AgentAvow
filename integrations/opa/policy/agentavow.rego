# AgentAvow policy for Open Policy Agent.
#
# Refuses an agent's tool call or MCP server connection when AgentAvow's answer for
# that server is "Do not connect" (or, with fail_on = "review", "Review before you
# connect"), and refuses a tool whose served definition no longer matches the
# per-tool digest signed into AgentAvow's scan (the rug-pull).
#
# Query data.agentavow.authz.allow (boolean) or data.agentavow.authz.result (the
# decision with its reasons). See ../README.md.
package agentavow.authz

# ── configuration (override under data.agentavow.config) ─────────────────────

default_config := {
	"base_url": "https://agentavow.com/api/v1",
	"web_url": "https://agentavow.com", # where report links point
	"fail_on": "do_not_connect", # "do_not_connect" | "review"
	"fail_closed": true, # an API error denies (true) or allows with a warning (false)
	"cache_seconds": 3600, # AgentAvow caches a verdict for an hour
	"timeout": "10s",
	"servers": {}, # {"<name>": "<coordinate>"} for servers referred to by name
}

default user_config := {}

user_config := data.agentavow.config

config := object.union(default_config, user_config)

# ── the coordinate ───────────────────────────────────────────────────────────

package_surfaces := {"npm", "pypi", "crates", "docker", "huggingface"}

# input.server is a coordinate (https://… MCP endpoint, npm:…, pypi:…, crates:…,
# docker:…, huggingface:…, github:owner/repo or owner/repo) or a name in
# config.servers.
coordinate := config.servers[input.server]

coordinate := input.server if {
	is_string(input.server)
	not config.servers[input.server]
}

low := lower(trim_space(coordinate))

kind := "mcp" if startswith(low, "https://")

kind := "mcp" if startswith(low, "mcp:")

kind := "github" if startswith(low, "github:")

kind := surface if {
	some surface in package_surfaces
	startswith(low, concat("", [surface, ":"]))
}

kind := "github" if {
	not contains(low, ":")
	count(split(trim(low, "/"), "/")) == 2
}

target := trim_space(coordinate) if startswith(low, "https://")

target := trim_space(substring(trim_space(coordinate), 4, -1)) if startswith(low, "mcp:")

target := trim(substring(trim_space(coordinate), 7, -1), "/ ") if startswith(low, "github:")

target := trim_space(substring(trim_space(coordinate), count(surface) + 1, -1)) if {
	some surface in package_surfaces
	startswith(low, concat("", [surface, ":"]))
}

target := trim(trim_space(coordinate), "/") if {
	kind == "github"
	not startswith(low, "github:")
}

base := trim_right(config.base_url, "/")

grade_url := sprintf("%s/public/scan/mcp?endpoint=%s", [base, urlquery.encode(target)]) if kind == "mcp"

grade_url := sprintf("%s/public/scan/%s", [base, target]) if kind == "github"

grade_url := sprintf("%s/public/scan/package/%s/%s", [base, kind, target]) if {
	kind in package_surfaces
}

# ── the lookup (cached by OPA for cache_seconds) ─────────────────────────────

response := http.send({
	"method": "GET",
	"url": grade_url,
	"headers": {"Accept": "application/json", "User-Agent": "agentavow-opa/1.0"},
	"force_cache": true,
	"force_cache_duration_seconds": config.cache_seconds,
	"raise_error": false,
	"timeout": config.timeout,
})

api_ok if {
	response.status_code == 200
	is_object(response.body)
	is_string(response.body.decision)
}

body := response.body if api_ok

# ── the answer ───────────────────────────────────────────────────────────────

severity := {"safe": 0, "review": 1, "do_not_connect": 2}

phrases := {
	"safe": "Safe to connect",
	"review": "Review before you connect",
	"do_not_connect": "Do not connect",
}

# A GitHub repo that is a collection of agent skills also carries the result of its
# weakest skill; the stricter of the two answers stands.
answers contains body.decision if api_ok

answers contains body.skill_collection.decision if {
	api_ok
	is_string(body.skill_collection.decision)
}

decision := d if {
	api_ok
	worst := max({severity[a] | some a in answers})
	some d, s in severity
	s == worst
}

fail_from := severity[config.fail_on]

reason := object.get(body, "decision_reason", "") if api_ok

web := trim_right(config.web_url, "/")

built_report_url := sprintf("%s/check/mcp?endpoint=%s", [web, urlquery.encode(target)]) if kind == "mcp"

built_report_url := sprintf("%s/check/%s", [web, target]) if kind == "github"

built_report_url := sprintf("%s/check/pkg/%s/%s", [web, kind, target]) if kind in package_surfaces

report_url := body.report_url if {
	api_ok
	is_string(body.report_url)
	body.report_url != ""
}

report_url := built_report_url if {
	api_ok
	not body_report_url
}

body_report_url if {
	is_string(body.report_url)
	body.report_url != ""
}

score := object.get(body, "trust_score", null) if api_ok

# ── deny reasons ─────────────────────────────────────────────────────────────

deny contains msg if {
	not coordinate
	msg := "no server coordinate in input.server"
}

deny contains msg if {
	coordinate
	not grade_url
	msg := sprintf("unrecognized server coordinate: %v", [coordinate])
}

deny contains msg if {
	severity[decision] >= fail_from
	msg := sprintf("AgentAvow: %s, %s (trust %v/100). Report: %s", [phrases[decision], reason, score, report_url])
}

deny contains msg if {
	grade_url
	not api_ok
	config.fail_closed
	msg := sprintf("AgentAvow could not answer for %s (HTTP %v); failing closed", [coordinate, response.status_code])
}

# Drift: the caller passes the served definition's digest (computed exactly as the
# attestation signs it: sha256 over JCS({profile, tool}); every AgentAvow SDK
# exports the function) and the tool's name. Only ASCII tool names are keyed here;
# others are reported as not checked.
has_digest if is_string(input.tool_digest)

signed_digests := object.get(body, "tool_digests", {}) if api_ok

tool_key := concat("", ["tool:", input.tool]) if {
	is_string(input.tool)
	regex.match(`^[\x21-\x7e]+$`, input.tool)
	not contains(input.tool, "%")
	not contains(input.tool, "=")
	count(input.tool) <= 128
}

deny contains msg if {
	has_digest
	tool_key
	signed := signed_digests[tool_key]
	signed != input.tool_digest
	msg := sprintf("AgentAvow: the definition of '%s' on %s changed since it was scanned (signed %s, served %s). Report: %s", [input.tool, coordinate, signed, input.tool_digest, report_url])
}

deny contains msg if {
	has_digest
	tool_key
	count(signed_digests) > 0
	not signed_digests[tool_key]
	msg := sprintf("AgentAvow: '%s' is not among the tools AgentAvow scanned on %s; the server added it since. Report: %s", [input.tool, coordinate, report_url])
}

warnings contains msg if {
	grade_url
	not api_ok
	not config.fail_closed
	msg := sprintf("AgentAvow could not answer for %s (HTTP %v); allowed because fail_closed is false", [coordinate, response.status_code])
}

warnings contains "a tool_digest was given without a usable tool name; drift not checked" if {
	has_digest
	not tool_key
}

warnings contains "no tool_digest was given; drift not checked" if {
	api_ok
	count(signed_digests) > 0
	not has_digest
}

# ── outputs ──────────────────────────────────────────────────────────────────

default allow := false

allow if count(deny) == 0

default out_decision := ""

out_decision := decision

default out_score := null

out_score := score

default out_report_url := ""

out_report_url := report_url

result := {
	"allow": allow,
	"decision": out_decision,
	"phrase": object.get(phrases, out_decision, ""),
	"trust_score": out_score,
	"report_url": out_report_url,
	"deny": deny,
	"warnings": warnings,
}
