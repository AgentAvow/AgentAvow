# AgentAvow tool manifest — `.agentavow.yml` (v0, draft)

**Status:** Draft · **Version:** `agentavow-manifest-v0`

A tool author can ship an **`.agentavow.yml`** at the root of their repo/package to
**declare what the tool is supposed to do** — the hosts it legitimately contacts and the
capabilities it uses. AgentAvow then holds the tool to its own declaration:

- The **behavioral tier** runs the tool in a sandbox and compares *observed* egress against
  the *declared* egress. Contacting an undeclared host is a finding — "the tool did
  something its author didn't declare" is a far stronger signal than a blocklist guess.
- Declared capabilities let a gateway apply least-privilege (grant only what's declared).

A manifest is **optional and never raises a tool's score** on its own — it can only be
*contradicted* by behavior. Declaring nothing is neutral; declaring something and then
violating it is the finding.

## Format

```yaml
# .agentavow.yml
version: agentavow-manifest-v0

# Hosts this tool legitimately contacts at install- or run-time. Exact hostnames;
# a leading "." means "this host and any subdomain".
egress:
  - registry.npmjs.org
  - .githubusercontent.com
  - api.mytool.com

# Capabilities the tool uses (least-privilege hints for a gateway).
capabilities:
  - filesystem:read        # scoped file reads
  - network:egress         # makes outbound calls (see egress:)
  - process:spawn          # spawns subprocesses

# Optional freeform note shown on the score page.
note: "Fetches models from api.mytool.com; writes only to the cache dir."
```

### Fields
- `version` (string, REQUIRED) — MUST be `agentavow-manifest-v0`.
- `egress` (list of strings, OPTIONAL) — declared outbound hosts. A leading `.` matches the
  host and its subdomains. The package registries are always implicitly allowed.
- `capabilities` (list of strings, OPTIONAL) — from a controlled vocabulary:
  `filesystem:read`, `filesystem:write`, `network:egress`, `process:spawn`, `env:read`.
- `note` (string, OPTIONAL) — a short human note, surfaced on the score page.

Unknown top-level keys are ignored (forward-compatible). A malformed manifest is treated as
*absent*, never as a failure.

## Semantics
- **Declared ⊇ observed ⇒ clean.** If everything the sandbox observes is covered by the
  declaration (+ the registries), no behavioral egress finding is raised.
- **Observed ⊄ declared ⇒ finding.** Any observed host not covered by `egress` (nor a
  registry) is an **undeclared-egress** finding — `high`, or `critical` for multiple.
- A tool with **no manifest** is judged against the registry allowlist only (the default).

## Relationship to other pieces
- Consumed by the behavioral tier: `src/scanner/behavioral/` (`parse_manifest` →
  `run_behavioral(expected_hosts=...)`).
- Complements `tool_manifest_digest` drift detection (static "did the definition change")
  with **declaration-vs-behavior** verification (did it do what it said).
