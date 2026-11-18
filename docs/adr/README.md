# Architecture decision records

Short notes on decisions that are already made, so nobody reopens them by accident.
Each record says what was decided, why, and what it costs. They are not plans or
proposals: a decision gets a record once the owner has made it.

## How to add one

1. Copy `0000-template.md` to the next free number, e.g. `0003-short-title.md`.
2. Fill it in. Point at the files, PRs or issues that show the decision.
3. Add a line to the index below in the same PR.

A record is not rewritten to say something different. If a decision changes, write a
new record that supersedes the old one and set the old one's status to
"Superseded by NNNN".

## Index

| # | Decision | Status |
|---|----------|--------|
| [0001](0001-tech-stack.md) | The tech stack is decided | Accepted |
| [0002](0002-old-machine-identifiers-stay.md) | Machine identifiers keep the `agentgraph` name after the rebrand | Accepted |
| [0003](0003-settings-validated-at-startup.md) | One settings class, validated at startup; safety refusals in production only | Accepted |
| [0004](0004-structured-logs-and-trace-ids.md) | Structured JSON logs, request and trace ids, redaction; no OpenTelemetry SDK | Accepted |
| [0005](0005-errors-are-problem-json.md) | API errors are RFC 9457 problem+json from one code catalog; old `detail` and `request_id` kept | Accepted |
| [0006](0006-api-contract.md) | The OpenAPI document is committed; CI fails when it is stale or breaks a client; routes stay under `/api/v1` | Accepted |
| [0007](0007-idempotency-key.md) | An optional `Idempotency-Key` makes retried POST and PATCH writes safe; never required, fails closed only for keyed requests | Accepted |
