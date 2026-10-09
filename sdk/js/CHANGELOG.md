# Changelog

## 0.3.2 (unreleased; prepared 2026-10-09)

- CLI `scan` leads with the answer (Safe to connect / Review before you connect / Do not connect) and its reason, adds "· Certified" only from `certified_mark` beside Safe, and no longer prints a letter grade. Report links use `/check/pkg/...` for packages and `jwks_url` comes from the response.
- CLI: the unimplemented `verify` command is gone from the accepted commands; verify offline with the `./verify` export.
- `gate`: `certifiedOf()` reads `certified_mark` (never raw `certified.eligible`), and the mark is off whenever the answer isn't Safe.
- `vercel-ai`: the headline adds Certified only on Safe to connect.

## 0.3.1 (2026-10-08)

- See the README's 0.2.x → 0.3.1 table.
