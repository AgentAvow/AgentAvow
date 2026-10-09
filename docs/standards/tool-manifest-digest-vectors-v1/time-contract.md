# Compare freshness on exact instants

`fresh` means `issuedAt <= evaluation_time < expiresAt` on instants, not on
the written strings or rounded milliseconds. `rely` needs each of the six axes
to be true; `not_evaluated` is not true.

The verifier accepts Gregorian calendar dates with four-digit years, uppercase
`T`, whole seconds, an optional one-to-nine digit fraction, and `Z` or an explicit
`+HH:MM`/`-HH:MM` offset. Equivalent offsets and fractions name the same instant.
It preserves fractions as integer nanoseconds. Calendar-invalid dates, leap
seconds, unknown `-00:00` offsets, whitespace, commas, missing offsets and finer
precision refuse. It never silently truncates them.

The original signed grade expires at `2026-10-02T21:28:34.085197+00:00`.
Mayur021's `2026-10-02T21:28:34.085Z` case is 197 microseconds before expiry.
`Date.parse` maps both to one millisecond, so the earlier verifier refused it.
It also accepted one nanosecond before issuance after the same truncation.
The later microsecond reader handles that original case, but still truncates
digits seven through nine. A separately signed local 200-nanosecond window
tests the resulting early-issuance acceptance and premature-expiry refusal.

The controls use the unchanged signed grade, with exact issuance, exact expiry,
one-nanosecond neighbors, equivalent representations, offsets, day/epoch crossings
and unsupported forms. The original signature, served definitions and digest
rules stay unchanged. The additional signed window uses an ephemeral local
fixture key; it creates no issuer credential or current admission.

From this directory:

```sh
set -eu
node verify.mjs
node --test test-time.mjs
```

Mayur021 supplied the discriminating boundary case. The original AgentAvow fixture
and its contributor attribution stay unchanged. These are offline fixture checks,
not current-time admission or runtime MCP execution.
