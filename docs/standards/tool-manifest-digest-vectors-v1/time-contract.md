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


## Keep the signed 200-nanosecond regression

[`nanosecond-window-vectors.json`](nanosecond-window-vectors.json) contains the
exact locally signed fixture used for the current-reader comparison. It retains
the six original control shapes and adds these four boundary cases:

| Case | Evaluation time (`2026-10-01T21:28:34` prefix) | `fresh` / `rely` |
| --- | --- | --- |
| `local-before-issuance` | `.085000899Z` | `false` / `false` |
| `local-exact-issuance` | `.085000900Z` | `true` / `true` |
| `local-before-expiry` | `.085001099Z` | `true` / `true` |
| `local-exact-expiry` | `.085001100Z` | `false` / `false` |

From this directory, run:

```sh
node verify.mjs nanosecond-window-vectors.json
```

The signed payload supplies the 200-nanosecond validity window. The copied
unsigned attestation summary retains its original timestamps; those fields do
not control this comparison. The boundary cases keep the copied positive-case
notes, but their `gate` and `expect` fields above define the distinct checks.

Only the ephemeral fixture's public key is included. These historical test
instants and that key establish no producer credential, current admission or
runtime observation. The original `tool-manifest-digest-v1-vectors.json` grade, signature and key stay
unchanged. SHA-256 of this additional file:

`5c17415e2db93b987f1ce5d244a542f22cf7a373fe952a63d8d0f416d0604d20`
