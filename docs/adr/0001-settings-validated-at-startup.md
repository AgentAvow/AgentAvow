# ADR 0001: One settings class, validated at startup

- Status: accepted
- Date: 2026-11-16
- Issue: #403

## Context

Several modules read environment variables directly, and a bad value often showed up
only when a request first touched it. The only startup check was a refusal of the
default `JWT_SECRET` outside debug, in `src/main.py`.

Staging and development on the Mac Mini run against localhost Postgres and Redis, so a
blanket "no localhost outside local" rule would stop them. Production runs in Docker
with `DEBUG=false` and doesn't set an environment name.

## Decision

1. **One settings class.** Every setting is a field on `Settings` in `src/config.py`.
   Other code reads `settings.<field>`. `tests/test_no_direct_env_reads.py` walks
   `src/` with `ast` and fails on new `os.environ` / `os.getenv` uses (including
   `import os as x` aliases and `from os import environ`). It is an AST check, not a
   text search, because the scanner's pattern files contain those strings as detection
   data. The reads that existed when the rule landed are a per-file baseline; a file
   may not go above its count, and counts are lowered as reads move into `Settings`.
2. **Format checks wherever settings load.** Pydantic checks the types; validators
   check that `DATABASE_URL` is PostgreSQL, `REDIS_URL` is Redis and `ENVIRONMENT` is
   one of `local`, `staging`, `production`. `load_settings()` turns pydantic's errors
   into a `ConfigError` that names each variable and drops the value (pydantic's own
   message includes the input, which can be a secret). These checks pass with no
   environment at all, so the slim scanner image and scripts still import settings.
3. **Safety refusals at web startup, production only.** `validate_startup()` runs when
   `src/main.py` is imported, so uvicorn exits non-zero before serving. It refuses the
   default `JWT_SECRET` outside debug (as before), a set-but-unusable Ed25519 signing
   seed, `DEBUG=true` with `ENVIRONMENT=production`, and, in production only,
   `DATABASE_URL` or `REDIS_URL` on localhost, a loopback address, `0.0.0.0` or a unix
   socket. All problems are reported together.
4. **Production is inferred when unset.** `ENVIRONMENT` empty means production when
   `DEBUG=false`, local when `DEBUG=true`. Prod needs no new variable; staging and
   tests already run with `DEBUG=true`.
5. **Warnings where prod's values aren't confirmed.** `BASE_URL` on localhost or not
   https, a localhost `CORS_ORIGINS` entry, an unset `ATTESTATION_SIGNING_KEY_ED25519`
   and a `JWT_SECRET` under 32 characters log a warning in production instead of
   refusing. Each can become a refusal once the prod values are confirmed.
6. **`.env.example` lists every field.** `tests/test_settings.py` fails when a field
   is missing from it (a commented-out `# NAME=default` line counts).

## Consequences

- A deploy with a bad or unsafe configuration fails at container start, and the
  deploy's health check sees it, instead of serving half-working scans.
- Adding a setting means a field in `Settings` plus a line in `.env.example`.
- The baseline in `tests/test_no_direct_env_reads.py` (26 reads in 10 files, mostly
  the ERC-8004 bridge, the Bluesky env writes in `src/jobs/scheduler.py` and the
  CI-side scanner entry points) still has to be worked down.
