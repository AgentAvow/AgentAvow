"""One validated settings class (#403): format checks, production-only refusals,
no values in errors, and .env.example parity."""
from __future__ import annotations

import base64
import logging
import re
from pathlib import Path

import pytest

from src.config import (
    _DEFAULT_SECRET,
    ConfigError,
    Settings,
    is_loopback_url,
    load_settings,
    validate_startup,
)

ROOT = Path(__file__).resolve().parent.parent

SECRET_LOOKING = "s3cr3t-value-that-must-not-leak"
GOOD_SEED = base64.b64encode(b"\x01" * 32).decode()

PROD_OK = {
    "debug": False,
    "environment": "",
    "database_url": "postgresql+asyncpg://agentgraph:pw@postgres:5432/agentgraph",
    "redis_url": "redis://:pw@redis:6379/0",
    "jwt_secret": "x" * 64,
    "base_url": "https://agentavow.com",
    "cors_origins": ["https://agentavow.com"],
    "attestation_signing_key_ed25519": GOOD_SEED,
}


def _settings(**kw) -> Settings:
    return load_settings(_env_file=None, **kw)


def _prod(**kw) -> Settings:
    return _settings(**{**PROD_OK, **kw})


# --- Environment -------------------------------------------------------------

@pytest.mark.parametrize(
    ("raw", "expected"),
    [("", ""), ("production", "production"), ("PROD", "production"),
     ("staging", "staging"), ("dev", "local"), ("Local", "local")],
)
def test_environment_aliases(raw, expected):
    assert _settings(environment=raw).environment == expected


def test_effective_environment_follows_debug_when_unset():
    assert _settings(debug=False).effective_environment == "production"
    assert _settings(debug=True).effective_environment == "local"
    assert _settings(debug=False, environment="staging").effective_environment == "staging"


def test_unknown_environment_is_refused_by_name():
    with pytest.raises(ConfigError) as exc:
        _settings(environment="qa-box")
    assert "ENVIRONMENT" in str(exc.value)
    assert "qa-box" not in str(exc.value)


# --- Malformed values: named, never echoed ------------------------------------

def test_malformed_int_names_variable_without_value():
    with pytest.raises(ConfigError) as exc:
        _settings(db_pool_size=SECRET_LOOKING)
    msg = str(exc.value)
    assert "DB_POOL_SIZE" in msg
    assert SECRET_LOOKING not in msg
    assert exc.value.__cause__ is None and exc.value.__suppress_context__


def test_every_bad_variable_is_listed():
    with pytest.raises(ConfigError) as exc:
        _settings(db_pool_size="nope", smtp_port="nope", debug="maybe")
    msg = str(exc.value)
    for name in ("DB_POOL_SIZE", "SMTP_PORT", "DEBUG"):
        assert name in msg
    assert "3 problem" in msg


def test_non_postgres_database_url_is_refused():
    url = f"mysql://root:{SECRET_LOOKING}@db/x"
    with pytest.raises(ConfigError) as exc:
        _settings(database_url=url)
    assert "DATABASE_URL" in str(exc.value)
    assert SECRET_LOOKING not in str(exc.value)


def test_non_redis_url_is_refused():
    with pytest.raises(ConfigError) as exc:
        _settings(redis_url=f"http://:{SECRET_LOOKING}@redis:6379")
    assert "REDIS_URL" in str(exc.value)
    assert SECRET_LOOKING not in str(exc.value)


def test_malformed_json_list_from_env_is_named(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "[not json")
    with pytest.raises(ConfigError) as exc:
        load_settings(_env_file=None)
    assert "cors_origins" in str(exc.value)
    assert "[not json" not in str(exc.value)


def test_defaults_load_everywhere():
    """The slim scanner image and scripts import settings with no env at all."""
    s = _settings()
    assert s.database_url.startswith("postgresql")


# --- Loopback detection --------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "postgresql+asyncpg://u:p@localhost:5432/db",
        "postgresql+asyncpg://u:p@127.0.0.1/db",
        "postgresql+asyncpg://u:p@127.0.0.2/db",
        "redis://[::1]:6379/0",
        "redis://0.0.0.0:6379",
        "redis://LOCALHOST:6379",
        "http://app.localhost:5173",
        "unix:///tmp/redis.sock",
    ],
)
def test_loopback_urls(url):
    assert is_loopback_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+asyncpg://agentgraph:pw@postgres:5432/agentgraph",
        "redis://:pw@redis:6379/0",
        "https://agentavow.com",
        "redis://10.0.0.4:6379",
        "postgresql+asyncpg:///agentgraph",
    ],
)
def test_non_loopback_urls(url):
    assert not is_loopback_url(url)


# --- Startup checks ------------------------------------------------------------

def test_prod_shaped_config_passes():
    assert validate_startup(_prod()) == []


@pytest.mark.parametrize("field", ["database_url", "redis_url"])
def test_loopback_refused_in_production(field):
    url = {
        "database_url": f"postgresql+asyncpg://u:{SECRET_LOOKING}@localhost/agentgraph",
        "redis_url": f"redis://:{SECRET_LOOKING}@127.0.0.1:6379/0",
    }[field]
    with pytest.raises(ConfigError) as exc:
        validate_startup(_prod(**{field: url}))
    assert field.upper() in str(exc.value)
    assert SECRET_LOOKING not in str(exc.value)


def test_missing_database_and_redis_refused_in_production(monkeypatch):
    """Unset means the localhost defaults, which production refuses."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    s = _settings(**{k: v for k, v in PROD_OK.items()
                     if k not in ("database_url", "redis_url")})
    with pytest.raises(ConfigError) as exc:
        validate_startup(s)
    assert "DATABASE_URL" in str(exc.value) and "REDIS_URL" in str(exc.value)


@pytest.mark.parametrize(
    "kw",
    [{"debug": True}, {"debug": False, "environment": "staging"},
     {"debug": False, "environment": "local"}],
)
def test_localhost_allowed_outside_production(kw):
    """Staging and dev on the Mac Mini use localhost Postgres and Redis."""
    s = _settings(
        database_url="postgresql+asyncpg://localhost:5432/agentgraph_staging",
        redis_url="redis://localhost:6379/1",
        jwt_secret="y" * 64,
        **kw,
    )
    assert validate_startup(s) == []


def test_default_jwt_secret_refused_outside_debug():
    for env in ("", "staging"):
        with pytest.raises(ConfigError) as exc:
            validate_startup(_prod(jwt_secret=_DEFAULT_SECRET, environment=env))
        assert "JWT_SECRET" in str(exc.value)


def test_debug_with_explicit_production_refused():
    with pytest.raises(ConfigError) as exc:
        validate_startup(_prod(debug=True, environment="production"))
    assert "DEBUG" in str(exc.value)


def test_bad_signing_seed_refused_without_value():
    bad = base64.b64encode(SECRET_LOOKING.encode()).decode()
    with pytest.raises(ConfigError) as exc:
        validate_startup(_prod(attestation_signing_key_ed25519=bad))
    assert "ATTESTATION_SIGNING_KEY_ED25519" in str(exc.value)
    assert bad not in str(exc.value)


def test_all_problems_reported_together():
    with pytest.raises(ConfigError) as exc:
        validate_startup(_prod(
            jwt_secret=_DEFAULT_SECRET,
            database_url="postgresql+asyncpg://localhost/agentgraph",
            redis_url="redis://localhost:6379/0",
        ))
    msg = str(exc.value)
    assert "3 problem" in msg
    for name in ("JWT_SECRET", "DATABASE_URL", "REDIS_URL"):
        assert name in msg


def test_unsure_production_settings_only_warn(caplog):
    s = _prod(
        base_url="http://localhost:5173",
        cors_origins=["http://localhost:3000", "https://agentavow.com"],
        jwt_secret="short-but-set",
        attestation_signing_key_ed25519=None,
    )
    with caplog.at_level(logging.WARNING, logger="src.config"):
        warnings = validate_startup(s)
    joined = " ".join(warnings)
    for name in ("BASE_URL", "CORS_ORIGINS", "JWT_SECRET", "ATTESTATION_SIGNING_KEY_ED25519"):
        assert name in joined
    assert "short-but-set" not in caplog.text


def test_main_runs_the_startup_check():
    src = (ROOT / "src" / "main.py").read_text(encoding="utf-8")
    assert "_validate_startup(settings)" in src


# --- .env.example parity -------------------------------------------------------

def _env_example_names() -> set[str]:
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    return set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]*)=", text, re.MULTILINE))


def test_every_setting_is_in_env_example():
    listed = _env_example_names()
    missing = sorted(n.upper() for n in Settings.model_fields if n.upper() not in listed)
    assert not missing, (
        "Add these settings to .env.example (commented out with the default is fine):\n  "
        + "\n  ".join(missing)
    )


def test_parity_check_catches_a_new_field():
    class Extended(Settings):
        brand_new_setting_for_test: int = 1

    listed = _env_example_names()
    missing = [n for n in Extended.model_fields if n.upper() not in listed]
    assert missing == ["brand_new_setting_for_test"]
