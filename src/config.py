from __future__ import annotations

import secrets

from pydantic_settings import BaseSettings

_DEFAULT_SECRET = "CHANGE-ME-IN-PRODUCTION"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "AgentAvow"
    # Brand shown on embeddable trust badges. Kept as "AgentGraph" until the
    # AgentAvow cutover; flip via env (BADGE_BRAND=AgentAvow) at launch so the
    # rebrand is a one-line change and the new name isn't leaked publicly early.
    badge_brand: str = "AgentAvow"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    base_url: str = "http://localhost:5173"

    # Database
    database_url: str = "postgresql+asyncpg://localhost:5432/agentgraph"
    db_pool_size: int = 10
    db_max_overflow: int = 20

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Auth
    jwt_secret: str = _DEFAULT_SECRET
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7

    # Google OAuth
    google_client_id: str | None = None
    google_client_secret: str | None = None

    # GitHub OAuth
    github_client_id: str | None = None
    github_client_secret: str | None = None

    # CORS
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        # Add your local dev server IPs to CORS_ORIGINS env var
        "https://agentgraph.co",
    ]

    # Rate limiting — human tier (default, also used by existing rate_limit_reads/writes)
    rate_limit_reads_per_minute: int = 100
    rate_limit_writes_per_minute: int = 20
    rate_limit_auth_per_minute: int = 5
    trusted_proxies: list[str] = []

    # Rate limiting — anonymous tier (no auth)
    rate_limit_anon_reads_per_minute: int = 30
    rate_limit_anon_writes_per_minute: int = 10

    # Rate limiting — public-scan history endpoint (more restrictive than
    # generic reads because each call does live-fetch + JCS canonicalize +
    # JWS sign + database lookup; defends launch-week press traffic)
    rate_limit_history_reads_per_minute: int = 10

    # On-demand /public/scan/{owner}/{repo} — a cache miss clones + scans a repo
    # (expensive). Tighter per-IP cap than generic reads to stop scan-hammering;
    # authenticated callers get 3x (see rate_limit_scans). Cache hits still count,
    # but 20/min/IP is generous for humans and stops abuse.
    rate_limit_scans_per_minute: int = 20

    # Rate limiting — provisional agent tier (unclaimed agents)
    rate_limit_provisional_reads_per_minute: int = 50
    rate_limit_provisional_writes_per_minute: int = 10

    # Rate limiting — agent tier (entity.type == "agent")
    rate_limit_agent_reads_per_minute: int = 300
    rate_limit_agent_writes_per_minute: int = 150

    # Rate limiting — trusted agent tier (agent with trust_score > 0.7)
    rate_limit_trusted_agent_reads_per_minute: int = 600
    rate_limit_trusted_agent_writes_per_minute: int = 300

    # Trust score threshold for the trusted_agent tier
    rate_limit_trusted_agent_threshold: float = 0.7

    # Stripe Connect
    stripe_secret_key: str | None = None
    stripe_webhook_secret: str | None = None
    stripe_platform_fee_percent: int = 10
    escrow_auto_release_hours: int = 72

    # Webhook encryption (Fernet key for signing key at-rest encryption)
    webhook_encryption_key: str | None = None

    # Ed25519 attestation signing key (base64-encoded 32-byte seed)
    # Generate with: scripts/generate_signing_key.py
    attestation_signing_key_ed25519: str | None = None

    # Dedicated Ed25519 key for Trust Score v2 envelopes (base64 32-byte seed).
    # When unset, v2 signing falls back to attestation_signing_key_ed25519 so
    # nothing breaks; set this to publish a distinct kid (trust-v2-2026) per
    # the spec (trust-score-v2-design §9.1).
    trust_v2_signing_key_ed25519: str | None = None

    # SSO
    sso_enabled: bool = False  # Must be explicitly enabled; mock impl is not safe
    sso_saml_entity_id: str = "agentgraph-sp"
    sso_callback_base_url: str = "http://localhost:8000"

    # Email — Resend (preferred) or SMTP fallback
    resend_api_key: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    from_email: str = "noreply@agentgraph.co"

    # Perspective API (Google text toxicity scoring)
    perspective_api_key: str | None = None
    perspective_toxicity_block: float = 0.85
    perspective_toxicity_flag: float = 0.70
    perspective_timeout: int = 5

    # Auto-moderation: auto-hide posts with this many flags
    auto_hide_flag_threshold: int = 5

    # Framework trust modifiers — per-framework multiplier for trust scoring
    # Applied to agents from each framework during registration and trust computation
    framework_trust_modifiers: dict[str, float] = {
        "native": 1.0,       # AgentGraph-native agents — full trust
        "nanoclaw": 0.95,    # NanoClaw — clean, lightweight
        "pydantic_ai": 0.90, # Pydantic AI — well-maintained, Tier 1
        "crewai": 0.85,      # CrewAI — established, good governance
        "langchain": 0.80,   # LangChain — large ecosystem, varying quality
        "autogen": 0.80,     # AutoGen — Microsoft-backed
        "mcp": 0.85,         # Generic MCP — varies by implementation
        "openclaw": 0.65,    # OpenClaw — 512 vulns, 12% malware in skills
    }

    # Provisional trust cap (max trust score for provisional agents)
    provisional_trust_cap: float = 0.3

    # Background scheduler
    enable_scheduler: bool = False
    trust_recompute_interval_seconds: int = 6 * 60 * 60  # 6 hours

    # GitHub API token (for higher rate limits in source import)
    # Legacy PAT — used only if GitHub App credentials below are not configured.
    github_token: str | None = None

    # GitHub App credentials (preferred over PAT — private key does not expire)
    # See src/github_auth.py for the token-minting flow.
    github_app_id: str | None = None
    github_app_private_key: str | None = None  # full PEM (may have escaped \n)
    github_app_installation_id: str | None = None

    # Security re-scan job (Job 19 in src/jobs/scheduler.py) — periodic re-scan of
    # catalog entries so grades don't rot. Caps are CONFIGURABLE and sized to stay
    # under the PAT's 5000 core-req/hr budget.
    #
    # Rate-limit math: each scan does ~1 API call per file (repo + tree + up to
    # scan._MAX_FILES_PER_REPO=200 file fetches), so ~200 calls is the per-scan
    # ceiling and ~25 maxed-out scans would exhaust 5000/hr. Real repos are far
    # smaller (~15–45 calls each), so 50 rescans + 25 cache-warms = 75 scans/run
    # ≈ ~2–3k calls in the common case. The job runs once/24h, so the per-run cap
    # is also the per-hour ceiling. Two backstops keep the worst case (every repo
    # at the 200-file cap) from blowing the budget: rescan_all_agents pre-checks
    # /rate_limit and bails when core-remaining drops under a floor, and
    # scan_health emits a throttled "rate limit low" admin alert. The aggressive
    # version of these caps lands later with the GitHub App (higher budget).
    security_rescan_limit: int = 50           # agents re-scanned per run (was 20)
    public_cache_refresh_limit: int = 25      # public repos cache-warmed per run (was 10)
    security_rescan_staleness_days: int = 7   # re-scan agents older than this many days
    security_rescan_spacing_seconds: float = 1.0  # sleep between scans to smooth bursts
    security_rescan_min_budget: int = 300     # abort the run if core-remaining drops below this

    # Admin account email (used for bot ownership, alerts, marketing)
    admin_email: str = "admin@agentgraph.co"

    # Marketing bot system
    marketing_enabled: bool = False

    # Operator recruitment (GitHub outreach)
    recruitment_enabled: bool = False
    recruitment_daily_limit: int = 20
    github_outreach_token: str | None = None

    # Bluesky feed generator
    bluesky_feed_enabled: bool = False

    # Bluesky starter pack — auto-refresh every 30 days
    starter_pack_refresh_enabled: bool = True
    bluesky_did: str = ""  # e.g. did:plc:abc123 — the agentgraph.bsky.social DID
    domain: str = "agentgraph.co"

    # Reply Guy system
    reply_guy_enabled: bool = True
    reply_guy_max_daily: int = 20
    reply_guy_monitor_interval: int = 300  # seconds
    reply_guy_auto_post: bool = True  # auto-post drafted replies (no manual approval)
    # Pacing — spread the daily batch instead of bursting at the 00:00 UTC counter reset.
    reply_guy_min_gap_minutes: int = 40  # min spacing between auto-posted replies (anti-burst)
    reply_guy_active_start_hour_utc: int = 14  # only auto-post from this UTC hour (US daytime)

    # Email rate limiting & retry
    email_rate_limit_per_minute: int = 30
    email_retry_max_attempts: int = 3
    email_retry_base_delay: float = 1.0  # seconds, doubles each retry

    # Error tracking
    sentry_dsn: str | None = None

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()

# If debug mode uses the default secret, replace it with a random one so
# even dev tokens are unpredictable.  Non-debug mode crashes in main.py.
if settings.debug and settings.jwt_secret == _DEFAULT_SECRET:
    settings.jwt_secret = secrets.token_urlsafe(64)
