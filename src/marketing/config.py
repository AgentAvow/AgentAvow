"""Marketing system configuration.

All settings load from environment variables with sensible defaults.
API keys default to None — adapters gracefully skip when unconfigured.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings


class MarketingSettings(BaseSettings):
    """Marketing bot configuration loaded from environment."""

    # --- Feature flag ---
    marketing_enabled: bool = False

    # --- LLM budget ---
    marketing_llm_daily_budget: float = 1.0  # USD per day
    marketing_llm_monthly_budget: float = 20.0  # USD per month

    # --- Local LLM (Ollama) ---
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3.5:9b"
    ollama_timeout: int = 300  # 5 min for 9B model

    # --- Anthropic API ---
    anthropic_api_key: str | None = None
    anthropic_haiku_model: str = "claude-haiku-4-5-20251001"
    anthropic_sonnet_model: str = "claude-sonnet-4-6"
    anthropic_opus_model: str = "claude-opus-4-7"

    # --- Platform API keys (all optional — skip if missing) ---

    # Twitter/X — labels match Twitter Developer Portal exactly
    twitter_bearer_token: str | None = None
    twitter_consumer_key: str | None = None
    twitter_consumer_key_secret: str | None = None
    twitter_access_token: str | None = None
    twitter_access_token_secret: str | None = None
    twitter_client_id: str | None = None
    twitter_client_secret: str | None = None

    # Reddit (via asyncpraw)
    reddit_client_id: str | None = None
    reddit_client_secret: str | None = None
    reddit_username: str | None = None
    reddit_password: str | None = None
    reddit_user_agent: str = "AgentAvowBot/1.0 (by /u/agentavow; +https://agentavow.com)"

    # Discord
    discord_bot_token: str | None = None
    discord_default_channel_id: str | None = None  # Channel for marketing posts

    # LinkedIn (Company page API v2)
    linkedin_access_token: str | None = None
    linkedin_org_id: str | None = None

    # Telegram
    telegram_bot_token: str | None = None
    telegram_channel_id: str | None = None

    # Bluesky (AT Protocol)
    bluesky_handle: str | None = None
    bluesky_app_password: str | None = None

    # Dev.to
    devto_api_key: str | None = None

    # Hashnode
    hashnode_api_key: str | None = None
    hashnode_publication_id: str | None = None

    # GitHub (for Discussions — reuses main github_token from config.py)
    # Falls back to src.config.settings.github_token

    # HuggingFace
    huggingface_token: str | None = None

    # --- Scheduling cadences (seconds) ---
    twitter_post_interval: int = 24 * 60 * 60       # 1/day
    reddit_post_interval: int = 24 * 60 * 60         # 1/day
    discord_post_interval: int = 24 * 60 * 60        # 1/day
    linkedin_post_interval: int = 24 * 60 * 60       # 1/day
    bluesky_post_interval: int = 24 * 60 * 60        # 1/day
    telegram_post_interval: int = 24 * 60 * 60       # 1/day
    devto_post_interval: int = 7 * 24 * 60 * 60      # Weekly
    hashnode_post_interval: int = 7 * 24 * 60 * 60   # Weekly

    # Reactive keyword check interval
    monitor_check_interval: int = 15 * 60  # 15 min

    # Metric refresh interval
    metrics_refresh_interval: int = 2 * 60 * 60  # 2hr

    # --- Content settings ---
    topic_cooldown_hours: int = 48  # Don't repeat same topic on same platform
    max_retry_count: int = 3
    content_dedup_window_days: int = 30  # SHA-256 dedup window

    # --- Launch phase ---
    # Set to False after public launch to remove "coming soon" framing
    pre_launch: bool = False

    # --- Reddit posting-day reminder ---
    # Email nudge to manually post to Reddit on scheduled days. Set to False in
    # prod (env: REDDIT_REMINDER_ENABLED=false) to disable the reminder without a
    # code change — the nudge is just noise while Reddit is paused/dead.
    reddit_reminder_enabled: bool = True

    # --- Notification email ---
    marketing_notify_email: str = "social@agentavow.com"

    # --- UTM defaults ---
    utm_source: str = "agentavow_bot"

    model_config = {
        "env_file": (".env", ".env.secrets"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


marketing_settings = MarketingSettings()

# Per-platform posting schedule: which days to post, how many per week,
# and whether the platform can auto-post or needs human review.
# Reduced schedule — quality over quantity.
# Every post must contain original scan data or analysis.
# Reply guy (Job 21) stays at 20/day. Auto-follow stays on.
PLATFORM_SCHEDULE: dict[str, dict] = {
    # Auto-post restored Jun 9 after fixing the engine self-label leak
    # (_strip_meta_prefix + prompt guards in content/engine.py).
    "twitter": {"posts_per_week": 1, "auto_post": True, "days": ["wed"]},
    "bluesky": {"posts_per_week": 2, "auto_post": True, "days": ["mon", "fri"]},
    # DISABLED until May 1 — account karma is -1, dead channel
    "reddit": {"posts_per_week": 0, "auto_post": False, "days": []},
    "huggingface": {"posts_per_week": 1, "auto_post": True, "days": ["wed"]},
    "devto": {"posts_per_week": 1, "auto_post": True, "days": ["thu"]},  # weekly article
    # Founder posts: 1 draft/week → human_review. Kenne edits into his own voice and posts from
    # his PERSONAL Founder profile (personal reach >> company page). Never auto-posts.
    # 1/week baseline keeps it sustainable + uncluttered; milestone trigger adds extra drafts for
    # real news so timely moments aren't missed. (Was 3/week — too much unconsumed supply.)
    "linkedin": {"posts_per_week": 1, "auto_post": False, "days": ["wed"]},
    "hashnode": {"posts_per_week": 0, "auto_post": False, "days": []},  # manual only
    "github_discussions": {"posts_per_week": 0, "auto_post": False, "days": []},  # MCP ban risk
    "telegram": {"posts_per_week": 0, "auto_post": False, "days": []},  # no audience
    "discord": {"posts_per_week": 0, "auto_post": False, "days": []},  # DISABLED — no audience
}
