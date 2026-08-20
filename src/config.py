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
    # github_app_private_key accepts raw PEM, escaped-\n PEM, or base64-of-PEM.
    github_app_id: str | None = None
    github_app_private_key: str | None = None  # PEM (raw, escaped-\n, or base64)
    github_app_installation_id: str | None = None
    # Public "slug" of the App (the github.com/apps/<slug> name) — used to build
    # the per-owner install URL for opt-in private-repo scanning.
    github_app_slug: str | None = None

    # Route bulk repo file-content fetches through raw.githubusercontent.com,
    # which is UNMETERED (does not consume the GitHub API rate-limit budget) —
    # cuts the ~1-API-call-per-file cost of a scan dramatically. The authenticated
    # tree fetch still uses the API (it needs auth), and any raw miss (private
    # repo → 404, transient error) falls back to the Contents API automatically.
    # Set to False to force every content fetch back through the authenticated API.
    scanner_use_raw_content: bool = True

    # --- Phase 1 supply-chain pipeline (OSV / deps.dev / OpenSSF Scorecard) ----
    # Replaces the ~20-package regex dependency check with a real vuln DB: parse
    # the repo's lockfiles → OSV querybatch → hydrate severity → count CVE/GHSA/
    # MAL by band (a MAL- known-malicious match is an automatic critical). All
    # calls are free/no-auth. Fully FEATURE-FLAGGED and FAIL-OPEN: if OSV/deps.dev/
    # Scorecard are unreachable the scan falls back to the legacy regex behaviour
    # and logs — a supply-chain lookup must never break a scan. Flip
    # scanner_use_osv=False to disable the whole pipeline and revert to regex-only.
    scanner_use_osv: bool = True
    scanner_use_depsdev: bool = True       # deps.dev enrichment (license/dependents)
    scanner_use_scorecard: bool = True     # OpenSSF Scorecard aggregate (precomputed)
    # ADVISORY mode: when True, OSV supply-chain findings are collected, signed,
    # and surfaced but do NOT deduct from the grade. Now False — the aggregation
    # is validated: dependency vulns score via the BOUNDED penalty in
    # scan._dependency_penalty (CVE-class capped at 18pts, saturating; a
    # known-malicious/MAL package is disqualifying at 70pts), plus prod-only
    # lockfile filtering + vuln dedupe. This prevents a monorepo's transitive
    # example/test vulns from false-flipping a healthy package to F while still
    # letting real supply-chain risk (especially MAL) move the grade.
    scanner_osv_advisory: bool = False
    # Max lockfile + workflow files fetched per scan for the supply-chain pass.
    scanner_supply_chain_max_lockfiles: int = 8
    scanner_supply_chain_max_workflows: int = 12

    # --- Phase 3 provenance / signing verification ----------------------------
    # Fetch + cryptographically verify a published package's build provenance
    # (npm Sigstore SLSA attestations / PyPI PEP 740) and bind the artifact to its
    # source repo+commit+CI-builder. ADDITIVE, FEATURE-FLAGGED (default OFF until
    # reviewed), and FAIL-OPEN: any network/parse/verify error is treated as "not
    # present" and never breaks a scan. Scoring policy (Kenne decision #4): absent
    # provenance is N/A (never a penalty); present+verified is a small bonus and
    # sets coverage.provenance_binding="verified:<repo>@<commit>"; a package that
    # CLAIMS provenance but fails verification is a small penalty (real red flag).
    # Verification is offline via `cryptography` (DSSE PAE signature + Fulcio
    # SAN/issuer identity gate); it does NOT anchor the Fulcio TUF trust-root nor
    # prove Rekor inclusion — the result records exactly what level was achieved.
    scanner_verify_provenance: bool = True   # enabled 08-09 (additive bonus; verified=+4, absent=0)

    # --- Phase 2: published-ARTIFACT fetch + scan + repo↔artifact drift --------
    # We grade the GitHub repo, but an agent installs the PUBLISHED package, which
    # can differ ("clean repo, poisoned tarball" — event-stream, ctx, xz-utils).
    # When on, after the repo scan we resolve+download the real npm/PyPI artifact
    # FROM THE REGISTRY ONLY (SSRF-guarded, host-allowlisted, size/zip-bomb capped),
    # compute its sha256 digest, unpack it STATICALLY (no execution), re-run the
    # 12-category engine on the extracted tree, detect published install hooks
    # (npm pre/post/install + setup.py AST), and diff the artifact tree vs the repo
    # to surface drift. Sets coverage.scan_depth="artifact" + a real artifact_digest.
    # ADDITIVE, FEATURE-FLAGGED (default OFF — enable after review), and FAIL-OPEN:
    # any fetch/unpack error falls back to the repo-only grade and never breaks a scan.
    scanner_scan_artifact: bool = True   # enabled 08-09 — validate grades + latency live

    # --- Behavioral tier (runs the tool in a gVisor sandbox to observe egress) ----
    # OFF until a dedicated sandbox box is configured. NEVER run the runner locally on
    # prod (it executes untrusted code) — set scanner_behavioral_sandbox_host to the
    # dedicated gVisor instance and the runner is SSH'd there. Fail-open.
    scanner_behavioral_enabled: bool = False
    scanner_behavioral_sandbox_host: str = ""      # dedicated gVisor box IP/host
    scanner_behavioral_sandbox_user: str = "ec2-user"
    scanner_behavioral_sandbox_key: str = ""       # path to the SSH key on the app host
    scanner_behavioral_sandbox_runner: str = "/home/ec2-user/behavioral_run.sh"
    # SSM exec path (preferred — no SSH key on prod). When mode="ssm" and an
    # instance id is set, the runner is sent via AWS Systems Manager instead of SSH.
    scanner_behavioral_sandbox_mode: str = ""      # "ssm" | "ssh" | "" (local)
    scanner_behavioral_sandbox_instance_id: str = ""   # e.g. i-01f112e173bdcfdb6
    scanner_behavioral_sandbox_region: str = "us-east-1"

    # --- Phase 5: maintainer / behavioral trust signals -----------------------
    # Cheap GitHub-METADATA maintainer signals (NO code execution, NO sandbox):
    # bus factor / contributor concentration (/contributors), release cadence +
    # last-push staleness (/releases + pushed_at), archived/abandoned flags,
    # open-issue responsiveness, default-branch protection (/branches), org 2FA
    # (/orgs), and a signed-commit ratio (/commits). ADDITIVE, FEATURE-FLAGGED
    # (default OFF until reviewed), and FAIL-OPEN: any API error → empty signals,
    # the scan is unaffected. Cost-aware: capped at ~5 extra API calls per scan
    # (scanner_maintainer_max_calls), reusing the existing token/client. Scoring
    # (§2.E anti-gaming): strong positives (active maintenance, protected branch,
    # org 2FA, signed commits, contributor diversity) flow through the normal
    # positive_signals bonus; clear negatives (archived/abandoned) apply a small
    # BOUNDED penalty (capped like the dependency model, never a false-F on a
    # small/new repo). Absent/unreadable signals contribute 0 (absence never
    # penalized).
    scanner_maintainer_signals: bool = True  # additive positives + bounded penalty; validated live
    scanner_maintainer_max_calls: int = 5

    # --- A+ "Certified" grade gate (roadmap §7) -------------------------------
    # When ON, the top "A+" label is reserved for tools that pass the full 6-point
    # certified gate (artifact-scanned + verified provenance bound to source + no
    # drift + zero critical/high + recompute-clean + full coverage). A repo-only
    # scan scoring 96+ is then capped at "A" (never A+), and a certified scan in
    # the A band (81+) earns "A+ (Certified)". This ONLY changes the letter LABEL,
    # never the 0-100 score or the trust tier. Default OFF: until it's on,
    # _display_grade == _grade_from_score (score-only), so grades are unchanged.
    # The `certified` block is still computed + surfaced regardless of this flag,
    # so the score page can show certified status before the label gate is flipped.
    scanner_certified_grade_gate: bool = True  # enabled 08-10 — A+ now = certified

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

    # --- Catalog re-scan + growth loop (keeps the browse catalog fresh + grows it) --
    # The browse catalog otherwise goes stale: only watched/claimed/registered tools
    # get routine background re-scans. This loop (a) re-scans the stalest community_scans
    # rows so on-demand grades stay current, and (b) backfills the launch-corpus error
    # backlog into community_scans via the (now more precise) live scanners.
    scheduler_catalog_rescan: bool = True
    catalog_rescan_interval_sec: int = 6 * 60 * 60   # cycle cadence (6h)
    catalog_rescan_startup_delay_sec: int = 300      # don't scan-storm right after deploy
    catalog_rescan_fresh_limit: int = 60             # stalest community rows re-scanned/cycle
    catalog_backfill_limit: int = 40                 # launch-corpus rows backfilled/cycle
    catalog_rescan_spacing_seconds: float = 1.5      # sleep between scans to smooth bursts

    # --- Real-time GitHub rate-limit protection for the PUBLIC scan path -------
    # The daily re-scan job (Job 19) only probes GitHub's budget once/24h. Under
    # live user traffic the public scan API can drain or 429 the 5000/hr GitHub
    # budget mid-day with no signal until the next daily tick. These knobs close
    # that gap: real-time alerting, a self-imposed fresh-scan rate limit, and
    # graceful degradation that serves stale cache instead of blowing the budget.
    #
    # Alert when GitHub's X-RateLimit-Remaining drops below this (a scan can burn
    # up to ~200 core calls, though most file reads go through the unmetered raw
    # host). Fires a throttled admin alert from the live scan path, not just the
    # daily probe. Mirrors scan_health.LOW_REMAINING_THRESHOLD.
    github_ratelimit_alert_threshold: int = 500
    # Throttle window for the real-time rate-limit / low-budget admin alert
    # (independent of the daily 6h scan-health throttle). ~90 min = nudge once
    # per couple hours while a problem persists, without spamming.
    github_ratelimit_alert_throttle_seconds: int = 90 * 60
    # Degradation floor: when remaining drops below this, the public scan path
    # serves STALE cache (even past the 1h TTL) and defers fresh GitHub-hitting
    # scans rather than spending the last of the budget. Lower than the alert
    # threshold so Kenne is warned (500) well before scans start degrading (200).
    github_budget_floor: int = 200
    # TTL on the Redis "github_budget_low" flag — auto-clears so the scan path
    # recovers on its own once the hourly budget resets, even if the probe lags.
    github_budget_low_flag_ttl_seconds: int = 20 * 60
    # Periodic budget probe interval (free GET /rate_limit) that sets/clears the
    # flag between daily ticks. 15-30 min keeps the flag fresh cheaply.
    github_budget_probe_interval_seconds: int = 20 * 60
    # Max seconds the scanner will back off WITHIN a single request when GitHub
    # signals a rate limit (honors Retry-After / X-RateLimit-Reset, capped so a
    # rate-limited GitHub can't hang a uvicorn worker past the request timeout).
    scanner_ratelimit_backoff_cap_seconds: float = 5.0

    # Self-imposed rate limit on the public scan API's FRESH (GitHub-hitting)
    # scans, so user traffic can't uncontrollably drain the GitHub budget. Cached
    # (1h) hits do NOT count — only cache-miss / force=true scans do. Per-IP cap;
    # authenticated callers get 3x (matches the other scan limiter). A clean 429
    # with Retry-After is returned when exceeded.
    rate_limit_fresh_scans_per_minute: int = 10
    # Global fresh-scan cap across ALL IPs, sized under the GitHub budget: ~20/min
    # ≈ 1200/hr; at ~2-4 metered calls/scan (repo + tree; file reads use the
    # unmetered raw host) that stays well under 5000/hr with headroom for the
    # daily re-scan job and badge regeneration.
    rate_limit_global_fresh_scans_per_minute: int = 20

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
    # RAMPED DOWN 2026-08-20: the bot was replying up to ~20/day, unsolicited, to
    # hand-picked strangers with no topic threshold — spam-adjacent, and it earned ~0
    # engagement (a complaint from Xe iaso triggered the review). New posture: FAR less
    # volume, on-topic ONLY, at most once/week per account, quality-gated. No per-post
    # bot disclosure (solo operator) — defensibility comes from behaving well: low
    # frequency, genuine relevance, and never pestering the same person.
    reply_guy_enabled: bool = True
    reply_guy_max_daily: int = 4  # was 20 — global cap across platforms
    reply_guy_monitor_interval: int = 300  # seconds
    reply_guy_auto_post: bool = True  # auto-post drafted replies (no manual approval)
    # Pacing — spread the daily batch instead of bursting at the 00:00 UTC counter reset.
    reply_guy_min_gap_minutes: int = 120  # was 40 — wider spacing between auto-posted replies
    reply_guy_active_start_hour_utc: int = 14  # only auto-post from this UTC hour (US daytime)
    # Twitter writes are metered by the monthly API cap and reply engagement is ~zero.
    reply_guy_twitter_max_daily: int = 2  # was 4
    # Never reply to the same account more than once per this window (anti-pestering).
    reply_guy_target_cooldown_hours: int = 168  # 7 days
    # Only draft/post replies at or above this urgency, AND (when require_relevance) only
    # when the post actually hit a topic keyword — so it never replies to off-topic posts.
    reply_guy_min_urgency: float = 2.8
    reply_guy_require_relevance: bool = True
    # Stale drafts that never posted (daily cap / window / gap) clog the queue and
    # age out of relevance — expire them after this many hours.
    reply_guy_draft_ttl_hours: int = 48
    # Shared secret so an external tool (e.g. the news-digest bot) can POST candidate
    # AI-slop phrases into the approval queue without a full admin login. Empty = the
    # ingest endpoint is disabled. Set via env SLOP_PROPOSAL_SECRET.
    slop_proposal_secret: str = ""

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
