from __future__ import annotations

import os

import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

DB_URL = os.environ.get(
    "DATABASE_URL", "postgresql+asyncpg://localhost:5432/agentgraph_test"
)

# Tables to truncate before the test session (order respects FK constraints).
_TABLES = [
    "linked_accounts",
    "issue_reports",
    "trust_score_history",
    "aip_messages", "aip_channels",
    "content_links",
    "behavioral_baselines", "interaction_events", "service_contracts",
    "population_alerts", "attestation_providers", "formal_attestations",
    "anomaly_alerts", "propagation_alerts", "org_usage_records",
    "delegations", "agent_capability_registry", "organization_memberships",
    "organizations", "audit_records", "verification_badges",
    "framework_security_scans", "moderation_appeals", "analytics_events",
    "submolt_memberships", "direct_messages", "conversations",
    "entity_blocks", "reviews", "trust_attestations",
    "capability_endorsements", "post_edits", "bookmarks",
    "webhook_delivery_logs",
    "webhook_subscriptions", "notification_preferences", "notifications",
    "marketing_campaigns", "marketing_posts",
    "disputes", "transactions", "listing_reviews", "listings",
    "token_blacklist", "password_reset_tokens", "email_verifications",
    "audit_logs", "evolution_records", "moderation_flags",
    "api_keys", "did_documents", "trust_scores", "votes", "posts",
    "community_scans",
    "entity_relationships", "submolts", "entities",
]


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _clean_db_once():
    """Truncate all tables once at the start of the test session.

    This removes stale committed data from prior runs so that each test
    starts from a known-clean database (combined with the per-test
    transaction rollback in the ``db`` fixture).
    """
    engine = create_async_engine(DB_URL, echo=False)
    async with engine.begin() as conn:
        # Ensure newer tables exist (migration may not have run on test DB)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS interaction_events ("
            "  id UUID PRIMARY KEY,"
            "  entity_a_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  entity_b_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  interaction_type VARCHAR(50) NOT NULL,"
            "  context JSONB,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_interaction_entity_a "
            "ON interaction_events (entity_a_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_interaction_entity_b "
            "ON interaction_events (entity_b_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_interaction_type "
            "ON interaction_events (interaction_type)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_interaction_created_at "
            "ON interaction_events (created_at)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_interaction_pairwise "
            "ON interaction_events (entity_a_id, entity_b_id, interaction_type)"
        ))
        # Ensure primary_context column exists on entities (migration m01)
        await conn.execute(text(
            "ALTER TABLE entities ADD COLUMN IF NOT EXISTS "
            "primary_context VARCHAR(100)"
        ))
        # Ensure recurring delegation columns exist (migration n01)
        await conn.execute(text(
            "ALTER TABLE delegations ADD COLUMN IF NOT EXISTS "
            "recurrence VARCHAR(20)"
        ))
        await conn.execute(text(
            "ALTER TABLE delegations ADD COLUMN IF NOT EXISTS "
            "recurrence_count INTEGER DEFAULT 0 NOT NULL"
        ))
        await conn.execute(text(
            "ALTER TABLE delegations ADD COLUMN IF NOT EXISTS "
            "max_recurrences INTEGER"
        ))
        await conn.execute(text(
            "ALTER TABLE delegations ADD COLUMN IF NOT EXISTS "
            "parent_delegation_id UUID REFERENCES delegations(id) ON DELETE SET NULL"
        ))
        # Ensure population_alerts table exists (migration m02)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS population_alerts ("
            "  id UUID PRIMARY KEY,"
            "  alert_type VARCHAR(50) NOT NULL,"
            "  severity VARCHAR(20) NOT NULL,"
            "  details JSONB,"
            "  is_resolved BOOLEAN NOT NULL DEFAULT false,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        ))
        # Ensure service_contracts table exists (migration n01)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS service_contracts ("
            "  id UUID PRIMARY KEY,"
            "  provider_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  consumer_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  listing_id UUID REFERENCES listings(id) ON DELETE SET NULL,"
            "  terms JSONB,"
            "  status VARCHAR(20) NOT NULL DEFAULT 'active',"
            "  paused_by UUID,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  terminated_at TIMESTAMPTZ"
            ")"
        ))
        # Ensure behavioral_baselines table exists (migration n02)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS behavioral_baselines ("
            "  id UUID PRIMARY KEY,"
            "  entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  period_start DATE NOT NULL,"
            "  period_end DATE NOT NULL,"
            "  metrics JSONB NOT NULL,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        ))
        # Ensure agent heartbeat columns exist (migration o01)
        await conn.execute(text(
            "ALTER TABLE entities ADD COLUMN IF NOT EXISTS "
            "last_seen_at TIMESTAMPTZ"
        ))
        await conn.execute(text(
            "ALTER TABLE entities ADD COLUMN IF NOT EXISTS "
            "agent_status VARCHAR(20)"
        ))
        # Ensure attestation_providers table exists
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS attestation_providers ("
            "  id UUID PRIMARY KEY,"
            "  operator_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  provider_name VARCHAR(200) NOT NULL UNIQUE,"
            "  provider_url VARCHAR(500),"
            "  description TEXT,"
            "  supported_types JSONB DEFAULT '[]'::jsonb,"
            "  api_key_hash VARCHAR(128) NOT NULL,"
            "  is_active BOOLEAN NOT NULL DEFAULT false,"
            "  attestation_count INTEGER NOT NULL DEFAULT 0,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_attestation_providers_operator "
            "ON attestation_providers (operator_entity_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_attestation_providers_active "
            "ON attestation_providers (is_active)"
        ))
        # Ensure formal_attestations table exists (attestation framework)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS formal_attestations ("
            "  id UUID PRIMARY KEY,"
            "  issuer_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  subject_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  attestation_type VARCHAR(50) NOT NULL,"
            "  evidence TEXT,"
            "  expires_at TIMESTAMPTZ,"
            "  is_revoked BOOLEAN NOT NULL DEFAULT false,"
            "  revoked_at TIMESTAMPTZ,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  CONSTRAINT uq_formal_attestation"
            "    UNIQUE (issuer_entity_id, subject_entity_id, attestation_type)"
            ")"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_formal_attestations_issuer "
            "ON formal_attestations (issuer_entity_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_formal_attestations_subject "
            "ON formal_attestations (subject_entity_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_formal_attestations_type "
            "ON formal_attestations (attestation_type)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_formal_attestations_revoked "
            "ON formal_attestations (is_revoked)"
        ))
        # Ensure provisional registration + onboarding columns exist on entities
        await conn.execute(text(
            "ALTER TABLE entities ADD COLUMN IF NOT EXISTS "
            "is_provisional BOOLEAN NOT NULL DEFAULT false"
        ))
        await conn.execute(text(
            "ALTER TABLE entities ADD COLUMN IF NOT EXISTS "
            "claim_token VARCHAR(64) UNIQUE"
        ))
        await conn.execute(text(
            "ALTER TABLE entities ADD COLUMN IF NOT EXISTS "
            "provisional_expires_at TIMESTAMPTZ"
        ))
        await conn.execute(text(
            "ALTER TABLE entities ADD COLUMN IF NOT EXISTS "
            "onboarding_data JSONB DEFAULT '{}'::jsonb"
        ))
        # Ensure operator_approved column exists on entities (task #184)
        await conn.execute(text(
            "ALTER TABLE entities ADD COLUMN IF NOT EXISTS "
            "operator_approved BOOLEAN NOT NULL DEFAULT false"
        ))
        # Ensure source import columns exist (migration s09)
        await conn.execute(text(
            "ALTER TABLE entities ADD COLUMN IF NOT EXISTS "
            "source_url VARCHAR(1000)"
        ))
        await conn.execute(text(
            "ALTER TABLE entities ADD COLUMN IF NOT EXISTS "
            "source_type VARCHAR(30)"
        ))
        await conn.execute(text(
            "ALTER TABLE entities ADD COLUMN IF NOT EXISTS "
            "source_verified_at TIMESTAMPTZ"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_entities_source_url "
            "ON entities (source_url)"
        ))
        # Ensure registration_ip column exists (Sybil detection, migration s04)
        await conn.execute(text(
            "ALTER TABLE entities ADD COLUMN IF NOT EXISTS "
            "registration_ip VARCHAR(45)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_entities_registration_ip "
            "ON entities (registration_ip)"
        ))
        # Ensure aip_channels table exists (migration r05)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS aip_channels ("
            "  id UUID PRIMARY KEY,"
            "  name VARCHAR(200) NOT NULL,"
            "  description TEXT,"
            "  created_by_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  participant_ids JSONB DEFAULT '[]'::jsonb,"
            "  is_active BOOLEAN NOT NULL DEFAULT true,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_aip_channels_created_by "
            "ON aip_channels (created_by_entity_id)"
        ))
        # Ensure aip_messages table exists (migration r05)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS aip_messages ("
            "  id UUID PRIMARY KEY,"
            "  sender_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  recipient_entity_id UUID REFERENCES entities(id) ON DELETE CASCADE,"
            "  channel_id UUID REFERENCES aip_channels(id) ON DELETE CASCADE,"
            "  message_type VARCHAR(20) NOT NULL,"
            "  payload JSONB DEFAULT '{}'::jsonb,"
            "  sender_trust_score DOUBLE PRECISION,"
            "  is_read BOOLEAN NOT NULL DEFAULT false,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_aip_messages_sender "
            "ON aip_messages (sender_entity_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_aip_messages_recipient "
            "ON aip_messages (recipient_entity_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_aip_messages_channel "
            "ON aip_messages (channel_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_aip_messages_created_at "
            "ON aip_messages (created_at)"
        ))
        # Ensure content_links table exists (migration r02)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS content_links ("
            "  id UUID PRIMARY KEY,"
            "  source_type VARCHAR(30) NOT NULL,"
            "  source_id UUID NOT NULL,"
            "  target_type VARCHAR(30) NOT NULL,"
            "  target_id UUID NOT NULL,"
            "  link_type VARCHAR(30) NOT NULL,"
            "  created_by UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  CONSTRAINT ck_content_link_source_type"
            "    CHECK (source_type IN ('post', 'entity', 'evolution_record', 'listing')),"
            "  CONSTRAINT ck_content_link_target_type"
            "    CHECK (target_type IN ('post', 'entity', 'evolution_record', 'listing')),"
            "  CONSTRAINT ck_content_link_link_type"
            "    CHECK (link_type IN ('mentions', 'references', 'related', 'replies_about')),"
            "  CONSTRAINT uq_content_link"
            "    UNIQUE (source_type, source_id, target_type, target_id, link_type)"
            ")"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_content_links_source "
            "ON content_links (source_type, source_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_content_links_target "
            "ON content_links (target_type, target_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_content_links_created_by "
            "ON content_links (created_by)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_content_links_link_type "
            "ON content_links (link_type)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_content_links_created_at "
            "ON content_links (created_at)"
        ))
        # Ensure trust_score_history table exists (migration r07)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS trust_score_history ("
            "  id UUID PRIMARY KEY,"
            "  entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  score DOUBLE PRECISION NOT NULL,"
            "  components JSONB DEFAULT '{}'::jsonb,"
            "  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_trust_score_history_entity_time "
            "ON trust_score_history (entity_id, recorded_at)"
        ))
        # Ensure posts media columns exist (migration r06)
        await conn.execute(text(
            "ALTER TABLE posts ADD COLUMN IF NOT EXISTS "
            "media_url VARCHAR(1000)"
        ))
        await conn.execute(text(
            "ALTER TABLE posts ADD COLUMN IF NOT EXISTS "
            "media_type VARCHAR(20)"
        ))
        # Ensure webhook_delivery_logs table exists (webhook worker)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS webhook_delivery_logs ("
            "  id UUID PRIMARY KEY,"
            "  subscription_id UUID NOT NULL"
            "    REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,"
            "  event_type VARCHAR(100) NOT NULL,"
            "  payload JSONB NOT NULL DEFAULT '{}'::jsonb,"
            "  status_code INTEGER,"
            "  success BOOLEAN NOT NULL DEFAULT false,"
            "  error_message TEXT,"
            "  attempt_number INTEGER NOT NULL DEFAULT 1,"
            "  duration_ms INTEGER,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_delivery_logs_subscription "
            "ON webhook_delivery_logs (subscription_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_delivery_logs_created_at "
            "ON webhook_delivery_logs (created_at)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_delivery_logs_event_type "
            "ON webhook_delivery_logs (event_type)"
        ))
        # Ensure updated_at columns exist on all tables that have them
        for tbl in [
            "agent_capability_registry", "aip_channels", "api_keys",
            "attestation_providers", "delegations", "did_documents",
            "disputes", "entities", "evolution_records",
            "listing_reviews", "listings", "moderation_flags",
            "notification_preferences", "notifications",
            "organizations", "posts", "reviews",
            "service_contracts", "submolts", "transactions",
            "trust_scores", "webhook_subscriptions",
        ]:
            await conn.execute(text(
                f"ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS "
                "updated_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ))
        # Ensure trust_scores has contextual_scores column
        await conn.execute(text(
            "ALTER TABLE trust_scores ADD COLUMN IF NOT EXISTS "
            "contextual_scores JSONB DEFAULT '{}'::jsonb"
        ))
        # Ensure api_keys has organization_id column
        await conn.execute(text(
            "ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS "
            "organization_id UUID"
        ))
        # Multi-surface columns (migrations t15–t18) — the test DB is patched via
        # raw DDL, not alembic, so add the newer columns here to avoid schema drift.
        # `ALTER TABLE IF EXISTS` patches pre-existing tables and no-ops on tables
        # not yet created (create_all builds those fresh from current metadata).
        for _ddl in [
            "ALTER TABLE IF EXISTS community_scans ADD COLUMN IF NOT EXISTS grade VARCHAR(4)",
            "ALTER TABLE IF EXISTS community_scans ADD COLUMN IF NOT EXISTS surface "
            "VARCHAR(16) NOT NULL DEFAULT 'github'",
            "ALTER TABLE IF EXISTS community_scans ALTER COLUMN repo TYPE VARCHAR(512)",
            "ALTER TABLE IF EXISTS community_scans ADD COLUMN IF NOT EXISTS "
            "adoption_score INTEGER",
            "ALTER TABLE IF EXISTS community_scans ADD COLUMN IF NOT EXISTS "
            "adoption_count BIGINT",
            "ALTER TABLE IF EXISTS community_scans ADD COLUMN IF NOT EXISTS "
            "adoption_unit VARCHAR(24)",
            "ALTER TABLE IF EXISTS repo_claims ADD COLUMN IF NOT EXISTS surface "
            "VARCHAR(16) NOT NULL DEFAULT 'github'",
            "ALTER TABLE IF EXISTS repo_claims ADD COLUMN IF NOT EXISTS proof_method VARCHAR(24)",
            "ALTER TABLE IF EXISTS repo_claims ALTER COLUMN repo TYPE VARCHAR(512)",
            "ALTER TABLE IF EXISTS tool_watches ADD COLUMN IF NOT EXISTS surface "
            "VARCHAR(16) NOT NULL DEFAULT 'github'",
            "ALTER TABLE IF EXISTS tool_watches ALTER COLUMN repo TYPE VARCHAR(512)",
        ]:
            await conn.execute(text(_ddl))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_webhooks_active "
            "ON webhook_subscriptions (is_active)"
        ))
        # Performance indexes (migration s01)
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_trust_scores_score "
            "ON trust_scores (score)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_api_keys_active "
            "ON api_keys (is_active)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_transactions_created_at "
            "ON transactions (created_at)"
        ))
        # Ensure DID status columns exist (migration s01)
        # Check if enum exists; if it has wrong values, drop column + type first
        enum_check = await conn.execute(text(
            "SELECT 1 FROM pg_type WHERE typname = 'didstatus'"
        ))
        if enum_check.scalar_one_or_none():
            # Check if values are uppercase (SQLAlchemy uses enum names)
            val_check = await conn.execute(text(
                "SELECT unnest(enum_range(NULL::didstatus))::text LIMIT 1"
            ))
            first_val = val_check.scalar_one_or_none()
            if first_val and first_val != "PROVISIONAL":
                # Wrong case — drop and recreate with uppercase
                await conn.execute(text(
                    "ALTER TABLE did_documents DROP COLUMN IF EXISTS did_status"
                ))
                await conn.execute(text("DROP TYPE didstatus"))
                await conn.execute(text(
                    "CREATE TYPE didstatus AS ENUM "
                    "('PROVISIONAL', 'FULL', 'REVOKED')"
                ))
        else:
            await conn.execute(text(
                "CREATE TYPE didstatus AS ENUM "
                "('PROVISIONAL', 'FULL', 'REVOKED')"
            ))
        await conn.execute(text(
            "ALTER TABLE did_documents ADD COLUMN IF NOT EXISTS "
            "did_status didstatus NOT NULL DEFAULT 'FULL'"
        ))
        await conn.execute(text(
            "ALTER TABLE did_documents ADD COLUMN IF NOT EXISTS "
            "promoted_at TIMESTAMPTZ"
        ))
        await conn.execute(text(
            "ALTER TABLE did_documents ADD COLUMN IF NOT EXISTS "
            "promoted_by UUID"
        ))
        await conn.execute(text(
            "ALTER TABLE did_documents ADD COLUMN IF NOT EXISTS "
            "promotion_reason VARCHAR(200)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_did_documents_did_status "
            "ON did_documents (did_status)"
        ))
        # Ensure issue_reports table exists (migration s05)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS issue_reports ("
            "  id UUID PRIMARY KEY,"
            "  post_id UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,"
            "  bot_reply_id UUID REFERENCES posts(id) ON DELETE SET NULL,"
            "  reporter_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  bot_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  issue_type VARCHAR(20) NOT NULL,"
            "  status VARCHAR(20) NOT NULL DEFAULT 'open',"
            "  title VARCHAR(255) NOT NULL,"
            "  resolution_note TEXT,"
            "  resolved_by UUID REFERENCES entities(id) ON DELETE SET NULL,"
            "  resolved_at TIMESTAMPTZ,"
            "  resolution_reply_id UUID REFERENCES posts(id) ON DELETE SET NULL,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
            "  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
            ")"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_issue_reports_status "
            "ON issue_reports(status)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_issue_reports_reporter "
            "ON issue_reports(reporter_entity_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_issue_reports_type_status "
            "ON issue_reports(issue_type, status)"
        ))
        # Ensure email_notifications_enabled column exists (migration s05)
        await conn.execute(text(
            "ALTER TABLE notification_preferences "
            "ADD COLUMN IF NOT EXISTS email_notifications_enabled BOOLEAN NOT NULL DEFAULT TRUE"
        ))
        # Ensure issue_resolution_enabled column exists
        await conn.execute(text(
            "ALTER TABLE notification_preferences "
            "ADD COLUMN IF NOT EXISTS issue_resolution_enabled BOOLEAN DEFAULT TRUE"
        ))
        # Ensure per-kind email preference columns exist (migration s07)
        for col, default in [
            ("email_follow_enabled", "false"),
            ("email_vote_enabled", "false"),
            ("email_reply_enabled", "false"),
            ("email_mention_enabled", "true"),
            ("email_endorsement_enabled", "false"),
            ("email_review_enabled", "false"),
            ("email_moderation_enabled", "true"),
            ("email_message_enabled", "true"),
            ("email_issue_resolution_enabled", "true"),
        ]:
            await conn.execute(text(
                f"ALTER TABLE notification_preferences "
                f"ADD COLUMN IF NOT EXISTS {col} BOOLEAN NOT NULL DEFAULT {default}"
            ))
        # Ensure linked_accounts table exists (migration s08)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS linked_accounts ("
            "  id UUID PRIMARY KEY,"
            "  entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,"
            "  provider VARCHAR(50) NOT NULL,"
            "  provider_user_id VARCHAR(255) NOT NULL,"
            "  provider_username VARCHAR(255),"
            "  verification_status VARCHAR(30) NOT NULL DEFAULT 'pending',"
            "  access_token VARCHAR(500),"
            "  refresh_token VARCHAR(500),"
            "  token_expires_at TIMESTAMPTZ,"
            "  profile_data JSONB DEFAULT '{}'::jsonb,"
            "  reputation_data JSONB DEFAULT '{}'::jsonb,"
            "  reputation_score DOUBLE PRECISION DEFAULT 0.0,"
            "  last_synced_at TIMESTAMPTZ,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  CONSTRAINT uq_linked_account_provider UNIQUE (entity_id, provider)"
            ")"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_linked_accounts_entity "
            "ON linked_accounts (entity_id)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_linked_accounts_provider "
            "ON linked_accounts (provider)"
        ))
        # Ensure marketing_campaigns table exists (marketing system)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS marketing_campaigns ("
            "  id UUID PRIMARY KEY,"
            "  name VARCHAR(200) NOT NULL,"
            "  topic VARCHAR(100) NOT NULL,"
            "  platforms VARCHAR(50)[] NOT NULL DEFAULT '{}',"
            "  status VARCHAR(20) NOT NULL DEFAULT 'draft',"
            "  schedule_config JSONB,"
            "  start_date DATE,"
            "  end_date DATE,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_mktg_campaign_status "
            "ON marketing_campaigns (status)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_mktg_campaign_topic "
            "ON marketing_campaigns (topic)"
        ))
        # Ensure marketing_posts table exists (marketing system)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS marketing_posts ("
            "  id UUID PRIMARY KEY,"
            "  campaign_id UUID REFERENCES marketing_campaigns(id) ON DELETE SET NULL,"
            "  platform VARCHAR(50) NOT NULL,"
            "  external_id VARCHAR(255),"
            "  content TEXT NOT NULL,"
            "  content_hash VARCHAR(64) NOT NULL,"
            "  post_type VARCHAR(20) NOT NULL,"
            "  topic VARCHAR(100),"
            "  status VARCHAR(20) NOT NULL DEFAULT 'draft',"
            "  parent_external_id VARCHAR(255),"
            "  llm_model VARCHAR(50),"
            "  llm_tokens_in INTEGER,"
            "  llm_tokens_out INTEGER,"
            "  llm_cost_usd DOUBLE PRECISION,"
            "  metrics_json JSONB,"
            "  utm_params JSONB,"
            "  error_message TEXT,"
            "  retry_count INTEGER NOT NULL DEFAULT 0,"
            "  posted_at TIMESTAMPTZ,"
            "  metrics_updated_at TIMESTAMPTZ,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  CONSTRAINT uq_mktg_platform_external UNIQUE (platform, external_id)"
            ")"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_mktg_post_platform "
            "ON marketing_posts (platform)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_mktg_post_status "
            "ON marketing_posts (status)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_mktg_post_type "
            "ON marketing_posts (post_type)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_mktg_post_posted_at "
            "ON marketing_posts (posted_at)"
        ))
        # Ensure source_type index exists on entities (deep dive audit)
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_entities_source_type "
            "ON entities (source_type)"
        ))
        # Ensure community_scans table exists (migration t08)
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS community_scans ("
            "  id UUID PRIMARY KEY,"
            "  owner VARCHAR(255) NOT NULL,"
            "  repo VARCHAR(255) NOT NULL,"
            "  full_name VARCHAR(512) NOT NULL,"
            "  trust_score INTEGER,"
            "  critical INTEGER,"
            "  high INTEGER,"
            "  findings_count INTEGER,"
            "  primary_language VARCHAR(120),"
            "  scan_count INTEGER NOT NULL DEFAULT 1,"
            "  first_scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  last_scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  CONSTRAINT uq_community_scan_target UNIQUE (owner, repo)"
            ")"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_community_scans_full_name "
            "ON community_scans (full_name)"
        ))
        await conn.execute(
            text("TRUNCATE " + ", ".join(_TABLES) + " CASCADE")
        )
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def _reset_rate_limiter():
    """Clear rate limiter state (in-memory + Redis) and relax auth limit."""
    from src.api.rate_limit import _limiter
    from src.config import settings

    await _limiter.clear_all()
    original = settings.rate_limit_auth_per_minute
    settings.rate_limit_auth_per_minute = 100
    # Clear caches to prevent cross-test contamination
    from src import cache
    await cache.invalidate_pattern("insights:*")
    await cache.invalidate_pattern("search:*")
    await cache.invalidate_pattern("activity:*")
    await cache.invalidate_pattern("bootstrap:ip:*")
    await cache.invalidate_pattern("login:fail:*")
    yield
    settings.rate_limit_auth_per_minute = original
    await _limiter.clear_all()


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine(DB_URL, echo=False)
    async with engine.connect() as conn:
        trans = await conn.begin()
        session = AsyncSession(bind=conn, expire_on_commit=False)
        try:
            yield session
        finally:
            await session.close()
            await trans.rollback()
    await engine.dispose()
