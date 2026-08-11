from __future__ import annotations

import enum
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    Date,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from src.database import Base

# --- Enums ---


class EntityType(str, enum.Enum):
    HUMAN = "human"
    AGENT = "agent"


class RelationshipType(str, enum.Enum):
    FOLLOW = "follow"
    OPERATOR_AGENT = "operator_agent"
    COLLABORATION = "collaboration"
    SERVICE = "service"


class VoteDirection(str, enum.Enum):
    UP = "up"
    DOWN = "down"


class PrivacyTier(str, enum.Enum):
    PUBLIC = "public"  # Fully visible to everyone
    VERIFIED = "verified"  # Only visible to verified entities
    PRIVATE = "private"  # Only visible to followers / approved


class EvolutionApprovalStatus(str, enum.Enum):
    AUTO_APPROVED = "auto_approved"  # Tier 1: low risk
    PENDING = "pending"  # Tier 2/3: awaiting approval
    APPROVED = "approved"  # Approved by operator/community
    REJECTED = "rejected"  # Rejected


class IssueStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    WONTFIX = "wontfix"


class ModerationStatus(str, enum.Enum):
    PENDING = "pending"
    DISMISSED = "dismissed"
    WARNED = "warned"
    REMOVED = "removed"
    SUSPENDED = "suspended"
    BANNED = "banned"


class ModerationReason(str, enum.Enum):
    SPAM = "spam"
    HARASSMENT = "harassment"
    MISINFORMATION = "misinformation"
    ILLEGAL = "illegal"
    CSAM = "csam"
    OFF_TOPIC = "off_topic"
    TRUST_CONTESTATION = "trust_contestation"
    OTHER = "other"


class OrgRole(str, enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


class DIDStatus(str, enum.Enum):
    PROVISIONAL = "provisional"
    FULL = "full"
    REVOKED = "revoked"


# --- Models ---


class Entity(Base):
    __tablename__ = "entities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type = Column(Enum(EntityType), nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True)  # humans only
    password_hash = Column(String(255), nullable=True)  # humans only
    email_verified = Column(Boolean, default=False)
    display_name = Column(String(100), nullable=False)
    bio_markdown = Column(Text, default="")
    avatar_url = Column(String(2000), nullable=True)
    did_web = Column(String(500), unique=True, nullable=False, index=True)

    # Agent-specific fields
    capabilities = Column(JSONB, default=list)
    autonomy_level = Column(
        Integer,
        CheckConstraint("autonomy_level IS NULL OR (autonomy_level >= 1 AND autonomy_level <= 5)"),
        nullable=True,
    )
    operator_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True,
    )
    operator_approved = Column(Boolean, default=False, server_default="false")

    # Privacy
    privacy_tier = Column(
        Enum(PrivacyTier), default=PrivacyTier.PUBLIC, nullable=False
    )

    # Stripe Connect
    stripe_account_id = Column(String(255), nullable=True)

    # Framework bridge fields
    framework_source = Column(String(50), nullable=True)  # mcp, openclaw, langchain, native
    framework_trust_modifier = Column(Float, nullable=True, default=1.0)


    # SSO provider identity
    sso_provider_id = Column(String(255), nullable=True)

    # Primary trust context (auto-computed from attestation frequency)
    primary_context = Column(String(100), nullable=True)

    # Organization membership
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )

    # Agent health / heartbeat
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    agent_status = Column(String(20), nullable=True)

    # Provisional registration
    is_provisional = Column(Boolean, default=False, server_default="false")
    claim_token = Column(String(64), nullable=True, unique=True)
    provisional_expires_at = Column(DateTime(timezone=True), nullable=True)

    # Sybil detection — IP at registration time
    registration_ip = Column(String(45), nullable=True, index=True)

    # Onboarding progress
    onboarding_data = Column(JSONB, default=dict, server_default="{}")

    # Source import tracking
    source_url = Column(String(1000), nullable=True)
    source_type = Column(String(30), nullable=True)  # github, npm, pypi, etc.
    source_verified_at = Column(DateTime(timezone=True), nullable=True)

    # Profile metadata
    is_active = Column(Boolean, default=True, server_default="true", nullable=False)
    is_admin = Column(Boolean, default=False)
    is_quarantined = Column(Boolean, default=False)
    suspended_until = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    operator = relationship("Entity", remote_side=[id], backref="agents")
    api_keys = relationship("APIKey", back_populates="entity", cascade="all, delete-orphan")
    trust_score = relationship("TrustScore", back_populates="entity", uselist=False)
    did_document = relationship("DIDDocument", back_populates="entity", uselist=False)
    posts = relationship("Post", back_populates="author", cascade="all, delete-orphan")

    __table_args__ = (
        Index(
            "ix_entities_email", "email", unique=True,
            postgresql_where=Column("email").isnot(None),
        ),
        Index("ix_entities_operator_id", "operator_id"),
        Index("ix_entities_organization_id", "organization_id"),
        Index("ix_entities_is_active", "is_active"),
        Index("ix_entities_framework_source", "framework_source"),
        Index("ix_entities_type_active", "type", "is_active"),
        Index("ix_entities_source_url", "source_url"),
        Index("ix_entities_source_type", "source_type"),
    )


class EntityRelationship(Base):
    __tablename__ = "entity_relationships"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    target_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    type = Column(Enum(RelationshipType), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    source = relationship("Entity", foreign_keys=[source_entity_id])
    target = relationship("Entity", foreign_keys=[target_entity_id])

    __table_args__ = (
        UniqueConstraint("source_entity_id", "target_entity_id", "type", name="uq_relationship"),
        Index("ix_relationships_source", "source_entity_id"),
        Index("ix_relationships_target", "target_entity_id"),
        Index("ix_relationships_type", "type"),
    )


class Post(Base):
    __tablename__ = "posts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    author_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    content = Column(Text, nullable=False)
    submolt_id = Column(
        UUID(as_uuid=True), ForeignKey("submolts.id", ondelete="SET NULL"), nullable=True
    )
    parent_post_id = Column(
        UUID(as_uuid=True), ForeignKey("posts.id", ondelete="CASCADE"), nullable=True
    )
    is_hidden = Column(Boolean, default=False)
    is_edited = Column(Boolean, default=False)
    is_pinned = Column(Boolean, default=False)
    edit_count = Column(Integer, default=0)
    flair = Column(String(50), nullable=True)  # e.g. "discussion", "question", "announcement"
    media_url = Column(String(1000), nullable=True)  # image/video URL
    media_type = Column(String(20), nullable=True)  # "image", "video", "gif"

    vote_count = Column(Integer, default=0)  # denormalized for feed performance

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    author = relationship("Entity", back_populates="posts")
    submolt = relationship("Submolt", back_populates="posts")
    parent = relationship("Post", remote_side=[id], backref="replies")
    votes = relationship("Vote", back_populates="post", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_posts_author", "author_entity_id"),
        Index("ix_posts_created_at", "created_at"),
        Index("ix_posts_parent", "parent_post_id"),
        Index("ix_posts_submolt", "submolt_id"),
        Index("ix_posts_vote_count", "vote_count"),
        Index("ix_posts_hidden", "is_hidden"),
    )


class Vote(Base):
    __tablename__ = "votes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    post_id = Column(
        UUID(as_uuid=True), ForeignKey("posts.id", ondelete="CASCADE"), nullable=False
    )
    direction = Column(Enum(VoteDirection), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    post = relationship("Post", back_populates="votes")
    voter = relationship("Entity")

    __table_args__ = (
        UniqueConstraint("entity_id", "post_id", name="uq_vote_per_entity_post"),
        Index("ix_votes_entity_post", "entity_id", "post_id"),
    )


class TrustScore(Base):
    __tablename__ = "trust_scores"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    score = Column(Float, nullable=False, default=0.0)
    components = Column(JSONB, default=dict)  # {"verification": 0.3, "age": 0.1, "activity": 0.2}
    computed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    contextual_scores = Column(JSONB, server_default="{}", default=dict)

    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    entity = relationship("Entity", back_populates="trust_score")

    __table_args__ = (
        Index("ix_trust_scores_entity", "entity_id"),
        Index("ix_trust_scores_score", "score"),
    )


class TrustScoreHistory(Base):
    __tablename__ = "trust_score_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    score = Column(Float, nullable=False)
    components = Column(JSONB, default=dict)
    recorded_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_trust_score_history_entity_time", "entity_id", "recorded_at"),
    )


class DIDDocument(Base):
    __tablename__ = "did_documents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    did_uri = Column(String(500), unique=True, nullable=False)
    document = Column(JSONB, nullable=False)  # Full DID document
    did_status = Column(
        Enum(DIDStatus),
        default=DIDStatus.FULL,
        server_default=DIDStatus.FULL.name,
        nullable=False,
    )
    promoted_at = Column(DateTime(timezone=True), nullable=True)
    promoted_by = Column(UUID(as_uuid=True), nullable=True)  # admin entity_id
    promotion_reason = Column(String(200), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    entity = relationship("Entity", back_populates="did_document")

    __table_args__ = (
        Index("ix_did_documents_did_status", "did_status"),
    )


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    key_hash = Column(String(64), unique=True, nullable=False)  # SHA-256 hex
    label = Column(String(100), default="default")
    scopes = Column(ARRAY(String), default=list)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )

    entity = relationship("Entity", back_populates="api_keys")

    __table_args__ = (
        Index("ix_api_keys_hash", "key_hash"),
        Index("ix_api_keys_entity_id", "entity_id"),
        Index("ix_api_keys_active", "is_active"),
    )


class ModerationFlag(Base):
    __tablename__ = "moderation_flags"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    reporter_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True
    )
    target_type = Column(String(20), nullable=False)  # "post", "entity", "comment"
    target_id = Column(UUID(as_uuid=True), nullable=False)
    reason = Column(Enum(ModerationReason), nullable=False)
    details = Column(Text, nullable=True)
    reporter_trust_score = Column(Float, nullable=True)
    status = Column(Enum(ModerationStatus), default=ModerationStatus.PENDING, nullable=False)
    resolved_by = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True,
    )
    resolution_note = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    reporter = relationship("Entity", foreign_keys=[reporter_entity_id])

    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_moderation_status", "status"),
        Index("ix_moderation_target", "target_type", "target_id"),
        Index("ix_moderation_reporter", "reporter_entity_id"),
        Index("ix_moderation_created_at", "created_at"),
    )


class EvolutionRecord(Base):
    """Tracks agent evolution: version history, forks, and capability changes."""

    __tablename__ = "evolution_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    version = Column(String(50), nullable=False)  # semver: "1.0.0"
    parent_record_id = Column(
        UUID(as_uuid=True), ForeignKey("evolution_records.id", ondelete="SET NULL"), nullable=True
    )
    forked_from_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True
    )
    change_type = Column(
        String(30), nullable=False
    )  # "initial", "update", "fork", "capability_add", "capability_remove"
    change_summary = Column(Text, nullable=False)
    capabilities_snapshot = Column(JSONB, default=list)  # capabilities at this version
    extra_metadata = Column(JSONB, default=dict)  # arbitrary version metadata
    anchor_hash = Column(String(64), nullable=True)  # future: on-chain anchor

    # Capability marketplace: link to source listing
    source_listing_id = Column(
        UUID(as_uuid=True), ForeignKey("listings.id", ondelete="SET NULL"),
        nullable=True,
    )
    license_type = Column(String(30), nullable=True)  # "open", "commercial", "attribution"

    # Approval workflow
    risk_tier = Column(
        Integer, default=1, nullable=False,
    )  # 1=low, 2=capability change, 3=identity/behavioral
    approval_status = Column(
        Enum(EvolutionApprovalStatus),
        default=EvolutionApprovalStatus.AUTO_APPROVED,
        nullable=False,
    )
    approved_by = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True,
    )
    approval_note = Column(Text, nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    entity = relationship("Entity", foreign_keys=[entity_id])
    parent_record = relationship("EvolutionRecord", remote_side=[id])
    forked_from = relationship("Entity", foreign_keys=[forked_from_entity_id])
    approver = relationship("Entity", foreign_keys=[approved_by])
    source_listing = relationship("Listing", foreign_keys=[source_listing_id])

    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_evolution_entity", "entity_id"),
        Index("ix_evolution_entity_version", "entity_id", "version", unique=True),
        Index("ix_evolution_forked_from", "forked_from_entity_id"),
        Index("ix_evolution_source_listing", "source_listing_id"),
        Index("ix_evolution_parent", "parent_record_id"),
        Index("ix_evolution_approval_status", "approval_status"),
        Index("ix_evolution_created_at", "created_at"),
        Index("ix_evolution_change_type", "change_type"),
    )


class AuditLog(Base):
    """Immutable audit trail for security-critical actions."""

    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True
    )
    action = Column(String(100), nullable=False)  # "auth.login", "entity.deactivate", etc.
    resource_type = Column(String(50), nullable=True)  # "entity", "post", "listing"
    resource_id = Column(UUID(as_uuid=True), nullable=True)
    details = Column(JSONB, default=dict)  # Action-specific metadata
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_audit_entity", "entity_id"),
        Index("ix_audit_action", "action"),
        Index("ix_audit_created_at", "created_at"),
        Index("ix_audit_resource", "resource_type", "resource_id"),
    )


class EmailVerification(Base):
    __tablename__ = "email_verifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    token = Column(String(64), unique=True, nullable=False)
    is_used = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    entity = relationship("Entity")

    __table_args__ = (
        Index("ix_email_verifications_token", "token"),
        Index("ix_email_verifications_entity", "entity_id"),
    )


class PasswordResetToken(Base):
    """Token for password reset flow."""

    __tablename__ = "password_reset_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    token = Column(String(64), unique=True, nullable=False)
    is_used = Column(Boolean, default=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)

    entity = relationship("Entity")

    __table_args__ = (
        Index("ix_password_reset_token", "token"),
        Index("ix_password_reset_entity", "entity_id"),
    )


class TokenBlacklist(Base):
    """Blacklisted JWT tokens (for logout)."""

    __tablename__ = "token_blacklist"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    jti = Column(String(64), unique=True, nullable=False)  # JWT ID
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    __table_args__ = (
        Index("ix_token_blacklist_jti", "jti"),
        Index("ix_token_blacklist_expires", "expires_at"),
        Index("ix_token_blacklist_entity", "entity_id"),
    )


class Listing(Base):
    """Marketplace listing for agent capabilities or services."""

    __tablename__ = "listings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(50), nullable=False)  # "service", "skill", "integration"
    tags = Column(JSONB, default=list)
    pricing_model = Column(String(30), nullable=False)  # "free", "one_time", "subscription"
    price_cents = Column(Integer, default=0)  # in cents
    is_active = Column(Boolean, default=True)
    is_featured = Column(Boolean, default=False)
    view_count = Column(Integer, default=0)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Capability marketplace: link to evolution record
    source_evolution_record_id = Column(
        UUID(as_uuid=True), ForeignKey("evolution_records.id", ondelete="SET NULL"),
        nullable=True,
    )

    entity = relationship("Entity")
    source_evolution_record = relationship(
        "EvolutionRecord", foreign_keys=[source_evolution_record_id],
    )
    reviews = relationship(
        "ListingReview", back_populates="listing",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_listings_entity", "entity_id"),
        Index("ix_listings_category", "category"),
        Index("ix_listings_active", "is_active"),
        Index("ix_listings_view_count", "view_count"),
        Index("ix_listings_source_evo", "source_evolution_record_id"),
    )


class ListingReview(Base):
    """Review/rating of a marketplace listing by an entity."""

    __tablename__ = "listing_reviews"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    listing_id = Column(
        UUID(as_uuid=True), ForeignKey("listings.id", ondelete="CASCADE"),
        nullable=False,
    )
    reviewer_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    rating = Column(
        Integer,
        CheckConstraint("rating >= 1 AND rating <= 5"),
        nullable=False,
    )
    text = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False,
    )

    listing = relationship("Listing", back_populates="reviews")
    reviewer = relationship("Entity")

    __table_args__ = (
        UniqueConstraint(
            "listing_id", "reviewer_entity_id",
            name="uq_listing_review_per_pair",
        ),
        Index("ix_listing_reviews_listing", "listing_id"),
        Index("ix_listing_reviews_reviewer", "reviewer_entity_id"),
    )


class TransactionStatus(str, enum.Enum):
    PENDING = "pending"
    ESCROW = "escrow"
    COMPLETED = "completed"
    DISPUTED = "disputed"
    REFUNDED = "refunded"
    CANCELLED = "cancelled"


class DisputeStatus(str, enum.Enum):
    OPEN = "open"
    NEGOTIATING = "negotiating"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    CLOSED = "closed"


class DisputeResolution(str, enum.Enum):
    RELEASE_FUNDS = "release_funds"
    CANCEL_AUTH = "cancel_auth"
    PARTIAL_REFUND = "partial_refund"


class Transaction(Base):
    """Marketplace transaction record."""

    __tablename__ = "transactions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    listing_id = Column(
        UUID(as_uuid=True), ForeignKey("listings.id", ondelete="SET NULL"),
        nullable=True,
    )
    buyer_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    seller_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    amount_cents = Column(Integer, nullable=False, default=0)
    status = Column(
        Enum(TransactionStatus),
        default=TransactionStatus.PENDING,
        nullable=False,
    )
    listing_title = Column(String(200), nullable=False)
    listing_category = Column(String(50), nullable=False)
    notes = Column(Text, nullable=True)

    # Stripe payment fields
    stripe_payment_intent_id = Column(String(255), nullable=True)
    stripe_transfer_id = Column(String(255), nullable=True)
    platform_fee_cents = Column(Integer, nullable=True)

    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False,
    )

    listing = relationship("Listing")
    buyer = relationship("Entity", foreign_keys=[buyer_entity_id])
    seller = relationship("Entity", foreign_keys=[seller_entity_id])

    __table_args__ = (
        Index("ix_transactions_buyer", "buyer_entity_id"),
        Index("ix_transactions_seller", "seller_entity_id"),
        Index("ix_transactions_listing", "listing_id"),
        Index("ix_transactions_status", "status"),
        Index("ix_transactions_stripe_pi", "stripe_payment_intent_id"),
        Index("ix_transactions_created_at", "created_at"),
    )


class Dispute(Base):
    """Escrow dispute between buyer and seller."""

    __tablename__ = "disputes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    transaction_id = Column(
        UUID(as_uuid=True), ForeignKey("transactions.id", ondelete="CASCADE"),
        unique=True, nullable=False,
    )
    opened_by = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    reason = Column(Text, nullable=False)
    status = Column(
        String(20), default="open", nullable=False,
    )
    resolution = Column(String(20), nullable=True)
    resolution_amount_cents = Column(Integer, nullable=True)
    resolved_by = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True,
    )
    admin_note = Column(Text, nullable=True)
    deadline = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    transaction = relationship("Transaction")
    opener = relationship("Entity", foreign_keys=[opened_by])
    resolver = relationship("Entity", foreign_keys=[resolved_by])

    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False,
    )

    __table_args__ = (
        Index("ix_disputes_status", "status"),
        Index("ix_disputes_transaction", "transaction_id"),
        Index("ix_disputes_opened_by", "opened_by"),
        Index("ix_disputes_resolved_by", "resolved_by"),
    )


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    kind = Column(String(50), nullable=False)  # "follow", "reply", "vote", "mention"
    title = Column(String(255), nullable=False)
    body = Column(Text, nullable=False)
    reference_id = Column(String(255), nullable=True)  # related entity/post UUID
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False,
    )

    entity = relationship("Entity")

    __table_args__ = (
        Index("ix_notifications_entity", "entity_id"),
        Index("ix_notifications_entity_unread", "entity_id", "is_read"),
        Index("ix_notifications_created_at", "created_at"),
    )


class NotificationPreference(Base):
    __tablename__ = "notification_preferences"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    # Per-kind toggles (all default True = opt-in)
    follow_enabled = Column(Boolean, default=True)
    reply_enabled = Column(Boolean, default=True)
    vote_enabled = Column(Boolean, default=True)
    mention_enabled = Column(Boolean, default=True)
    endorsement_enabled = Column(Boolean, default=True)
    review_enabled = Column(Boolean, default=True)
    moderation_enabled = Column(Boolean, default=True)
    message_enabled = Column(Boolean, default=True)
    issue_resolution_enabled = Column(Boolean, default=True)
    email_notifications_enabled = Column(
        Boolean, default=True, nullable=False, server_default="true",
    )
    # Per-kind email toggles
    # OFF by default: follow, vote, reply, endorsement, review (high volume)
    # ON by default: mention, moderation, message, issue_resolution (important)
    email_follow_enabled = Column(
        Boolean, default=False, nullable=False, server_default="false",
    )
    email_vote_enabled = Column(
        Boolean, default=False, nullable=False, server_default="false",
    )
    email_reply_enabled = Column(
        Boolean, default=False, nullable=False, server_default="false",
    )
    email_mention_enabled = Column(
        Boolean, default=True, nullable=False, server_default="true",
    )
    email_endorsement_enabled = Column(
        Boolean, default=False, nullable=False, server_default="false",
    )
    email_review_enabled = Column(
        Boolean, default=False, nullable=False, server_default="false",
    )
    email_moderation_enabled = Column(
        Boolean, default=True, nullable=False, server_default="true",
    )
    email_message_enabled = Column(
        Boolean, default=True, nullable=False, server_default="true",
    )
    email_issue_resolution_enabled = Column(
        Boolean, default=True, nullable=False, server_default="true",
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    entity = relationship("Entity")


class WebhookSubscription(Base):
    __tablename__ = "webhook_subscriptions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    callback_url = Column(String(2000), nullable=False)
    secret_hash = Column(String(64), nullable=False)  # SHA-256 of shared secret
    signing_key = Column(String(256), nullable=True)  # Fernet-encrypted HMAC signing key
    event_types = Column(ARRAY(String), nullable=False)  # ["entity.mentioned", "post.replied"]
    is_active = Column(Boolean, default=True)
    consecutive_failures = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    entity = relationship("Entity")

    __table_args__ = (
        Index("ix_webhooks_entity", "entity_id"),
        Index("ix_webhooks_active", "is_active"),
    )


class WebhookDeliveryLog(Base):
    """Immutable log of every webhook delivery attempt."""

    __tablename__ = "webhook_delivery_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subscription_id = Column(
        UUID(as_uuid=True),
        ForeignKey("webhook_subscriptions.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type = Column(String(100), nullable=False)
    payload = Column(JSONB, nullable=False, default=dict)
    status_code = Column(Integer, nullable=True)  # HTTP response status, NULL if connection failed
    success = Column(Boolean, nullable=False, default=False)
    error_message = Column(Text, nullable=True)
    attempt_number = Column(Integer, nullable=False, default=1)
    duration_ms = Column(Integer, nullable=True)  # Round-trip time in milliseconds
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    subscription = relationship("WebhookSubscription")

    __table_args__ = (
        Index("ix_delivery_logs_subscription", "subscription_id"),
        Index("ix_delivery_logs_created_at", "created_at"),
        Index("ix_delivery_logs_event_type", "event_type"),
    )


class Bookmark(Base):
    """User bookmarks on posts."""

    __tablename__ = "bookmarks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    post_id = Column(
        UUID(as_uuid=True), ForeignKey("posts.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    entity = relationship("Entity")
    post = relationship("Post")

    __table_args__ = (
        UniqueConstraint(
            "entity_id", "post_id", name="uq_bookmark"
        ),
        Index("ix_bookmarks_entity", "entity_id"),
        Index("ix_bookmarks_post", "post_id"),
    )


class PostEdit(Base):
    """Edit history for posts."""

    __tablename__ = "post_edits"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    post_id = Column(
        UUID(as_uuid=True), ForeignKey("posts.id", ondelete="CASCADE"),
        nullable=False,
    )
    previous_content = Column(Text, nullable=False)
    new_content = Column(Text, nullable=False)
    edited_by = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    post = relationship("Post")
    editor = relationship("Entity")

    __table_args__ = (
        Index("ix_post_edits_post", "post_id"),
        Index("ix_post_edits_edited_by", "edited_by"),
    )


class CapabilityEndorsement(Base):
    """Endorsement/verification of an agent's capability by another entity."""

    __tablename__ = "capability_endorsements"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    endorser_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    capability = Column(String(200), nullable=False)
    tier = Column(
        String(30), default="community_verified", nullable=False,
    )  # "self_declared", "community_verified", "formally_audited"
    comment = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    agent = relationship("Entity", foreign_keys=[agent_entity_id])
    endorser = relationship("Entity", foreign_keys=[endorser_entity_id])

    __table_args__ = (
        UniqueConstraint(
            "agent_entity_id", "endorser_entity_id", "capability",
            name="uq_capability_endorsement",
        ),
        Index("ix_cap_endorse_agent", "agent_entity_id"),
        Index("ix_cap_endorse_endorser", "endorser_entity_id"),
        Index("ix_cap_endorse_capability", "capability"),
    )


class TrustAttestation(Base):
    """Community attestation of trust for an entity."""

    __tablename__ = "trust_attestations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    attester_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    attestation_type = Column(
        String(20), nullable=False,
    )  # "competent", "reliable", "safe", "responsive"
    context = Column(String(100), nullable=True)  # e.g. "code_review", "data_analysis"
    weight = Column(Float, nullable=False, default=0.5)  # attester's trust score at creation
    comment = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    attester = relationship("Entity", foreign_keys=[attester_entity_id])
    target = relationship("Entity", foreign_keys=[target_entity_id])

    __table_args__ = (
        UniqueConstraint(
            "attester_entity_id", "target_entity_id", "attestation_type",
            name="uq_trust_attestation",
        ),
        Index("ix_trust_attestations_target", "target_entity_id"),
        Index("ix_trust_attestations_attester", "attester_entity_id"),
    )


class Review(Base):
    """Review/rating of an entity by another entity."""

    __tablename__ = "reviews"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    reviewer_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    rating = Column(
        Integer,
        CheckConstraint("rating >= 1 AND rating <= 5"),
        nullable=False,
    )
    text = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False,
    )

    target = relationship("Entity", foreign_keys=[target_entity_id])
    reviewer = relationship("Entity", foreign_keys=[reviewer_entity_id])

    __table_args__ = (
        UniqueConstraint(
            "target_entity_id", "reviewer_entity_id",
            name="uq_review_per_pair",
        ),
        Index("ix_reviews_target", "target_entity_id"),
        Index("ix_reviews_reviewer", "reviewer_entity_id"),
    )


class EntityBlock(Base):
    """Entity blocking another entity."""

    __tablename__ = "entity_blocks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    blocker_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    blocked_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    blocker = relationship("Entity", foreign_keys=[blocker_id])
    blocked = relationship("Entity", foreign_keys=[blocked_id])

    __table_args__ = (
        UniqueConstraint(
            "blocker_id", "blocked_id", name="uq_entity_block"
        ),
        Index("ix_entity_blocks_blocker", "blocker_id"),
        Index("ix_entity_blocks_blocked", "blocked_id"),
    )


class Submolt(Base):
    """Topic-based community (like a subreddit)."""

    __tablename__ = "submolts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(50), unique=True, nullable=False)  # slug-like
    display_name = Column(String(100), nullable=False)
    description = Column(Text, default="")
    rules = Column(Text, default="")
    tags = Column(JSONB, default=list)
    created_by = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"),
        nullable=True,
    )
    is_active = Column(Boolean, default=True)
    member_count = Column(Integer, default=0)  # denormalized

    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False,
    )

    creator = relationship("Entity")
    posts = relationship("Post", back_populates="submolt")
    memberships = relationship(
        "SubmoltMembership", back_populates="submolt",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_submolts_name", "name", unique=True),
        Index("ix_submolts_active", "is_active"),
    )


class Conversation(Base):
    """A direct message conversation between two entities."""

    __tablename__ = "conversations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    participant_a_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    participant_b_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    last_message_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    participant_a = relationship("Entity", foreign_keys=[participant_a_id])
    participant_b = relationship("Entity", foreign_keys=[participant_b_id])
    messages = relationship(
        "DirectMessage", back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="DirectMessage.created_at",
    )

    __table_args__ = (
        UniqueConstraint(
            "participant_a_id", "participant_b_id",
            name="uq_conversation_pair",
        ),
        Index("ix_conversations_a", "participant_a_id"),
        Index("ix_conversations_b", "participant_b_id"),
        Index("ix_conversations_last_msg", "last_message_at"),
    )


class DirectMessage(Base):
    """A direct message within a conversation."""

    __tablename__ = "direct_messages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    conversation_id = Column(
        UUID(as_uuid=True), ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=False,
    )
    sender_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    content = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    conversation = relationship("Conversation", back_populates="messages")
    sender = relationship("Entity")

    __table_args__ = (
        Index("ix_dm_conversation", "conversation_id"),
        Index("ix_dm_sender", "sender_id"),
        Index("ix_dm_created_at", "created_at"),
    )


class SubmoltMembership(Base):
    """Membership in a submolt (community)."""

    __tablename__ = "submolt_memberships"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    submolt_id = Column(
        UUID(as_uuid=True), ForeignKey("submolts.id", ondelete="CASCADE"),
        nullable=False,
    )
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    role = Column(
        String(20), default="member", nullable=False,
    )  # "member", "moderator", "owner"
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    submolt = relationship("Submolt", back_populates="memberships")
    entity = relationship("Entity")

    __table_args__ = (
        UniqueConstraint(
            "submolt_id", "entity_id", name="uq_submolt_member"
        ),
        Index("ix_submolt_memberships_submolt", "submolt_id"),
        Index("ix_submolt_memberships_entity", "entity_id"),
    )


class AnalyticsEvent(Base):
    """Lightweight conversion funnel event for guest-to-register tracking."""

    __tablename__ = "analytics_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(String(50), nullable=False)  # guest_page_view, guest_cta_click, etc.
    session_id = Column(String(64), nullable=False)  # anonymous localStorage UUID
    page = Column(String(200), nullable=False)  # URL path where event occurred
    intent = Column(String(50), nullable=True)  # vote, follow, reply, etc.
    referrer = Column(String(500), nullable=True)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True
    )
    extra_metadata = Column(JSONB, default=dict)  # arbitrary event data
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_analytics_event_type", "event_type"),
        Index("ix_analytics_created_at", "created_at"),
        Index("ix_analytics_session_id", "session_id"),
    )


class ModerationAppeal(Base):
    """Appeal against a moderation decision."""

    __tablename__ = "moderation_appeals"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    flag_id = Column(
        UUID(as_uuid=True), ForeignKey("moderation_flags.id", ondelete="CASCADE"),
        nullable=False,
    )
    appellant_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    reason = Column(Text, nullable=False)
    status = Column(String(20), default="pending", nullable=False)  # pending/upheld/overturned
    resolved_by = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True,
    )
    resolution_note = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    flag = relationship("ModerationFlag")
    appellant = relationship("Entity", foreign_keys=[appellant_id])
    resolver = relationship("Entity", foreign_keys=[resolved_by])

    __table_args__ = (
        Index("ix_appeal_flag", "flag_id"),
        Index("ix_appeal_status", "status"),
        Index("ix_appeal_appellant", "appellant_id"),
    )


class FrameworkSecurityScan(Base):
    """Security scan record for framework-imported agents."""

    __tablename__ = "framework_security_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    framework = Column(String(50), nullable=False)  # mcp, openclaw, langchain
    scan_result = Column(String(20), nullable=False)  # clean, warnings, critical
    vulnerabilities = Column(JSONB, default=list)
    scanned_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    entity = relationship("Entity")

    __table_args__ = (
        Index("ix_framework_scans_entity", "entity_id"),
        Index("ix_framework_scans_framework", "framework"),
        Index("ix_framework_scans_scanned_at", "scanned_at"),
    )


class VerificationBadge(Base):
    """Formal verification badge issued to an entity."""

    __tablename__ = "verification_badges"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    badge_type = Column(
        String(50), nullable=False,
    )  # email_verified, identity_verified, capability_audited, agentgraph_verified
    issued_by = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"),
        nullable=True,
    )
    proof_url = Column(String(1000), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    entity = relationship("Entity", foreign_keys=[entity_id])
    issuer = relationship("Entity", foreign_keys=[issued_by])

    __table_args__ = (
        Index("ix_verification_badges_entity", "entity_id"),
        Index("ix_verification_badges_type", "badge_type"),
        Index("ix_verification_badges_active", "is_active"),
    )


class AuditRecord(Base):
    """Formal audit record for an entity."""

    __tablename__ = "audit_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    auditor_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    audit_type = Column(
        String(30), nullable=False,
    )  # security, capability, compliance
    result = Column(
        String(20), nullable=False,
    )  # pass, fail, partial
    findings = Column(JSONB, default=dict, nullable=True)
    report_url = Column(String(1000), nullable=True)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    target = relationship("Entity", foreign_keys=[target_entity_id])
    auditor = relationship("Entity", foreign_keys=[auditor_entity_id])

    __table_args__ = (
        Index("ix_audit_records_target", "target_entity_id"),
        Index("ix_audit_records_auditor", "auditor_entity_id"),
        Index("ix_audit_records_type", "audit_type"),
    )


class PropagationAlert(Base):
    """Network-wide safety alert record."""

    __tablename__ = "propagation_alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_type = Column(String(50), nullable=False)  # "freeze", "quarantine", "network_alert"
    severity = Column(String(20), nullable=False)  # "info", "warning", "critical"
    message = Column(Text, nullable=False)
    issued_by = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True,
    )
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    issuer = relationship("Entity", foreign_keys=[issued_by])

    __table_args__ = (
        Index("ix_propagation_alerts_type", "alert_type"),
        Index("ix_propagation_alerts_resolved", "is_resolved"),
        Index("ix_propagation_alerts_created", "created_at"),
    )


class Organization(Base):
    """Organization for grouping entities under enterprise management."""

    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False)
    display_name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    settings = Column(JSONB, default=dict)  # org-level config
    tier = Column(String(20), default="free", nullable=False)  # "free", "pro", "enterprise"
    is_active = Column(Boolean, default=True)
    created_by = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="RESTRICT"), nullable=False,
    )
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    creator = relationship("Entity", foreign_keys=[created_by])
    memberships = relationship(
        "OrganizationMembership", back_populates="organization", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_organizations_name", "name", unique=True),
        Index("ix_organizations_active", "is_active"),
        Index("ix_organizations_tier", "tier"),
    )


class OrganizationMembership(Base):
    """Membership linking an entity to an organization with a specific role."""

    __tablename__ = "organization_memberships"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    role = Column(Enum(OrgRole), default=OrgRole.MEMBER, nullable=False)
    joined_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    organization = relationship("Organization", back_populates="memberships")
    entity = relationship("Entity")

    __table_args__ = (
        UniqueConstraint("organization_id", "entity_id", name="uq_org_membership"),
        Index("ix_org_memberships_org", "organization_id"),
        Index("ix_org_memberships_entity", "entity_id"),
    )


class OrgUsageRecord(Base):
    """Usage metering record for enterprise organizations."""

    __tablename__ = "org_usage_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    period_start = Column(DateTime(timezone=True), nullable=False)
    period_end = Column(DateTime(timezone=True), nullable=False)
    api_calls = Column(Integer, default=0)
    storage_bytes = Column(Integer, default=0)
    active_agents = Column(Integer, default=0)
    active_members = Column(Integer, default=0)
    extra_metadata = Column(JSONB, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    organization = relationship("Organization")

    __table_args__ = (
        UniqueConstraint("organization_id", "period_start", name="uq_org_usage_period"),
        Index("ix_usage_org", "organization_id"),
        Index("ix_usage_period", "period_start", "period_end"),
    )


class DelegationStatus(str, enum.Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class Delegation(Base):
    """AIP delegation: a task delegated from one entity to another."""

    __tablename__ = "delegations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    delegator_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    delegate_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    task_description = Column(Text, nullable=False)
    constraints = Column(JSONB, default=dict)
    status = Column(String(20), default="pending", nullable=False)
    result = Column(JSONB, nullable=True)
    correlation_id = Column(String(64), unique=True, nullable=False)
    timeout_at = Column(DateTime(timezone=True), nullable=True)
    accepted_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False,
    )

    # Recurring delegation fields
    recurrence = Column(String(20), nullable=True)  # null=one-shot, "daily", "weekly", "monthly"
    recurrence_count = Column(Integer, default=0, nullable=False, server_default="0")
    max_recurrences = Column(Integer, nullable=True)  # null = unlimited
    parent_delegation_id = Column(
        UUID(as_uuid=True), ForeignKey("delegations.id", ondelete="SET NULL"),
        nullable=True,
    )

    delegator = relationship("Entity", foreign_keys=[delegator_entity_id])
    delegate = relationship("Entity", foreign_keys=[delegate_entity_id])
    parent_delegation = relationship(
        "Delegation", remote_side="Delegation.id", foreign_keys=[parent_delegation_id],
    )

    __table_args__ = (
        Index("ix_delegations_delegator", "delegator_entity_id"),
        Index("ix_delegations_delegate", "delegate_entity_id"),
        Index("ix_delegations_status", "status"),
        Index("ix_delegations_correlation", "correlation_id"),
        Index("ix_delegations_parent", "parent_delegation_id"),
        Index("ix_delegations_recurrence", "recurrence"),
    )


class ServiceContract(Base):
    """Service contract between a provider and consumer entity."""

    __tablename__ = "service_contracts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    provider_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    consumer_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    listing_id = Column(
        UUID(as_uuid=True), ForeignKey("listings.id", ondelete="SET NULL"),
        nullable=True,
    )
    terms = Column(JSONB, nullable=True)
    status = Column(String(20), default="active", nullable=False)  # active, paused, terminated
    paused_by = Column(UUID(as_uuid=True), nullable=True)  # who paused it
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False,
    )
    terminated_at = Column(DateTime(timezone=True), nullable=True)

    provider = relationship("Entity", foreign_keys=[provider_entity_id])
    consumer = relationship("Entity", foreign_keys=[consumer_entity_id])
    listing = relationship("Listing", foreign_keys=[listing_id])

    __table_args__ = (
        Index("ix_service_contracts_provider", "provider_entity_id"),
        Index("ix_service_contracts_consumer", "consumer_entity_id"),
        Index("ix_service_contracts_status", "status"),
        Index("ix_service_contracts_listing", "listing_id"),
    )


class AgentCapabilityRegistry(Base):
    """AIP capability registry: capabilities an agent exposes for discovery."""

    __tablename__ = "agent_capability_registry"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    capability_name = Column(String(200), nullable=False)
    version = Column(String(50), default="1.0.0")
    description = Column(Text, default="")
    input_schema = Column(JSONB, default=dict)
    output_schema = Column(JSONB, default=dict)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False,
    )

    entity = relationship("Entity")

    __table_args__ = (
        UniqueConstraint("entity_id", "capability_name", name="uq_entity_capability"),
        Index("ix_cap_registry_entity", "entity_id"),
        Index("ix_cap_registry_name", "capability_name"),
        Index("ix_cap_registry_active", "is_active"),
    )


class AnomalyAlert(Base):
    """Anomaly detection alert for suspicious entity behavior."""

    __tablename__ = "anomaly_alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    alert_type = Column(
        String(50), nullable=False,
    )  # "trust_velocity", "relationship_churn", "cluster_anomaly"
    severity = Column(
        String(20), nullable=False,
    )  # "low", "medium", "high"
    z_score = Column(Float, nullable=False)
    details = Column(JSONB, default=dict)
    is_resolved = Column(Boolean, default=False)
    resolved_by = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"),
        nullable=True,
    )
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    entity = relationship("Entity", foreign_keys=[entity_id])
    resolver = relationship("Entity", foreign_keys=[resolved_by])

    __table_args__ = (
        Index("ix_anomaly_alerts_entity", "entity_id"),
        Index("ix_anomaly_alerts_type", "alert_type"),
        Index("ix_anomaly_alerts_resolved", "is_resolved"),
        Index("ix_anomaly_alerts_created", "created_at"),
    )


class PopulationAlert(Base):
    """Population composition monitoring alert.

    Detects Sybil attacks, framework monoculture, operator floods, and
    registration spikes at the platform level (not tied to a single entity).
    """

    __tablename__ = "population_alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_type = Column(
        String(50), nullable=False, index=True,
    )  # "framework_monoculture", "operator_flood", "registration_spike", "sybil_cluster"
    severity = Column(
        String(20), nullable=False,
    )  # "low", "medium", "high"
    details = Column(JSONB, nullable=True)
    is_resolved = Column(Boolean, default=False, nullable=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    __table_args__ = (
        Index("ix_population_alerts_type", "alert_type"),
        Index("ix_population_alerts_resolved", "is_resolved"),
        Index("ix_population_alerts_created", "created_at"),
    )


class InteractionEvent(Base):
    """Unified pairwise interaction event for tracking all entity-to-entity interactions."""

    __tablename__ = "interaction_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_a_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    entity_b_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    interaction_type = Column(
        String(50), nullable=False, index=True,
    )  # "follow", "unfollow", "attestation", "endorsement", "delegation",
    #    "vote", "reply", "dm", "review", "block"
    context = Column(JSONB, nullable=True)  # stores reference_id, additional metadata
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True,
    )

    entity_a = relationship("Entity", foreign_keys=[entity_a_id])
    entity_b = relationship("Entity", foreign_keys=[entity_b_id])

    __table_args__ = (
        Index("ix_interaction_pairwise", "entity_a_id", "entity_b_id", "interaction_type"),
        Index("ix_interaction_entity_a", "entity_a_id"),
        Index("ix_interaction_entity_b", "entity_b_id"),
        Index("ix_interaction_type", "interaction_type"),
        Index("ix_interaction_created_at", "created_at"),
    )


class BehavioralBaseline(Base):
    """Rolling behavioral baseline metrics for an entity over a time period.

    Captures aggregated activity metrics (posts, votes, follows, attestations, etc.)
    to enable future shaping-dynamics detection.  No alerting or anomaly detection
    logic lives here — this is pure data collection.
    """

    __tablename__ = "behavioral_baselines"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    period_start = Column(Date, nullable=False)
    period_end = Column(Date, nullable=False)
    metrics = Column(JSONB, nullable=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    entity = relationship("Entity", foreign_keys=[entity_id])

    __table_args__ = (
        Index("ix_behavioral_baselines_entity", "entity_id"),
        Index("ix_behavioral_baselines_period", "period_start", "period_end"),
    )


class ContentLink(Base):
    """Cross-reference between content items (posts, entities, evolution records, listings).

    Enables a rich graph of related content: @mentions auto-detected in posts,
    explicit references, editorial "related" links, and replies_about links.
    """

    __tablename__ = "content_links"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_type = Column(
        String(30), nullable=False,
    )  # "post", "entity", "evolution_record", "listing"
    source_id = Column(UUID(as_uuid=True), nullable=False)
    target_type = Column(
        String(30), nullable=False,
    )  # "post", "entity", "evolution_record", "listing"
    target_id = Column(UUID(as_uuid=True), nullable=False)
    link_type = Column(
        String(30), nullable=False,
    )  # "mentions", "references", "related", "replies_about"
    created_by = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    creator = relationship("Entity", foreign_keys=[created_by])

    __table_args__ = (
        CheckConstraint(
            "source_type IN ('post', 'entity', 'evolution_record', 'listing')",
            name="ck_content_link_source_type",
        ),
        CheckConstraint(
            "target_type IN ('post', 'entity', 'evolution_record', 'listing')",
            name="ck_content_link_target_type",
        ),
        CheckConstraint(
            "link_type IN ('mentions', 'references', 'related', 'replies_about')",
            name="ck_content_link_link_type",
        ),
        UniqueConstraint(
            "source_type", "source_id", "target_type", "target_id", "link_type",
            name="uq_content_link",
        ),
        Index("ix_content_links_source", "source_type", "source_id"),
        Index("ix_content_links_target", "target_type", "target_id"),
        Index("ix_content_links_created_by", "created_by"),
        Index("ix_content_links_link_type", "link_type"),
        Index("ix_content_links_created_at", "created_at"),
    )


class FormalAttestation(Base):
    """Formal attestation issued by one entity about another.

    Unlike lightweight TrustAttestations (competent/reliable/safe/responsive),
    formal attestations represent structured, typed verification claims such as
    identity_verified, capability_certified, security_audited, operator_verified,
    and community_endorsed.  They can carry evidence text, expire, and be revoked.
    """

    __tablename__ = "formal_attestations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    issuer_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    subject_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    attestation_type = Column(
        String(50), nullable=False,
    )  # identity_verified, capability_certified, security_audited, etc.
    evidence = Column(Text, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    issuer = relationship("Entity", foreign_keys=[issuer_entity_id])
    subject = relationship("Entity", foreign_keys=[subject_entity_id])

    __table_args__ = (
        UniqueConstraint(
            "issuer_entity_id", "subject_entity_id", "attestation_type",
            name="uq_formal_attestation",
        ),
        Index("ix_formal_attestations_issuer", "issuer_entity_id"),
        Index("ix_formal_attestations_subject", "subject_entity_id"),
        Index("ix_formal_attestations_type", "attestation_type"),
        Index("ix_formal_attestations_revoked", "is_revoked"),
    )


class AttestationProvider(Base):
    """External attestation provider that can submit verified attestations.

    Providers register, get an API key, and once admin-approved can submit
    formal attestations on behalf of their operator entity.
    """

    __tablename__ = "attestation_providers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    operator_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider_name = Column(String(200), nullable=False, unique=True)
    provider_url = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)
    supported_types = Column(JSONB, default=list)  # list of attestation_type strings
    api_key_hash = Column(String(128), nullable=False)
    is_active = Column(Boolean, default=False, nullable=False)
    attestation_count = Column(Integer, default=0, nullable=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(),
        nullable=False,
    )

    operator = relationship("Entity", foreign_keys=[operator_entity_id])

    __table_args__ = (
        Index("ix_attestation_providers_operator", "operator_entity_id"),
        Index("ix_attestation_providers_active", "is_active"),
    )


class AIPChannel(Base):
    """AIP v2 named channel for multi-party agent communication."""

    __tablename__ = "aip_channels"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    created_by_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    participant_ids = Column(JSONB, default=list)  # list of UUID strings
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(),
        nullable=False,
    )

    creator = relationship("Entity", foreign_keys=[created_by_entity_id])

    __table_args__ = (
        Index("ix_aip_channels_created_by", "created_by_entity_id"),
    )


class AIPMessage(Base):
    """AIP v2 direct agent-to-agent message with trust capture."""

    __tablename__ = "aip_messages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sender_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    recipient_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=True,  # null for channel-only messages
    )
    channel_id = Column(
        UUID(as_uuid=True), ForeignKey("aip_channels.id", ondelete="CASCADE"),
        nullable=True,
    )
    message_type = Column(
        String(20), nullable=False,
    )  # "request", "response", "event", "notification"
    payload = Column(JSONB, default=dict)
    sender_trust_score = Column(Float, nullable=True)
    is_read = Column(Boolean, default=False, nullable=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    sender = relationship("Entity", foreign_keys=[sender_entity_id])
    recipient = relationship("Entity", foreign_keys=[recipient_entity_id])
    channel = relationship("AIPChannel", foreign_keys=[channel_id])

    __table_args__ = (
        Index("ix_aip_messages_sender", "sender_entity_id"),
        Index("ix_aip_messages_recipient", "recipient_entity_id"),
        Index("ix_aip_messages_channel", "channel_id"),
        Index("ix_aip_messages_created_at", "created_at"),
    )


class IssueReport(Base):
    """Bug report or feature request tracked by platform bots."""

    __tablename__ = "issue_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    post_id = Column(
        UUID(as_uuid=True), ForeignKey("posts.id", ondelete="CASCADE"),
        nullable=False,
    )
    bot_reply_id = Column(
        UUID(as_uuid=True), ForeignKey("posts.id", ondelete="SET NULL"),
        nullable=True,
    )
    reporter_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    bot_entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    issue_type = Column(String(20), nullable=False)  # "bug" or "feature"
    status = Column(
        String(20), default=IssueStatus.OPEN.value, nullable=False,
    )
    title = Column(String(255), nullable=False)
    resolution_note = Column(Text, nullable=True)
    resolved_by = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"),
        nullable=True,
    )
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolution_reply_id = Column(
        UUID(as_uuid=True), ForeignKey("posts.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False,
    )

    post = relationship("Post", foreign_keys=[post_id])
    bot_reply = relationship("Post", foreign_keys=[bot_reply_id])
    reporter = relationship("Entity", foreign_keys=[reporter_entity_id])
    bot = relationship("Entity", foreign_keys=[bot_entity_id])
    resolver = relationship("Entity", foreign_keys=[resolved_by])
    resolution_reply = relationship("Post", foreign_keys=[resolution_reply_id])

    __table_args__ = (
        Index("ix_issue_reports_status", "status"),
        Index("ix_issue_reports_reporter", "reporter_entity_id"),
        Index("ix_issue_reports_type_status", "issue_type", "status"),
    )


class LinkedAccount(Base):
    """External account linked to an entity for reputation aggregation."""

    __tablename__ = "linked_accounts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider = Column(String(50), nullable=False)  # "github", "npm", "pypi", "huggingface"
    provider_user_id = Column(String(255), nullable=False)
    provider_username = Column(String(255), nullable=True)
    verification_status = Column(
        String(30), default="pending", nullable=False,
    )  # "pending", "verified_oauth", "verified_challenge", "unverified_claim"
    access_token = Column(String(500), nullable=True)  # encrypted
    refresh_token = Column(String(500), nullable=True)  # encrypted
    token_expires_at = Column(DateTime(timezone=True), nullable=True)
    profile_data = Column(JSONB, default=dict)  # raw API snapshot
    reputation_data = Column(JSONB, default=dict)  # computed metrics
    reputation_score = Column(Float, default=0.0)  # 0.0–1.0 normalized
    last_synced_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False,
    )

    entity = relationship("Entity")

    __table_args__ = (
        UniqueConstraint("entity_id", "provider", name="uq_linked_account_provider"),
        Index("ix_linked_accounts_entity", "entity_id"),
        Index("ix_linked_accounts_provider", "provider"),
    )


class ApiHealthCheck(Base):
    """API endpoint health monitoring for agents with API-only presence."""

    __tablename__ = "api_health_checks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    endpoint_url = Column(String(1000), nullable=False)
    is_active = Column(Boolean, server_default="true", nullable=False)
    last_status = Column(Integer, nullable=True)
    last_response_ms = Column(Integer, nullable=True)
    last_checked_at = Column(DateTime(timezone=True), nullable=True)
    uptime_pct_30d = Column(Float, default=0.0)
    total_checks = Column(Integer, default=0)
    successful_checks = Column(Integer, default=0)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False,
    )

    entity = relationship("Entity")

    __table_args__ = (
        Index("ix_api_health_checks_entity", "entity_id"),
        Index("ix_api_health_checks_active", "is_active"),
    )


class RecruitmentProspect(Base):
    """Tracks discovered repos/packages for operator recruitment outreach."""

    __tablename__ = "recruitment_prospects"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    platform = Column(String(50), nullable=False)  # github, npm, pypi, etc.
    platform_id = Column(String(500), nullable=False)  # repo full_name or package name
    owner_login = Column(String(200), nullable=False)
    repo_name = Column(String(500))
    stars = Column(Integer, default=0)
    description = Column(Text)
    framework_detected = Column(String(100))
    status = Column(String(50), default="discovered")
    contacted_at = Column(DateTime(timezone=True))
    issue_url = Column(String(500))
    notes = Column(Text)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False,
    )

    __table_args__ = (
        UniqueConstraint("platform", "platform_id", name="uq_recruitment_platform_id"),
        Index("ix_recruitment_status", "status"),
        Index("ix_recruitment_owner", "owner_login"),
    )


class ReplyTarget(Base):
    """Account to monitor for reply opportunities."""

    __tablename__ = "reply_targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    platform = Column(String(50), nullable=False)  # twitter, bluesky
    handle = Column(String(200), nullable=False)
    display_name = Column(String(300))
    follower_count = Column(Integer, default=0)
    priority_tier = Column(Integer, default=2)  # 1=must-reply, 2=high, 3=nice-to-have
    topics = Column(JSONB, default=list)  # e.g. ["ai agents", "mcp", "langchain"]
    is_active = Column(Boolean, default=True, nullable=False)
    last_checked_at = Column(DateTime(timezone=True))
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    opportunities = relationship("ReplyOpportunity", back_populates="target")

    __table_args__ = (
        UniqueConstraint("platform", "handle", name="uq_reply_target_platform_handle"),
        Index("ix_reply_target_active_tier", "is_active", "priority_tier"),
    )


class ReplyOpportunity(Base):
    """A detected post from a monitored account -- potential reply opportunity."""

    __tablename__ = "reply_opportunities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(
        UUID(as_uuid=True), ForeignKey("reply_targets.id"), nullable=False,
    )
    platform = Column(String(50), nullable=False)
    post_uri = Column(String(500), nullable=False)
    post_content = Column(Text)
    post_timestamp = Column(DateTime(timezone=True), nullable=False)
    status = Column(
        String(50), default="new", nullable=False,
    )  # new, drafted, approved, posted, skipped
    draft_content = Column(Text)
    drafted_at = Column(DateTime(timezone=True))
    posted_at = Column(DateTime(timezone=True))
    reply_url = Column(String(500))
    urgency_score = Column(Float, default=0.0)
    engagement_count = Column(Integer, default=0)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    target = relationship("ReplyTarget", back_populates="opportunities")

    __table_args__ = (
        UniqueConstraint("platform", "post_uri", name="uq_reply_opportunity_post"),
        Index("ix_reply_opp_status_urgency", "status", "urgency_score"),
        Index("ix_reply_opp_target", "target_id", "post_timestamp"),
    )


class WalletBinding(Base):
    """Maps blockchain wallet addresses to entities for cross-provider lookup.

    Used by the insumer multi-attestation WG: a single wallet address
    resolves to an entity → linked accounts → source repos → scan data.
    """

    __tablename__ = "wallet_bindings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    wallet_address = Column(String(255), nullable=False)
    chain = Column(String(50), nullable=False)  # "ethereum", "solana", "base", etc.
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    entity = relationship("Entity")

    __table_args__ = (
        UniqueConstraint("wallet_address", "chain", name="uq_wallet_binding"),
        Index("ix_wallet_binding_address", "wallet_address"),
        Index("ix_wallet_binding_entity", "entity_id"),
    )


class ProviderIdMapping(Base):
    """Maps AgentGraph entity IDs to external provider-specific IDs.

    Enables the gateway to query RNWY, MoltBridge, AgentID etc. with
    the correct identifier for each provider.
    """

    __tablename__ = "provider_id_mappings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider = Column(String(50), nullable=False)  # "rnwy", "moltbridge", "agentid"
    provider_entity_id = Column(String(255), nullable=False)  # provider's ID for this entity
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    entity = relationship("Entity")

    __table_args__ = (
        UniqueConstraint("entity_id", "provider", name="uq_provider_id_mapping"),
        Index("ix_provider_id_entity", "entity_id"),
        Index("ix_provider_id_provider", "provider", "provider_entity_id"),
    )


class AggregateEnvelope(Base):
    """Persisted Trust Score v2 signed envelope (design §5.2).

    The durable store behind the /aggregate surface: one row per subject DID
    holding the latest signed envelope JSON, its score, and freshness window.
    Complements the Redis cache (the hot path) — this is the source of truth
    that survives Redis flushes, backs event-driven recompute, and lets the Q3
    paper count envelopes issued. Writes are best-effort from the endpoint;
    absence of a row simply means "recompute".
    """

    __tablename__ = "aggregate_envelopes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subject_did = Column(String(500), nullable=False, unique=True)
    trust_score = Column(Float, nullable=False)
    score_version = Column(String(10), nullable=False)
    envelope = Column(JSONB, nullable=False)  # full signed v2 envelope
    computed_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(),
        onupdate=func.now(), nullable=False,
    )

    __table_args__ = (
        Index("ix_aggregate_envelopes_subject", "subject_did"),
        Index("ix_aggregate_envelopes_expires", "expires_at"),
    )


class ToolWatch(Base):
    """A user watching a tool/repo for grade or signed-definition changes (rug-pull alerts)."""

    __tablename__ = "tool_watches"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    watcher_id = Column(
        UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Multi-surface: 'github' (owner/repo) · 'npm'/'pypi' (repo = package name) ·
    # 'mcp' (repo = endpoint URL) · 'openclaw' (owner/repo skill). Default github
    # so existing rows are unchanged.
    surface = Column(String(16), nullable=False, default="github", server_default="github")
    owner = Column(String(255), nullable=False)
    repo = Column(String(512), nullable=False)
    last_score = Column(Integer, nullable=True)
    last_manifest_digest = Column(String(128), nullable=True)
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_checked_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # surface is part of the key: the same owner/repo can be watched both as a
        # github repo and as an openclaw skill (they share coordinates).
        UniqueConstraint("watcher_id", "surface", "owner", "repo", name="uq_tool_watch_target"),
    )


class RepoClaim(Base):
    """A user's claim of ownership of a tool, across every graded surface. A verified
    claim unlocks the fix-it report, responding to findings, and (GitHub) private
    scans. Proof is out-of-band per surface — no token stored:
      github/openclaw → GitHub topic or App install (a skill IS a repo)
      npm/pypi        → link back to a claimed repo (provenance/declared) or a
                        published keyword challenge
      mcp             → a challenge returned by the endpoint (header / serverInfo)."""

    __tablename__ = "repo_claims"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Multi-surface coordinate (mirrors ToolWatch): github/openclaw → owner/repo ·
    # npm/pypi → owner=surface, repo=package · mcp → owner='mcp', repo=endpoint URL.
    surface = Column(String(16), nullable=False, default="github", server_default="github")
    owner = Column(String(255), nullable=False)
    repo = Column(String(512), nullable=False)  # 512 so an MCP endpoint URL fits
    full_name = Column(String(512), nullable=False)
    status = Column(String(20), default="pending", nullable=False)  # pending | verified
    verify_code = Column(String(64), nullable=False)
    # How ownership was proven — for display/audit. topic|token|app (github/openclaw)
    # · provenance|declared-repo|keyword (npm/pypi) · mcp-challenge (mcp).
    proof_method = Column(String(24), nullable=True)
    # Whether the claimed repo is PRIVATE (via GitHub App / token). Authoritative,
    # set at claim time — public (topic-proof) claims are always False. Drives the
    # "publish to search" affordance (public repos are auto-listed; private ones
    # are listed only on explicit publish). Registry/MCP surfaces are always public.
    is_private = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    verified_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # surface is part of the key: a github repo and an openclaw skill can share
        # owner/repo coordinates without colliding (same lesson as ToolWatch/t16).
        UniqueConstraint("entity_id", "surface", "owner", "repo", name="uq_repo_claim_target"),
    )


class GitHubAppInstallation(Base):
    """An owner's installation of the AgentAvow GitHub App, granting scoped
    read-only access to their (public or PRIVATE) repos for scheduled re-scans.
    We store only the installation id — GitHub mints short-lived, auto-rotating
    installation tokens on demand, so no long-lived secret is kept. Revocable by
    the owner in GitHub at any time."""

    __tablename__ = "github_app_installations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    installation_id = Column(String(32), nullable=False, index=True)
    account_login = Column(String(255), nullable=True)  # the GitHub account it's installed on
    account_type = Column(String(20), nullable=True)     # "User" | "Organization"
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("entity_id", "installation_id", name="uq_gh_app_installation"),
    )


class AlertWebhook(Base):
    """Per-account webhook that receives grade-change alerts for the user's watched
    tools. The daily re-scan loop POSTs here when a watched tool's grade drops or its
    signed definition changes — webhook alert-delivery alongside email/in-app."""

    __tablename__ = "alert_webhooks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    url = Column(String(512), nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_delivery_at = Column(DateTime(timezone=True), nullable=True)
    last_status = Column(Integer, nullable=True)


class CommunityScan(Base):
    """A tool someone scanned on-demand — persisted so the catalog grows beyond the
    static launch corpus. Upserted on every fresh scan; surfaced as the 'community'
    surface in the browse catalog. One row per owner/repo (latest scan wins)."""

    __tablename__ = "community_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Multi-surface (mirrors ToolWatch/RepoClaim): github/openclaw → owner/repo ·
    # npm/pypi → owner=surface, repo=package · mcp → owner='mcp', repo=endpoint URL.
    surface = Column(String(16), nullable=False, default="github", server_default="github")
    owner = Column(String(255), nullable=False)
    repo = Column(String(512), nullable=False)  # 512 so an MCP endpoint URL fits
    full_name = Column(String(512), nullable=False, index=True)
    trust_score = Column(Integer, nullable=True)
    # Letter grade WITH the A+ certified gate applied (roadmap §7) — stored so the
    # browse catalog shows the accurate grade instead of deriving A+ from score
    # alone. Null on rows scanned before this column (catalog caps those from score).
    grade = Column(String(4), nullable=True)
    critical = Column(Integer, nullable=True)
    high = Column(Integer, nullable=True)
    findings_count = Column(Integer, nullable=True)
    primary_language = Column(String(120), nullable=True)
    scan_count = Column(Integer, default=1, nullable=False)
    # Adoption ("do real, independent parties rely on this?") — DISTINCT from the trust
    # grade. Populated by the catalog re-scan loop (not every live capture, to keep
    # scans fast). Powers the "Widely relied upon" browse filter/sort. Nullable =
    # not yet computed. adoption_count is the headline number (downloads/wk or stars).
    adoption_score = Column(Integer, nullable=True)          # 0-100 adoption tier score
    adoption_count = Column(BigInteger, nullable=True)       # headline count (dl/wk, stars)
    adoption_unit = Column(String(24), nullable=True)        # 'downloads/wk' | 'stars' | …
    first_scanned_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_scanned_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        # surface in the key so a github repo and an openclaw skill sharing
        # owner/repo don't collide (same lesson as t16/t17).
        UniqueConstraint("surface", "owner", "repo", name="uq_community_scan_target"),
    )


class PrivateScanResult(Base):
    """The stored result of a scheduled PRIVATE-repo scan run via a connected
    GitHub App installation. Owner-scoped and NEVER surfaced in the public catalog
    or search — unlike CommunityScan, this row is only ever returned to the account
    that owns the installation.

    ``result_json`` stores the full ``_scan_result_to_dict`` output so the frontend
    "View report" can re-render the report offline without re-scanning. ``prev_score``
    holds the previous scan's trust_score so the re-scan loop can detect drops /
    improvements. One row per (entity, owner, repo) — the latest scan wins."""

    __tablename__ = "private_scan_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(
        UUID(as_uuid=True),
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    owner = Column(String(255), nullable=False)
    repo = Column(String(255), nullable=False)
    full_name = Column(String(512), nullable=False)
    trust_score = Column(Integer, nullable=True)
    grade = Column(String(4), nullable=True)
    # Full _scan_result_to_dict output — lets the report re-render without re-scan.
    result_json = Column(JSONB, nullable=True)
    prev_score = Column(Integer, nullable=True)  # previous trust_score (change detection)
    source = Column(String(16), default="app", nullable=False)  # "app" (GitHub App install)
    # Owner opted to publish this private repo's grade to the public catalog/search.
    published = Column(Boolean, default=False, server_default="false", nullable=False)
    scanned_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("entity_id", "owner", "repo", name="uq_private_scan_target"),
    )


# Import marketing models so Alembic can discover them
from src.marketing.models import MarketingCampaign, MarketingPost  # noqa: E402, F401
